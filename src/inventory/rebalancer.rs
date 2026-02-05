//! Threshold-based rebalance planner.
//!
//! Generates rebalancing plans when inventory skew exceeds threshold.
//! Plans only — does NOT execute transfers.

use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::collections::HashMap;

use super::tracker::InventoryTracker;
use super::types::Venue;

/// A planned transfer between venues.
#[derive(Debug, Clone)]
pub struct TransferPlan {
    pub from_venue: Venue,
    pub to_venue: Venue,
    pub asset: String,
    /// Gross amount sent (before fee deduction at receiver).
    pub amount: Decimal,
    pub estimated_fee: Decimal,
    pub estimated_time_min: u32,
}

impl TransferPlan {
    /// Amount received after fees.
    pub fn net_amount(&self) -> Decimal {
        self.amount - self.estimated_fee
    }
}

/// Transfer fee config for estimation (testnet / hardcoded).
#[derive(Debug, Clone)]
pub struct TransferFeeConfig {
    pub withdrawal_fee: Decimal,
    pub min_withdrawal: Decimal,
    pub estimated_time_min: u32,
}

fn get_transfer_fee(asset: &str) -> Option<TransferFeeConfig> {
    match asset {
        "ETH" => Some(TransferFeeConfig {
            withdrawal_fee: dec!(0.005),
            min_withdrawal: dec!(0.01),
            estimated_time_min: 15,
        }),
        "USDT" => Some(TransferFeeConfig {
            withdrawal_fee: dec!(1.0),
            min_withdrawal: dec!(10.0),
            estimated_time_min: 15,
        }),
        "USDC" => Some(TransferFeeConfig {
            withdrawal_fee: dec!(1.0),
            min_withdrawal: dec!(10.0),
            estimated_time_min: 15,
        }),
        _ => None,
    }
}

fn get_min_operating_balance(asset: &str) -> Decimal {
    match asset {
        "ETH" => dec!(0.5),
        "USDT" | "USDC" => dec!(500),
        _ => dec!(0),
    }
}

/// Result of skew check for a single asset.
#[derive(Debug, Clone)]
pub struct AssetSkewCheck {
    pub asset: String,
    pub max_deviation_pct: Decimal,
    pub needs_rebalance: bool,
}

/// Cost estimate for executing rebalance plans.
#[derive(Debug, Clone)]
pub struct CostEstimate {
    pub total_transfers: usize,
    pub total_fees_usd: Decimal,
    pub total_time_min: u32,
    pub assets_affected: Vec<String>,
}

/// Generates rebalancing plans when inventory skew exceeds threshold.
/// Plans only — does NOT execute transfers.
pub struct RebalancePlanner<'a> {
    tracker: &'a InventoryTracker,
    threshold_pct: f64,
    target_ratio: Option<HashMap<Venue, f64>>,
}

impl<'a> RebalancePlanner<'a> {
    /// Create planner with tracker reference.
    /// `threshold_pct`: rebalance when deviation > this (default 30.0).
    /// `target_ratio`: optional per-venue target ratio; if None, equal split.
    pub fn new(
        tracker: &'a InventoryTracker,
        threshold_pct: f64,
        target_ratio: Option<HashMap<Venue, f64>>,
    ) -> Self {
        Self {
            tracker,
            threshold_pct,
            target_ratio,
        }
    }

    /// Check all tracked assets for skew.
    /// Returns list of assets with their skew status.
    pub fn check_all(&self) -> Vec<AssetSkewCheck> {
        let snapshot = self.tracker.snapshot(None);
        let threshold = Decimal::try_from(self.threshold_pct).unwrap_or(dec!(30));

        snapshot
            .totals
            .keys()
            .map(|asset| {
                let skew = self.tracker.skew(asset);
                let needs_rebalance =
                    !skew.total.is_zero() && skew.max_deviation_pct >= threshold;
                AssetSkewCheck {
                    asset: asset.clone(),
                    max_deviation_pct: skew.max_deviation_pct,
                    needs_rebalance,
                }
            })
            .collect()
    }

    /// Generate transfer plan to rebalance a specific asset.
    /// Returns empty list if no rebalance needed or constraints cannot be met.
    pub fn plan(&self, asset: &str) -> Vec<TransferPlan> {
        let skew = self.tracker.skew(asset);
        let threshold = Decimal::try_from(self.threshold_pct).unwrap_or(dec!(30));
        if skew.total.is_zero() || skew.max_deviation_pct < threshold {
            return vec![];
        }

        let fee_config = match get_transfer_fee(asset) {
            Some(c) => c,
            None => return vec![],
        };
        let min_operating = get_min_operating_balance(asset);

        let venue_list = Self::parse_venue_amounts(&skew.venues);
        let [a, b] = venue_list.as_slice() else {
            return vec![];
        };

        let (target_a, target_b) = self.target_amounts(&[a.0, b.0], skew.total);
        let (from_venue, to_venue, surplus, deficit_needed) =
            match Self::find_surplus_deficit(*a, *b, target_a, target_b) {
                Some(x) => x,
                None => return vec![],
            };

        let from_amount = self.tracker.get_available(from_venue, asset);
        let gross = match Self::compute_gross_transfer(
            surplus,
            deficit_needed,
            from_amount,
            min_operating,
            &fee_config,
        ) {
            Some(g) => g,
            None => return vec![],
        };

        vec![TransferPlan {
            from_venue,
            to_venue,
            asset: asset.to_string(),
            amount: gross,
            estimated_fee: fee_config.withdrawal_fee,
            estimated_time_min: fee_config.estimated_time_min,
        }]
    }

    fn parse_venue_amounts(venues: &HashMap<String, super::types::VenueSkew>) -> Vec<(Venue, Decimal)> {
        venues
            .iter()
            .filter_map(|(name, v)| {
                let venue = match name.as_str() {
                    "binance" => Venue::Binance,
                    "wallet" => Venue::Wallet,
                    _ => return None,
                };
                Some((venue, v.amount))
            })
            .collect()
    }

    fn find_surplus_deficit(
        (venue_a, amount_a): (Venue, Decimal),
        (venue_b, amount_b): (Venue, Decimal),
        target_a: Decimal,
        target_b: Decimal,
    ) -> Option<(Venue, Venue, Decimal, Decimal)> {
        if amount_a > target_a && amount_b < target_b {
            Some((venue_a, venue_b, amount_a - target_a, target_b - amount_b))
        } else if amount_b > target_b && amount_a < target_a {
            Some((venue_b, venue_a, amount_b - target_b, target_a - amount_a))
        } else {
            None
        }
    }

    fn compute_gross_transfer(
        surplus: Decimal,
        deficit_needed: Decimal,
        from_amount: Decimal,
        min_operating: Decimal,
        fee_config: &TransferFeeConfig,
    ) -> Option<Decimal> {
        let max_sendable = from_amount - min_operating;
        if max_sendable <= Decimal::ZERO {
            return None;
        }
        let net_to_move = surplus.min(deficit_needed).min(max_sendable);
        if net_to_move <= Decimal::ZERO {
            return None;
        }
        let gross = net_to_move + fee_config.withdrawal_fee;
        if gross < fee_config.min_withdrawal {
            return None;
        }
        if from_amount - gross < min_operating {
            return None;
        }
        Some(gross)
    }

    fn target_amounts(&self, venues: &[Venue], total: Decimal) -> (Decimal, Decimal) {
        let n = venues.len() as u32;
        match &self.target_ratio {
            Some(ratio) => {
                let r0 = Decimal::try_from(*ratio.get(&venues[0]).unwrap_or(&0.5))
                    .unwrap_or(dec!(0.5));
                let r1 = Decimal::try_from(*ratio.get(&venues[1]).unwrap_or(&0.5))
                    .unwrap_or(dec!(0.5));
                let sum = r0 + r1;
                let norm0 = if sum.is_zero() { dec!(0.5) } else { r0 / sum };
                let norm1 = if sum.is_zero() { dec!(0.5) } else { r1 / sum };
                (total * norm0, total * norm1)
            }
            None => {
                let equal = Decimal::from(100) / Decimal::from(n) / Decimal::from(100);
                (total * equal, total * equal)
            }
        }
    }

    /// Generate rebalancing plans for all skewed assets.
    pub fn plan_all(&self) -> HashMap<String, Vec<TransferPlan>> {
        let checks = self.check_all();
        let mut result = HashMap::new();
        for check in checks {
            if check.needs_rebalance {
                let plans = self.plan(&check.asset);
                if !plans.is_empty() {
                    result.insert(check.asset, plans);
                }
            }
        }
        result
    }

    /// Estimate total cost of executing rebalance plans.
    /// Uses fixed ETH price ~2000 for fee-to-USD conversion.
    pub fn estimate_cost(&self, plans: &[TransferPlan]) -> CostEstimate {
        let eth_price_usd = Decimal::from(2000);

        let total_transfers = plans.len();
        let mut total_fees_usd = Decimal::ZERO;
        let mut max_time = 0u32;
        let mut assets: Vec<String> = Vec::with_capacity(plans.len());

        for p in plans {
            total_fees_usd += match p.asset.as_str() {
                "ETH" => p.estimated_fee * eth_price_usd,
                "USDT" | "USDC" => p.estimated_fee,
                _ => Decimal::ZERO,
            };
            max_time = max_time.max(p.estimated_time_min);
            if !assets.contains(&p.asset) {
                assets.push(p.asset.clone());
            }
        }

        CostEstimate {
            total_transfers,
            total_fees_usd,
            total_time_min: max_time,
            assets_affected: assets,
        }
    }
}
