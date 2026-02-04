//! Multi-venue position tracker.
//!
//! Tracks positions across CEX and DEX venues. Single source of truth for where your money is.

use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::collections::{HashMap, HashSet};

use crate::exchange::AssetBalance;
use super::errors::InventoryTrackerError;
use super::types::{
    CanExecuteResult, PortfolioSnapshot, SkewResult, Venue, VenueSkew,
};
use time::OffsetDateTime;

/// Tracks positions across CEX and DEX venues.
#[derive(Debug)]
pub struct InventoryTracker {
    venues: HashSet<Venue>,
    /// venue -> asset -> balance
    balances: HashMap<Venue, HashMap<String, AssetBalance>>,
}

impl InventoryTracker {
    /// Initialize tracker for given venues. Returns error if venues is empty.
    pub fn new(venues: Vec<Venue>) -> Result<Self, InventoryTrackerError> {
        if venues.is_empty() {
            return Err(InventoryTrackerError::EmptyVenues);
        }
        let venues: HashSet<Venue> = venues.into_iter().collect();
        Ok(Self {
            venues: venues.clone(),
            balances: venues.into_iter().map(|v| (v, HashMap::new())).collect(),
        })
    }

    /// Update balances from ExchangeClient.fetch_balance(). Replaces previous snapshot for this venue.
    /// Rejects Venue::Wallet and venues not in the initial set.
    pub fn update_from_cex(
        &mut self,
        venue: Venue,
        balances: HashMap<String, AssetBalance>,
    ) -> Result<(), InventoryTrackerError> {
        if venue == Venue::Wallet {
            return Err(InventoryTrackerError::InvalidVenue(
                "update_from_cex requires a CEX venue, not Wallet".to_string(),
            ));
        }
        if !self.venues.contains(&venue) {
            return Err(InventoryTrackerError::VenueNotTracked(venue));
        }
        self.balances.insert(venue, balances);
        Ok(())
    }

    /// Update balances from on-chain wallet query. Replaces previous snapshot for this venue.
    /// Rejects Venue::Binance (and other CEX) and venues not in the initial set.
    pub fn update_from_wallet(
        &mut self,
        venue: Venue,
        balances: HashMap<String, Decimal>,
    ) -> Result<(), InventoryTrackerError> {
        if venue != Venue::Wallet {
            return Err(InventoryTrackerError::InvalidVenue(
                "update_from_wallet requires Wallet venue".to_string(),
            ));
        }
        if !self.venues.contains(&venue) {
            return Err(InventoryTrackerError::VenueNotTracked(venue));
        }
        let asset_balances: HashMap<String, AssetBalance> = balances
            .into_iter()
            .map(|(asset, amount)| {
                (
                    asset,
                    AssetBalance {
                        free: amount,
                        locked: dec!(0),
                        total: amount,
                    },
                )
            })
            .collect();
        self.balances.insert(venue, asset_balances);
        Ok(())
    }

    /// Full portfolio snapshot at current time.
    /// If prices is Some, computes total_usd; otherwise total_usd is None.
    pub fn snapshot(
        &self,
        prices: Option<&HashMap<String, Decimal>>,
    ) -> PortfolioSnapshot {
        let timestamp = OffsetDateTime::now_utc();

        let mut venues: HashMap<String, HashMap<String, AssetBalance>> =
            HashMap::with_capacity(self.venues.len());
        for venue in &self.venues {
            let venue_name = venue.to_string();
            let venue_balances = self
                .balances
                .get(venue)
                .cloned()
                .unwrap_or_default();
            venues.insert(venue_name, venue_balances);
        }

        let mut totals: HashMap<String, Decimal> = HashMap::new();
        for venue_balances in self.balances.values() {
            for (asset, balance) in venue_balances {
                totals
                    .entry(asset.clone())
                    .and_modify(|t| *t += balance.total)
                    .or_insert(balance.total);
            }
        }

        let total_usd = prices.map(|p| {
            totals
                .iter()
                .filter_map(|(asset, amount)| {
                    p.get(asset).map(|price| *amount * *price)
                })
                .fold(Decimal::ZERO, |acc, x| acc + x)
        });

        PortfolioSnapshot {
            timestamp,
            venues,
            totals,
            total_usd,
        }
    }

    /// How much of `asset` is available to trade at `venue` (free balance only).
    pub fn get_available(&self, venue: Venue, asset: &str) -> Decimal {
        self.balances
            .get(&venue)
            .and_then(|m| m.get(asset))
            .map(|b| b.free)
            .unwrap_or(Decimal::ZERO)
    }

    /// Pre-flight check: can we execute both legs of an arb?
    pub fn can_execute(
        &self,
        buy_venue: Venue,
        buy_asset: &str,
        buy_amount: Decimal,
        sell_venue: Venue,
        sell_asset: &str,
        sell_amount: Decimal,
    ) -> CanExecuteResult {
        let buy_available = self.get_available(buy_venue, buy_asset);
        let sell_available = self.get_available(sell_venue, sell_asset);

        let buy_ok = buy_available >= buy_amount;
        let sell_ok = sell_available >= sell_amount;

        let (can_execute, reason) = if !buy_ok && !sell_ok {
            (
                false,
                Some(format!(
                    "Insufficient {} at buy venue (have {}, need {}) and insufficient {} at sell venue (have {}, need {})",
                    buy_asset, buy_available, buy_amount, sell_asset, sell_available, sell_amount
                )),
            )
        } else if !buy_ok {
            (
                false,
                Some(format!(
                    "Insufficient {} at buy venue: have {}, need {}",
                    buy_asset, buy_available, buy_amount
                )),
            )
        } else if !sell_ok {
            (
                false,
                Some(format!(
                    "Insufficient {} at sell venue: have {}, need {}",
                    sell_asset, sell_available, sell_amount
                )),
            )
        } else {
            (true, None)
        };

        CanExecuteResult {
            can_execute,
            buy_venue_available: buy_available,
            buy_venue_needed: buy_amount,
            sell_venue_available: sell_available,
            sell_venue_needed: sell_amount,
            reason,
        }
    }

    /// Update internal balances after a trade executes.
    /// Buy: base increases, quote decreases. Sell: base decreases, quote increases. Fee deducted from fee_asset.
    pub fn record_trade(
        &mut self,
        venue: Venue,
        side: &str,
        base_asset: &str,
        quote_asset: &str,
        base_amount: Decimal,
        quote_amount: Decimal,
        fee: Decimal,
        fee_asset: &str,
    ) -> Result<(), InventoryTrackerError> {
        if !self.venues.contains(&venue) {
            return Err(InventoryTrackerError::VenueNotTracked(venue));
        }

        let venue_balances = self
            .balances
            .entry(venue)
            .or_default();

        let side_lower = side.to_lowercase();
        let (base_delta, quote_delta) = match side_lower.as_str() {
            "buy" => (base_amount, -quote_amount),
            "sell" => (-base_amount, quote_amount),
            _ => {
                return Err(InventoryTrackerError::InvalidVenue(format!(
                    "Invalid side: {}",
                    side
                )))
            }
        };

        let get_or_zero = |asset: &str| {
            venue_balances
                .get(asset)
                .map(|b| b.free)
                .unwrap_or(Decimal::ZERO)
        };

        // Net change per asset: base gets base_delta, quote gets quote_delta, fee_asset gets -fee.
        // When fee_asset equals base or quote, combine the deltas.
        let base_fee = if fee_asset == base_asset { fee } else { dec!(0) };
        let quote_fee = if fee_asset == quote_asset { fee } else { dec!(0) };

        let new_base = get_or_zero(base_asset)
            .checked_add(base_delta)
            .and_then(|x| x.checked_sub(base_fee))
            .ok_or(InventoryTrackerError::ArithmeticOverflow)?;
        let new_quote = get_or_zero(quote_asset)
            .checked_add(quote_delta)
            .and_then(|x| x.checked_sub(quote_fee))
            .ok_or(InventoryTrackerError::ArithmeticOverflow)?;

        let new_fee_asset = if fee_asset != base_asset && fee_asset != quote_asset {
            Some(
                get_or_zero(fee_asset)
                    .checked_sub(fee)
                    .ok_or(InventoryTrackerError::ArithmeticOverflow)?,
            )
        } else {
            None
        };

        if new_base < Decimal::ZERO || new_quote < Decimal::ZERO {
            return Err(InventoryTrackerError::ArithmeticOverflow);
        }
        if let Some(ref nfa) = new_fee_asset {
            if *nfa < Decimal::ZERO {
                return Err(InventoryTrackerError::ArithmeticOverflow);
            }
        }

        venue_balances.insert(
            base_asset.to_string(),
            AssetBalance {
                free: new_base,
                locked: dec!(0),
                total: new_base,
            },
        );
        venue_balances.insert(
            quote_asset.to_string(),
            AssetBalance {
                free: new_quote,
                locked: dec!(0),
                total: new_quote,
            },
        );
        if let Some(nfa) = new_fee_asset {
            venue_balances.insert(
                fee_asset.to_string(),
                AssetBalance {
                    free: nfa,
                    locked: dec!(0),
                    total: nfa,
                },
            );
        }

        Ok(())
    }

    /// Calculate distribution skew for an asset across venues.
    /// needs_rebalance is true when max_deviation_pct > 30.
    pub fn skew(&self, asset: &str) -> SkewResult {
        let n = self.venues.len() as u32;
        let equal_pct = if n > 0 {
            Decimal::from(100) / Decimal::from(n)
        } else {
            Decimal::ZERO
        };

        let mut venue_amounts: HashMap<String, Decimal> = HashMap::new();
        for venue in &self.venues {
            let venue_name = venue.to_string();
            let amount = self
                .balances
                .get(venue)
                .and_then(|m| m.get(asset))
                .map(|b| b.total)
                .unwrap_or(Decimal::ZERO);
            venue_amounts.insert(venue_name, amount);
        }

        let total: Decimal = venue_amounts.values().copied().sum();

        let mut venues: HashMap<String, VenueSkew> = HashMap::new();
        let mut max_deviation_pct = Decimal::ZERO;

        for (venue_name, amount) in &venue_amounts {
            let pct = if total.is_zero() {
                Decimal::ZERO
            } else {
                *amount / total * Decimal::from(100)
            };
            let deviation_pct = (pct - equal_pct).abs();
            if deviation_pct > max_deviation_pct {
                max_deviation_pct = deviation_pct;
            }
            venues.insert(
                venue_name.clone(),
                VenueSkew {
                    amount: *amount,
                    pct,
                    deviation_pct,
                },
            );
        }

        let needs_rebalance = !total.is_zero() && max_deviation_pct > dec!(30);

        SkewResult {
            asset: asset.to_string(),
            total,
            venues,
            max_deviation_pct,
            needs_rebalance,
        }
    }
}
