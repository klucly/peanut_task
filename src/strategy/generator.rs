use rust_decimal::Decimal;
use std::collections::HashMap;
use time::{Duration, OffsetDateTime};

use super::fees::FeeStructure;
use super::signal::{Direction, Signal};
use crate::integration::arb_checker::ArbChecker;

#[derive(Debug, Clone)]
pub struct GeneratorConfig {
    pub min_profit_usd: Decimal,
    pub max_position_usd: Decimal,
    pub signal_ttl_seconds: i64,
    pub cooldown_seconds: i64,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            min_profit_usd: Decimal::from(5),
            max_position_usd: Decimal::from(10_000),
            signal_ttl_seconds: 5,
            cooldown_seconds: 2,
        }
    }
}

impl GeneratorConfig {
    pub fn new(
        min_profit_usd: Decimal,
        max_position_usd: Decimal,
        signal_ttl_seconds: i64,
        cooldown_seconds: i64,
    ) -> Self {
        Self {
            min_profit_usd,
            max_position_usd,
            signal_ttl_seconds,
            cooldown_seconds,
        }
    }
}

pub struct SignalGenerator {
    arb_checker: ArbChecker,
    fee_structure: FeeStructure,
    config: GeneratorConfig,
    last_signal_time: HashMap<String, OffsetDateTime>,
}

impl SignalGenerator {
    pub fn new(
        arb_checker: ArbChecker,
        fee_structure: FeeStructure,
        config: GeneratorConfig,
    ) -> Self {
        Self {
            arb_checker,
            fee_structure,
            config,
            last_signal_time: HashMap::new(),
        }
    }

    pub fn generate(&mut self, pair: &str) -> Option<Signal> {
        if self.in_cooldown(pair) {
            tracing::debug!("Skipping {} due to cooldown", pair);
            return None;
        }

        let opportunity = match self.arb_checker.check(pair) {
            Ok(Some(opp)) => opp,
            Ok(None) => {
                tracing::debug!("No opportunity found for {}", pair);
                return None;
            }
            Err(e) => {
                tracing::warn!("Error checking {}: {}", pair, e);
                return None;
            }
        };

        if !opportunity.executable {
            tracing::debug!("Opportunity for {} not executable (inventory/profit)", pair);
            return None;
        }

        let direction = match opportunity.direction {
            crate::integration::arb_checker::ExchangeTypeDirection::BuyCexSellDex => {
                Direction::BuyCexSellDex
            }
            crate::integration::arb_checker::ExchangeTypeDirection::BuyDexSellCex => {
                Direction::BuyDexSellCex
            }
        };

        // Price to use for USD valuation and for the Signal
        let cex_price_ref = match direction {
            Direction::BuyCexSellDex => opportunity.cex_ask,
            Direction::BuyDexSellCex => opportunity.cex_bid,
        };

        // Safety check: if price is 0, we can't trade
        if cex_price_ref <= Decimal::ZERO {
            tracing::warn!("Signals generated with zero CEX price for {}", pair);
            return None;
        }

        let now = OffsetDateTime::now_utc();
        let expiry = now + Duration::seconds(self.config.signal_ttl_seconds);

        // Calculate USD stats using the relevant CEX price
        let trade_value_usd = opportunity.amount * cex_price_ref;
        let gross_pnl = (opportunity.gap_bps / Decimal::from(10_000)) * trade_value_usd;
        let fees = (opportunity.estimated_costs_bps / Decimal::from(10_000)) * trade_value_usd;
        let net_pnl = gross_pnl - fees;

        // Check configured limits
        // Check configured limits
        if net_pnl < self.config.min_profit_usd {
            tracing::debug!(
                "Skipping {}: Net PnL ${:.2} < Min Profit ${:.2}. Trade Value: ${:.2}, Gross: ${:.2}, Fees: ${:.2}",
                pair,
                net_pnl,
                self.config.min_profit_usd,
                trade_value_usd,
                gross_pnl,
                fees
            );
            return None;
        }

        if trade_value_usd > self.config.max_position_usd {
            tracing::debug!(
                "Skipping {}: Trade Value ${:.2} > Max Position ${:.2}",
                pair,
                trade_value_usd,
                self.config.max_position_usd
            );
            return None;
        }

        let signal = Signal::create(
            pair.to_string(),
            direction,
            cex_price_ref, // Pass the correct price (ask or bid)
            opportunity.dex_price,
            opportunity.gap_bps,
            opportunity.amount,
            gross_pnl,
            fees,
            net_pnl,
            opportunity.estimated_net_pnl_bps,
            expiry,
            opportunity.inventory_ok,
            opportunity.executable,
        );

        tracing::info!(
            "SIGNAL GENERATED: {} {:?} Amount: {}. Net PnL: ${:.2}. Expiry: {}",
            pair,
            direction,
            opportunity.amount,
            net_pnl,
            expiry
        );

        self.last_signal_time.insert(pair.to_string(), now);

        Some(signal)
    }

    fn in_cooldown(&self, pair: &str) -> bool {
        if let Some(&last_time) = self.last_signal_time.get(pair) {
            let now = OffsetDateTime::now_utc();
            let elapsed = (now - last_time).whole_seconds();
            elapsed < self.config.cooldown_seconds
        } else {
            false
        }
    }

    pub fn config(&self) -> &GeneratorConfig {
        &self.config
    }
    pub fn fee_structure(&self) -> &FeeStructure {
        &self.fee_structure
    }
    pub fn arb_checker(&self) -> &ArbChecker {
        &self.arb_checker
    }
}
