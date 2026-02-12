use rust_decimal::Decimal;
use std::collections::HashMap;
use time::{Duration, OffsetDateTime};

use crate::integration::arb_checker::ArbChecker;
use super::fees::FeeStructure;
use super::signal::{Direction, Signal};

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
            return None;
        }

        let opportunity = match self.arb_checker.check(pair) {
            Ok(opp) => opp,
            Err(_) => return None,
        };

        if !opportunity.executable {
            return None;
        }

        let direction = match opportunity.direction {
            crate::integration::arb_checker::ExchangeTypeDirection::BuyCexSellDex => Direction::BuyCexSellDex,
            crate::integration::arb_checker::ExchangeTypeDirection::BuyDexSellCex => Direction::BuyDexSellCex,
        };

        let now = OffsetDateTime::now_utc();
        let expiry = now + Duration::seconds(self.config.signal_ttl_seconds);
        let signal = Signal::create(
            pair.to_string(),
            direction,
            opportunity.cex_ask,
            opportunity.dex_price,
            opportunity.gap_bps,
            Decimal::ZERO, // Size not directly available from OpportunitySwap
            Decimal::ZERO, // Gross PnL - would need size to calculate
            opportunity.estimated_costs_bps / Decimal::from(10_000), // Convert bps to ratio
            opportunity.estimated_net_pnl_bps / Decimal::from(10_000), // Convert bps to ratio
            opportunity.estimated_net_pnl_bps, // Use net PnL bps as score
            expiry,
            opportunity.inventory_ok,
            opportunity.executable,
        );

        // Update cooldown tracker
        self.last_signal_time.insert(pair.to_string(), now);

        Some(signal)
    }

    /// Check if a pair is in cooldown period.
    fn in_cooldown(&self, pair: &str) -> bool {
        if let Some(&last_time) = self.last_signal_time.get(pair) {
            let now = OffsetDateTime::now_utc();
            let elapsed = (now - last_time).whole_seconds();
            elapsed < self.config.cooldown_seconds
        } else {
            false
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &GeneratorConfig {
        &self.config
    }

    /// Get the fee structure.
    pub fn fee_structure(&self) -> &FeeStructure {
        &self.fee_structure
    }
}
