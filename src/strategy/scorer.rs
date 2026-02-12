use rust_decimal::Decimal;
use rust_decimal_macros::dec;

use super::signal::Signal;
use crate::inventory::SkewResult;

#[derive(Debug, Clone)]
pub struct ScorerConfig {
    pub spread_weight: Decimal,
    pub liquidity_weight: Decimal,
    pub inventory_weight: Decimal,
    pub history_weight: Decimal,
    pub excellent_spread_bps: Decimal,
    pub min_spread_bps: Decimal,
}

impl Default for ScorerConfig {
    fn default() -> Self {
        Self {
            spread_weight: dec!(0.4),
            liquidity_weight: dec!(0.2),
            inventory_weight: dec!(0.2),
            history_weight: dec!(0.2),
            excellent_spread_bps: dec!(100),
            min_spread_bps: dec!(30),
        }
    }
}

impl ScorerConfig {
    pub fn new(
        spread_weight: Decimal,
        liquidity_weight: Decimal,
        inventory_weight: Decimal,
        history_weight: Decimal,
        excellent_spread_bps: Decimal,
        min_spread_bps: Decimal,
    ) -> Self {
        Self {
            spread_weight,
            liquidity_weight,
            inventory_weight,
            history_weight,
            excellent_spread_bps,
            min_spread_bps,
        }
    }
}

pub struct SignalScorer {
    config: ScorerConfig,
    recent_results: Vec<(String, bool)>,
}

impl SignalScorer {
    pub fn new(config: Option<ScorerConfig>) -> Self {
        Self {
            config: config.unwrap_or_default(),
            recent_results: Vec::new(),
        }
    }

    pub fn score(&self, signal: &Signal, inventory_skews: &[SkewResult]) -> Decimal {
        let spread_score = self._score_spread(signal.spread_bps);
        let liquidity_score = dec!(80); // Placeholder
        let inventory_score = self._score_inventory(signal, inventory_skews);
        let history_score = self._score_history(&signal.pair);

        let weighted = spread_score * self.config.spread_weight
            + liquidity_score * self.config.liquidity_weight
            + inventory_score * self.config.inventory_weight
            + history_score * self.config.history_weight;

        let clamped = weighted.max(dec!(0)).min(dec!(100));
        round_to_one_decimal(clamped)
    }

    fn _score_spread(&self, spread_bps: Decimal) -> Decimal {
        if spread_bps <= self.config.min_spread_bps {
            return dec!(0);
        }
        if spread_bps >= self.config.excellent_spread_bps {
            return dec!(100);
        }

        let range_bps = self.config.excellent_spread_bps - self.config.min_spread_bps;
        let spread_above_min = spread_bps - self.config.min_spread_bps;
        
        (spread_above_min / range_bps) * dec!(100)
    }

    fn _score_inventory(&self, signal: &Signal, skews: &[SkewResult]) -> Decimal {
        let base = signal.pair.split('/').next().unwrap_or("");
        let needs_rebalance = skews.iter()
            .any(|s| s.asset == base && s.needs_rebalance);

        if needs_rebalance {
            dec!(20)
        } else {
            dec!(60)
        }
    }

    fn _score_history(&self, pair: &str) -> Decimal {
        let relevant_results: Vec<bool> = self.recent_results
            .iter()
            .rev()
            .take(20)
            .filter(|(p, _)| p == pair)
            .map(|(_, success)| *success)
            .collect();

        if relevant_results.len() < 3 {
            return dec!(50);
        }

        let successes = relevant_results.iter().filter(|&&s| s).count();
        let total = relevant_results.len();
        
        Decimal::from(successes * 100) / Decimal::from(total)
    }

    pub fn record_result(&mut self, pair: String, success: bool) {
        self.recent_results.push((pair, success));
        
        if self.recent_results.len() > 100 {
            self.recent_results = self.recent_results
                .iter()
                .skip(self.recent_results.len() - 100)
                .cloned()
                .collect();
        }
    }

    pub fn apply_decay(&self, signal: &Signal) -> Decimal {
        let age = Decimal::from_f64_retain(signal.age_seconds())
            .unwrap_or(dec!(0));
        
        let ttl = (signal.expiry - signal.timestamp).as_seconds_f64();
        let ttl_decimal = Decimal::from_f64_retain(ttl)
            .unwrap_or(dec!(1));

        if ttl_decimal <= dec!(0) {
            return dec!(0);
        }

        let decay_factor = dec!(1) - (age / ttl_decimal) * dec!(0.5);
        let decay_factor = decay_factor.max(dec!(0));

        signal.score * decay_factor
    }
}

fn round_to_one_decimal(value: Decimal) -> Decimal {
    (value * dec!(10)).round() / dec!(10)
}
