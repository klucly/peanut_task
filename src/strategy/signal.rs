//! Signal types for validated arbitrage opportunities.

use rust_decimal::Decimal;
use time::OffsetDateTime;
use uuid::Uuid;

/// Direction of the arbitrage trade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Buy on CEX, sell on DEX
    BuyCexSellDex,
    /// Buy on DEX, sell on CEX
    BuyDexSellCex,
}

/// A validated arbitrage opportunity ready for execution.
#[derive(Debug, Clone)]
pub struct Signal {
    pub signal_id: String,
    pub pair: String,
    pub direction: Direction,

    pub cex_price: Decimal,
    pub dex_price: Decimal,
    pub spread_bps: Decimal,
    pub size: Decimal,

    pub expected_gross_pnl: Decimal,
    pub expected_fees: Decimal,
    pub expected_net_pnl: Decimal,

    pub score: Decimal,
    pub timestamp: OffsetDateTime,
    pub expiry: OffsetDateTime,

    pub inventory_ok: bool,
    pub within_limits: bool,
}

impl Signal {
    pub fn create(
        pair: String,
        direction: Direction,
        cex_price: Decimal,
        dex_price: Decimal,
        spread_bps: Decimal,
        size: Decimal,
        expected_gross_pnl: Decimal,
        expected_fees: Decimal,
        expected_net_pnl: Decimal,
        score: Decimal,
        expiry: OffsetDateTime,
        inventory_ok: bool,
        within_limits: bool,
    ) -> Self {
        let pair_clean = pair.replace('/', "");
        let uuid_short = Uuid::new_v4().to_string()[..8].to_string();
        let signal_id = format!("{}_{}", pair_clean, uuid_short);
        let timestamp = OffsetDateTime::now_utc();

        Self {
            signal_id,
            pair,
            direction,
            cex_price,
            dex_price,
            spread_bps,
            size,
            expected_gross_pnl,
            expected_fees,
            expected_net_pnl,
            score,
            timestamp,
            expiry,
            inventory_ok,
            within_limits,
        }
    }

    pub fn is_valid(&self) -> bool {
        let now = OffsetDateTime::now_utc();
        now < self.expiry
            && self.inventory_ok
            && self.within_limits
            && self.expected_net_pnl > Decimal::ZERO
            && self.score > Decimal::ZERO
    }

    pub fn age_seconds(&self) -> f64 {
        let now = OffsetDateTime::now_utc();
        (now - self.timestamp).as_seconds_f64()
    }
}
