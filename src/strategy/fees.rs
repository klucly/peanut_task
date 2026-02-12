//! Fee calculation for trading operations.

use rust_decimal::Decimal;

/// Fee structure for arbitrage trades.
#[derive(Debug, Clone)]
pub struct FeeStructure {
    /// CEX taker fee in basis points
    pub cex_taker_bps: Decimal,
    /// DEX swap fee in basis points
    pub dex_swap_bps: Decimal,
    /// Gas cost in USD
    pub gas_cost_usd: Decimal,
}

impl Default for FeeStructure {
    fn default() -> Self {
        Self {
            cex_taker_bps: Decimal::from(10),
            dex_swap_bps: Decimal::from(30),
            gas_cost_usd: Decimal::from(5),
        }
    }
}

impl FeeStructure {
    /// Create a new fee structure with custom values.
    pub fn new(cex_taker_bps: Decimal, dex_swap_bps: Decimal, gas_cost_usd: Decimal) -> Self {
        Self {
            cex_taker_bps,
            dex_swap_bps,
            gas_cost_usd,
        }
    }

    /// Calculate total fee in basis points for a given trade value.
    ///
    /// # Arguments
    ///
    /// * `trade_value_usd` - Trade value in USD
    ///
    /// # Returns
    ///
    /// Total fee in basis points
    pub fn total_fee_bps(&self, trade_value_usd: Decimal) -> Decimal {
        let gas_bps = if trade_value_usd > Decimal::ZERO {
            (self.gas_cost_usd / trade_value_usd) * Decimal::from(10_000)
        } else {
            Decimal::ZERO
        };
        self.cex_taker_bps + self.dex_swap_bps + gas_bps
    }

    /// Calculate breakeven spread in basis points.
    ///
    /// This is the minimum spread needed to break even after fees.
    ///
    /// # Arguments
    ///
    /// * `trade_value_usd` - Trade value in USD
    ///
    /// # Returns
    ///
    /// Breakeven spread in basis points
    pub fn breakeven_spread_bps(&self, trade_value_usd: Decimal) -> Decimal {
        self.total_fee_bps(trade_value_usd)
    }

    /// Calculate net profit in USD after fees.
    ///
    /// # Arguments
    ///
    /// * `spread_bps` - Spread in basis points
    /// * `trade_value_usd` - Trade value in USD
    ///
    /// # Returns
    ///
    /// Net profit in USD (can be negative)
    pub fn net_profit_usd(&self, spread_bps: Decimal, trade_value_usd: Decimal) -> Decimal {
        let gross = (spread_bps / Decimal::from(10_000)) * trade_value_usd;
        let fees = (self.total_fee_bps(trade_value_usd) / Decimal::from(10_000)) * trade_value_usd;
        gross - fees
    }
}
