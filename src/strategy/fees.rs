use rust_decimal::Decimal;

#[derive(Debug, Clone)]
pub struct FeeStructure {
    pub cex_taker_bps: Decimal,
    pub dex_swap_bps: Decimal,
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
    pub fn new(cex_taker_bps: Decimal, dex_swap_bps: Decimal, gas_cost_usd: Decimal) -> Self {
        Self {
            cex_taker_bps,
            dex_swap_bps,
            gas_cost_usd,
        }
    }

    pub fn total_fee_bps(&self, trade_value_usd: Decimal) -> Decimal {
        let gas_bps = if trade_value_usd > Decimal::ZERO {
            (self.gas_cost_usd / trade_value_usd) * Decimal::from(10_000)
        } else {
            Decimal::ZERO
        };
        self.cex_taker_bps + self.dex_swap_bps + gas_bps
    }

    pub fn breakeven_spread_bps(&self, trade_value_usd: Decimal) -> Decimal {
        self.total_fee_bps(trade_value_usd)
    }

    pub fn net_profit_usd(&self, spread_bps: Decimal, trade_value_usd: Decimal) -> Decimal {
        let gross = (spread_bps / Decimal::from(10_000)) * trade_value_usd;
        let fees = (self.total_fee_bps(trade_value_usd) / Decimal::from(10_000)) * trade_value_usd;
        gross - fees
    }
}
