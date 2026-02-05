//! PnL Engine: trade and profit/loss tracking for arb trades.
//!
//! Tracks completed arb trades (buy on one venue, sell on another) and produces
//! aggregate PnL reports, recent trade summaries, and CSV export.

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::collections::HashMap;
use std::io::Write;

use crate::exchange::OrderSide;
use super::types::Venue;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Single execution leg of an arb trade.
#[derive(Debug, Clone)]
pub struct TradeLeg {
    pub id: String,
    pub timestamp: OffsetDateTime,
    pub venue: Venue,
    pub symbol: String,
    pub side: OrderSide,
    pub amount: Decimal,
    pub price: Decimal,
    pub fee: Decimal,
    pub fee_asset: String,
    /// Fee in USD for PnL calculations (caller provides).
    pub fee_usd: Decimal,
}

/// Complete arb trade with both legs.
#[derive(Debug, Clone)]
pub struct ArbRecord {
    pub id: String,
    pub timestamp: OffsetDateTime,
    pub buy_leg: TradeLeg,
    pub sell_leg: TradeLeg,
    pub gas_cost_usd: Decimal,
}

impl ArbRecord {
    /// Price difference revenue: sell revenue - buy cost.
    pub fn gross_pnl(&self) -> Decimal {
        let sell_revenue = self.sell_leg.amount * self.sell_leg.price;
        let buy_cost = self.buy_leg.amount * self.buy_leg.price;
        sell_revenue - buy_cost
    }

    /// All fees: both legs + gas.
    pub fn total_fees(&self) -> Decimal {
        self.buy_leg.fee_usd + self.sell_leg.fee_usd + self.gas_cost_usd
    }

    /// Gross PnL minus fees.
    pub fn net_pnl(&self) -> Decimal {
        self.gross_pnl() - self.total_fees()
    }

    /// Trade size in quote currency.
    pub fn notional(&self) -> Decimal {
        self.buy_leg.amount * self.buy_leg.price
    }

    /// Net PnL in basis points of notional. Returns 0 when notional is 0.
    pub fn net_pnl_bps(&self) -> Decimal {
        let notional = self.notional();
        if notional.is_zero() {
            return Decimal::ZERO;
        }
        self.net_pnl() / notional * dec!(10000)
    }
}

/// Aggregate PnL summary.
#[derive(Debug, Clone)]
pub struct PnLSummary {
    pub total_trades: usize,
    pub total_pnl_usd: Decimal,
    pub total_fees_usd: Decimal,
    pub avg_pnl_per_trade: Decimal,
    pub avg_pnl_bps: Decimal,
    pub win_rate: f64,
    pub best_trade_pnl: Decimal,
    pub worst_trade_pnl: Decimal,
    pub total_notional: Decimal,
    pub sharpe_estimate: f64,
    pub pnl_by_hour: HashMap<u8, Decimal>,
}

/// Display-friendly summary of a single arb trade.
#[derive(Debug, Clone)]
pub struct ArbRecordSummary {
    pub id: String,
    pub timestamp: OffsetDateTime,
    pub symbol: String,
    pub buy_venue: Venue,
    pub sell_venue: Venue,
    pub net_pnl: Decimal,
    pub net_pnl_bps: Decimal,
    pub is_win: bool,
}

/// Tracks all arb trades and produces PnL reports.
#[derive(Debug, Default)]
pub struct PnLEngine {
    trades: Vec<ArbRecord>,
}

impl PnLEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a completed arb trade.
    pub fn record(&mut self, trade: ArbRecord) {
        self.trades.push(trade);
    }

    /// Aggregate PnL summary over all recorded trades.
    pub fn summary(&self) -> PnLSummary {
        let filtered: Vec<&ArbRecord> = self.trades.iter().collect();
        if filtered.is_empty() {
            return Self::empty_summary();
        }

        let n = filtered.len();
        let total_pnl: Decimal = filtered.iter().map(|r| r.net_pnl()).sum();
        let total_fees: Decimal = filtered.iter().map(|r| r.total_fees()).sum();
        let total_notional: Decimal = filtered.iter().map(|r| r.notional()).sum();
        let net_pnls: Vec<Decimal> = filtered.iter().map(|r| r.net_pnl()).collect();

        let wins = filtered.iter().filter(|r| r.net_pnl() > Decimal::ZERO).count();
        let win_rate = wins as f64 / n as f64;
        let best = net_pnls.iter().copied().max().unwrap_or(Decimal::ZERO);
        let worst = net_pnls.iter().copied().min().unwrap_or(Decimal::ZERO);
        let avg_pnl = total_pnl / Decimal::from(n);
        let avg_pnl_bps = if total_notional.is_zero() {
            Decimal::ZERO
        } else {
            total_pnl / total_notional * dec!(10000)
        };

        PnLSummary {
            total_trades: n,
            total_pnl_usd: total_pnl,
            total_fees_usd: total_fees,
            avg_pnl_per_trade: avg_pnl,
            avg_pnl_bps,
            win_rate,
            best_trade_pnl: best,
            worst_trade_pnl: worst,
            total_notional,
            sharpe_estimate: Self::compute_sharpe(&net_pnls),
            pnl_by_hour: Self::compute_pnl_by_hour(&filtered),
        }
    }

    fn empty_summary() -> PnLSummary {
        PnLSummary {
            total_trades: 0,
            total_pnl_usd: Decimal::ZERO,
            total_fees_usd: Decimal::ZERO,
            avg_pnl_per_trade: Decimal::ZERO,
            avg_pnl_bps: Decimal::ZERO,
            win_rate: 0.0,
            best_trade_pnl: Decimal::ZERO,
            worst_trade_pnl: Decimal::ZERO,
            total_notional: Decimal::ZERO,
            sharpe_estimate: 0.0,
            pnl_by_hour: HashMap::new(),
        }
    }

    fn compute_sharpe(net_pnls: &[Decimal]) -> f64 {
        let pnl_f64: Vec<f64> = net_pnls.iter().filter_map(|d| d.to_f64()).collect();
        let m = pnl_f64.len();
        if m == 0 {
            return 0.0;
        }
        let mean = pnl_f64.iter().sum::<f64>() / m as f64;
        let variance = pnl_f64
            .iter()
            .map(|x| (x - mean) * (x - mean))
            .sum::<f64>()
            / m as f64;
        let std = variance.sqrt();
        if std > 0.0 {
            mean / std
        } else {
            0.0
        }
    }

    fn compute_pnl_by_hour(trades: &[&ArbRecord]) -> HashMap<u8, Decimal> {
        let mut pnl_by_hour: HashMap<u8, Decimal> = HashMap::new();
        for r in trades {
            let hour = r.timestamp.hour();
            pnl_by_hour
                .entry(hour)
                .and_modify(|v| *v += r.net_pnl())
                .or_insert(r.net_pnl());
        }
        pnl_by_hour
    }

    /// Last N trades as summary structs for display.
    pub fn recent(&self, n: usize) -> Vec<ArbRecordSummary> {
        let start = self.trades.len().saturating_sub(n);
        self.trades[start..]
            .iter()
            .map(|r| ArbRecordSummary {
                id: r.id.clone(),
                timestamp: r.timestamp,
                symbol: r.buy_leg.symbol.clone(),
                buy_venue: r.buy_leg.venue,
                sell_venue: r.sell_leg.venue,
                net_pnl: r.net_pnl(),
                net_pnl_bps: r.net_pnl_bps(),
                is_win: r.net_pnl() > Decimal::ZERO,
            })
            .collect()
    }

    /// Export all trades to CSV.
    pub fn export_csv(&self, path: &str) -> Result<(), std::io::Error> {
        let mut file = std::fs::File::create(path)?;
        writeln!(
            file,
            "id,timestamp,symbol,buy_venue,sell_venue,buy_amount,buy_price,sell_amount,sell_price,gross_pnl,total_fees,net_pnl,net_pnl_bps,notional,gas_cost_usd"
        )?;
        for r in &self.trades {
            let ts = r.timestamp.format(&Rfc3339).unwrap_or_else(|_| "".to_string());
            writeln!(
                file,
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                r.id,
                ts,
                r.buy_leg.symbol,
                r.buy_leg.venue,
                r.sell_leg.venue,
                r.buy_leg.amount,
                r.buy_leg.price,
                r.sell_leg.amount,
                r.sell_leg.price,
                r.gross_pnl(),
                r.total_fees(),
                r.net_pnl(),
                r.net_pnl_bps(),
                r.notional(),
                r.gas_cost_usd
            )?;
        }
        Ok(())
    }
}
