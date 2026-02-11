//! Order book analyzer for trading decisions.
//!
//! Analyzes order book snapshots from `ExchangeClient::fetch_order_book()`.

use crate::exchange::types::OrderBook;
use rust_decimal::Decimal;
use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use rust_decimal_macros::dec;
use std::cmp::min;
use std::str::FromStr;
use thiserror::Error;

/// Side for walk-the-book: buy (walk asks) or sell (walk bids).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderSide {
    Buy,
    Sell,
}

impl FromStr for OrderSide {
    type Err = OrderBookAnalyzerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "buy" => Ok(OrderSide::Buy),
            "sell" => Ok(OrderSide::Sell),
            _ => Err(OrderBookAnalyzerError::InvalidSide(format!(
                "expected 'buy' or 'sell', got '{}'",
                s
            ))),
        }
    }
}

/// Side of the book for depth queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookSide {
    Bid,
    Ask,
}

impl FromStr for BookSide {
    type Err = OrderBookAnalyzerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bid" => Ok(BookSide::Bid),
            "ask" => Ok(BookSide::Ask),
            _ => Err(OrderBookAnalyzerError::InvalidSide(format!(
                "expected 'bid' or 'ask', got '{}'",
                s
            ))),
        }
    }
}

/// Single level fill from walking the book.
#[derive(Debug, Clone, PartialEq)]
pub struct Fill {
    pub price: Decimal,
    pub qty: Decimal,
    pub cost: Decimal,
}

/// Result of simulating a fill against the order book.
#[derive(Debug, Clone)]
pub struct WalkResult {
    pub avg_price: Decimal,
    pub total_cost: Decimal,
    pub slippage_bps: Decimal,
    pub levels_consumed: usize,
    pub fully_filled: bool,
    pub fills: Vec<Fill>,
}

/// Errors from order book analysis.
#[derive(Debug, Error)]
pub enum OrderBookAnalyzerError {
    #[error("Invalid side: {0}")]
    InvalidSide(String),

    #[error("Invalid quantity: {0}")]
    InvalidQuantity(String),
}

/// Analyzes order book snapshots for trading decisions.
pub struct OrderBookAnalyzer {
    orderbook: OrderBook,
}

impl OrderBookAnalyzer {
    /// Create analyzer from order book (e.g. from `ExchangeClient::fetch_order_book()`).
    pub fn new(orderbook: OrderBook) -> Self {
        Self { orderbook }
    }

    /// Simulate filling `qty` of base asset against the order book.
    pub fn walk_the_book(
        &self,
        side: OrderSide,
        qty: Decimal,
    ) -> Result<WalkResult, OrderBookAnalyzerError> {
        if qty < Decimal::ZERO {
            return Err(OrderBookAnalyzerError::InvalidQuantity(
                "quantity must be non-negative".to_string(),
            ));
        }
        if qty.is_zero() {
            return Ok(WalkResult {
                avg_price: Decimal::ZERO,
                total_cost: Decimal::ZERO,
                slippage_bps: Decimal::ZERO,
                levels_consumed: 0,
                fully_filled: true,
                fills: vec![],
            });
        }

        let (levels, best_price) = match side {
            OrderSide::Buy => (&self.orderbook.asks, self.orderbook.best_ask.0),
            OrderSide::Sell => (&self.orderbook.bids, self.orderbook.best_bid.0),
        };

        let mut remaining = qty;
        let mut total_cost = Decimal::ZERO;
        let mut fills = Vec::new();

        for (price, level_qty) in levels {
            if remaining.is_zero() {
                break;
            }
            let fill_qty = min_decimal(remaining, *level_qty);
            if fill_qty.is_zero() {
                continue;
            }
            let cost = fill_qty * *price;
            total_cost += cost;
            remaining -= fill_qty;
            fills.push(Fill {
                price: *price,
                qty: fill_qty,
                cost,
            });
        }

        let total_filled = qty - remaining;
        let avg_price = if total_filled.is_zero() {
            Decimal::ZERO
        } else {
            total_cost / total_filled
        };

        let slippage_bps = if best_price.is_zero() {
            Decimal::ZERO
        } else {
            match side {
                OrderSide::Buy => (avg_price - best_price) / best_price * dec!(10000),
                OrderSide::Sell => (best_price - avg_price) / best_price * dec!(10000),
            }
        };

        Ok(WalkResult {
            avg_price,
            total_cost,
            slippage_bps,
            levels_consumed: fills.len(),
            fully_filled: remaining.is_zero(),
            fills,
        })
    }

    /// Total quantity available within `bps` basis points of best price.
    pub fn depth_at_bps(&self, side: BookSide, bps: f64) -> Result<Decimal, OrderBookAnalyzerError> {
        let (qty, _) = self.depth_at_bps_inner(side, bps)?;
        Ok(qty)
    }

    /// Sum of (price × qty) for levels within `bps` of best (quote value).
    pub fn depth_quote_value_at_bps(
        &self,
        side: BookSide,
        bps: f64,
    ) -> Result<Decimal, OrderBookAnalyzerError> {
        let (_, quote_value) = self.depth_at_bps_inner(side, bps)?;
        Ok(quote_value)
    }

    fn depth_at_bps_inner(
        &self,
        side: BookSide,
        bps: f64,
    ) -> Result<(Decimal, Decimal), OrderBookAnalyzerError> {
        let bps_d = Decimal::from_f64(bps).unwrap_or(dec!(0));
        let one = Decimal::ONE;
        let ten_thousand = dec!(10000);

        let mut qty = Decimal::ZERO;
        let mut quote_value = Decimal::ZERO;

        if side == BookSide::Bid {
            let threshold = self.orderbook.best_bid.0 * (one - bps_d / ten_thousand);
            for (price, level_qty) in &self.orderbook.bids {
                if *price < threshold {
                    break;
                }
                qty += level_qty;
                quote_value += price * level_qty;
            }
        } else {
            let threshold = self.orderbook.best_ask.0 * (one + bps_d / ten_thousand);
            for (price, level_qty) in &self.orderbook.asks {
                if *price > threshold {
                    break;
                }
                qty += level_qty;
                quote_value += price * level_qty;
            }
        }

        Ok((qty, quote_value))
    }

    /// Order book imbalance ratio over first `levels` on each side.
    ///
    /// Returns value in [-1.0, 1.0]:
    /// - +1.0 = all bids (buy pressure)
    /// - -1.0 = all asks (sell pressure)
    pub fn imbalance(&self, levels: usize) -> f64 {
        let bid_levels = min(levels, self.orderbook.bids.len());
        let ask_levels = min(levels, self.orderbook.asks.len());

        let bid_qty: Decimal = self
            .orderbook
            .bids
            .iter()
            .take(bid_levels)
            .map(|(_, q)| q)
            .sum();
        let ask_qty: Decimal = self
            .orderbook
            .asks
            .iter()
            .take(ask_levels)
            .map(|(_, q)| q)
            .sum();

        let sum = bid_qty + ask_qty;
        if sum.is_zero() {
            return 0.0;
        }

        let ratio = (bid_qty - ask_qty) / sum;
        let f: f64 = ratio.to_f64().unwrap_or(0.0);
        f.clamp(-1.0, 1.0)
    }

    /// Effective spread for a round-trip of size `qty` in bps.
    ///
    /// = (avg_ask_fill - avg_bid_fill) / mid_price * 10000
    pub fn effective_spread(&self, qty: Decimal) -> Result<Decimal, OrderBookAnalyzerError> {
        if self.orderbook.mid_price.is_zero() {
            return Ok(Decimal::ZERO);
        }

        let buy_result = self.walk_the_book(OrderSide::Buy, qty)?;
        let sell_result = self.walk_the_book(OrderSide::Sell, qty)?;

        let avg_ask = buy_result.avg_price;
        let avg_bid = sell_result.avg_price;

        Ok((avg_ask - avg_bid) / self.orderbook.mid_price * dec!(10000))
    }
}

fn min_decimal(a: Decimal, b: Decimal) -> Decimal {
    if a <= b {
        a
    } else {
        b
    }
}
