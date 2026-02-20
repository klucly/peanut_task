//! Exchange client wrapping ccxt-rust for Binance Spot Testnet.

use crate::exchange::config::ExchangeConfig;
use crate::exchange::errors::ExchangeError;
use crate::exchange::types::{AssetBalance, OrderBook, OrderResult, TradingFees};
use ccxt_core::ExchangeConfig as CcxtConfig;
use ccxt_exchanges::binance::{Binance, BinanceBuilder, BinanceOptions};
use ccxt_rust::prelude::*;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::collections::HashMap;
use tokio::runtime::Runtime;
use tracing;

/// Wrapper around ccxt-rust for Binance testnet.
/// Handles rate limiting, error handling, and response normalization.
pub struct ExchangeClient {
    exchange: Binance,
    runtime: Runtime,
}

impl ExchangeClient {
    /// Initialize with config. Validates connection on init (fetch_markets).
    pub fn new(config: ExchangeConfig) -> std::result::Result<Self, ExchangeError> {
        let exchange = if let Some(ref url) = config.url_override {
            // Use ccxt_core::ExchangeConfig for url override (testing/mocking)
            let ccxt_config = CcxtConfig::builder()
                .id("binance")
                .name("Binance")
                .api_key(&config.api_key)
                .secret(&config.secret)
                .sandbox(config.sandbox)
                .enable_rate_limit(true)
                .url_override("public", url)
                .url_override("private", url)
                .option(
                    "defaultTimeInForce",
                    serde_json::Value::String("IOC".to_string()),
                )
                .build();
            let options = BinanceOptions {
                default_type: DefaultType::Spot,
                ..Default::default()
            };
            Binance::new_with_options(ccxt_config, options).map_err(|e| {
                ExchangeError::Auth(format!("Failed to build Binance client: {}", e))
            })?
        } else {
            let mut builder = BinanceBuilder::new()
                .api_key(config.api_key.clone())
                .secret(config.secret.clone())
                .sandbox(config.sandbox)
                .enable_rate_limit(true)
                .default_type(DefaultType::Spot);
            builder = builder.option(
                "defaultTimeInForce".to_string(),
                serde_json::Value::String("IOC".to_string()),
            );
            builder.build().map_err(|e| {
                ExchangeError::Auth(format!("Failed to build Binance client: {}", e))
            })?
        };

        let runtime = Runtime::new()
            .map_err(|e| ExchangeError::Network(format!("Failed to create runtime: {}", e)))?;

        // Connection health check
        runtime.block_on(async {
            exchange.fetch_markets().await.map_err(map_ccxt_error)?;
            Ok::<(), ExchangeError>(())
        })?;

        Ok(Self { exchange, runtime })
    }

    /// Fetch L2 order book snapshot.
    pub fn fetch_order_book(
        &self,
        symbol: &str,
        limit: u32,
    ) -> std::result::Result<OrderBook, ExchangeError> {
        let limit = if limit == 0 { 20 } else { limit };

        let ob: ccxt_rust::OrderBook = self.runtime.block_on(async {
            self.exchange
                .fetch_order_book(symbol, Some(limit))
                .await
                .map_err(map_ccxt_error)
        })?;

        let bids: Vec<(Decimal, Decimal)> = ob
            .bids
            .iter()
            .map(|e| (e.price.as_decimal(), e.amount.as_decimal()))
            .collect();
        let asks: Vec<(Decimal, Decimal)> = ob
            .asks
            .iter()
            .map(|e| (e.price.as_decimal(), e.amount.as_decimal()))
            .collect();

        let best_bid = ob.best_bid().ok_or_else(|| {
            ExchangeError::InvalidResponse("empty order book (no bids)".to_string())
        })?;
        let best_ask = ob.best_ask().ok_or_else(|| {
            ExchangeError::InvalidResponse("empty order book (no asks)".to_string())
        })?;

        let best_bid_tuple = (best_bid.price.as_decimal(), best_bid.amount.as_decimal());
        let best_ask_tuple = (best_ask.price.as_decimal(), best_ask.amount.as_decimal());

        let mid_price = ob.mid_price().ok_or_else(|| {
            ExchangeError::InvalidResponse("cannot compute mid price".to_string())
        })?;
        let mid_price = mid_price.as_decimal();

        let spread_bps = ob
            .spread_percentage()
            .map(|p| p * dec!(10000))
            .unwrap_or(dec!(0));

        Ok(OrderBook {
            symbol: ob.symbol.clone(),
            timestamp: ob.timestamp,
            bids,
            asks,
            best_bid: best_bid_tuple,
            best_ask: best_ask_tuple,
            mid_price,
            spread_bps,
        })
    }

    /// Fetch account balances. Filters out zero-balance assets.
    pub fn fetch_balance(
        &self,
    ) -> std::result::Result<HashMap<String, AssetBalance>, ExchangeError> {
        let balance = self.runtime.block_on(async {
            self.exchange
                .fetch_balance(None)
                .await
                .map_err(map_ccxt_error)
        })?;

        let mut result = HashMap::new();
        for (currency, entry) in &balance.balances {
            let total = entry.free + entry.used;
            if total.is_zero() {
                continue;
            }
            result.insert(
                currency.clone(),
                AssetBalance {
                    free: entry.free,
                    locked: entry.used,
                    total,
                },
            );
        }

        Ok(result)
    }

    /// Place a LIMIT IOC (Immediate Or Cancel) order.
    pub fn create_limit_ioc_order(
        &self,
        symbol: &str,
        side: &str,
        amount: f64,
        price: f64,
    ) -> std::result::Result<OrderResult, ExchangeError> {
        let order_side = parse_side(side)?;
        let amount_decimal = Decimal::try_from(amount)
            .map_err(|_| ExchangeError::InvalidResponse("invalid amount".to_string()))?;
        let price_decimal = Decimal::try_from(price)
            .map_err(|_| ExchangeError::InvalidResponse("invalid price".to_string()))?;

        let mut params = HashMap::new();
        params.insert("timeInForce".to_string(), "IOC".to_string());
        let order = self.runtime.block_on(async {
            self.exchange
                .create_order(
                    symbol,
                    OrderType::Limit,
                    order_side,
                    Amount::new(amount_decimal),
                    Some(Price::new(price_decimal)),
                    Some(params),
                )
                .await
                .map_err(map_ccxt_error)
        })?;

        let result = order_to_result(&order);
        Ok(result)
    }

    /// Place a market order.
    pub fn create_market_order(
        &self,
        symbol: &str,
        side: &str,
        amount: f64,
    ) -> std::result::Result<OrderResult, ExchangeError> {
        let order_side = parse_side(side)?;
        let amount_decimal = Decimal::try_from(amount)
            .map_err(|_| ExchangeError::InvalidResponse("invalid amount".to_string()))?;

        let order = self.runtime.block_on(async {
            self.exchange
                .create_order(
                    symbol,
                    OrderType::Market,
                    order_side,
                    Amount::new(amount_decimal),
                    None,
                    None,
                )
                .await
                .map_err(map_ccxt_error)
        })?;

        let result = order_to_result(&order);
        Ok(result)
    }

    /// Cancel an open order.
    pub fn cancel_order(
        &self,
        order_id: &str,
        symbol: &str,
    ) -> std::result::Result<OrderResult, ExchangeError> {
        let order = self.runtime.block_on(async {
            self.exchange
                .cancel_order(order_id, symbol)
                .await
                .map_err(map_ccxt_error)
        })?;

        let result = order_to_result(&order);
        Ok(result)
    }

    /// Check current status of an order.
    pub fn fetch_order_status(
        &self,
        order_id: &str,
        symbol: &str,
    ) -> std::result::Result<OrderResult, ExchangeError> {
        let order = self.runtime.block_on(async {
            self.exchange
                .fetch_order(order_id, symbol)
                .await
                .map_err(map_ccxt_error)
        })?;

        let result = order_to_result(&order);
        Ok(result)
    }

    /// Get trading fee structure for a symbol.
    pub fn get_trading_fees(
        &self,
        symbol: &str,
    ) -> std::result::Result<TradingFees, ExchangeError> {
        let market = self
            .runtime
            .block_on(async { self.exchange.market(symbol).await.map_err(map_ccxt_error) })?;

        let (maker, taker) = match (market.maker, market.taker) {
            (Some(m), Some(t)) => (m, t),
            _ => (dec!(0.001), dec!(0.001)), // Binance default 0.1%
        };

        Ok(TradingFees { maker, taker })
    }
}

fn parse_side(side: &str) -> std::result::Result<OrderSide, ExchangeError> {
    match side.to_lowercase().as_str() {
        "buy" => Ok(OrderSide::Buy),
        "sell" => Ok(OrderSide::Sell),
        _ => Err(ExchangeError::InvalidResponse(format!(
            "invalid side: {}",
            side
        ))),
    }
}

fn order_to_result(order: &ccxt_rust::Order) -> OrderResult {
    let amount_requested = order.amount;
    let amount_filled = order.filled.unwrap_or(dec!(0));
    let avg_fill_price = order.average.unwrap_or(dec!(0));
    let (fee, fee_asset) = order
        .fee
        .as_ref()
        .map(|f| (f.cost, f.currency.clone()))
        .unwrap_or((dec!(0), String::new()));
    let status = format!("{:?}", order.status).to_lowercase();
    let timestamp = order.timestamp.unwrap_or(0);

    OrderResult {
        id: order.id.clone(),
        symbol: order.symbol.clone(),
        side: format!("{:?}", order.side).to_lowercase(),
        order_type: format!("{:?}", order.order_type).to_lowercase(),
        time_in_force: order.time_in_force.clone().unwrap_or_default(),
        amount_requested,
        amount_filled,
        avg_fill_price,
        fee,
        fee_asset,
        status,
        timestamp,
    }
}

fn map_ccxt_error(e: ccxt_rust::Error) -> ExchangeError {
    use ccxt_rust::Error;
    match &e {
        Error::Network(_) => ExchangeError::Network(e.to_string()),
        Error::Authentication(msg) => ExchangeError::Auth(msg.to_string()),
        Error::Exchange(_) => ExchangeError::Exchange(e.to_string()),
        _ => ExchangeError::Exchange(e.to_string()),
    }
}
