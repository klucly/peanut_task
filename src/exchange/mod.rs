//! Exchange client for Binance Spot Testnet.
//!
//! Wraps ccxt-rust with normalized types, error handling, and logging.

pub mod config;
pub mod errors;
pub mod orderbook;
pub mod types;

mod client;

pub use client::ExchangeClient;
pub use config::ExchangeConfig;
pub use errors::ExchangeError;
pub use orderbook::{
    BookSide, Fill, OrderBookAnalyzer, OrderBookAnalyzerError, OrderSide, WalkResult,
};
pub use types::{AssetBalance, OrderBook, OrderResult, TradingFees};
