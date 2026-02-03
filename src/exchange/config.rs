use crate::exchange::errors::ExchangeError;
use std::env;

/// Configuration for the exchange client (per spec "config dict").
#[derive(Debug, Clone)]
pub struct ExchangeConfig {
    pub api_key: String,
    pub secret: String,
    pub sandbox: bool,
    /// Optional URL override for public API (used in tests for mocking).
    #[doc(hidden)]
    pub url_override: Option<String>,
}

impl ExchangeConfig {
    /// Load configuration from environment variables.
    /// Uses BINANCE_TESTNET_API_KEY, BINANCE_TESTNET_SECRET.
    /// Sandbox defaults to true for testnet.
    pub fn from_env() -> Result<Self, ExchangeError> {
        dotenvy::dotenv().ok();

        let api_key = env::var("BINANCE_TESTNET_API_KEY")
            .map_err(|_| ExchangeError::Auth("BINANCE_TESTNET_API_KEY not set".to_string()))?;
        let secret = env::var("BINANCE_TESTNET_SECRET")
            .map_err(|_| ExchangeError::Auth("BINANCE_TESTNET_SECRET not set".to_string()))?;

        Ok(Self {
            api_key,
            secret,
            sandbox: true,
            url_override: None,
        })
    }
}
