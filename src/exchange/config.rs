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
    ///
    /// **Mainnet:** Set `BINANCE_API_KEY` and `BINANCE_SECRET` → `sandbox: false`.
    /// **Testnet:** Set `BINANCE_TESTNET_API_KEY` and `BINANCE_TESTNET_SECRET` → `sandbox: true`.
    /// Mainnet takes precedence when both pairs are present.
    /// Fails if neither (mainnet or testnet) pair is complete.
    pub fn from_env() -> Result<Self, ExchangeError> {
        dotenvy::dotenv().ok();

        let mainnet_key = env::var("BINANCE_API_KEY").ok();
        let mainnet_secret = env::var("BINANCE_SECRET").ok();
        let testnet_key = env::var("BINANCE_TESTNET_API_KEY").ok();
        let testnet_secret = env::var("BINANCE_TESTNET_SECRET").ok();

        let (api_key, secret, sandbox) = if mainnet_key.as_deref().and(mainnet_secret.as_deref()).is_some() {
            (
                mainnet_key.unwrap(),
                mainnet_secret.unwrap(),
                false,
            )
        } else if testnet_key.as_deref().and(testnet_secret.as_deref()).is_some() {
            (
                testnet_key.unwrap(),
                testnet_secret.unwrap(),
                true,
            )
        } else {
            return Err(ExchangeError::Auth(
                "Set either BINANCE_API_KEY+BINANCE_SECRET (mainnet) or \
                 BINANCE_TESTNET_API_KEY+BINANCE_TESTNET_SECRET (testnet)".to_string(),
            ));
        };

        Ok(Self {
            api_key,
            secret,
            sandbox,
            url_override: None,
        })
    }
}
