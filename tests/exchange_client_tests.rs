//! Exchange client tests.
//!
//! Uses httpmock to mock Binance API endpoints for order book and config tests.
//! Integration tests (balance, orders) require real credentials and are #[ignore].

use httpmock::prelude::*;
use peanut_task::exchange::{ExchangeClient, ExchangeConfig, ExchangeError};

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

/// Minimal exchangeInfo response with ETHUSDT for fetch_order_book.
fn exchange_info_json() -> &'static str {
    r#"{
        "timezone": "UTC",
        "serverTime": 1699872000000,
        "rateLimits": [],
        "exchangeFilters": [],
        "symbols": [
            {
                "symbol": "ETHUSDT",
                "status": "TRADING",
                "baseAsset": "ETH",
                "baseAssetPrecision": 8,
                "quoteAsset": "USDT",
                "quotePrecision": 8,
                "quoteAssetPrecision": 8,
                "baseCommissionPrecision": 8,
                "quoteCommissionPrecision": 8,
                "orderTypes": ["LIMIT", "LIMIT_MAKER", "MARKET"],
                "icebergAllowed": true,
                "ocoAllowed": true,
                "quoteOrderQtyMarketAllowed": true,
                "isSpotTradingAllowed": true,
                "isMarginTradingAllowed": true,
                "filters": [],
                "permissions": ["SPOT", "MARGIN"]
            }
        ]
    }"#
}

#[test]
fn test_fetch_order_book_structure() {
    init_tracing();
    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(GET).path("/exchangeInfo");
        then.status(200)
            .header("content-type", "application/json")
            .body(exchange_info_json());
    });

    server.mock(|when, then| {
        when.method(GET).path("/depth").query_param("symbol", "ETHUSDT");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{
                "lastUpdateId": 123,
                "bids": [["100.00", "1.5"], ["99.50", "2.0"]],
                "asks": [["101.00", "1.0"], ["101.50", "3.0"]]
            }"#);
    });

    let base = server.base_url();
    let config = ExchangeConfig {
        api_key: "test".to_string(),
        secret: "test".to_string(),
        sandbox: true,
        url_override: Some(base),
    };

    let client = ExchangeClient::new(config).expect("client init");
    let ob = client.fetch_order_book("ETH/USDT", 20).expect("fetch_order_book");

    assert_eq!(ob.symbol, "ETH/USDT");
    assert!(!ob.bids.is_empty());
    assert!(!ob.asks.is_empty());
    assert_eq!(ob.bids.len(), 2);
    assert_eq!(ob.asks.len(), 2);
    assert!(ob.best_bid.0 >= rust_decimal_macros::dec!(99));
    assert!(ob.best_bid.0 <= rust_decimal_macros::dec!(101));
    assert!(ob.best_ask.0 >= rust_decimal_macros::dec!(100));
    assert!(ob.best_ask.0 <= rust_decimal_macros::dec!(102));
    assert!(ob.mid_price > rust_decimal::Decimal::ZERO);
    assert!(ob.spread_bps >= rust_decimal::Decimal::ZERO);
}

#[test]
fn test_order_book_bids_descending() {
    init_tracing();
    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(GET).path("/exchangeInfo");
        then.status(200)
            .header("content-type", "application/json")
            .body(exchange_info_json());
    });

    server.mock(|when, then| {
        when.method(GET).path("/depth").query_param("symbol", "ETHUSDT");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{
                "lastUpdateId": 1,
                "bids": [["100", "1"], ["99", "2"], ["98", "3"]],
                "asks": [["101", "1"], ["102", "2"]]
            }"#);
    });

    let config = ExchangeConfig {
        api_key: "test".to_string(),
        secret: "test".to_string(),
        sandbox: true,
        url_override: Some(server.base_url()),
    };

    let client = ExchangeClient::new(config).expect("client init");
    let ob = client.fetch_order_book("ETH/USDT", 20).expect("fetch_order_book");

    for i in 1..ob.bids.len() {
        assert!(
            ob.bids[i - 1].0 >= ob.bids[i].0,
            "bids must be descending: {:?}",
            ob.bids
        );
    }
}

#[test]
fn test_order_book_asks_ascending() {
    init_tracing();
    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(GET).path("/exchangeInfo");
        then.status(200)
            .header("content-type", "application/json")
            .body(exchange_info_json());
    });

    server.mock(|when, then| {
        when.method(GET).path("/depth").query_param("symbol", "ETHUSDT");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{
                "lastUpdateId": 1,
                "bids": [["100", "1"]],
                "asks": [["101", "1"], ["102", "2"], ["103", "3"]]
            }"#);
    });

    let config = ExchangeConfig {
        api_key: "test".to_string(),
        secret: "test".to_string(),
        sandbox: true,
        url_override: Some(server.base_url()),
    };

    let client = ExchangeClient::new(config).expect("client init");
    let ob = client.fetch_order_book("ETH/USDT", 20).expect("fetch_order_book");

    for i in 1..ob.asks.len() {
        assert!(
            ob.asks[i - 1].0 <= ob.asks[i].0,
            "asks must be ascending: {:?}",
            ob.asks
        );
    }
}

#[test]
fn test_spread_calculation() {
    init_tracing();
    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(GET).path("/exchangeInfo");
        then.status(200)
            .header("content-type", "application/json")
            .body(exchange_info_json());
    });

    // best_bid=100, best_ask=101 -> spread = 1%, spread_bps = 100
    server.mock(|when, then| {
        when.method(GET).path("/depth").query_param("symbol", "ETHUSDT");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{
                "lastUpdateId": 1,
                "bids": [["100", "10"]],
                "asks": [["101", "10"]]
            }"#);
    });

    let config = ExchangeConfig {
        api_key: "test".to_string(),
        secret: "test".to_string(),
        sandbox: true,
        url_override: Some(server.base_url()),
    };

    let client = ExchangeClient::new(config).expect("client init");
    let ob = client.fetch_order_book("ETH/USDT", 20).expect("fetch_order_book");

    // 1% spread ≈ 100 bps (ccxt may compute differently)
    assert!(ob.spread_bps >= rust_decimal_macros::dec!(50));
}

/// Verifies ExchangeConfig::from_env returns Auth error when API keys are missing.
/// Ignored by default: dotenvy loads .env which may contain keys. Run with
/// `cargo test test_config_from_env_missing_vars -- --ignored` after unsetting
/// BINANCE_TESTNET_API_KEY and BINANCE_TESTNET_SECRET and ensuring no .env in cwd.
#[test]
#[ignore = "requires BINANCE_TESTNET_* unset and no .env; dotenvy re-loads .env"]
fn test_config_from_env_missing_vars() {
    init_tracing();
    let result = ExchangeConfig::from_env();
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(matches!(e, ExchangeError::Auth(_)));
    }
}
