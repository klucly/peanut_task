//! Integration tests: generator → executor in simulation (CEX-first and DEX-first).
//! Requires a running Anvil fork; skipped when FORK_URL is not set or fork is unreachable.

use httpmock::prelude::*;
use peanut_task::chain::{ChainClient, RpcUrl};
use peanut_task::core::base_types::Address;
use peanut_task::exchange::{ExchangeClient, ExchangeConfig};
use peanut_task::integration::ArbChecker;
use peanut_task::inventory::{InventoryTracker, PnLEngine, Venue};
use peanut_task::pricing::{Chain, PricingEngine};
use peanut_task::strategy::fees::FeeStructure;
use peanut_task::strategy::{Executor, ExecutorConfig, ExecutorState, GeneratorConfig, SignalGenerator};
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

fn fork_url() -> Option<String> {
    env::var("FORK_URL").ok()
}

/// Build PricingEngine with loaded WETH-USDT pool. Returns None if fork is not running.
fn pricing_engine_with_pool() -> Option<PricingEngine> {
    let fork = fork_url()?;
    if std::net::TcpStream::connect("127.0.0.1:8545").is_err() {
        return None;
    }
    let rpc = RpcUrl::new("{}", &fork).ok()?;
    let client = ChainClient::new(vec![rpc], 10, 1).ok()?;
    let sender = Address::from_string("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
    let mut engine = PricingEngine::new(
        client,
        &fork,
        "ws://127.0.0.1:8546",
        Chain::EthereumMainnet,
        Some(sender),
    )
    .ok()?;
    let pair_address = Address::from_string("0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852").ok()?;
    engine.load_pools(&[pair_address]).ok()?;
    Some(engine)
}

fn mock_binance_eth_usdt(server: &MockServer, bid: &str, ask: &str) {
    server.mock(|when, then| {
        when.method(GET).path("/exchangeInfo");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{
                "timezone": "UTC",
                "serverTime": 1699872000000,
                "rateLimits": [],
                "exchangeFilters": [],
                "symbols": [{
                    "symbol": "ETHUSDT",
                    "status": "TRADING",
                    "baseAsset": "ETH",
                    "baseAssetPrecision": 8,
                    "quoteAsset": "USDT",
                    "quotePrecision": 8,
                    "quoteAssetPrecision": 8,
                    "baseCommissionPrecision": 8,
                    "quoteCommissionPrecision": 8,
                    "orderTypes": ["LIMIT", "MARKET"],
                    "icebergAllowed": true,
                    "ocoAllowed": true,
                    "quoteOrderQtyMarketAllowed": true,
                    "isSpotTradingAllowed": true,
                    "isMarginTradingAllowed": true,
                    "filters": [],
                    "permissions": ["SPOT"]
                }]
            }"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/depth").query_param("symbol", "ETHUSDT");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(
                r#"{{ "lastUpdateId": 123, "bids": [["{}", "10.0"]], "asks": [["{}", "10.0"]] }}"#,
                bid, ask
            ));
    });
    server.mock(|when, then| {
        when.method(GET).path("/asset/tradeFee").query_param("symbol", "ETHUSDT");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"[{ "symbol": "ETHUSDT", "makerCommission": "0.001", "takerCommission": "0.001" }]"#,
            );
    });
}

/// CEX-first (use_flashbots: false): generator → executor in simulation; assert Done and no panic.
#[test]
fn test_generator_executor_cex_first_simulation() {
    init_tracing();
    let mut pricing_engine = match pricing_engine_with_pool() {
        Some(pe) => pe,
        None => {
            eprintln!("Skipping test_generator_executor_cex_first_simulation: Fork not running");
            return;
        }
    };

    let weth = pricing_engine.get_token_by_symbol("WETH").unwrap();
    let usdc = pricing_engine.get_token_by_symbol("USDT").unwrap();
    let quote = pricing_engine
        .get_quote(&weth, &usdc, 1_000_000_000_000_000_000, 30, 3)
        .unwrap();
    let dex_price_approx = quote.expected_output as u64 as f64 / 1_000_000.0;
    let low_cex = dex_price_approx * 0.5;
    let server = MockServer::start();
    mock_binance_eth_usdt(
        &server,
        &format!("{:.2}", low_cex * 0.99),
        &format!("{:.2}", low_cex),
    );

    let exchange_config = ExchangeConfig {
        api_key: "test".to_string(),
        secret: "test".to_string(),
        sandbox: true,
        url_override: Some(server.base_url()),
    };
    let exchange_client = ExchangeClient::new(exchange_config).unwrap();

    let mut inventory_tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();
    let mut cex_balances = HashMap::new();
    cex_balances.insert(
        "USDT".to_string(),
        peanut_task::exchange::AssetBalance {
            free: Decimal::from(100_000),
            locked: Decimal::ZERO,
            total: Decimal::from(100_000),
        },
    );
    inventory_tracker
        .update_from_cex(Venue::Binance, cex_balances.clone())
        .unwrap();
    let mut wallet_balances = HashMap::new();
    wallet_balances.insert("ETH".to_string(), Decimal::from(100));
    inventory_tracker
        .update_from_wallet(Venue::Wallet, wallet_balances.clone())
        .unwrap();

    let arb_checker = ArbChecker::new(
        Arc::new(Mutex::new(pricing_engine)),
        Arc::new(Mutex::new(exchange_client)),
        Arc::new(Mutex::new(inventory_tracker)),
        PnLEngine::new(),
    );

    let mut generator = SignalGenerator::new(
        arb_checker,
        FeeStructure::default(),
        GeneratorConfig::default(),
    );

    let fork = fork_url().unwrap();
    let rpc = RpcUrl::new("{}", &fork).unwrap();
    let chain_client = Arc::new(ChainClient::new(vec![rpc], 60, 3).unwrap());

    let exchange_for_exec = Arc::new(Mutex::new(
        ExchangeClient::new(ExchangeConfig {
            api_key: "test".to_string(),
            secret: "test".to_string(),
            sandbox: true,
            url_override: Some(server.base_url()),
        })
        .unwrap(),
    ));
    let pricing_for_exec = Arc::new(Mutex::new(pricing_engine_with_pool().unwrap()));
    let mut inv_for_exec = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();
    inv_for_exec
        .update_from_cex(Venue::Binance, cex_balances.clone())
        .unwrap();
    inv_for_exec
        .update_from_wallet(Venue::Wallet, wallet_balances.clone())
        .unwrap();

    let mut executor = Executor::new(
        exchange_for_exec,
        pricing_for_exec,
        Arc::new(Mutex::new(inv_for_exec)),
        Arc::clone(&chain_client),
        None, // no DexExecutor in simulation test
        FeeStructure::default(),
        Some(ExecutorConfig {
            simulation_mode: true,
            use_flashbots: false,
            ..ExecutorConfig::default()
        }),
    );

    let signal = match generator.generate("ETH/USDT") {
        Some(s) => s,
        None => {
            eprintln!("Skipping: no opportunity (fork/mock state)");
            return;
        }
    };
    let ctx = executor.execute(signal);
    assert_eq!(
        ctx.state,
        ExecutorState::Done,
        "CEX-first simulation should finish with Done; error: {:?}",
        ctx.error
    );
}

/// DEX-first (use_flashbots: true): generator → executor in simulation; assert Done and no panic.
#[test]
fn test_generator_executor_dex_first_simulation() {
    init_tracing();
    let mut pricing_engine = match pricing_engine_with_pool() {
        Some(pe) => pe,
        None => {
            eprintln!("Skipping test_generator_executor_dex_first_simulation: Fork not running");
            return;
        }
    };

    let weth = pricing_engine.get_token_by_symbol("WETH").unwrap();
    let usdc = pricing_engine.get_token_by_symbol("USDT").unwrap();
    let quote = pricing_engine
        .get_quote(&weth, &usdc, 1_000_000_000_000_000_000, 30, 3)
        .unwrap();
    let dex_price_approx = quote.expected_output as u64 as f64 / 1_000_000.0;
    let low_cex = dex_price_approx * 0.5;
    let server = MockServer::start();
    mock_binance_eth_usdt(
        &server,
        &format!("{:.2}", low_cex * 0.99),
        &format!("{:.2}", low_cex),
    );

    let exchange_config = ExchangeConfig {
        api_key: "test".to_string(),
        secret: "test".to_string(),
        sandbox: true,
        url_override: Some(server.base_url()),
    };
    let exchange_client = ExchangeClient::new(exchange_config).unwrap();

    let mut inventory_tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();
    let mut cex_balances = HashMap::new();
    cex_balances.insert(
        "USDT".to_string(),
        peanut_task::exchange::AssetBalance {
            free: Decimal::from(100_000),
            locked: Decimal::ZERO,
            total: Decimal::from(100_000),
        },
    );
    inventory_tracker
        .update_from_cex(Venue::Binance, cex_balances.clone())
        .unwrap();
    let mut wallet_balances = HashMap::new();
    wallet_balances.insert("ETH".to_string(), Decimal::from(100));
    inventory_tracker
        .update_from_wallet(Venue::Wallet, wallet_balances.clone())
        .unwrap();

    let arb_checker = ArbChecker::new(
        Arc::new(Mutex::new(pricing_engine)),
        Arc::new(Mutex::new(exchange_client)),
        Arc::new(Mutex::new(inventory_tracker)),
        PnLEngine::new(),
    );

    let mut generator = SignalGenerator::new(
        arb_checker,
        FeeStructure::default(),
        GeneratorConfig::default(),
    );

    let fork = fork_url().unwrap();
    let rpc = RpcUrl::new("{}", &fork).unwrap();
    let chain_client = Arc::new(ChainClient::new(vec![rpc], 60, 3).unwrap());

    let exchange_for_exec = Arc::new(Mutex::new(
        ExchangeClient::new(ExchangeConfig {
            api_key: "test".to_string(),
            secret: "test".to_string(),
            sandbox: true,
            url_override: Some(server.base_url()),
        })
        .unwrap(),
    ));
    let pricing_for_exec = Arc::new(Mutex::new(pricing_engine_with_pool().unwrap()));
    let mut inv_for_exec = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();
    inv_for_exec
        .update_from_cex(Venue::Binance, cex_balances.clone())
        .unwrap();
    inv_for_exec
        .update_from_wallet(Venue::Wallet, wallet_balances.clone())
        .unwrap();

    let mut executor = Executor::new(
        exchange_for_exec,
        pricing_for_exec,
        Arc::new(Mutex::new(inv_for_exec)),
        Arc::clone(&chain_client),
        None, // no DexExecutor in simulation test
        FeeStructure::default(),
        Some(ExecutorConfig {
            simulation_mode: true,
            use_flashbots: true,
            ..ExecutorConfig::default()
        }),
    );

    let signal = match generator.generate("ETH/USDT") {
        Some(s) => s,
        None => {
            eprintln!("Skipping: no opportunity (fork/mock state)");
            return;
        }
    };
    let ctx = executor.execute(signal);
    assert_eq!(
        ctx.state,
        ExecutorState::Done,
        "DEX-first simulation should finish with Done; error: {:?}",
        ctx.error
    );
}
