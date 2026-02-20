use httpmock::prelude::*;
use peanut_task::chain::{ChainClient, RpcUrl};
use peanut_task::core::base_types::{Address, Token};
use peanut_task::exchange::{ExchangeClient, ExchangeConfig};
use peanut_task::integration::ArbChecker;
use peanut_task::inventory::{InventoryTracker, PnLEngine, Venue};
use peanut_task::pricing::{Chain, PricingEngine};
use rust_decimal::Decimal;
use std::env;
use std::sync::{Arc, Mutex};

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

fn pricing_engine_and_fork() -> Option<PricingEngine> {
    let fork_url = env::var("FORK_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    // Simple check if fork is running
    if std::net::TcpStream::connect("127.0.0.1:8545").is_err() {
        return None;
    }

    let rpc = RpcUrl::new("{}", &fork_url).ok()?;
    let client = ChainClient::new(vec![rpc], 10, 1).ok()?;

    // Use Anvil account 0 which is pre-funded
    let sender = Address::from_string("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    Some(
        PricingEngine::new(
            client,
            &fork_url,
            "ws://127.0.0.1:8546",
            Chain::EthereumMainnet,
            Some(sender),
        )
        .unwrap(),
    )
}

fn mock_binance_eth_usdt(server: &MockServer, bid: &str, ask: &str) {
    // Exchange Info
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
                        "orderTypes": ["LIMIT", "MARKET"],
                        "icebergAllowed": true,
                        "ocoAllowed": true,
                        "quoteOrderQtyMarketAllowed": true,
                        "isSpotTradingAllowed": true,
                        "isMarginTradingAllowed": true,
                        "filters": [],
                        "permissions": ["SPOT"]
                    }
                ]
            }"#,
            );
    });

    // Order Book
    server.mock(|when, then| {
        when.method(GET)
            .path("/depth")
            .query_param("symbol", "ETHUSDT");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(
                r#"{{
                "lastUpdateId": 123,
                "bids": [["{}", "10.0"]],
                "asks": [["{}", "10.0"]]
            }}"#,
                bid, ask
            ));
    });

    // Fees: default 10 bps (0.001) for tests that do not need a custom taker
    mock_binance_eth_usdt_fees(server, "0.001");
}

/// Mock Binance ETH/USDT with custom taker commission (e.g. "0.001" = 10 bps, "0.003" = 30 bps).
fn mock_binance_eth_usdt_with_fees(server: &MockServer, bid: &str, ask: &str, taker_commission: &str) {
    // Exchange Info
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
                        "orderTypes": ["LIMIT", "MARKET"],
                        "icebergAllowed": true,
                        "ocoAllowed": true,
                        "quoteOrderQtyMarketAllowed": true,
                        "isSpotTradingAllowed": true,
                        "isMarginTradingAllowed": true,
                        "filters": [],
                        "permissions": ["SPOT"]
                    }
                ]
            }"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET)
            .path("/depth")
            .query_param("symbol", "ETHUSDT");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(
                r#"{{
                "lastUpdateId": 123,
                "bids": [["{}", "10.0"]],
                "asks": [["{}", "10.0"]]
            }}"#,
                bid, ask
            ));
    });
    mock_binance_eth_usdt_fees(server, taker_commission);
}

fn mock_binance_eth_usdt_fees(server: &MockServer, taker_commission: &str) {
    server.mock(|when, then| {
        when.method(GET)
            .path("/asset/tradeFee")
            .query_param("symbol", "ETHUSDT");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(
                r#"[
                {{
                    "symbol": "ETHUSDT",
                    "makerCommission": "0.001",
                    "takerCommission": "{}"
                }}
            ]"#,
                taker_commission
            ));
    });
}

#[test]
fn test_arb_profit() {
    init_tracing();
    let mut pricing_engine = match pricing_engine_and_fork() {
        Some(pe) => pe,
        None => {
            eprintln!("Skipping test_arb_profit: Fork not running");
            return;
        }
    };

    // Load WETH-USDT pool
    let pair_address = Address::from_string("0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852").unwrap();
    pricing_engine
        .load_pools(&[pair_address])
        .expect("Failed to load WETH-USDT pool");

    // Get current DEX price (approximate) to set CEX price lower
    // We'll just ask for a small amount to get the price
    let weth = pricing_engine.get_token_by_symbol("WETH").unwrap();
    let usdc = pricing_engine.get_token_by_symbol("USDT").unwrap(); // Actually USDT in this pool
    let quote = pricing_engine
        .get_quote(&weth, &usdc, 1_000_000_000_000_000_000, 30, 3)
        .unwrap();

    // DEX price is roughly quote.expected_output (USDT has 6 decimals, WETH 18)
    // Price = output / 1e6.
    // Let's set CEX price to be significantly lower (e.g. 50% lower) to guarantee profit
    let dex_output_u64 = quote.expected_output as u64;
    let dex_price_approx = dex_output_u64 as f64 / 1_000_000.0;
    let low_cex_price = dex_price_approx * 0.5;

    let server = MockServer::start();
    let ask_price_str = format!("{:.2}", low_cex_price);
    let bid_price_str = format!("{:.2}", low_cex_price * 0.99); // Bid slightly lower
    mock_binance_eth_usdt(&server, &bid_price_str, &ask_price_str);

    let exchange_config = ExchangeConfig {
        api_key: "test".to_string(),
        secret: "test".to_string(),
        sandbox: true,
        url_override: Some(server.base_url()),
    };
    let exchange_client = ExchangeClient::new(exchange_config).unwrap();

    // Initialize inventory tracker with sufficient balances for the arb
    let mut inventory_tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();

    // Set up inventory: we need USDT on CEX to buy ETH, and ETH on wallet to sell on DEX
    use peanut_task::exchange::AssetBalance;
    use std::collections::HashMap;

    // CEX balances: Give plenty of USDT to buy ETH
    let mut cex_balances = HashMap::new();
    cex_balances.insert(
        "USDT".to_string(),
        AssetBalance {
            free: Decimal::from(100_000), // 100k USDT
            locked: Decimal::ZERO,
            total: Decimal::from(100_000),
        },
    );
    inventory_tracker
        .update_from_cex(Venue::Binance, cex_balances)
        .unwrap();

    // Wallet balances: Give plenty of ETH to sell on DEX
    let mut wallet_balances = HashMap::new();
    wallet_balances.insert("ETH".to_string(), Decimal::from(100)); // 100 ETH
    inventory_tracker
        .update_from_wallet(Venue::Wallet, wallet_balances)
        .unwrap();

    let pnl_engine = PnLEngine::new();

    let arb_checker = ArbChecker::new(
        Arc::new(Mutex::new(pricing_engine)),
        Arc::new(Mutex::new(exchange_client)),
        Arc::new(Mutex::new(inventory_tracker)),
        pnl_engine,
    );

    // Check 1 ETH
    let amount_in = Decimal::ONE;
    let result = arb_checker.opportunity_swap_by_amount("ETH/USDT", amount_in);
    assert!(result.is_ok());
    let swap = result.unwrap();

    println!(
        "DEX Price: {}, CEX Ask: {}, Profit: {}",
        swap.dex_price, swap.cex_ask, swap.estimated_net_pnl_bps
    );

    assert!(swap.inventory_ok, "Inventory should be sufficient");
    assert!(swap.executable);
    assert!(swap.estimated_net_pnl_bps > Decimal::ZERO);
}

#[test]
fn test_arb_no_profit() {
    init_tracing();
    let mut pricing_engine = match pricing_engine_and_fork() {
        Some(pe) => pe,
        None => {
            eprintln!("Skipping test_arb_no_profit: Fork not running");
            return;
        }
    };

    // Load WETH-USDT pool
    let pair_address = Address::from_string("0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852").unwrap();
    pricing_engine
        .load_pools(&[pair_address])
        .expect("Failed to load WETH-USDT pool");

    // Get current DEX price
    let weth = pricing_engine.get_token_by_symbol("WETH").unwrap();
    let usdc = pricing_engine.get_token_by_symbol("USDT").unwrap();
    let quote = pricing_engine
        .get_quote(&weth, &usdc, 1_000_000_000_000_000_000, 30, 3)
        .unwrap();

    let dex_output_u64 = quote.expected_output as u64;
    let dex_price_approx = dex_output_u64 as f64 / 1_000_000.0;

    // Set CEX bid and ask equal to the DEX price.
    // With zero spread, both arb directions are unprofitable after applying
    // CEX fees (~10 bps), DEX fees (30 bps) and gas (~20 bps).
    let cex_price = dex_price_approx;

    let server = MockServer::start();
    let ask_price_str = format!("{:.2}", cex_price);
    let bid_price_str = format!("{:.2}", cex_price); // same as ask — no spread
    mock_binance_eth_usdt(&server, &bid_price_str, &ask_price_str);

    let exchange_config = ExchangeConfig {
        api_key: "test".to_string(),
        secret: "test".to_string(),
        sandbox: true,
        url_override: Some(server.base_url()),
    };
    let exchange_client = ExchangeClient::new(exchange_config).unwrap();

    // Initialize inventory tracker with sufficient balances
    let mut inventory_tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();

    use peanut_task::exchange::AssetBalance;
    use std::collections::HashMap;

    // CEX balances: Give plenty of USDT to buy ETH
    let mut cex_balances = HashMap::new();
    cex_balances.insert(
        "USDT".to_string(),
        AssetBalance {
            free: Decimal::from(100_000),
            locked: Decimal::ZERO,
            total: Decimal::from(100_000),
        },
    );
    inventory_tracker
        .update_from_cex(Venue::Binance, cex_balances)
        .unwrap();

    // Wallet balances: Give plenty of ETH
    let mut wallet_balances = HashMap::new();
    wallet_balances.insert("ETH".to_string(), Decimal::from(100));
    inventory_tracker
        .update_from_wallet(Venue::Wallet, wallet_balances)
        .unwrap();

    let pnl_engine = PnLEngine::new();

    let arb_checker = ArbChecker::new(
        Arc::new(Mutex::new(pricing_engine)),
        Arc::new(Mutex::new(exchange_client)),
        Arc::new(Mutex::new(inventory_tracker)),
        pnl_engine,
    );

    // Check 1 ETH
    let amount_in = Decimal::ONE;
    let result = arb_checker.opportunity_swap_by_amount("ETH/USDT", amount_in);
    assert!(result.is_ok());
    let swap = result.unwrap();

    println!(
        "DEX Price: {}, CEX Ask: {}, Profit: {}",
        swap.dex_price, swap.cex_ask, swap.estimated_net_pnl_bps
    );

    // Should NOT be executable because it's not profitable (even though inventory is sufficient)
    assert!(swap.inventory_ok, "Inventory should be sufficient");
    assert!(
        !swap.executable,
        "Should not be executable due to negative PnL"
    );
    assert!(swap.estimated_net_pnl_bps < Decimal::ZERO);
}

/// Profitable case: CEX ask below DEX price, low fees (10 bps ≈ 2 USD on 2000 notional) → net_pnl > 0 → accept.
#[test]
fn test_arb_check_profitable_accepts() {
    init_tracing();
    let mut pricing_engine = match pricing_engine_and_fork() {
        Some(pe) => pe,
        None => {
            eprintln!("Skipping test_arb_check_profitable_accepts: Fork not running");
            return;
        }
    };

    let pair_address = Address::from_string("0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852").unwrap();
    pricing_engine
        .load_pools(&[pair_address])
        .expect("Failed to load WETH-USDT pool");

    let weth = pricing_engine.get_token_by_symbol("WETH").unwrap();
    let usdc = pricing_engine.get_token_by_symbol("USDT").unwrap();
    let quote = pricing_engine
        .get_quote(&weth, &usdc, 1_000_000_000_000_000_000, 30, 3)
        .unwrap();
    let dex_output_u64 = quote.expected_output as u64;
    let dex_price_approx = dex_output_u64 as f64 / 1_000_000.0;
    let low_cex_price = dex_price_approx * 0.5;

    let server = MockServer::start();
    let ask_str = format!("{:.2}", low_cex_price);
    let bid_str = format!("{:.2}", low_cex_price * 0.99);
    // 10 bps taker ≈ 2 USD fees on 2000 USD notional
    mock_binance_eth_usdt_with_fees(&server, &bid_str, &ask_str, "0.001");

    let exchange_config = ExchangeConfig {
        api_key: "test".to_string(),
        secret: "test".to_string(),
        sandbox: true,
        url_override: Some(server.base_url()),
    };
    let exchange_client = ExchangeClient::new(exchange_config).unwrap();

    let mut inventory_tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();
    use peanut_task::exchange::AssetBalance;
    use std::collections::HashMap;
    let mut cex_balances = HashMap::new();
    cex_balances.insert(
        "USDT".to_string(),
        AssetBalance {
            free: Decimal::from(100_000),
            locked: Decimal::ZERO,
            total: Decimal::from(100_000),
        },
    );
    inventory_tracker
        .update_from_cex(Venue::Binance, cex_balances)
        .unwrap();
    let mut wallet_balances = HashMap::new();
    wallet_balances.insert("ETH".to_string(), Decimal::from(100));
    inventory_tracker
        .update_from_wallet(Venue::Wallet, wallet_balances)
        .unwrap();

    let pnl_engine = PnLEngine::new();
    let arb_checker = ArbChecker::new(
        Arc::new(Mutex::new(pricing_engine)),
        Arc::new(Mutex::new(exchange_client)),
        Arc::new(Mutex::new(inventory_tracker)),
        pnl_engine,
    );

    let result = arb_checker.opportunity_swap_by_amount("ETH/USDT", Decimal::ONE);
    assert!(result.is_ok(), "arb check should return Ok when profitable");
    let swap = result.unwrap();
    assert!(swap.inventory_ok, "inventory should be sufficient");
    assert!(swap.executable, "opportunity should be executable (profitable)");
    assert!(
        swap.estimated_net_pnl_bps > Decimal::ZERO,
        "estimated_net_pnl_bps should be positive"
    );
    let trade_value_usd = swap.amount * swap.cex_ask;
    let net_pnl_usd = (swap.estimated_net_pnl_bps / Decimal::from(10_000)) * trade_value_usd;
    assert!(
        net_pnl_usd >= Decimal::from(3),
        "net_pnl_usd should be at least 3 (got {})",
        net_pnl_usd
    );
}

/// Unprofitable case: CEX ask = DEX price (no spread), high fees (30 bps ≈ 6 USD on 2000 notional) → net_pnl < 0 → reject.
#[test]
fn test_arb_check_unprofitable_rejects() {
    init_tracing();
    let mut pricing_engine = match pricing_engine_and_fork() {
        Some(pe) => pe,
        None => {
            eprintln!("Skipping test_arb_check_unprofitable_rejects: Fork not running");
            return;
        }
    };

    let pair_address = Address::from_string("0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852").unwrap();
    pricing_engine
        .load_pools(&[pair_address])
        .expect("Failed to load WETH-USDT pool");

    let weth = pricing_engine.get_token_by_symbol("WETH").unwrap();
    let usdc = pricing_engine.get_token_by_symbol("USDT").unwrap();
    let quote = pricing_engine
        .get_quote(&weth, &usdc, 1_000_000_000_000_000_000, 30, 3)
        .unwrap();
    let dex_output_u64 = quote.expected_output as u64;
    let cex_price = dex_output_u64 as f64 / 1_000_000.0;

    let server = MockServer::start();
    let price_str = format!("{:.2}", cex_price);
    // 30 bps taker ≈ 6 USD fees on 2000 USD notional
    mock_binance_eth_usdt_with_fees(&server, &price_str, &price_str, "0.003");

    let exchange_config = ExchangeConfig {
        api_key: "test".to_string(),
        secret: "test".to_string(),
        sandbox: true,
        url_override: Some(server.base_url()),
    };
    let exchange_client = ExchangeClient::new(exchange_config).unwrap();

    let mut inventory_tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();
    use peanut_task::exchange::AssetBalance;
    use std::collections::HashMap;
    let mut cex_balances = HashMap::new();
    cex_balances.insert(
        "USDT".to_string(),
        AssetBalance {
            free: Decimal::from(100_000),
            locked: Decimal::ZERO,
            total: Decimal::from(100_000),
        },
    );
    inventory_tracker
        .update_from_cex(Venue::Binance, cex_balances)
        .unwrap();
    let mut wallet_balances = HashMap::new();
    wallet_balances.insert("ETH".to_string(), Decimal::from(100));
    inventory_tracker
        .update_from_wallet(Venue::Wallet, wallet_balances)
        .unwrap();

    let pnl_engine = PnLEngine::new();
    let arb_checker = ArbChecker::new(
        Arc::new(Mutex::new(pricing_engine)),
        Arc::new(Mutex::new(exchange_client)),
        Arc::new(Mutex::new(inventory_tracker)),
        pnl_engine,
    );

    let result = arb_checker.opportunity_swap_by_amount("ETH/USDT", Decimal::ONE);
    assert!(result.is_ok(), "arb check should return Ok (may return opportunity with executable=false)");
    let swap = result.unwrap();
    assert!(
        !swap.executable,
        "opportunity should not be executable (unprofitable)"
    );
    assert!(
        swap.estimated_net_pnl_bps < Decimal::ZERO,
        "estimated_net_pnl_bps should be negative"
    );
    let trade_value_usd = swap.amount * swap.cex_ask;
    let net_pnl_usd = (swap.estimated_net_pnl_bps / Decimal::from(10_000)) * trade_value_usd;
    assert!(
        net_pnl_usd <= Decimal::ZERO,
        "net_pnl_usd should be <= 0 (got {})",
        net_pnl_usd
    );
}
