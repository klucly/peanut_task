use peanut_task::core::base_types::{Address, Token};
use peanut_task::pricing::{
    Chain, PricingEngine, Quote, QuoteError, Route, TokenInPair, UniswapV2Pair,
};

fn addr(s: &str) -> Address {
    Address::from_string(s).unwrap()
}

fn token0() -> TokenInPair {
    TokenInPair::new(
        Token::new(18, Some("T0".to_string())),
        addr("0x0000000000000000000000000000000000000001"),
    )
}

fn token1() -> TokenInPair {
    TokenInPair::new(
        Token::new(18, Some("T1".to_string())),
        addr("0x0000000000000000000000000000000000000002"),
    )
}

fn make_route() -> Route {
    let pool = UniswapV2Pair::new(
        addr("0x1000000000000000000000000000000000000000"),
        token0(),
        token1(),
        1000,
        2000,
        0,
        30,
    );
    Route::new(
        vec![pool],
        vec![token0().token.clone(), token1().token.clone()],
    )
    .unwrap()
}

// --- Unit tests (no network) ---

#[test]
fn test_quote_is_valid_within_tolerance() {
    let route = make_route();
    let quote = Quote {
        route,
        amount_in: 100,
        expected_output: 1000,
        simulated_output: 1000,
        gas_estimate: 150_000,
        timestamp: 0.0,
    };
    assert!(quote.is_valid());
}

#[test]
fn test_quote_is_invalid_when_not_exact() {
    let route = make_route();
    let quote = Quote {
        route,
        amount_in: 100,
        expected_output: 1_000_000,
        simulated_output: 999_500,
        gas_estimate: 150_000,
        timestamp: 0.0,
    };
    assert!(!quote.is_valid(), "must match exactly, no tolerance");
}

#[test]
fn test_quote_is_invalid_when_mismatch() {
    let route = make_route();
    // diff = 0.002 > 0.001
    let quote = Quote {
        route,
        amount_in: 100,
        expected_output: 1_000_000,
        simulated_output: 998_000,
        gas_estimate: 150_000,
        timestamp: 0.0,
    };
    assert!(!quote.is_valid());
}

#[test]
fn test_quote_is_invalid_when_expected_zero() {
    let route = make_route();
    let quote = Quote {
        route,
        amount_in: 100,
        expected_output: 0,
        simulated_output: 0,
        gas_estimate: 150_000,
        timestamp: 0.0,
    };
    assert!(!quote.is_valid());
}

// --- Integration tests (require fork) ---

fn pricing_engine_and_fork() -> Option<PricingEngine> {
    let fork_url =
        std::env::var("FORK_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let rpc = peanut_task::chain::RpcUrl::new("{}", &fork_url).ok()?;
    let client = peanut_task::chain::ChainClient::new(vec![rpc], 10, 1).ok()?;
    let engine = PricingEngine::new(
        client,
        &fork_url,
        "wss://localhost:8546",
        Chain::EthereumMainnet,
        None,
    )
    .ok()?;
    Some(engine)
}

#[test]
fn test_get_quote_no_pools_loaded() {
    let engine = pricing_engine_and_fork().expect(
        "Fork not running or invalid FORK_URL. Run `just fork` (requires ETH_RPC_URL or INFURA_API_KEY).",
    );
    // Do not call load_pools
    let err = engine
        .get_quote(
            &Token::native_eth(),
            &Token::new(6, Some("USDC".to_string())),
            1_000_000,
            30,
            3,
        )
        .unwrap_err();
    assert!(matches!(err, QuoteError::NoPoolsLoaded));
}

#[test]
fn test_get_quote_no_route_exists() {
    let mut engine =
        pricing_engine_and_fork().expect("Fork not running or invalid FORK_URL. Run `just fork`.");
    // Load a single pool (USDC-WETH) - no path to a disconnected token
    let pair_addr = addr("0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc");
    engine.load_pools(&[pair_addr]).expect("load pools failed");
    let disconnected = Token::new(18, Some("DISC".to_string()));
    let usdc = Token::new(6, Some("USDC".to_string()));
    let err = engine
        .get_quote(&usdc, &disconnected, 1_000_000, 30, 3)
        .unwrap_err();
    assert!(matches!(err, QuoteError::NoRoute));
}

#[test]
fn test_refresh_pool_not_found() {
    let mut engine =
        pricing_engine_and_fork().expect("Fork not running or invalid FORK_URL. Run `just fork`.");
    let pair_addr = addr("0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc");
    engine.load_pools(&[pair_addr]).expect("load pools failed");
    let other_addr = addr("0x0000000000000000000000000000000000000000");
    let err = engine.refresh_pool(&other_addr).unwrap_err();
    assert!(matches!(err, QuoteError::PoolNotFound(_)));
}

#[test]
fn test_pricing_engine_load_pools_rebuilds_router() {
    let mut engine =
        pricing_engine_and_fork().expect("Fork not running or invalid FORK_URL. Run `just fork`.");
    assert_eq!(engine.pool_count(), 0);
    let pair_addr = addr("0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc");
    engine.load_pools(&[pair_addr]).expect("load pools failed");
    assert_eq!(engine.pool_count(), 1);
}

#[test]
fn test_get_quote_full_flow() {
    let mut engine =
        pricing_engine_and_fork().expect("Fork not running or invalid FORK_URL. Run `just fork`.");
    let pair_addr = addr("0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc");
    engine.load_pools(&[pair_addr]).expect("load pools failed");
    // Use tokens from the loaded pool (WETH has symbol "WETH", not "ETH").
    // Swap ETH->USDC so simulation succeeds (default Anvil account has ETH, not USDC).
    let tokens = engine.pool_tokens();
    let weth = tokens
        .iter()
        .find(|t| {
            t.symbol()
                .map(|s| s == "WETH" || s == "ETH")
                .unwrap_or(false)
        })
        .unwrap()
        .clone();
    let usdc = tokens
        .iter()
        .find(|t| t.symbol() == Some("USDC"))
        .unwrap()
        .clone();
    let amount_in = 1_000_000_000_000_000_000u128; // 1 ETH (18 decimals)
    let quote = engine
        .get_quote(&weth, &usdc, amount_in, 30, 3)
        .expect("get_quote failed");
    assert_eq!(quote.amount_in, amount_in);
    assert!(quote.expected_output > 0);
    assert!(quote.simulated_output > 0);
    assert!(quote.gas_estimate > 0);
    assert!(quote.timestamp > 0.0);
    assert!(quote.is_valid(), "quote should be valid within tolerance");
}
