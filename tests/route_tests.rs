use peanut_task::core::base_types::{Address, Token, TokenAmount};
use peanut_task::pricing::{Route, RouteFinder, TokenInPair, UniswapV2Pair};

fn addr(s: &str) -> Address {
    Address::from_string(s).unwrap()
}

// Shared tokens - reuse same instance across pools so graph connects correctly
fn shib_token() -> Token {
    Token::new(18, Some("SHIB".to_string()))
}
fn eth_token() -> Token {
    Token::native_eth()
}
fn usdc_token() -> Token {
    Token::new(6, Some("USDC".to_string()))
}
fn disconnected_token() -> Token {
    Token::new(18, Some("DISC".to_string()))
}
fn other_token() -> Token {
    Token::new(18, Some("OTHER".to_string()))
}

fn shib_in_pair() -> TokenInPair {
    TokenInPair::new(
        shib_token(),
        addr("0x0000000000000000000000000000000000000001"),
    )
}
fn eth_in_pair() -> TokenInPair {
    TokenInPair::new(
        eth_token(),
        addr("0x0000000000000000000000000000000000000002"),
    )
}
fn usdc_in_pair() -> TokenInPair {
    TokenInPair::new(
        usdc_token(),
        addr("0x0000000000000000000000000000000000000003"),
    )
}
fn disconnected_in_pair() -> TokenInPair {
    TokenInPair::new(
        disconnected_token(),
        addr("0x0000000000000000000000000000000000000004"),
    )
}
fn other_in_pair() -> TokenInPair {
    TokenInPair::new(
        other_token(),
        addr("0x0000000000000000000000000000000000000005"),
    )
}

#[test]
fn test_direct_vs_multihop() {
    // Thin direct: 1e18 SHIB / 1e6 USDC
    let shib_usdc = UniswapV2Pair::new(
        addr("0x1000000000000000000000000000000000000000"),
        shib_in_pair(),
        usdc_in_pair(),
        1 * 10u128.pow(18),
        1 * 10u128.pow(6),
        0,
        30,
    );
    // Good liquidity: 10e18 SHIB / 10e18 ETH
    let shib_eth = UniswapV2Pair::new(
        addr("0x2000000000000000000000000000000000000000"),
        shib_in_pair(),
        eth_in_pair(),
        10 * 10u128.pow(18),
        10 * 10u128.pow(18),
        0,
        30,
    );
    // Good liquidity: 10e18 ETH / 1e9 USDC (1 ETH = 1000 USDC)
    let eth_usdc = UniswapV2Pair::new(
        addr("0x3000000000000000000000000000000000000000"),
        eth_in_pair(),
        usdc_in_pair(),
        10 * 10u128.pow(18),
        1_000 * 10u128.pow(6),
        0,
        30,
    );

    let finder = RouteFinder::new(vec![shib_usdc.clone(), shib_eth, eth_usdc]);
    let amount_in = 1 * 10u128.pow(18); // 1 SHIB
    let gas_price_gwei = 30;

    let (best_route, net_output) = finder
        .find_best_route(&shib_token(), &usdc_token(), amount_in, gas_price_gwei, 3)
        .unwrap()
        .expect("should find a route");

    // Multi-hop (SHIB->ETH->USDC) should beat direct (SHIB->USDC) due to thin direct pool
    assert_eq!(best_route.num_hops(), 2, "multi-hop should win");
    assert!(net_output > 0);

    // Verify multi-hop yields more than direct
    let comparisons = finder
        .compare_routes(&shib_token(), &usdc_token(), amount_in, gas_price_gwei, 3)
        .unwrap();
    let multihop = comparisons
        .iter()
        .find(|c| c.route.num_hops() == 2)
        .unwrap();
    let direct = comparisons
        .iter()
        .find(|c| c.route.num_hops() == 1)
        .unwrap();
    assert!(
        multihop.net_output > direct.net_output,
        "multi-hop net {} should exceed direct net {}",
        multihop.net_output,
        direct.net_output
    );
}

#[test]
fn test_gas_makes_direct_better() {
    // Direct: SHIB-ETH, 1 hop
    let shib_eth = UniswapV2Pair::new(
        addr("0x4000000000000000000000000000000000000000"),
        shib_in_pair(),
        eth_in_pair(),
        10 * 10u128.pow(18),
        10 * 10u128.pow(18),
        0,
        30,
    );
    // Multi-hop: SHIB-USDC, USDC-ETH (2 hops) - tune so multi-hop gives slightly more ETH at low gas
    let shib_usdc = UniswapV2Pair::new(
        addr("0x5000000000000000000000000000000000000000"),
        shib_in_pair(),
        usdc_in_pair(),
        10 * 10u128.pow(18),
        20_000 * 10u128.pow(6), // 20k USDC
        0,
        30,
    );
    let usdc_eth = UniswapV2Pair::new(
        addr("0x6000000000000000000000000000000000000000"),
        usdc_in_pair(),
        eth_in_pair(),
        20_000 * 10u128.pow(6),
        10 * 10u128.pow(18),
        0,
        30,
    );

    let finder = RouteFinder::new(vec![shib_eth.clone(), shib_usdc, usdc_eth]);
    let amount_in = 1 * 10u128.pow(18); // 1 SHIB

    // At low gas: multi-hop may win (better effective price via USDC)
    let (_, net_low) = finder
        .find_best_route(&shib_token(), &eth_token(), amount_in, 30, 3)
        .unwrap()
        .expect("route at low gas");

    // At high gas: direct should win (less gas)
    let (best_high, net_high) = finder
        .find_best_route(&shib_token(), &eth_token(), amount_in, 500, 3)
        .unwrap()
        .expect("route at high gas");

    assert_eq!(best_high.num_hops(), 1, "direct should win at high gas");
    assert!(net_high <= net_low, "high gas should reduce net output");
}

#[test]
fn test_no_route_exists() {
    let shib_eth = UniswapV2Pair::new(
        addr("0x7000000000000000000000000000000000000000"),
        shib_in_pair(),
        eth_in_pair(),
        1000,
        1000,
        0, // block_timestamp_last
        30,
    );
    let eth_usdc = UniswapV2Pair::new(
        addr("0x8000000000000000000000000000000000000000"),
        eth_in_pair(),
        usdc_in_pair(),
        1000,
        1000,
        0, // block_timestamp_last
        30,
    );
    let disconnected_other = UniswapV2Pair::new(
        addr("0x9000000000000000000000000000000000000000"),
        disconnected_in_pair(),
        other_in_pair(),
        1000,
        1000,
        0, // block_timestamp_last
        30,
    );

    let finder = RouteFinder::new(vec![shib_eth, eth_usdc, disconnected_other]);

    let routes = finder.find_all_routes(&shib_token(), &disconnected_token(), 3);
    assert!(routes.is_empty(), "no path from SHIB to DISCONNECTED");

    let best = finder
        .find_best_route(&shib_token(), &disconnected_token(), 1000, 30, 3)
        .unwrap();
    assert!(best.is_none());
}

#[test]
fn test_route_output_matches_sequential_swaps() {
    // T0 -> T1 -> T2 with two pools
    let t0 = TokenInPair::new(
        Token::new(18, Some("T0".to_string())),
        addr("0xa000000000000000000000000000000000000001"),
    );
    let t1 = TokenInPair::new(
        Token::new(18, Some("T1".to_string())),
        addr("0xa000000000000000000000000000000000000002"),
    );
    let t2 = TokenInPair::new(
        Token::new(18, Some("T2".to_string())),
        addr("0xa000000000000000000000000000000000000003"),
    );

    let pool1 = UniswapV2Pair::new(
        addr("0xa100000000000000000000000000000000000000"),
        t0.clone(),
        t1.clone(),
        1000 * 10u128.pow(18),
        2000 * 10u128.pow(18),
        0,
        30,
    );
    let pool2 = UniswapV2Pair::new(
        addr("0xa200000000000000000000000000000000000000"),
        t1.clone(),
        t2.clone(),
        2000 * 10u128.pow(18),
        3000 * 10u128.pow(18),
        0,
        30,
    );

    let path = vec![t0.token.clone(), t1.token.clone(), t2.token.clone()];
    let route = Route::new(vec![pool1.clone(), pool2.clone()], path).unwrap();

    let amount_in_raw = 100 * 10u128.pow(18);

    // Manual sequential swaps
    let amt_in = TokenAmount::new(amount_in_raw, t0.token.clone());
    let amt1 = pool1.get_amount_out(&amt_in).unwrap();
    let amt2 = pool2.get_amount_out(&amt1).unwrap();

    let route_output = route.get_output(amount_in_raw).unwrap();
    assert_eq!(route_output.raw, amt2.raw);
    assert_eq!(route_output.token, t2.token);

    let intermediate = route.get_intermediate_amounts(amount_in_raw).unwrap();
    assert_eq!(intermediate, vec![amount_in_raw, amt1.raw, amt2.raw]);
}
