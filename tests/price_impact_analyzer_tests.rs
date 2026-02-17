use peanut_task::core::base_types::{Address, Token, TokenAmount};
use peanut_task::pricing::{
    Decimal, PriceImpactAnalyzer, PriceImpactAnalyzerError, TokenInPair, UniswapV2Pair,
};

fn pair_address() -> Address {
    Address::from_string("0x0000000000000000000000000000000000000000").unwrap()
}

fn token0() -> TokenInPair {
    TokenInPair::new(
        Token::new(18, Some("T0".to_string())),
        Address::from_string("0x0000000000000000000000000000000000000001").unwrap(),
    )
}

fn token1() -> TokenInPair {
    TokenInPair::new(
        Token::new(18, Some("T1".to_string())),
        Address::from_string("0x0000000000000000000000000000000000000002").unwrap(),
    )
}

fn eth_token_in_pair() -> TokenInPair {
    TokenInPair::new(
        Token::native_eth(),
        Address::from_string("0x0000000000000000000000000000000000000002").unwrap(),
    )
}

fn make_pair(reserve0: u128, reserve1: u128, fee_bps: u16) -> UniswapV2Pair {
    UniswapV2Pair::new(
        pair_address(),
        token0(),
        token1(),
        reserve0,
        reserve1,
        0,
        fee_bps,
    )
}

/// Pair where token0 is non-ETH and token1 is ETH; swapping token0 gives ETH out.
fn make_pair_with_eth_out(reserve_token0: u128, reserve_eth: u128, fee_bps: u16) -> UniswapV2Pair {
    UniswapV2Pair::new(
        pair_address(),
        token0(),
        eth_token_in_pair(),
        reserve_token0,
        reserve_eth,
        0,
        fee_bps,
    )
}

#[test]
fn test_generate_impact_table_empty_sizes() {
    let pair = make_pair(1000, 2000, 30);
    let analyzer = PriceImpactAnalyzer::new(pair);
    let t0 = token0();
    let rows = analyzer.generate_impact_table(&t0.token, &[]).unwrap();
    assert!(rows.is_empty());
}

#[test]
fn test_generate_impact_table_matches_pair_methods() {
    let pair = make_pair(1000, 2000, 30);
    let analyzer = PriceImpactAnalyzer::new(pair);
    let t0 = token0();
    let sizes = [100u128, 200];
    let rows = analyzer.generate_impact_table(&t0.token, &sizes).unwrap();
    assert_eq!(rows.len(), 2);
    let amt100 = TokenAmount::new(100, t0.token.clone());
    let expected_out = analyzer.pair.get_amount_out(&amt100).unwrap();
    assert_eq!(rows[0].amount_in, 100);
    assert_eq!(rows[0].amount_out, expected_out.raw);
    assert!(rows[0].price_impact_pct >= Decimal::ZERO);
}

#[test]
fn test_generate_impact_table_token_not_in_pair() {
    let pair = make_pair(1000, 2000, 30);
    let analyzer = PriceImpactAnalyzer::new(pair);
    let other = Token::new(8, Some("OTHER".to_string()));
    let err = analyzer.generate_impact_table(&other, &[100]).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("not found") || msg.contains("Token"));
}

#[test]
fn test_find_max_size_zero_reserve_returns_zero() {
    let pair = make_pair(0, 2000, 30);
    let analyzer = PriceImpactAnalyzer::new(pair);
    let t0 = token0();
    let max = analyzer
        .find_max_size_for_impact(&t0.token, Decimal::new(1, 0))
        .unwrap();
    assert_eq!(max, 0);
}

#[test]
fn test_find_max_size_for_impact_respects_max_impact() {
    let pair = make_pair(100_000, 200_000, 30);
    let analyzer = PriceImpactAnalyzer::new(pair);
    let t0 = token0();
    let max_impact = Decimal::new(1, 2);
    let max_size = analyzer
        .find_max_size_for_impact(&t0.token, max_impact)
        .unwrap();
    if max_size > 0 {
        let amt = TokenAmount::new(max_size, t0.token.clone());
        let impact = analyzer.pair.get_price_impact(&amt).unwrap();
        assert!(
            impact <= max_impact,
            "impact {} > max {}",
            impact,
            max_impact
        );
    }
}

#[test]
fn test_estimate_true_cost_zero_amount_in() {
    let pair = make_pair(1000, 2000, 30);
    let analyzer = PriceImpactAnalyzer::new(pair);
    let t0 = token0();
    let zero_in = TokenAmount::new(0, t0.token.clone());
    let cost = analyzer.estimate_true_cost(&zero_in, 30, 150_000).unwrap();
    assert_eq!(cost.gross_output, 0);
    assert_eq!(cost.net_output, 0);
    assert!(cost.effective_price.is_zero());
    assert!(cost.gas_cost_eth > 0);
}

#[test]
fn test_estimate_true_cost_net_output_deduction() {
    let pair = make_pair(100_000, 200_000, 30);
    let analyzer = PriceImpactAnalyzer::new(pair);
    let t0 = token0();
    let amount_in = TokenAmount::new(1000, t0.token.clone());
    let cost = analyzer
        .estimate_true_cost(&amount_in, 30, 150_000)
        .unwrap();
    assert!(cost.gross_output > 0);
    assert!(cost.gas_cost_eth > 0);
    assert!(cost.net_output <= cost.gross_output);
    assert!(cost.effective_price >= Decimal::ZERO);
}

#[test]
fn test_generate_impact_table_spot_execution_impact_match_pair() {
    let pair = make_pair(10_000, 20_000, 30);
    let analyzer = PriceImpactAnalyzer::new(pair);
    let t0 = token0();
    let sizes = [500u128];
    let rows = analyzer.generate_impact_table(&t0.token, &sizes).unwrap();
    assert_eq!(rows.len(), 1);
    let amt = TokenAmount::new(500, t0.token.clone());
    let expected_spot = analyzer.pair.get_spot_price(&t0.token).unwrap();
    let expected_exec = analyzer.pair.get_execution_price(&amt).unwrap();
    let expected_impact = analyzer.pair.get_price_impact(&amt).unwrap();
    assert_eq!(rows[0].spot_price, expected_spot);
    assert_eq!(rows[0].execution_price, expected_exec);
    assert_eq!(rows[0].price_impact_pct, expected_impact);
    assert_eq!(rows[0].amount_in, 500);
    assert_eq!(
        rows[0].amount_out,
        analyzer.pair.get_amount_out(&amt).unwrap().raw
    );
}

#[test]
fn test_estimate_true_cost_gas_overflow() {
    let pair = make_pair(1000, 2000, 30);
    let analyzer = PriceImpactAnalyzer::new(pair);
    let t0 = token0();
    let amount_in = TokenAmount::new(100, t0.token.clone());
    let gas_price_gwei = 20_000_000_000u64;
    let gas_estimate = u64::MAX;
    let res = analyzer.estimate_true_cost(&amount_in, gas_price_gwei, gas_estimate);
    let err = res.unwrap_err();
    assert!(matches!(err, PriceImpactAnalyzerError::Overflow));
}

#[test]
fn test_estimate_true_cost_net_output_underflow_when_eth_output() {
    let pair = make_pair_with_eth_out(1000, 1000, 30);
    let analyzer = PriceImpactAnalyzer::new(pair);
    let t0 = token0();
    let amount_in = TokenAmount::new(1, t0.token.clone());
    let gross = analyzer.pair.get_amount_out(&amount_in).unwrap().raw;
    assert!(
        gross < 10,
        "tiny trade should yield small gross output for underflow test"
    );
    let gas_price_gwei = 1_000_000u64;
    let gas_estimate = 500_000u64;
    let res = analyzer.estimate_true_cost(&amount_in, gas_price_gwei, gas_estimate);
    let err = res.unwrap_err();
    assert!(matches!(err, PriceImpactAnalyzerError::Overflow));
}

#[test]
fn test_estimate_true_cost_output_eth_deducts_gas() {
    let pair = make_pair_with_eth_out(1_000_000_000_000, 2_000_000_000_000, 30);
    let analyzer = PriceImpactAnalyzer::new(pair);
    let t0 = token0();
    let amount_in = TokenAmount::new(100_000_000_000, t0.token.clone());
    let cost = analyzer.estimate_true_cost(&amount_in, 1, 100).unwrap();
    assert!(cost.gross_output > 0);
    assert!(cost.gas_cost_eth > 0);
    assert_eq!(cost.gas_cost_in_output_token, cost.gas_cost_eth);
    assert_eq!(cost.net_output, cost.gross_output - cost.gas_cost_eth);
}

#[test]
fn test_find_max_size_boundary() {
    let pair = make_pair(100_000, 200_000, 30);
    let analyzer = PriceImpactAnalyzer::new(pair);
    let t0 = token0();
    let max_impact = Decimal::new(1, 2);
    let max_size = analyzer
        .find_max_size_for_impact(&t0.token, max_impact)
        .unwrap();
    if max_size > 0 {
        let amt = TokenAmount::new(max_size, t0.token.clone());
        let impact = analyzer.pair.get_price_impact(&amt).unwrap();
        assert!(
            impact <= max_impact,
            "max_size {} should have impact {} <= {}",
            max_size,
            impact,
            max_impact
        );
    }
}
