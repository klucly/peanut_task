use peanut_task::core::base_types::{Address, Token, TokenAmount};
use peanut_task::pricing::{Decimal, PriceImpactAnalyzer, TokenInPair, UniswapV2Pair};

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

fn make_pair(reserve0: u128, reserve1: u128, fee_bps: u16) -> UniswapV2Pair {
    UniswapV2Pair::new(pair_address(), token0(), token1(), reserve0, reserve1, fee_bps)
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
    let max = analyzer.find_max_size_for_impact(&t0.token, Decimal::new(1, 0)).unwrap();
    assert_eq!(max, 0);
}

#[test]
fn test_find_max_size_for_impact_respects_max_impact() {
    let pair = make_pair(100_000, 200_000, 30);
    let analyzer = PriceImpactAnalyzer::new(pair);
    let t0 = token0();
    let max_impact = Decimal::new(1, 2);
    let max_size = analyzer.find_max_size_for_impact(&t0.token, max_impact).unwrap();
    if max_size > 0 {
        let amt = TokenAmount::new(max_size, t0.token.clone());
        let impact = analyzer.pair.get_price_impact(&amt).unwrap();
        assert!(impact <= max_impact, "impact {} > max {}", impact, max_impact);
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
    let cost = analyzer.estimate_true_cost(&amount_in, 30, 150_000).unwrap();
    assert!(cost.gross_output > 0);
    assert!(cost.gas_cost_eth > 0);
    assert!(cost.net_output <= cost.gross_output);
    assert!(cost.effective_price >= Decimal::ZERO);
}
