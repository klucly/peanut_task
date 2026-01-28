use peanut_task::chain::{ChainClient, RpcUrl};
use peanut_task::core::base_types::{Address, TokenAmount, Token};
use peanut_task::pricing::{Decimal, TokenInPair, UniswapV2Pair};

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

fn usdc_token_in_pair() -> TokenInPair {
    TokenInPair::new(
        Token::new(6, None),
        Address::from_string("0x0000000000000000000000000000000000000002").unwrap(),
    )
}

fn make_pair(reserve0: u128, reserve1: u128, fee_bps: u16) -> UniswapV2Pair {
    UniswapV2Pair::new(pair_address(), token0(), token1(), reserve0, reserve1, fee_bps)
}

#[test]
fn test_get_amount_out_basic() {
    let pair = UniswapV2Pair::new(
        pair_address(),
        token0(),
        usdc_token_in_pair(),
        1000 * 10u128.pow(18),
        2_000_000 * 10u128.pow(6),
        30,
    );
    let usdc_in = TokenAmount::new(2000 * 10u128.pow(6), usdc_token_in_pair().token.clone());
    let eth_out = pair.get_amount_out(&usdc_in).unwrap();
    assert!(eth_out.raw < 10u128.pow(18), "expected less than 1 ETH, got {}", eth_out.raw);
    assert!(eth_out.raw > 99 * 10u128.pow(16), "expected more than 0.99 ETH, got {}", eth_out.raw);
}

#[test]
fn test_get_amount_out_matches_solidity_formula() {
    let pair = make_pair(1000, 2000, 30);
    let t0 = token0();
    let amt_in = TokenAmount::new(100, t0.token.clone());
    let out = pair.get_amount_out(&amt_in).unwrap();
    assert_eq!(out.raw, 181);
}

#[test]
fn test_integer_math_no_floats() {
    let reserve = 10u128.pow(18);
    let t0 = token0();
    let amount_in = TokenAmount::new(10u128.pow(15), t0.token.clone());
    let pair = make_pair(reserve, reserve, 30);
    let out = pair.get_amount_out(&amount_in).unwrap();
    assert!(out.raw > 0);
    assert!(out.raw < reserve);
}

#[test]
fn test_get_amount_out_token1_in() {
    let pair = make_pair(1000, 2000, 30);
    let t1 = token1();
    let amt_in = TokenAmount::new(100, t1.token.clone());
    let out = pair.get_amount_out(&amt_in).unwrap();
    assert_eq!(out.raw, 47);
}

#[test]
fn test_get_amount_in_roundtrip() {
    let pair = make_pair(1_000_000, 2_000_000, 30);
    let t0 = token0();
    let t1 = token1();
    let amount_in = TokenAmount::new(100_000, t0.token.clone());
    let amount_out = pair.get_amount_out(&amount_in).unwrap();
    let amount_in_req = pair.get_amount_in(&amount_out).unwrap();
    assert!(amount_in_req.raw >= amount_in.raw);
}

#[test]
fn test_get_amount_in_for_desired_out() {
    let pair = make_pair(1000, 2000, 30);
    let t0 = token0();
    let t1 = token1();
    let amount_out = TokenAmount::new(181, t1.token.clone());
    let amount_in = pair.get_amount_in(&amount_out).unwrap();
    let actual_out = pair.get_amount_out(&amount_in).unwrap();
    assert!(actual_out.raw >= amount_out.raw);
}

#[test]
fn test_get_spot_price_token0_in() {
    let pair = make_pair(1000, 2000, 30);
    let price = pair.get_spot_price(&pair.token0.token).unwrap();
    assert_eq!(price, Decimal::from(2u8));
    assert_eq!((price * Decimal::from(100u64)).trunc(), Decimal::from(200u64));
    assert_eq!(price.round_dp(8).to_string(), "2");
}

#[test]
fn test_get_spot_price_token1_in() {
    let pair = make_pair(1000, 2000, 30);
    let price = pair.get_spot_price(&pair.token1.token).unwrap();
    assert_eq!(price, Decimal::from(5u8) / Decimal::from(10u8));
    assert_eq!((price * Decimal::from(100u64)).trunc(), Decimal::from(50u64));
}

#[test]
fn test_get_execution_price() {
    let pair = make_pair(1000, 2000, 30);
    let amount_in = TokenAmount::new(100, pair.token0.token.clone());
    let price = pair.get_execution_price(&amount_in).unwrap();
    assert_eq!((price * Decimal::from(100u64)).trunc(), Decimal::from(181u64));
    assert_eq!(price.round_dp(2).to_string(), "1.81");
}

#[test]
fn test_get_price_impact_non_zero() {
    let pair = make_pair(1_000_000, 2_000_000, 30);
    let amount_in = TokenAmount::new(100_000, pair.token0.token.clone());
    let impact = pair.get_price_impact(&amount_in).unwrap();
    let bps = (impact * Decimal::from(10000u64)).trunc();
    assert!(bps > Decimal::ZERO);
    assert!(impact > Decimal::ZERO);
}

#[test]
fn test_simulate_swap_updates_reserves() {
    let pair = make_pair(1000, 2000, 30);
    let t0 = token0();
    let amt_in = TokenAmount::new(100, t0.token.clone());
    let after = pair.simulate_swap(&amt_in).unwrap();
    let expected_out = pair.get_amount_out(&amt_in).unwrap();
    assert_eq!(after.reserve0, 1000 + 100);
    assert_eq!(after.reserve1, 2000 - expected_out.raw);
}

#[test]
fn test_swap_is_immutable() {
    let pair = make_pair(1000, 2000, 30);
    let original_reserve0 = pair.reserve0;
    let original_reserve1 = pair.reserve1;
    let t0 = token0();
    let amt_in = TokenAmount::new(100, t0.token.clone());
    let new_pair = pair.simulate_swap(&amt_in).unwrap();
    assert_eq!(pair.reserve0, original_reserve0);
    assert_eq!(pair.reserve1, original_reserve1);
    assert_ne!(new_pair.reserve0, original_reserve0);
    assert_ne!(new_pair.reserve1, original_reserve1);
}

#[test]
fn test_simulate_swap_then_spot_price() {
    let pair = make_pair(1000, 2000, 30);
    let t0 = token0();
    let amt_in = TokenAmount::new(100, t0.token.clone());
    let after = pair.simulate_swap(&amt_in).unwrap();
    let spot_before = pair.get_spot_price(&pair.token0.token).unwrap();
    let spot_after = after.get_spot_price(&pair.token0.token).unwrap();
    assert!(spot_after < spot_before);
}

#[test]
fn test_token_not_in_pair_get_amount_out() {
    let pair = make_pair(1000, 2000, 30);
    let amt_in = TokenAmount::new(100, Token::new(8, Some("OTHER".to_string())));
    let err = pair.get_amount_out(&amt_in).unwrap_err();
    assert!(matches!(err, peanut_task::pricing::UniswapV2PairError::TokenNotInPair(_)));
}

#[test]
fn test_token_not_in_pair_get_spot_price() {
    let pair = make_pair(1000, 2000, 30);
    let other = Token::new(8, Some("OTHER".to_string()));
    let err = pair.get_spot_price(&other).unwrap_err();
    assert!(matches!(err, peanut_task::pricing::UniswapV2PairError::TokenNotInPair(_)));
}

#[test]
fn test_get_price_impact_calculations() {
    let pair = make_pair(100_000, 200_000, 30);
    let amount_in = TokenAmount::new(10_000, pair.token0.token.clone());
    let impact = pair.get_price_impact(&amount_in).unwrap();
    let bps = (impact * Decimal::from(10000u64)).trunc();
    assert!(bps <= Decimal::from(10000u64));
    assert!(impact <= Decimal::ONE);
    let _impact_on_amount = impact * Decimal::from(1000u64);
}

fn chain_client_with_infura() -> Option<ChainClient> {
    let api_key = std::env::var("INFURA_API_KEY").ok()?;
    if api_key.trim().eq_ignore_ascii_case("apikey") {
        return None;
    }
    let rpc = RpcUrl::new("https://mainnet.infura.io/v3/{}", &api_key).ok()?;
    ChainClient::new(vec![rpc], 10, 1).ok()
}

#[test]
fn test_from_chain_fetches_pair() {
    let client = match chain_client_with_infura() {
        Some(c) => c,
        None => return,
    };
    let pair_address = Address::from_string("0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc").unwrap();
    let pair = UniswapV2Pair::from_chain(pair_address.clone(), &client).unwrap();
    assert_eq!(pair.address, pair_address);
    assert_ne!(pair.token0.address, pair.token1.address);
    assert!(pair.reserve0 > 0);
    assert!(pair.reserve1 > 0);
    assert_eq!(pair.fee_bps, 30);
}

#[test]
fn test_from_chain_spot_and_amount_out_work() {
    let client = match chain_client_with_infura() {
        Some(c) => c,
        None => return,
    };
    let pair_address = Address::from_string("0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc").unwrap();
    let pair = UniswapV2Pair::from_chain(pair_address, &client).unwrap();
    let spot0 = pair.get_spot_price(&pair.token0.token).unwrap();
    assert!(spot0 > Decimal::ZERO);
    let amt_in = TokenAmount::new(1_000_000u128, pair.token0.token.clone());
    let amount_out = pair.get_amount_out(&amt_in).unwrap();
    assert!(amount_out.raw > 0);
}
