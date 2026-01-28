use peanut_task::chain::{ChainClient, RpcUrl};
use peanut_task::core::base_types::Address;
use peanut_task::pricing::{Decimal, Token, UniswapV2Pair};

fn pair_address() -> Address {
    Address::from_string("0x0000000000000000000000000000000000000000").unwrap()
}

fn token0() -> Token {
    Token::new(
        Address::from_string("0x0000000000000000000000000000000000000001").unwrap(),
        18,
        None,
    )
}

fn token1() -> Token {
    Token::new(
        Address::from_string("0x0000000000000000000000000000000000000002").unwrap(),
        18,
        None,
    )
}

fn make_pair(reserve0: u128, reserve1: u128, fee_bps: u16) -> UniswapV2Pair {
    UniswapV2Pair::new(pair_address(), token0(), token1(), reserve0, reserve1, fee_bps)
}

#[test]
fn test_get_amount_out_matches_solidity_formula() {
    // amount_in_with_fee = amount_in * (10000 - 30) = 100 * 9970 = 997_000
    // numerator = 997_000 * 2000 = 1_994_000_000
    // denominator = 1000 * 10000 + 997_000 = 10_000_000 + 997_000 = 10_997_000
    // amount_out = 1_994_000_000 / 10_997_000 = 181
    let pair = make_pair(1000, 2000, 30);
    let out = pair.get_amount_out(100, &token0()).unwrap();
    assert_eq!(out, 181);
}

#[test]
fn test_get_amount_out_token1_in() {
    let pair = make_pair(1000, 2000, 30);
    let out = pair.get_amount_out(100, &token1()).unwrap();
    // reserve_in=2000, reserve_out=1000, amount_in=100
    // amount_in_with_fee = 100 * 9970 = 997_000
    // numerator = 997_000 * 1000 = 997_000_000
    // denominator = 2000*10000 + 997_000 = 20_997_000
    // amount_out = 997_000_000 / 20_997_000 = 47
    assert_eq!(out, 47);
}

#[test]
fn test_get_amount_in_roundtrip() {
    let pair = make_pair(1_000_000, 2_000_000, 30);
    let amount_in: u128 = 100_000;
    let amount_out = pair.get_amount_out(amount_in, &token0()).unwrap();
    let amount_in_req = pair.get_amount_in(amount_out, &token0()).unwrap();
    // get_amount_in rounds up, so we need at least amount_in
    assert!(amount_in_req >= amount_in);
}

#[test]
fn test_get_amount_in_for_desired_out() {
    let pair = make_pair(1000, 2000, 30);
    let amount_out: u128 = 181;
    let amount_in = pair.get_amount_in(amount_out, &token0()).unwrap();
    let actual_out = pair.get_amount_out(amount_in, &token0()).unwrap();
    assert!(actual_out >= amount_out);
}

#[test]
fn test_get_spot_price_token0_in() {
    let pair = make_pair(1000, 2000, 30);
    let price = pair.get_spot_price(&token0()).unwrap();
    // reserve_out/reserve_in = 2000/1000 = 2; use Decimal arithmetic for calculations
    assert_eq!(price, Decimal::from(2u8));
    assert_eq!((price * Decimal::from(100u64)).trunc(), Decimal::from(200u64));
    assert_eq!(price.round_dp(8).to_string(), "2");
}

#[test]
fn test_get_spot_price_token1_in() {
    let pair = make_pair(1000, 2000, 30);
    let price = pair.get_spot_price(&token1()).unwrap();
    // reserve_out/reserve_in = 1000/2000 = 0.5
    assert_eq!(price, Decimal::from(5u8) / Decimal::from(10u8));
    assert_eq!((price * Decimal::from(100u64)).trunc(), Decimal::from(50u64));
}

#[test]
fn test_get_execution_price() {
    let pair = make_pair(1000, 2000, 30);
    let amount_in: u128 = 100;
    let price = pair.get_execution_price(amount_in, &token0()).unwrap();
    // execution price = amount_out/amount_in = 181/100; use for precise calculations
    assert_eq!((price * Decimal::from(100u64)).trunc(), Decimal::from(181u64));
    assert_eq!(price.round_dp(2).to_string(), "1.81");
}

#[test]
fn test_get_price_impact_non_zero() {
    let pair = make_pair(1_000_000, 2_000_000, 30);
    let amount_in: u128 = 100_000;
    let impact = pair.get_price_impact(amount_in, &token0()).unwrap();
    // Impact as Decimal; use (impact * 10000).trunc() for bps
    let bps = (impact * Decimal::from(10000u64)).trunc();
    assert!(bps > Decimal::ZERO);
    assert!(impact > Decimal::ZERO);
}

#[test]
fn test_simulate_swap_updates_reserves() {
    let pair = make_pair(1000, 2000, 30);
    let amount_in: u128 = 100;
    let after = pair.simulate_swap(amount_in, &token0()).unwrap();
    let expected_out = pair.get_amount_out(amount_in, &token0()).unwrap();
    assert_eq!(after.reserve0, 1000 + 100);
    assert_eq!(after.reserve1, 2000 - expected_out);
}

#[test]
fn test_simulate_swap_then_spot_price() {
    let pair = make_pair(1000, 2000, 30);
    let after = pair.simulate_swap(100, &token0()).unwrap();
    let spot_before = pair.get_spot_price(&token0()).unwrap();
    let spot_after = after.get_spot_price(&token0()).unwrap();
    // After selling token0 into the pair, reserve0 went up, reserve1 down -> price goes down
    assert!(spot_after < spot_before);
}

#[test]
fn test_token_not_in_pair_get_amount_out() {
    let pair = make_pair(1000, 2000, 30);
    let other = Token::new(
        Address::from_string("0x0000000000000000000000000000000000000003").unwrap(),
        18,
        None,
    );
    let err = pair.get_amount_out(100, &other).unwrap_err();
    assert!(matches!(err, peanut_task::pricing::UniswapV2PairError::TokenNotInPair(_)));
}

#[test]
fn test_token_not_in_pair_get_spot_price() {
    let pair = make_pair(1000, 2000, 30);
    let other = Token::new(
        Address::from_string("0x0000000000000000000000000000000000000003").unwrap(),
        18,
        None,
    );
    let err = pair.get_spot_price(&other).unwrap_err();
    assert!(matches!(err, peanut_task::pricing::UniswapV2PairError::TokenNotInPair(_)));
}

#[test]
fn test_get_price_impact_calculations() {
    // Impact as Decimal (0 = 0%, 1 = 100%); use impact * amount for calculations
    let pair = make_pair(100_000, 200_000, 30);
    let impact = pair.get_price_impact(10_000, &token0()).unwrap();
    let bps = (impact * Decimal::from(10000u64)).trunc();
    assert!(bps <= Decimal::from(10000u64));
    assert!(impact <= Decimal::ONE);
    let _impact_on_amount = impact * Decimal::from(1000u64);
}

/// Builds a ChainClient using INFURA_API_KEY. Returns None if the env var is not set or is the placeholder "apikey" (test will skip).
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
    // Uniswap V2 WETH/USDC pair on Ethereum mainnet
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
    let spot0 = pair.get_spot_price(&pair.token0).unwrap();
    let spot1 = pair.get_spot_price(&pair.token1).unwrap();
    assert!(spot0 > Decimal::ZERO);
    assert!(spot1 > Decimal::ZERO);
    // Tiny amount in (1e6 raw) so numerator/denominator don't overflow u128 with mainnet reserves
    let amount_out = pair.get_amount_out(1_000_000u128, &pair.token0).unwrap();
    assert!(amount_out > 0);
}
