use peanut_task::core::base_types::{Address, Token};
use peanut_task::pricing::{
    Chain, ChainConfig, ForkSimulator, Route, SwapParams, TokenInPair, UniswapV2Pair,
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

#[test]
fn test_chain_config_ethereum_mainnet() {
    let config = Chain::EthereumMainnet.config();
    assert_eq!(config.chain_id, 1);
    assert_eq!(
        config.router.value.to_lowercase(),
        "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
    );
    assert_eq!(
        config.weth.value.to_lowercase(),
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
    );
}

#[test]
fn test_chain_config_custom() {
    let router = addr("0x1234567890123456789012345678901234567890");
    let weth = addr("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd");
    let config = ChainConfig::custom(router.clone(), weth.clone(), 137);
    assert_eq!(config.router, router);
    assert_eq!(config.weth, weth);
    assert_eq!(config.chain_id, 137);
}

#[test]
fn test_path_addresses_single_hop() {
    let pair = UniswapV2Pair::new(
        addr("0x0000000000000000000000000000000000000000"),
        token0(),
        token1(),
        1000,
        2000,
        30,
    );
    let route = Route::new(vec![pair], vec![token0().token.clone(), token1().token.clone()])
        .unwrap();
    let addrs = route.path_addresses();
    assert_eq!(addrs.len(), 2);
    assert_eq!(addrs[0], token0().address);
    assert_eq!(addrs[1], token1().address);
}

#[test]
fn test_path_addresses_multi_hop() {
    let t0 = token0();
    let t1 = token1();
    let t2 = TokenInPair::new(
        Token::new(18, Some("T2".to_string())),
        addr("0x0000000000000000000000000000000000000003"),
    );
    let pool0 = UniswapV2Pair::new(
        addr("0x1000000000000000000000000000000000000000"),
        t0.clone(),
        t1.clone(),
        1000,
        2000,
        30,
    );
    let pool1 = UniswapV2Pair::new(
        addr("0x2000000000000000000000000000000000000000"),
        t1.clone(),
        t2.clone(),
        2000,
        3000,
        30,
    );
    let route = Route::new(
        vec![pool0, pool1],
        vec![t0.token.clone(), t1.token.clone(), t2.token.clone()],
    )
    .unwrap();
    let addrs = route.path_addresses();
    assert_eq!(addrs.len(), 3);
    assert_eq!(addrs[0], t0.address);
    assert_eq!(addrs[1], t1.address);
    assert_eq!(addrs[2], t2.address);
}

#[test]
fn test_swap_params_validation() {
    let sim = ForkSimulator::new("http://127.0.0.1:8545", Chain::EthereumMainnet).unwrap();
    let sender = addr("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    let router = Chain::EthereumMainnet.config().router;

    let invalid_params = SwapParams {
        amount_in: 1000,
        amount_out_min: 0,
        path: vec![addr("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")],
        to: sender.clone(),
        deadline: u64::MAX,
    };
    let err = sim.simulate_swap(&router, &invalid_params, &sender).unwrap_err();
    assert!(matches!(err, peanut_task::pricing::ForkSimulatorError::InvalidParams(_)));
}

#[test]
fn test_fork_simulator_new_invalid_url() {
    let result = ForkSimulator::new("not-a-valid-url", Chain::EthereumMainnet);
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(matches!(e, peanut_task::pricing::ForkSimulatorError::RpcUrl(_)));
    }
}

fn fork_simulator_and_client() -> Option<(ForkSimulator, peanut_task::chain::ChainClient)> {
    let fork_url =
        std::env::var("FORK_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let sim = ForkSimulator::new(&fork_url, Chain::EthereumMainnet).ok()?;
    let rpc = peanut_task::chain::RpcUrl::new("{}", &fork_url).ok()?;
    let client = peanut_task::chain::ChainClient::new(vec![rpc], 10, 1).ok()?;
    Some((sim, client))
}

#[test]
fn test_compare_simulation_vs_calculation() {
    let (sim, client) = fork_simulator_and_client().expect(
        "Fork not running or invalid FORK_URL. Run `just fork` (requires ETH_RPC_URL or INFURA_API_KEY) to start a local Anvil fork.",
    );

    let pair_address = addr("0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc");
    let pair = UniswapV2Pair::from_chain(pair_address, &client).expect(
        "Fork not running or pair fetch failed. Run `just fork` (requires ETH_RPC_URL or INFURA_API_KEY).",
    );

    let amount_in = 1_000_000u128;
    let token_in = pair.token0.token.clone();

    let comp = sim
        .compare_simulation_vs_calculation(&pair, amount_in, &token_in)
        .expect("RPC error during comparison. Run `just fork` (requires ETH_RPC_URL or INFURA_API_KEY).");

    assert!(comp.calculated > 0);
    assert!(comp.simulated > 0);
    assert!(comp.matches, "AMM math should match router getAmountsOut");
}
