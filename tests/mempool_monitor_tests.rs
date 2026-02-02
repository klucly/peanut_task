use peanut_task::core::base_types::{Address, TokenAmount, Transaction};
use peanut_task::pricing::{parse_transaction, Decimal, MempoolMonitor, ParsedSwap};

fn u256_be(n: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..16 {
        out[31 - i] = (n >> (i * 8)) as u8;
    }
    out
}

fn addr_bytes(addr: &str) -> [u8; 32] {
    let hex = addr.strip_prefix("0x").unwrap_or(addr);
    let bytes = hex::decode(hex).unwrap();
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(&bytes);
    out
}

#[test]
fn test_parse_swap_exact_tokens_for_tokens() {
    let token_a = Address::from_string("0x1111111111111111111111111111111111111111").unwrap();
    let token_b = Address::from_string("0x2222222222222222222222222222222222222222").unwrap();
    let to = Address::from_string("0x3333333333333333333333333333333333333333").unwrap();

    let amount_in: u128 = 1_000_000_000_000_000_000;
    let amount_out_min: u128 = 500_000_000_000_000_000;
    let path_offset: u128 = 160;
    let deadline: u128 = 1735689600;

    let mut data = Vec::new();
    data.extend_from_slice(&[0x38, 0xed, 0x17, 0x39]);
    data.extend_from_slice(&u256_be(amount_in));
    data.extend_from_slice(&u256_be(amount_out_min));
    data.extend_from_slice(&u256_be(path_offset));
    data.extend_from_slice(&addr_bytes(&to.to_string()));
    data.extend_from_slice(&u256_be(deadline));
    data.extend_from_slice(&u256_be(2));
    data.extend_from_slice(&addr_bytes(&token_a.to_string()));
    data.extend_from_slice(&addr_bytes(&token_b.to_string()));

    let tx = Transaction {
        from: Some(to.clone()),
        to: Address::from_string("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap(),
        value: TokenAmount::native_eth(0),
        data: data.clone(),
        nonce: Some(0),
        gas_limit: Some(200_000),
        max_fee_per_gas: Some(30_000_000_000),
        max_priority_fee: Some(1_000_000_000),
        chain_id: 1,
    };

    let swap = parse_transaction(&tx, "0xabc123").unwrap();
    assert_eq!(swap.method, "swapExactTokensForTokens");
    assert_eq!(swap.dex, "UniswapV2");
    assert_eq!(swap.amount_in, amount_in);
    assert_eq!(swap.min_amount_out, amount_out_min);
    assert_eq!(swap.deadline, deadline as u64);
    assert_eq!(swap.gas_price, 30_000_000_000);
    assert_eq!(swap.tx_hash, "0xabc123");
    assert_eq!(
        swap.token_in.as_ref().map(|a| a.to_string()),
        Some(token_a.to_string())
    );
    assert_eq!(
        swap.token_out.as_ref().map(|a| a.to_string()),
        Some(token_b.to_string())
    );
}

#[test]
fn test_parse_swap_exact_eth_for_tokens() {
    let weth = Address::from_string("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
    let token_out = Address::from_string("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
    let to = Address::from_string("0x3333333333333333333333333333333333333333").unwrap();

    let amount_out_min: u128 = 1_000_000;
    let path_offset: u128 = 128;
    let deadline: u128 = 1735689600;
    let value: u128 = 1_000_000_000_000_000_000;

    let mut data = Vec::new();
    data.extend_from_slice(&[0x7f, 0xf3, 0x6a, 0xb5]);
    data.extend_from_slice(&u256_be(amount_out_min));
    data.extend_from_slice(&u256_be(path_offset));
    data.extend_from_slice(&addr_bytes(&to.to_string()));
    data.extend_from_slice(&u256_be(deadline));
    data.extend_from_slice(&u256_be(2));
    data.extend_from_slice(&addr_bytes(&weth.to_string()));
    data.extend_from_slice(&addr_bytes(&token_out.to_string()));

    let tx = Transaction {
        from: Some(to.clone()),
        to: Address::from_string("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap(),
        value: TokenAmount::native_eth(value),
        data,
        nonce: Some(0),
        gas_limit: Some(200_000),
        max_fee_per_gas: Some(25_000_000_000),
        max_priority_fee: Some(1_000_000_000),
        chain_id: 1,
    };

    let swap = parse_transaction(&tx, "0xdef456").unwrap();
    assert_eq!(swap.method, "swapExactETHForTokens");
    assert_eq!(swap.amount_in, value);
    assert_eq!(swap.min_amount_out, amount_out_min);
    assert!(swap.token_in.is_none());
    assert_eq!(
        swap.token_out.as_ref().map(|a| a.to_string()),
        Some(token_out.to_string())
    );
}

#[test]
fn test_parse_non_swap_returns_none() {
    let tx = Transaction {
        from: None,
        to: Address::from_string("0x0000000000000000000000000000000000000000").unwrap(),
        value: TokenAmount::native_eth(0),
        data: vec![0x12, 0x34, 0x56, 0x78],
        nonce: None,
        gas_limit: None,
        max_fee_per_gas: None,
        max_priority_fee: None,
        chain_id: 1,
    };
    assert!(parse_transaction(&tx, "0x000").is_none());
}

#[test]
fn test_slippage_tolerance_with_expected() {
    let swap = ParsedSwap {
        tx_hash: "0x0".to_string(),
        router: "UniswapV2".to_string(),
        dex: "UniswapV2".to_string(),
        method: "swapExactTokensForTokens".to_string(),
        token_in: None,
        token_out: None,
        amount_in: 1000,
        min_amount_out: 950,
        deadline: 0,
        sender: Address::zero(),
        gas_price: 0,
    };
    let slippage = swap.slippage_tolerance_with_expected(1000).unwrap();
    assert!(slippage > Decimal::ZERO && slippage < Decimal::ONE);
}

#[test]
fn test_parse_swap_exact_tokens_for_eth() {
    let token_in = Address::from_string("0x1111111111111111111111111111111111111111").unwrap();
    let weth = Address::from_string("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
    let to = Address::from_string("0x3333333333333333333333333333333333333333").unwrap();

    let amount_in: u128 = 500_000_000_000_000_000;
    let amount_out_min: u128 = 250_000_000_000_000_000;
    let path_offset: u128 = 160;
    let deadline: u128 = 1735689600;

    let mut data = Vec::new();
    data.extend_from_slice(&[0x18, 0xcb, 0xaf, 0xe5]); // swapExactTokensForETH
    data.extend_from_slice(&u256_be(amount_in));
    data.extend_from_slice(&u256_be(amount_out_min));
    data.extend_from_slice(&u256_be(path_offset));
    data.extend_from_slice(&addr_bytes(&to.to_string()));
    data.extend_from_slice(&u256_be(deadline));
    data.extend_from_slice(&u256_be(2));
    data.extend_from_slice(&addr_bytes(&token_in.to_string()));
    data.extend_from_slice(&addr_bytes(&weth.to_string()));

    let tx = Transaction {
        from: Some(to.clone()),
        to: Address::from_string("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap(),
        value: TokenAmount::native_eth(0),
        data,
        nonce: Some(0),
        gas_limit: Some(200_000),
        max_fee_per_gas: Some(20_000_000_000),
        max_priority_fee: Some(1_000_000_000),
        chain_id: 1,
    };

    let swap = parse_transaction(&tx, "0xtokens4eth").unwrap();
    assert_eq!(swap.method, "swapExactTokensForETH");
    assert_eq!(swap.dex, "UniswapV2");
    assert_eq!(swap.amount_in, amount_in);
    assert_eq!(swap.min_amount_out, amount_out_min);
    assert_eq!(
        swap.token_in.as_ref().map(|a| a.to_string()),
        Some(token_in.to_string())
    );
    assert_eq!(
        swap.token_out.as_ref().map(|a| a.to_string()),
        Some(weth.to_string())
    );
}

#[test]
fn test_parse_truncated_data_returns_none() {
    let tx = Transaction {
        from: None,
        to: Address::zero(),
        value: TokenAmount::native_eth(0),
        data: vec![0x38, 0xed, 0x17, 0x39],
        nonce: None,
        gas_limit: None,
        max_fee_per_gas: None,
        max_priority_fee: None,
        chain_id: 1,
    };
    assert!(parse_transaction(&tx, "0x000").is_none());
}

#[test]
fn test_parse_invalid_path_length_returns_none() {
    let to = Address::from_string("0x3333333333333333333333333333333333333333").unwrap();
    let token_a = Address::from_string("0x1111111111111111111111111111111111111111").unwrap();

    let mut data = Vec::new();
    data.extend_from_slice(&[0x38, 0xed, 0x17, 0x39]);
    data.extend_from_slice(&u256_be(1_000_000_000_000_000_000u128));
    data.extend_from_slice(&u256_be(500_000_000_000_000_000u128));
    data.extend_from_slice(&u256_be(160u128));
    data.extend_from_slice(&addr_bytes(&to.to_string()));
    data.extend_from_slice(&u256_be(1735689600u128));
    data.extend_from_slice(&u256_be(1)); // path length 1 - invalid
    data.extend_from_slice(&addr_bytes(&token_a.to_string()));

    let tx = Transaction {
        from: Some(to),
        to: Address::from_string("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap(),
        value: TokenAmount::native_eth(0),
        data,
        nonce: Some(0),
        gas_limit: Some(200_000),
        max_fee_per_gas: Some(30_000_000_000),
        max_priority_fee: Some(1_000_000_000),
        chain_id: 1,
    };
    assert!(parse_transaction(&tx, "0xbad").is_none());
}

#[test]
fn test_parse_from_none_uses_zero_address() {
    let token_a = Address::from_string("0x1111111111111111111111111111111111111111").unwrap();
    let token_b = Address::from_string("0x2222222222222222222222222222222222222222").unwrap();
    let to = Address::from_string("0x3333333333333333333333333333333333333333").unwrap();

    let mut data = Vec::new();
    data.extend_from_slice(&[0x38, 0xed, 0x17, 0x39]);
    data.extend_from_slice(&u256_be(1_000_000_000_000_000_000u128));
    data.extend_from_slice(&u256_be(500_000_000_000_000_000u128));
    data.extend_from_slice(&u256_be(160u128));
    data.extend_from_slice(&addr_bytes(&to.to_string()));
    data.extend_from_slice(&u256_be(1735689600u128));
    data.extend_from_slice(&u256_be(2));
    data.extend_from_slice(&addr_bytes(&token_a.to_string()));
    data.extend_from_slice(&addr_bytes(&token_b.to_string()));

    let tx = Transaction {
        from: None,
        to: Address::from_string("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap(),
        value: TokenAmount::native_eth(0),
        data,
        nonce: None,
        gas_limit: None,
        max_fee_per_gas: None,
        max_priority_fee: None,
        chain_id: 1,
    };

    let swap = parse_transaction(&tx, "0xfrom_none").unwrap();
    assert_eq!(swap.sender, Address::zero());
}

#[test]
fn test_slippage_tolerance_returns_none() {
    let swap = ParsedSwap {
        tx_hash: "0x0".to_string(),
        router: "UniswapV2".to_string(),
        dex: "UniswapV2".to_string(),
        method: "swapExactTokensForTokens".to_string(),
        token_in: None,
        token_out: None,
        amount_in: 1000,
        min_amount_out: 950,
        deadline: 0,
        sender: Address::zero(),
        gas_price: 0,
    };
    assert!(swap.slippage_tolerance().is_none());
}

#[test]
fn test_slippage_tolerance_with_expected_zero_returns_none() {
    let swap = ParsedSwap {
        tx_hash: "0x0".to_string(),
        router: "UniswapV2".to_string(),
        dex: "UniswapV2".to_string(),
        method: "swapExactTokensForTokens".to_string(),
        token_in: None,
        token_out: None,
        amount_in: 1000,
        min_amount_out: 950,
        deadline: 0,
        sender: Address::zero(),
        gas_price: 0,
    };
    assert!(swap.slippage_tolerance_with_expected(0).is_none());
}

#[test]
fn test_slippage_tolerance_exact_match() {
    let swap = ParsedSwap {
        tx_hash: "0x0".to_string(),
        router: "UniswapV2".to_string(),
        dex: "UniswapV2".to_string(),
        method: "swapExactTokensForTokens".to_string(),
        token_in: None,
        token_out: None,
        amount_in: 1000,
        min_amount_out: 1000,
        deadline: 0,
        sender: Address::zero(),
        gas_price: 0,
    };
    let slippage = swap.slippage_tolerance_with_expected(1000).unwrap();
    assert_eq!(slippage, Decimal::ZERO);
}

#[test]
fn test_slippage_tolerance_high_slippage() {
    let swap = ParsedSwap {
        tx_hash: "0x0".to_string(),
        router: "UniswapV2".to_string(),
        dex: "UniswapV2".to_string(),
        method: "swapExactTokensForTokens".to_string(),
        token_in: None,
        token_out: None,
        amount_in: 1000,
        min_amount_out: 100,
        deadline: 0,
        sender: Address::zero(),
        gas_price: 0,
    };
    let slippage = swap.slippage_tolerance_with_expected(1000).unwrap();
    assert!(slippage > Decimal::try_from(0.8).unwrap());
}

/// Integration test: connects to Infura WebSocket, runs monitor for 5 seconds.
/// Skips if INFURA_API_KEY is not set. Run with: INFURA_API_KEY=... cargo test test_mempool_monitor_connect_with_timeout
#[tokio::test]
async fn test_mempool_monitor_connect_with_timeout() {
    let api_key = match std::env::var("INFURA_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => return,
    };
    let ws_url = format!("wss://mainnet.infura.io/ws/v3/{}", api_key);
    let monitor = MempoolMonitor::new(ws_url, |_| {});

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        monitor.start(),
    )
    .await;

    match result {
        Err(_) => {
            // Timeout: ran 5 seconds successfully, connection and subscription worked
        }
        Ok(Ok(())) => {
            // Stream ended (e.g. provider closed) - still valid
        }
        Ok(Err(e)) => panic!("MempoolMonitor connection failed: {}", e),
    }
}
