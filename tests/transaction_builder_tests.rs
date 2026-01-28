use peanut_task::chain::{
    ChainClient, Priority, RpcUrl, TransactionBuilder, TransactionBuilderError,
};
use peanut_task::core::base_types::{Address, TokenAmount};
use peanut_task::core::wallet_manager::WalletManager;

fn make_client() -> ChainClient {
    let rpc = RpcUrl::new("http://127.0.0.1:1/{}", "").unwrap();
    ChainClient::new(vec![rpc], 5, 1).unwrap()
}

fn make_wallet() -> WalletManager {
    WalletManager::from_hex_string(
        "0x0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap()
}

#[test]
fn test_build_fails_without_to() {
    let client = make_client();
    let wallet = make_wallet();
    let builder = TransactionBuilder::new(&client, &wallet);
    let err = builder.build().unwrap_err();
    assert!(matches!(err, TransactionBuilderError::MissingField(_)));
    assert!(err.to_string().contains("to"));
}

#[test]
fn test_priority_from_str() {
    assert!("low".parse::<Priority>().unwrap() == Priority::Low);
    assert!("medium".parse::<Priority>().unwrap() == Priority::Medium);
    assert!("high".parse::<Priority>().unwrap() == Priority::High);
    assert!("LOW".parse::<Priority>().unwrap() == Priority::Low);
    assert!("invalid".parse::<Priority>().is_err());
}

#[test]
fn test_with_gas_price_accepts_priority_enum() {
    let client = make_client();
    let wallet = make_wallet();
    for priority in [Priority::Low, Priority::Medium, Priority::High] {
        let builder = TransactionBuilder::new(&client, &wallet);
        let res = builder.with_gas_price(priority);
        // client.get_gas_price() fails (no real RPC)
        assert!(res.is_err(), "priority {:?} should fail on RPC", priority);
        let e = match res {
            Ok(_) => panic!("priority {:?} should fail", priority),
            Err(e) => e,
        };
        assert!(
            matches!(e, TransactionBuilderError::Chain(_)),
            "priority {:?} should fail on RPC: {:?}",
            priority,
            e
        );
    }
}

#[test]
fn test_fluent_chaining_to_value_data() {
    let client = make_client();
    let wallet = make_wallet();
    let to = Address::from_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0").unwrap();
    let value = TokenAmount::from_human_native_eth("0.1").unwrap();
    let builder = TransactionBuilder::new(&client, &wallet)
        .to(to)
        .value(value)
        .data(vec![0u8; 4]);
    // build() calls get_chain_id() and fails with AllEndpointsFailed
    let err = builder.build().unwrap_err();
    assert!(matches!(err, TransactionBuilderError::Chain(_)));
}

#[test]
fn test_build_and_sign_fails_without_gas_price_or_rpc() {
    let client = make_client();
    let wallet = make_wallet();
    let to = Address::from_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0").unwrap();
    let builder = TransactionBuilder::new(&client, &wallet)
        .to(to)
        .gas_limit(21_000);
    let res = builder.build_and_sign();
    let err = match res {
        Ok(_) => panic!("build_and_sign should fail when gas fees missing or RPC unreachable"),
        Err(e) => e,
    };
    // Either Chain (get_chain_id) or MissingField (gas fees)
    assert!(
        matches!(
            err,
            TransactionBuilderError::Chain(_) | TransactionBuilderError::MissingField(_)
        ),
        "build_and_sign should fail when gas fees missing or RPC unreachable: {}",
        err
    );
}
