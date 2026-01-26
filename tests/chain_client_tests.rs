use peanut_task::chain::{ChainClient, ChainClientError, RpcUrl};
use peanut_task::core::base_types::SignedTransaction;

#[test]
fn test_send_transaction_all_endpoints_failed() {
    let rpc = RpcUrl::new("http://127.0.0.1:1/{}", "").unwrap();
    let client = ChainClient::new(vec![rpc], 5, 1).unwrap();
    let signed = SignedTransaction::from_raw(format!("0x{}", hex::encode([0u8; 10]))).unwrap();
    let result = client.send_transaction(&signed);
    assert!(matches!(result, Err(ChainClientError::AllEndpointsFailed(_))));
}
