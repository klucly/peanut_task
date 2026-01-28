use httpmock::prelude::*;
use peanut_task::chain::{ChainClient, ChainClientError, RpcUrl};
use peanut_task::core::base_types::{Address, SignedTransaction};

fn unreachable_rpc() -> RpcUrl {
    RpcUrl::new("http://127.0.0.1:1/{}", "").unwrap()
}

fn rpc_from_mock_server(server: &MockServer, path: &str) -> RpcUrl {
    let base = server.url(path);
    RpcUrl::new(&format!("{}/{{}}", base.trim_end_matches('/')), "").unwrap()
}

#[test]
fn test_send_transaction_all_endpoints_failed() {
    let rpc = unreachable_rpc();
    let client = ChainClient::new(vec![rpc], 5, 1).unwrap();
    let signed = SignedTransaction::from_raw(format!("0x{}", hex::encode([0u8; 10]))).unwrap();
    let result = client.send_transaction(&signed);
    assert!(matches!(result, Err(ChainClientError::AllEndpointsFailed(_))));
}

#[test]
fn test_get_chain_id_all_endpoints_failed() {
    let rpc = unreachable_rpc();
    let client = ChainClient::new(vec![rpc], 5, 1).unwrap();
    let result = client.get_chain_id();
    assert!(matches!(result, Err(ChainClientError::AllEndpointsFailed(_))));
}

#[test]
fn test_multi_url_fallback_get_chain_id() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#);
    });

    let bad = unreachable_rpc();
    let good = rpc_from_mock_server(&server, "/");
    let client = ChainClient::new(vec![bad, good], 5, 1).unwrap();
    let result = client.get_chain_id();
    assert_eq!(result.unwrap(), 1);
}

#[test]
fn test_error_classification_rpc_error() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/");
        then.status(500).body("internal error");
    });

    let rpc = rpc_from_mock_server(&server, "/");
    let client = ChainClient::new(vec![rpc], 5, 1).unwrap();
    let result = client.get_chain_id();
    // Single URL failure surfaces as AllEndpointsFailed (last_error is RpcError internally).
    assert!(matches!(result, Err(ChainClientError::AllEndpointsFailed(_))));
}

#[test]
fn test_error_classification_invalid_response() {
    // Invalid block string -> parse_block_id fails -> InvalidResponse before any RPC call.
    let rpc = unreachable_rpc();
    let client = ChainClient::new(vec![rpc], 5, 1).unwrap();
    let result = client.get_nonce(Address::zero(), "not_a_block");
    assert!(matches!(result, Err(ChainClientError::InvalidResponse(_))));
}

#[test]
fn test_error_classification_transaction_not_found() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"result":null}"#);
    });

    let rpc = rpc_from_mock_server(&server, "/");
    let client = ChainClient::new(vec![rpc], 5, 1).unwrap();
    let tx_hash = "0x0000000000000000000000000000000000000000000000000000000000000001";
    let result = client.get_transaction(tx_hash);
    assert!(matches!(
        result,
        Err(ChainClientError::TransactionNotFound(_))
    ));
}

#[test]
fn test_wait_for_receipt_timeout() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"result":null}"#);
    });

    let rpc = rpc_from_mock_server(&server, "/");
    let client = ChainClient::new(vec![rpc], 5, 1).unwrap();
    let tx_hash = "0x0000000000000000000000000000000000000000000000000000000000000001";
    let result = client.wait_for_receipt(tx_hash, 1, 0.2);
    assert!(matches!(result, Err(ChainClientError::TimeoutError(_))));
}

#[test]
fn test_get_balance_all_endpoints_failed() {
    let rpc = unreachable_rpc();
    let client = ChainClient::new(vec![rpc], 5, 1).unwrap();
    let addr = Address::zero();
    let result = client.get_balance(addr);
    assert!(matches!(result, Err(ChainClientError::AllEndpointsFailed(_))));
}

#[test]
fn test_multi_url_fallback_get_balance() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"result":"0x0"}"#);
    });

    let bad = unreachable_rpc();
    let good = rpc_from_mock_server(&server, "/");
    let client = ChainClient::new(vec![bad, good], 5, 1).unwrap();
    let result = client.get_balance(Address::zero());
    assert!(result.is_ok());
    assert_eq!(result.unwrap().human(), "0");
}
