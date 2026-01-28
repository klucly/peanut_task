use peanut_task::core::transaction_receipt::{TransactionReceipt, TransactionReceiptError};
use serde_json::json;

#[test]
fn test_tx_fee_basic() {
    let receipt = TransactionReceipt {
        tx_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        block_number: 1000,
        status: true,
        gas_used: 21000,
        effective_gas_price: 20000000000,
        logs: vec![],
    };

    let fee = receipt.tx_fee();
    assert_eq!(fee.raw, 420000000000000);
    assert_eq!(fee.decimals(), 18);
    assert_eq!(fee.symbol(), Some("ETH"));
}

#[test]
fn test_tx_fee_zero_gas() {
    let receipt = TransactionReceipt {
        tx_hash: "0x123...".to_string(),
        block_number: 1000,
        status: true,
        gas_used: 0,
        effective_gas_price: 20000000000,
        logs: vec![],
    };
    
    let fee = receipt.tx_fee();
    assert_eq!(fee.raw, 0);
    assert_eq!(fee.decimals(), 18);
    assert_eq!(fee.symbol(), Some("ETH"));
}

#[test]
fn test_tx_fee_zero_price() {
    let receipt = TransactionReceipt {
        tx_hash: "0x123...".to_string(),
        block_number: 1000,
        status: true,
        gas_used: 21000,
        effective_gas_price: 0,
        logs: vec![],
    };
    
    let fee = receipt.tx_fee();
    assert_eq!(fee.raw, 0);
}

#[test]
fn test_tx_fee_large_values() {
    let receipt = TransactionReceipt {
        tx_hash: "0x123...".to_string(),
        block_number: 1000,
        status: true,
        gas_used: 1000000,
        effective_gas_price: 100000000000,
        logs: vec![],
    };

    let fee = receipt.tx_fee();
    assert_eq!(fee.raw, 100000000000000000);
}

#[test]
fn test_tx_fee_very_large() {
    let receipt = TransactionReceipt {
        tx_hash: "0x123...".to_string(),
        block_number: 1000,
        status: true,
        gas_used: 10000000,
        effective_gas_price: 1000000000000,
        logs: vec![],
    };
    
    let fee = receipt.tx_fee();
    assert_eq!(fee.raw, 10000000000000000000);
}

#[test]
fn test_from_web3_basic_hex_strings() {
    let receipt_json = json!({
        "transactionHash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "blockNumber": "0x3e8", // 1000
        "status": "0x1",
        "gasUsed": "0x5208", // 21000
        "effectiveGasPrice": "0x4a817c800", // 20000000000
        "logs": []
    });
    
    let receipt = TransactionReceipt::from_web3(receipt_json).unwrap();
    assert_eq!(receipt.tx_hash, "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    assert_eq!(receipt.block_number, 1000);
    assert_eq!(receipt.status, true);
    assert_eq!(receipt.gas_used, 21000);
    assert_eq!(receipt.effective_gas_price, 20000000000);
    assert_eq!(receipt.logs.len(), 0);
}

#[test]
fn test_from_web3_with_numbers() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": 1000,
        "status": 1,
        "gasUsed": 21000,
        "effectiveGasPrice": "0x4a817c800", // 20000000000
        "logs": []
    });
    
    let receipt = TransactionReceipt::from_web3(receipt_json).unwrap();
    assert_eq!(receipt.block_number, 1000);
    assert_eq!(receipt.status, true);
    assert_eq!(receipt.gas_used, 21000);
    assert_eq!(receipt.effective_gas_price, 20000000000);
}

#[test]
fn test_from_web3_status_failed() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x0",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": []
    });
    
    let receipt = TransactionReceipt::from_web3(receipt_json).unwrap();
    assert_eq!(receipt.status, false);
}

#[test]
fn test_from_web3_status_failed_number() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": 1000,
        "status": 0,
        "gasUsed": 21000,
        "effectiveGasPrice": "0x4a817c800", // 20000000000
        "logs": []
    });
    
    let receipt = TransactionReceipt::from_web3(receipt_json).unwrap();
    assert_eq!(receipt.status, false);
}

#[test]
fn test_from_web3_with_logs() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": [
            {
                "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
                "topics": [
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "0x000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f0beb0"
                ],
                "data": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000"
            }
        ]
    });
    
    let receipt = TransactionReceipt::from_web3(receipt_json).unwrap();
    assert_eq!(receipt.logs.len(), 1);
    
    let log = &receipt.logs[0];
    assert_eq!(log.address.lower(), "0x742d35cc6634c0532925a3b844bc9e7595f0beb0");
    assert_eq!(log.topics.len(), 3);
    assert_eq!(log.topics[0], "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
    assert_eq!(log.data, "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000");
}

#[test]
fn test_from_web3_multiple_logs() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": [
            {
                "address": "0x1111111111111111111111111111111111111111",
                "topics": ["0xtopic1"],
                "data": "0xdata1"
            },
            {
                "address": "0x2222222222222222222222222222222222222222",
                "topics": ["0xtopic2", "0xtopic3"],
                "data": "0xdata2"
            }
        ]
    });
    
    let receipt = TransactionReceipt::from_web3(receipt_json).unwrap();
    assert_eq!(receipt.logs.len(), 2);
    assert_eq!(receipt.logs[0].address.lower(), "0x1111111111111111111111111111111111111111");
    assert_eq!(receipt.logs[1].address.lower(), "0x2222222222222222222222222222222222222222");
    assert_eq!(receipt.logs[0].topics.len(), 1);
    assert_eq!(receipt.logs[1].topics.len(), 2);
}

#[test]
fn test_from_web3_log_without_topics() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": [
            {
                "address": "0x1111111111111111111111111111111111111111",
                "topics": [],
                "data": "0x"
            }
        ]
    });
    
    let receipt = TransactionReceipt::from_web3(receipt_json).unwrap();
    assert_eq!(receipt.logs.len(), 1);
    assert_eq!(receipt.logs[0].topics.len(), 0);
    assert_eq!(receipt.logs[0].data, "0x");
}

#[test]
fn test_from_web3_hex_without_prefix() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "3e8", // No 0x prefix
        "status": "0x1",
        "gasUsed": "5208", // No 0x prefix
        "effectiveGasPrice": "4a817c800", // No 0x prefix
        "logs": []
    });
    
    let receipt = TransactionReceipt::from_web3(receipt_json).unwrap();
    assert_eq!(receipt.block_number, 1000);
    assert_eq!(receipt.gas_used, 21000);
    assert_eq!(receipt.effective_gas_price, 20000000000);
}

#[test]
fn test_from_web3_status_hex_variations() {
    let receipt1 = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x01", // With leading zero
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": []
    });
    let receipt1_parsed = TransactionReceipt::from_web3(receipt1).unwrap();
    assert_eq!(receipt1_parsed.status, true);
    
    let receipt2 = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x00", // Failed with leading zero
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": []
    });
    let receipt2_parsed = TransactionReceipt::from_web3(receipt2).unwrap();
    assert_eq!(receipt2_parsed.status, false);
}

#[test]
fn test_from_web3_large_block_number() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0xffffffffffffffff", // Max u64
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": []
    });
    
    let receipt = TransactionReceipt::from_web3(receipt_json).unwrap();
    assert_eq!(receipt.block_number, u64::MAX);
}

#[test]
fn test_from_web3_missing_transaction_hash() {
    let receipt_json = json!({
        "blockNumber": "0x3e8",
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": []
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::MissingField(field) => {
            assert_eq!(field, "transactionHash");
        }
        _ => panic!("Expected MissingField error"),
    }
}

#[test]
fn test_from_web3_missing_block_number() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": []
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::MissingField(field) => {
            assert_eq!(field, "blockNumber");
        }
        _ => panic!("Expected MissingField error"),
    }
}

#[test]
fn test_from_web3_missing_status() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": []
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::MissingField(field) => {
            assert_eq!(field, "status");
        }
        _ => panic!("Expected MissingField error"),
    }
}

#[test]
fn test_from_web3_missing_gas_used() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x1",
        "effectiveGasPrice": "0x4a817c800",
        "logs": []
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::MissingField(field) => {
            assert_eq!(field, "gasUsed");
        }
        _ => panic!("Expected MissingField error"),
    }
}

#[test]
fn test_from_web3_missing_effective_gas_price() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x1",
        "gasUsed": "0x5208",
        "logs": []
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::MissingField(field) => {
            assert_eq!(field, "effectiveGasPrice");
        }
        _ => panic!("Expected MissingField error"),
    }
}

#[test]
fn test_from_web3_missing_logs() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800"
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::MissingField(field) => {
            assert_eq!(field, "logs");
        }
        _ => panic!("Expected MissingField error"),
    }
}

#[test]
fn test_from_web3_invalid_format_not_object() {
    let receipt_json = json!([]); // Array instead of object
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::InvalidFormat(msg) => {
            assert!(msg.contains("JSON object"));
        }
        _ => panic!("Expected InvalidFormat error"),
    }
}

#[test]
fn test_from_web3_invalid_status_value() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x2", // Invalid status
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": []
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::InvalidFormat(msg) => {
            assert!(msg.contains("status"));
        }
        _ => panic!("Expected InvalidFormat error"),
    }
}

#[test]
fn test_from_web3_invalid_status_type() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": true, // Boolean instead of string/number
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": []
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::InvalidFormat(msg) => {
            assert!(msg.contains("status"));
        }
        _ => panic!("Expected InvalidFormat error"),
    }
}

#[test]
fn test_from_web3_invalid_hex_block_number() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0xinvalid",
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": []
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::InvalidFormat(msg) => {
            assert!(msg.contains("hex"));
        }
        _ => panic!("Expected InvalidFormat error"),
    }
}

#[test]
fn test_from_web3_invalid_number_block_number() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": -1, // Negative number
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": []
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::InvalidFormat(msg) => {
            assert!(msg.contains("Number too large or negative") || msg.contains("hex string or number"));
        }
        _ => panic!("Expected InvalidFormat error"),
    }
}

#[test]
fn test_from_web3_log_missing_address() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": [
            {
                "topics": ["0xtopic1"],
                "data": "0xdata1"
            }
        ]
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::InvalidFormat(msg) => {
            assert!(msg.contains("address"));
        }
        _ => panic!("Expected InvalidFormat error"),
    }
}

#[test]
fn test_from_web3_log_missing_topics() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": [
            {
                "address": "0x1111111111111111111111111111111111111111",
                "data": "0xdata1"
            }
        ]
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::InvalidFormat(msg) => {
            assert!(msg.contains("topics"));
        }
        _ => panic!("Expected InvalidFormat error"),
    }
}

#[test]
fn test_from_web3_log_missing_data() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": [
            {
                "address": "0x1111111111111111111111111111111111111111",
                "topics": ["0xtopic1"]
            }
        ]
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::InvalidFormat(msg) => {
            assert!(msg.contains("data"));
        }
        _ => panic!("Expected InvalidFormat error"),
    }
}

#[test]
fn test_from_web3_log_not_object() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": [
            "not an object"
        ]
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::InvalidFormat(msg) => {
            assert!(msg.contains("JSON object"));
        }
        _ => panic!("Expected InvalidFormat error"),
    }
}

#[test]
fn test_from_web3_log_topic_not_string() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": [
            {
                "address": "0x1111111111111111111111111111111111111111",
                "topics": [123], // Number instead of string
                "data": "0xdata1"
            }
        ]
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::InvalidFormat(msg) => {
            assert!(msg.contains("topic") || msg.contains("string"));
        }
        _ => panic!("Expected InvalidFormat error"),
    }
}

#[test]
fn test_from_web3_logs_not_array() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x4a817c800",
        "logs": {} // Object instead of array
    });
    
    let result = TransactionReceipt::from_web3(receipt_json);
    assert!(result.is_err());
    match result.unwrap_err() {
        TransactionReceiptError::MissingField(field) => {
            assert_eq!(field, "logs");
        }
        _ => panic!("Expected MissingField error"),
    }
}

#[test]
fn test_tx_fee_after_from_web3() {
    let receipt_json = json!({
        "transactionHash": "0xabc...",
        "blockNumber": "0x3e8",
        "status": "0x1",
        "gasUsed": "0x5208", // 21000
        "effectiveGasPrice": "0x4a817c800", // 20000000000
        "logs": []
    });
    
    let receipt = TransactionReceipt::from_web3(receipt_json).unwrap();
    let fee = receipt.tx_fee();
    assert_eq!(fee.raw, 420000000000000);
    assert_eq!(fee.decimals(), 18);
    assert_eq!(fee.symbol(), Some("ETH"));
}

#[test]
fn test_receipt_with_complex_logs() {
    let receipt_json = json!({
        "transactionHash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "blockNumber": "0x1a2b3c",
        "status": "0x1",
        "gasUsed": "0x186a0", // 100000
        "effectiveGasPrice": "0x5d21dba00", // 25000000000
        "logs": [
            {
                "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
                "topics": [
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                ],
                "data": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000"
            },
            {
                "address": "0x1111111111111111111111111111111111111111",
                "topics": [
                    "0x8be0079c53165914144cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "0x0000000000000000000000002222222222222222222222222222222222222222"
                ],
                "data": "0x"
            },
            {
                "address": "0x3333333333333333333333333333333333333333",
                "topics": [],
                "data": "0x1234567890abcdef"
            }
        ]
    });
    
    let receipt = TransactionReceipt::from_web3(receipt_json).unwrap();
    
    assert_eq!(receipt.logs.len(), 3);
    assert_eq!(receipt.logs[0].topics.len(), 1);
    assert_eq!(receipt.logs[1].topics.len(), 3);
    assert_eq!(receipt.logs[2].topics.len(), 0);
    
    let fee = receipt.tx_fee();
    assert_eq!(fee.raw, 2500000000000000);
}
