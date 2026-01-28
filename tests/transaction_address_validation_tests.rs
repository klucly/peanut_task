use peanut_task::core::base_types::{Address, TokenAmount};
use peanut_task::core::utility::Transaction;
use peanut_task::core::wallet_manager::{WalletManager, TransactionError};

#[test]
fn test_valid_address_passes_validation() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        to: Address::from_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0").unwrap(),
        value: TokenAmount::native_eth(1000000000000000000),
        data: vec![],
        nonce: Some(0),
        gas_limit: Some(21000),
        max_fee_per_gas: Some(20000000000),
        max_priority_fee: Some(1000000000),
        chain_id: 1,
    };

    let result = wallet.sign_transaction(tx);
    assert!(result.is_ok(), "Valid address should pass validation");
}

#[test]
fn test_none_address_passes_validation() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        to: Address::from_string("0x0000000000000000000000000000000000000000").unwrap(),
        value: TokenAmount::native_eth(0),
        data: vec![0x60, 0x60, 0x60],
        nonce: Some(0),
        gas_limit: Some(21000),
        max_fee_per_gas: Some(20000000000),
        max_priority_fee: Some(1000000000),
        chain_id: 1,
    };

    let result = wallet.sign_transaction(tx);
    assert!(result.is_ok(), "Zero address (contract creation) should pass validation");
}

#[test]
fn test_address_missing_0x_prefix_fails() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        to: Address::from_string("742d35Cc6634C0532925a3b844Bc9e7595f0bEb0").unwrap_or_else(|_| {
            Address { value: "742d35Cc6634C0532925a3b844Bc9e7595f0bEb0".to_string() }
        }),
        value: TokenAmount::native_eth(1000000000000000000),
        data: vec![],
        nonce: Some(0),
        gas_limit: Some(21000),
        max_fee_per_gas: Some(20000000000),
        max_priority_fee: Some(1000000000),
        chain_id: 1,
    };

    let result = wallet.sign_transaction(tx);
    assert!(result.is_err(), "Address without 0x prefix should fail validation");
    
    if let Err(TransactionError::InvalidAddress(msg)) = result {
        assert!(msg.contains("must start with '0x'"), 
            "Error message should mention missing 0x prefix");
    } else {
        panic!("Expected InvalidAddress error");
    }
}

#[test]
fn test_address_too_short_fails() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        to: Address::from_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb").unwrap_or_else(|_| {
            Address { value: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".to_string() }
        }), // 41 chars (too short)
        value: TokenAmount::native_eth(1000000000000000000),
        data: vec![],
        nonce: Some(0),
        gas_limit: Some(21000),
        max_fee_per_gas: Some(20000000000),
        max_priority_fee: Some(1000000000),
        chain_id: 1,
    };

    let result = wallet.sign_transaction(tx);
    assert!(result.is_err(), "Address that is too short should fail validation");
    
    if let Err(TransactionError::InvalidAddress(msg)) = result {
        assert!(msg.contains("42 characters"), 
            "Error message should mention expected length of 42 characters");
    } else {
        panic!("Expected InvalidAddress error");
    }
}

#[test]
fn test_address_too_long_fails() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        to: Address::from_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb00").unwrap_or_else(|_| {
            Address { value: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb00".to_string() }
        }), // 43 chars (too long)
        value: TokenAmount::native_eth(1000000000000000000),
        data: vec![],
        nonce: Some(0),
        gas_limit: Some(21000),
        max_fee_per_gas: Some(20000000000),
        max_priority_fee: Some(1000000000),
        chain_id: 1,
    };

    let result = wallet.sign_transaction(tx);
    assert!(result.is_err(), "Address that is too long should fail validation");
    
    if let Err(TransactionError::InvalidAddress(msg)) = result {
        assert!(msg.contains("42 characters"), 
            "Error message should mention expected length of 42 characters");
    } else {
        panic!("Expected InvalidAddress error");
    }
}

#[test]
fn test_address_with_invalid_hex_characters_fails() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        to: Address::from_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEbG").unwrap_or_else(|_| {
            Address { value: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEbG".to_string() }
        }), // Invalid 'G' character
        value: TokenAmount::native_eth(1000000000000000000),
        data: vec![],
        nonce: Some(0),
        gas_limit: Some(21000),
        max_fee_per_gas: Some(20000000000),
        max_priority_fee: Some(1000000000),
        chain_id: 1,
    };

    let result = wallet.sign_transaction(tx);
    assert!(result.is_err(), "Address with invalid hex characters should fail validation");
    
    if let Err(TransactionError::InvalidAddress(msg)) = result {
        assert!(msg.contains("invalid hex characters"), 
            "Error message should mention invalid hex characters");
    } else {
        panic!("Expected InvalidAddress error");
    }
}

#[test]
fn test_address_with_special_characters_fails() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        to: Address::from_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb@").unwrap_or_else(|_| {
            Address { value: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb@".to_string() }
        }), // Invalid '@' character
        value: TokenAmount::native_eth(1000000000000000000),
        data: vec![],
        nonce: Some(0),
        gas_limit: Some(21000),
        max_fee_per_gas: Some(20000000000),
        max_priority_fee: Some(1000000000),
        chain_id: 1,
    };

    let result = wallet.sign_transaction(tx);
    assert!(result.is_err(), "Address with special characters should fail validation");
}

#[test]
fn test_address_with_uppercase_and_lowercase_hex_passes() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        to: Address::from_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0").unwrap(), // Mixed case is valid
        value: TokenAmount::native_eth(1000000000000000000),
        data: vec![],
        nonce: Some(0),
        gas_limit: Some(21000),
        max_fee_per_gas: Some(20000000000),
        max_priority_fee: Some(1000000000),
        chain_id: 1,
    };

    let result = wallet.sign_transaction(tx);
    assert!(result.is_ok(), "Address with mixed case hex should pass validation");
}

#[test]
fn test_address_all_lowercase_passes() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        to: Address::from_string("0x742d35cc6634c0532925a3b844bc9e7595f0beb0").unwrap(), // All lowercase
        value: TokenAmount::native_eth(1000000000000000000),
        data: vec![],
        nonce: Some(0),
        gas_limit: Some(21000),
        max_fee_per_gas: Some(20000000000),
        max_priority_fee: Some(1000000000),
        chain_id: 1,
    };

    let result = wallet.sign_transaction(tx);
    assert!(result.is_ok(), "Address with all lowercase hex should pass validation");
}

#[test]
fn test_address_all_uppercase_passes() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        to: Address::from_string("0x742D35CC6634C0532925A3B844BC9E7595F0BEB0").unwrap(), // All uppercase
        value: TokenAmount::native_eth(1000000000000000000),
        data: vec![],
        nonce: Some(0),
        gas_limit: Some(21000),
        max_fee_per_gas: Some(20000000000),
        max_priority_fee: Some(1000000000),
        chain_id: 1,
    };

    let result = wallet.sign_transaction(tx);
    assert!(result.is_ok(), "Address with all uppercase hex should pass validation");
}

#[test]
fn test_empty_address_fails() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        to: Address::from_string("").unwrap_or_else(|_| {
            Address { value: "".to_string() }
        }), // Empty string
        value: TokenAmount::native_eth(1000000000000000000),
        data: vec![],
        nonce: Some(0),
        gas_limit: Some(21000),
        max_fee_per_gas: Some(20000000000),
        max_priority_fee: Some(1000000000),
        chain_id: 1,
    };

    let result = wallet.sign_transaction(tx);
    assert!(result.is_err(), "Empty address should fail validation");
}

#[test]
fn test_address_with_only_0x_prefix_fails() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        to: Address::from_string("0x").unwrap_or_else(|_| {
            Address { value: "0x".to_string() }
        }), // Only prefix, no hex
        value: TokenAmount::native_eth(1000000000000000000),
        data: vec![],
        nonce: Some(0),
        gas_limit: Some(21000),
        max_fee_per_gas: Some(20000000000),
        max_priority_fee: Some(1000000000),
        chain_id: 1,
    };

    let result = wallet.sign_transaction(tx);
    assert!(result.is_err(), "Address with only 0x prefix should fail validation");
}

#[test]
fn test_well_known_address_passes() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        to: Address::from_string("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(), // Hardhat/Anvil test address
        value: TokenAmount::native_eth(1000000000000000000),
        data: vec![],
        nonce: Some(0),
        gas_limit: Some(21000),
        max_fee_per_gas: Some(20000000000),
        max_priority_fee: Some(1000000000),
        chain_id: 1,
    };

    let result = wallet.sign_transaction(tx);
    assert!(result.is_ok(), "Well-known valid address should pass validation");
}
