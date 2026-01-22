use peanut_task::core::wallet_manager::{WalletManager, TransactionError};
use peanut_task::core::utility::{Transaction, Address};

#[test]
fn test_valid_address_passes_validation() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        nonce: 0,
        gas_price: 20000000000,
        gas_limit: 21000,
        to: Some(Address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0".to_string())),
        value: 1000000000000000000,
        data: vec![],
        chain_id: 1,
    };

    // Should not panic or return an error
    let result = wallet.sign_transaction(tx);
    assert!(result.is_ok(), "Valid address should pass validation");
}

#[test]
fn test_none_address_passes_validation() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        nonce: 0,
        gas_price: 20000000000,
        gas_limit: 21000,
        to: None, // Contract creation transaction
        value: 0,
        data: vec![0x60, 0x60, 0x60], // Some init code
        chain_id: 1,
    };

    // Should not panic or return an error
    let result = wallet.sign_transaction(tx);
    assert!(result.is_ok(), "None address (contract creation) should pass validation");
}

#[test]
fn test_address_missing_0x_prefix_fails() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        nonce: 0,
        gas_price: 20000000000,
        gas_limit: 21000,
        to: Some(Address("742d35Cc6634C0532925a3b844Bc9e7595f0bEb0".to_string())), // Missing 0x
        value: 1000000000000000000,
        data: vec![],
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
        nonce: 0,
        gas_price: 20000000000,
        gas_limit: 21000,
        to: Some(Address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".to_string())), // 41 chars (too short)
        value: 1000000000000000000,
        data: vec![],
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
        nonce: 0,
        gas_price: 20000000000,
        gas_limit: 21000,
        to: Some(Address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb00".to_string())), // 43 chars (too long)
        value: 1000000000000000000,
        data: vec![],
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
        nonce: 0,
        gas_price: 20000000000,
        gas_limit: 21000,
        to: Some(Address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEbG".to_string())), // Invalid 'G' character
        value: 1000000000000000000,
        data: vec![],
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
        nonce: 0,
        gas_price: 20000000000,
        gas_limit: 21000,
        to: Some(Address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb@".to_string())), // Invalid '@' character
        value: 1000000000000000000,
        data: vec![],
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

    // Test with mixed case (valid hex)
    let tx = Transaction {
        nonce: 0,
        gas_price: 20000000000,
        gas_limit: 21000,
        to: Some(Address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0".to_string())), // Mixed case is valid
        value: 1000000000000000000,
        data: vec![],
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
        nonce: 0,
        gas_price: 20000000000,
        gas_limit: 21000,
        to: Some(Address("0x742d35cc6634c0532925a3b844bc9e7595f0beb0".to_string())), // All lowercase
        value: 1000000000000000000,
        data: vec![],
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
        nonce: 0,
        gas_price: 20000000000,
        gas_limit: 21000,
        to: Some(Address("0x742D35CC6634C0532925A3B844BC9E7595F0BEB0".to_string())), // All uppercase
        value: 1000000000000000000,
        data: vec![],
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
        nonce: 0,
        gas_price: 20000000000,
        gas_limit: 21000,
        to: Some(Address("".to_string())), // Empty string
        value: 1000000000000000000,
        data: vec![],
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
        nonce: 0,
        gas_price: 20000000000,
        gas_limit: 21000,
        to: Some(Address("0x".to_string())), // Only prefix, no hex
        value: 1000000000000000000,
        data: vec![],
        chain_id: 1,
    };

    let result = wallet.sign_transaction(tx);
    assert!(result.is_err(), "Address with only 0x prefix should fail validation");
}

#[test]
fn test_well_known_address_passes() {
    // Test with a well-known Ethereum address
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let tx = Transaction {
        nonce: 0,
        gas_price: 20000000000,
        gas_limit: 21000,
        to: Some(Address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string())), // Hardhat/Anvil test address
        value: 1000000000000000000,
        data: vec![],
        chain_id: 1,
    };

    let result = wallet.sign_transaction(tx);
    assert!(result.is_ok(), "Well-known valid address should pass validation");
}
