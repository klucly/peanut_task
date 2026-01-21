use peanut_task::core::wallet_manager::WalletManager;

#[test]
fn test_address_derivation_from_known_key() {
    // Test with a known private key and its expected Ethereum address
    // Private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    // Expected address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
    // This is a well-known test account from Hardhat/Anvil
    
    let wallet = WalletManager::from_hex_string(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    ).unwrap();
    
    let address = wallet.address();
    
    // Ethereum addresses are case-insensitive, but often displayed with EIP-55 checksum
    // For this test, we'll compare in lowercase
    assert_eq!(
        address.0.to_lowercase(),
        "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
    );
}

#[test]
fn test_address_derivation_consistency() {
    // Same wallet should always produce the same address
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();
    
    let address1 = wallet.address();
    let address2 = wallet.address();
    
    assert_eq!(address1.0, address2.0);
}

#[test]
fn test_address_format() {
    // Address should start with 0x and be 42 characters long (0x + 40 hex chars)
    let wallet = WalletManager::from_hex_string(
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ).unwrap();
    
    let address = wallet.address();
    
    assert!(address.0.starts_with("0x"), "Address should start with 0x");
    assert_eq!(address.0.len(), 42, "Address should be 42 characters (0x + 40 hex chars)");
    
    // Check that all characters after 0x are valid hex
    let hex_part = &address.0[2..];
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()), "Address should contain only hex digits");
}

#[test]
fn test_different_keys_produce_different_addresses() {
    let wallet1 = WalletManager::from_hex_string(
        "0x0000000000000000000000000000000000000000000000000000000000000001"
    ).unwrap();
    
    let wallet2 = WalletManager::from_hex_string(
        "0x0000000000000000000000000000000000000000000000000000000000000002"
    ).unwrap();
    
    let address1 = wallet1.address();
    let address2 = wallet2.address();
    
    assert_ne!(address1.0, address2.0, "Different keys should produce different addresses");
}
