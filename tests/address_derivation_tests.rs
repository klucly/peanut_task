use peanut_task::core::wallet_manager::WalletManager;

#[test]
fn test_address_derivation_from_known_key() {
    let wallet = WalletManager::from_hex_string(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    ).unwrap();

    let address = wallet.address();
    assert_eq!(
        address.lower(),
        "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
    );
}

#[test]
fn test_address_derivation_consistency() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let address1 = wallet.address();
    let address2 = wallet.address();
    assert_eq!(address1.value, address2.value);
}

#[test]
fn test_address_format() {
    let wallet = WalletManager::from_hex_string(
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ).unwrap();

    let address = wallet.address();
    assert!(address.value.starts_with("0x"), "Address should start with 0x");
    assert_eq!(address.value.len(), 42, "Address should be 42 characters (0x + 40 hex chars)");
    let hex_part = &address.value[2..];
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
    assert_ne!(address1.value, address2.value, "Different keys should produce different addresses");
}
