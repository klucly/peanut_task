#[cfg(test)]
mod tests {
    use peanut_task::core::wallet_manager::WalletManager;
    use k256::ecdsa::SigningKey;

    #[test]
    fn test_display_to_string_does_not_expose_private_key() {
        let test_key = "0xdeadbeefcafe1234deadbeefcafe1234deadbeefcafe1234deadbeefcafe1234";
        let wallet = WalletManager::from_hex_string(test_key).expect("Valid key should load");

        let display_output = format!("{}", wallet);
        let to_string_output = wallet.to_string();

        let key_substring = "deadbeefcafe1234";
        assert!(
            !display_output.contains(key_substring),
            "Display must not contain private key: {}",
            display_output
        );
        assert!(
            !to_string_output.contains(key_substring),
            "ToString must not contain private key: {}",
            to_string_output
        );

        assert!(
            display_output.contains("WalletManager"),
            "Display should identify type: {}",
            display_output
        );
        assert!(
            to_string_output.contains("WalletManager"),
            "ToString should identify type: {}",
            to_string_output
        );
    }

    #[test]
    fn test_debug_does_not_expose_private_key() {
        let test_key = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let wallet = WalletManager::from_hex_string(test_key).expect("Valid key should load");

        let debug_output = format!("{:?}", wallet);

        assert!(!debug_output.contains("abcdef1234567890"),
            "Debug output should not contain the actual private key: {}", debug_output);
        assert!(debug_output.contains("WalletManager"),
            "Debug output should contain struct name");
        assert!(debug_output.contains("address"),
            "Debug output should show address field: {}", debug_output);
        let addr = wallet.address();
        assert!(debug_output.contains(addr.checksum()),
            "Debug output should contain derived address: {}", debug_output);
        assert!(!debug_output.contains("SigningKey"),
            "Debug must not show SigningKey: {}", debug_output);
    }

    #[test]
    fn test_debug_output_is_deterministic() {
        let test_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let wallet1 = WalletManager::from_hex_string(test_key).expect("Valid key should load");
        let wallet2 = WalletManager::from_hex_string(test_key).expect("Valid key should load");

        let debug1 = format!("{:?}", wallet1);
        let debug2 = format!("{:?}", wallet2);

        assert_eq!(debug1, debug2, "Same private key should produce same debug output");
    }

    #[test]
    fn test_debug_output_does_not_differ_for_different_keys() {
        let test_key1 = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let test_key2 = "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";

        let wallet1 = WalletManager::from_hex_string(test_key1).expect("Valid key should load");
        let wallet2 = WalletManager::from_hex_string(test_key2).expect("Valid key should load");

        let debug1 = format!("{:?}", wallet1);
        let debug2 = format!("{:?}", wallet2);

        assert_ne!(debug1, debug2, "Different keys have different addresses");
        assert!(!debug1.contains("1234567890abcdef"),
            "Debug output should not contain key bytes: {}", debug1);
        assert!(!debug2.contains("fedcba0987654321"),
            "Debug output should not contain key bytes: {}", debug2);
    }

    #[test]
    fn test_error_messages_do_not_expose_private_key() {
        let test_key = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let result = WalletManager::from_hex_string(&test_key[2..]);
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(!error_msg.contains("abcdef1234567890"),
            "Error message should not contain private key data: {}", error_msg);

        let short_key = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678";
        let result = WalletManager::from_hex_string(short_key);
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(!error_msg.contains("abcdef"),
            "Error message should not contain private key data: {}", error_msg);
    }

    #[test]
    fn test_signing_key_debug_does_not_expose_key() {
        let key_bytes: [u8; 32] = [
            0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
            0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
            0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
            0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
        ];
        let signing_key = SigningKey::from_bytes((&key_bytes).into())
            .expect("Valid test key");

        let debug_output = format!("{:?}", signing_key);

        let hex_lower = key_bytes.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        let hex_upper = key_bytes.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>();

        assert!(!debug_output.contains(&hex_lower),
            "Debug output should not contain hex key: {}", debug_output);
        assert!(!debug_output.contains(&hex_upper),
            "Debug output should not contain hex key: {}", debug_output);

        for window in key_bytes.windows(3) {
            let decimal_seq = format!("{}, {}, {}", window[0], window[1], window[2]);
            assert!(!debug_output.contains(&decimal_seq),
                "Debug output should not contain decimal byte sequence: {}", decimal_seq);
        }

        assert!(!debug_output.to_lowercase().contains("[171"),
            "Debug output should not contain array notation: {}", debug_output);
    }

    #[test]
    fn test_wallet_manager_pretty_debug() {
        let test_key = "0xcafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe";
        let wallet = WalletManager::from_hex_string(test_key).expect("Valid key should load");

        let pretty_debug = format!("{:#?}", wallet);

        assert!(!pretty_debug.contains("cafebabe"),
            "Pretty debug should not contain private key: {}", pretty_debug);
        assert!(pretty_debug.contains("WalletManager"),
            "Pretty debug should show struct name");
    }

    #[test]
    fn test_sequential_key_pattern() {
        let key_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let signing_key = SigningKey::from_bytes((&key_bytes).into())
            .expect("Valid test key");

        let debug_output = format!("{:?}", signing_key);

        assert!(!debug_output.contains("[0x"),
            "Should not show array representation: {}", debug_output);
        assert!(!debug_output.contains("[1"),
            "Should not show decimal array: {}", debug_output);
        assert!(!debug_output.contains("0102"),
            "Should not show hex sequential pattern: {}", debug_output);
        assert!(!debug_output.contains("1, 2, 3"),
            "Should not show decimal sequential pattern: {}", debug_output);
    }
}
