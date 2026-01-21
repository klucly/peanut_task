#[cfg(test)]
mod tests {
    use peanut_task::core::wallet_manager::WalletManager;
    use peanut_task::core::basic_structs::PrivateKey;

    #[test]
    fn test_debug_does_not_expose_private_key() {
        // Test that Debug implementation does not expose the actual private key
        let test_key = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let wallet = WalletManager::from_hex_string(test_key).expect("Valid key should load");
        
        let debug_output = format!("{:?}", wallet);
        
        // The debug output should NOT contain the actual private key bytes
        assert!(!debug_output.contains("abcdef1234567890"), 
            "Debug output should not contain the actual private key: {}", debug_output);
        
        // Should contain "WalletManager" to indicate the struct type
        assert!(debug_output.contains("WalletManager"), 
            "Debug output should contain struct name");
        
        // Should contain "Hash" to indicate we're showing a hash
        assert!(debug_output.contains("Hash"), 
            "Debug output should indicate it's showing a hash");
    }

    #[test]
    fn test_debug_output_is_deterministic() {
        // Test that the same key produces the same debug output (hash should be consistent)
        let test_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let wallet1 = WalletManager::from_hex_string(test_key).expect("Valid key should load");
        let wallet2 = WalletManager::from_hex_string(test_key).expect("Valid key should load");
        
        let debug1 = format!("{:?}", wallet1);
        let debug2 = format!("{:?}", wallet2);
        
        assert_eq!(debug1, debug2, "Same private key should produce same debug output");
    }

    #[test]
    fn test_debug_output_differs_for_different_keys() {
        // Test that different keys produce different debug outputs
        let test_key1 = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let test_key2 = "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        
        let wallet1 = WalletManager::from_hex_string(test_key1).expect("Valid key should load");
        let wallet2 = WalletManager::from_hex_string(test_key2).expect("Valid key should load");
        
        let debug1 = format!("{:?}", wallet1);
        let debug2 = format!("{:?}", wallet2);
        
        assert_ne!(debug1, debug2, "Different private keys should produce different debug outputs");
    }

    #[test]
    fn test_error_messages_do_not_expose_private_key() {
        // Test that error messages don't accidentally leak the private key
        let test_key = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        
        // Test with missing prefix error
        let result = WalletManager::from_hex_string(&test_key[2..]); // Remove 0x
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(!error_msg.contains("abcdef1234567890"), 
            "Error message should not contain private key data: {}", error_msg);
        
        // Test with invalid length error
        let short_key = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678";
        let result = WalletManager::from_hex_string(short_key);
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(!error_msg.contains("abcdef"), 
            "Error message should not contain private key data: {}", error_msg);
    }

    #[test]
    fn test_private_key_debug_does_not_expose_key() {
        // Test that PrivateKey Debug implementation doesn't expose the actual key
        let key_bytes: [u8; 32] = [
            0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
            0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
            0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
            0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
        ];
        let private_key = PrivateKey(key_bytes);
        
        let debug_output = format!("{:?}", private_key);
        
        // Convert key bytes to various string formats and verify NONE appear in debug output
        
        // Check for hex representation (lowercase and uppercase)
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
        
        // Check for any consecutive byte sequences (3+ bytes) in decimal format
        for window in key_bytes.windows(3) {
            let decimal_seq = format!("{}, {}, {}", window[0], window[1], window[2]);
            assert!(!debug_output.contains(&decimal_seq),
                "Debug output should not contain decimal byte sequence: {}", decimal_seq);
        }
        
        // Check for array format representations
        assert!(!debug_output.to_lowercase().contains("[171"), // 0xab
            "Debug output should not contain array notation: {}", debug_output);
        
        // Should contain expected structure indicators
        assert!(debug_output.contains("PrivateKey"), 
            "Debug output should contain struct name");
        assert!(debug_output.contains("Hash"), 
            "Debug output should show hash of key");
    }

    #[test]
    fn test_wallet_manager_pretty_debug() {
        // Test that pretty-print debug format also doesn't leak keys
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
        // Test with a sequential pattern to ensure no byte patterns leak
        let key_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let private_key = PrivateKey(key_bytes);
        
        let debug_output = format!("{:?}", private_key);
        
        // Should not show array representation
        assert!(!debug_output.contains("[0x"), 
            "Should not show array representation: {}", debug_output);
        assert!(!debug_output.contains("[1"), 
            "Should not show decimal array: {}", debug_output);
        
        // Should not contain sequential patterns in hex or decimal
        assert!(!debug_output.contains("0102"), 
            "Should not show hex sequential pattern: {}", debug_output);
        assert!(!debug_output.contains("1, 2, 3"), 
            "Should not show decimal sequential pattern: {}", debug_output);
        
        // Should show hash instead
        assert!(debug_output.contains("Hash"), 
            "Should show hash");
    }
}
