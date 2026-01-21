#[cfg(test)]
mod tests {
    use peanut_task::core::wallet_manager::{WalletManager, KeyLoadError};

    #[test]
    fn test_from_hex_string_valid_key() {
        // Test 1: Valid key with 0x prefix (64 hex chars = 32 bytes)
        let valid_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = WalletManager::from_hex_string(valid_key);
        assert!(result.is_ok(), "Valid key should load successfully");
    }

    #[test]
    fn test_from_hex_string_missing_prefix() {
        // Test 2: Missing 0x prefix
        let no_prefix_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = WalletManager::from_hex_string(no_prefix_key);
        assert!(result.is_err(), "Key without 0x prefix should fail");
        match result.unwrap_err() {
            KeyLoadError::MissingHexPrefix => {},
            _ => panic!("Expected MissingHexPrefix error"),
        }
    }

    #[test]
    fn test_from_hex_string_short_key() {
        // Test 3: Invalid length (too short - 30 bytes instead of 32)
        let short_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab";
        let result = WalletManager::from_hex_string(short_key);
        assert!(result.is_err(), "Short key should fail");
        match result.unwrap_err() {
            KeyLoadError::VecConversion(len) => assert_eq!(len, 30, "Expected 30 bytes"),
            _ => panic!("Expected VecConversion error"),
        }
    }

    #[test]
    fn test_from_hex_string_long_key() {
        // Test 4: Invalid length (too long - 34 bytes instead of 32)
        let long_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234";
        let result = WalletManager::from_hex_string(long_key);
        assert!(result.is_err(), "Long key should fail");
        match result.unwrap_err() {
            KeyLoadError::VecConversion(len) => assert_eq!(len, 34, "Expected 34 bytes"),
            _ => panic!("Expected VecConversion error"),
        }
    }

    #[test]
    fn test_from_hex_string_invalid_hex() {
        // Test 5: Invalid hex characters
        let invalid_hex = "0x123456789Gabcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = WalletManager::from_hex_string(invalid_hex);
        assert!(result.is_err(), "Invalid hex characters should fail");
        match result.unwrap_err() {
            KeyLoadError::ParseHex(_) => {},
            _ => panic!("Expected ParseHex error"),
        }
    }

    #[test]
    fn test_from_hex_string_odd_length() {
        // Test 6: Odd number of hex characters (63 chars instead of 64)
        // Cannot be converted from hex since each byte needs 2 hex digits
        let odd_length_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcde";
        let result = WalletManager::from_hex_string(odd_length_key);
        assert!(result.is_err(), "Odd-length hex string should fail");
        match result.unwrap_err() {
            KeyLoadError::OddLength => {},
            _ => panic!("Expected OddLength error"),
        }
    }

    #[test]
    fn test_from_hex_string_zero_key() {
        // Test 7: All zeros key (cryptographically invalid for secp256k1)
        let zero_key = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let result = WalletManager::from_hex_string(zero_key);
        assert!(result.is_err(), "Zero key should be rejected as invalid");
        match result.unwrap_err() {
            KeyLoadError::InvalidPrivateKey => {},
            _ => panic!("Expected InvalidPrivateKey error"),
        }
    }

    #[test]
    fn test_from_hex_string_key_at_curve_order() {
        // Test 8: Key equal to secp256k1 curve order (invalid - must be less than order)
        // secp256k1 order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        let curve_order_key = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
        let result = WalletManager::from_hex_string(curve_order_key);
        assert!(result.is_err(), "Key at curve order should be rejected");
        match result.unwrap_err() {
            KeyLoadError::InvalidPrivateKey => {},
            _ => panic!("Expected InvalidPrivateKey error"),
        }
    }

    #[test]
    fn test_from_hex_string_key_above_curve_order() {
        // Test 9: Key greater than secp256k1 curve order (invalid)
        let above_order_key = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142";
        let result = WalletManager::from_hex_string(above_order_key);
        assert!(result.is_err(), "Key above curve order should be rejected");
        match result.unwrap_err() {
            KeyLoadError::InvalidPrivateKey => {},
            _ => panic!("Expected InvalidPrivateKey error"),
        }
    }

    #[test]
    fn test_from_hex_string_max_valid_key() {
        // Test 10: Maximum valid key (curve order - 1)
        // This should be accepted as it's the largest valid private key
        let max_valid_key = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140";
        let result = WalletManager::from_hex_string(max_valid_key);
        assert!(result.is_ok(), "Maximum valid key should be accepted");
    }

    #[test]
    fn test_generate_produces_valid_keys() {
        // Test 11: Generate method should always produce valid keys
        // Generate multiple keys to ensure consistency
        for _ in 0..10 {
            let wallet = WalletManager::generate();
            assert!(wallet.is_ok(), "Generated wallet should always be valid");
            
            // Verify we can derive an address (this would fail if key was invalid)
            let wallet = wallet.unwrap();
            let _address = wallet.address(); // Should not panic
        }
    }
}
