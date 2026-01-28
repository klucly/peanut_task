#[cfg(test)]
mod tests {
    use peanut_task::core::wallet_manager::{WalletManager, KeyLoadError};

    #[test]
    fn test_from_hex_string_valid_key() {
        let valid_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = WalletManager::from_hex_string(valid_key);
        assert!(result.is_ok(), "Valid key should load successfully");
    }

    #[test]
    fn test_from_hex_string_missing_prefix() {
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
        let invalid_hex = "0x123456789Gabcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = WalletManager::from_hex_string(invalid_hex);
        assert!(result.is_err(), "Invalid hex characters should fail");
        match result.unwrap_err() {
            KeyLoadError::HexDecode(_) => {},
            _ => panic!("Expected HexDecode error"),
        }
    }

    #[test]
    fn test_from_hex_string_odd_length() {
        let odd_length_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcde";
        let result = WalletManager::from_hex_string(odd_length_key);
        assert!(result.is_err(), "Odd-length hex string should fail");
        match result.unwrap_err() {
            KeyLoadError::HexDecode(_) => {},
            _ => panic!("Expected HexDecode error"),
        }
    }

    #[test]
    fn test_from_hex_string_zero_key() {
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
        let max_valid_key = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140";
        let result = WalletManager::from_hex_string(max_valid_key);
        assert!(result.is_ok(), "Maximum valid key should be accepted");
    }

    #[test]
    fn test_generate_produces_valid_keys() {
        for _ in 0..10 {
            let wallet = WalletManager::generate();
            assert!(wallet.is_ok(), "Generated wallet should always be valid");
            let wallet = wallet.unwrap();
            let _address = wallet.address();
        }
    }
}
