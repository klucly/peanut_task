use peanut_task::core::wallet_manager::WalletManager;
use peanut_task::core::utility::Message;
use peanut_task::core::signatures::{Signature, SignedMessage};
use peanut_task::core::signature_algorithms::{SignatureAlgorithm, SignatureData};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_signature_is_accepted() {
        // Create a wallet and sign a message
        let wallet = WalletManager::from_hex_string(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        
        let message = Message("Hello, Ethereum!".to_string());
        let signed = wallet.sign_message(message);
        
        // Verify that the signature is valid
        assert!(signed.verify().is_ok(), "Valid signature should be accepted");
    }

    #[test]
    fn test_invalid_recovery_id_is_rejected() {
        // Create a wallet and sign a message
        let wallet = WalletManager::from_hex_string(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        
        let message = Message("Hello, Ethereum!".to_string());
        let signed = wallet.sign_message(message);
        
        // Try to create a SignedMessage with an invalid v value
        let invalid_sig = Signature::new(signed.signature.r, signed.signature.s, 26);
        let result = SignedMessage::new(
            signed.signature_data.clone(),
            invalid_sig,
            &wallet.address()
        );
        
        assert!(result.is_err(), "Signature with invalid v should be rejected");
        assert!(result.unwrap_err().to_string().contains("Invalid recovery id"));
    }

    #[test]
    fn test_all_zero_signature_is_rejected() {
        // Create a message and an invalid all-zero signature
        let message = Message("Hello, Ethereum!".to_string());
        
        // Use a dummy address for testing
        let dummy_address = peanut_task::core::utility::Address(
            "0x0000000000000000000000000000000000000000".to_string()
        );
        
        let zero_sig = Signature::new([0u8; 32], [0u8; 32], 27);
        let signature_data = SignatureData::from_message(message);
        let result = SignedMessage::new(
            signature_data,
            zero_sig,
            &dummy_address
        );
        
        // All-zero signature should be rejected as it's not a valid ECDSA signature
        assert!(result.is_err(), "All-zero signature should be rejected");
    }

    #[test]
    fn test_signature_with_recovery_id_variations() {
        // Create a wallet and sign a message
        let wallet = WalletManager::from_hex_string(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        
        let message = Message("Hello, Ethereum!".to_string());
        let signed = wallet.sign_message(message);
        
        // The signature should have v = 27 or v = 28
        assert!(
            signed.signature.v == 27 || signed.signature.v == 28,
            "Valid signature should have v = 27 or 28, got v = {}",
            signed.signature.v
        );
    }

    #[test]
    fn test_multiple_signatures_all_valid() {
        // Create a wallet and sign multiple messages
        let wallet = WalletManager::from_hex_string(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        
        let messages = vec![
            "Hello, World!",
            "Ethereum",
            "Test message 123",
            "Unicode: 你好 🌍",
        ];
        
        for msg_text in messages {
            let message = Message(msg_text.to_string());
            let signed = wallet.sign_message(message);
            
            assert!(
                signed.verify().is_ok(),
                "Signature for message '{}' should be valid",
                msg_text
            );
        }
    }

    #[test]
    fn test_signature_components_cannot_be_swapped() {
        // Create a wallet and sign a message
        let wallet = WalletManager::from_hex_string(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        
        let message = Message("Hello, Ethereum!".to_string());
        let signed = wallet.sign_message(message);
        
        // Try to swap r and s components
        let swapped_sig = Signature::new(signed.signature.s, signed.signature.r, signed.signature.v);
        let result = SignedMessage::new(
            signed.signature_data.clone(),
            swapped_sig,
            &wallet.address()
        );
        
        assert!(result.is_err(), "Signature with swapped components should be rejected");
    }

    #[test]
    fn test_wrong_signer_is_rejected() {
        // Create two different wallets
        let wallet1 = WalletManager::from_hex_string(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        let wallet2 = WalletManager::from_hex_string(
            "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        ).unwrap();
        
        // Sign a message with wallet1
        let message = Message("Hello, Ethereum!".to_string());
        let signed = wallet1.sign_message(message);
        
        // Try to create a SignedMessage claiming it was signed by wallet2
        let result = SignedMessage::new(
            signed.signature_data.clone(),
            signed.signature.clone(),
            &wallet2.address()
        );
        
        assert!(result.is_err(), "Signature with wrong signer should be rejected");
    }

    #[test]
    fn test_signed_message_guarantees_validity() {
        // Create a wallet and sign a message
        let wallet = WalletManager::from_hex_string(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        
        let message = Message("Hello, Ethereum!".to_string());
        let signed = wallet.sign_message(message);
        
        // Verification should always succeed for a properly created SignedMessage
        assert!(signed.verify().is_ok(), "SignedMessage should always be verifiable");
        
        // Test that we can manually create a SignedMessage with valid signature
        let message2 = Message("Another test".to_string());
        let signed2 = wallet.sign_message(message2);
        
        // Manually recreate it with the correct signer
        let manual = SignedMessage::new(
            signed2.signature_data.clone(),
            signed2.signature.clone(),
            &wallet.address()
        );
        assert!(manual.is_ok(), "Valid signature should create SignedMessage successfully");
    }
}
