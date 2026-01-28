use peanut_task::core::wallet_manager::WalletManager;
use peanut_task::core::utility::Message;
use peanut_task::core::signatures::{Signature, SignedMessage};
use peanut_task::core::signature_algorithms::{SignatureAlgorithm, SignatureData};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_signature_is_accepted() {
        let wallet = WalletManager::from_hex_string(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        
        let message = Message("Hello, Ethereum!".to_string());
        let signed = wallet.sign_message(message).unwrap();
        assert!(signed.verify().is_ok(), "Valid signature should be accepted");
    }

    #[test]
    fn test_invalid_recovery_id_is_rejected() {
        let wallet = WalletManager::from_hex_string(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        
        let message = Message("Hello, Ethereum!".to_string());
        let signed = wallet.sign_message(message).unwrap();
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
        let message = Message("Hello, Ethereum!".to_string());
        let dummy_address = peanut_task::core::utility::Address::from_string(
            "0x0000000000000000000000000000000000000000"
        ).unwrap();
        
        let zero_sig = Signature::new([0u8; 32], [0u8; 32], 27);
        let signature_data = SignatureData::from_message(message);
        let result = SignedMessage::new(
            signature_data,
            zero_sig,
            &dummy_address
        );
        assert!(result.is_err(), "All-zero signature should be rejected");
    }

    #[test]
    fn test_signature_with_recovery_id_variations() {
        let wallet = WalletManager::from_hex_string(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        
        let message = Message("Hello, Ethereum!".to_string());
        let signed = wallet.sign_message(message).unwrap();
        assert!(
            signed.signature.v == 27 || signed.signature.v == 28,
            "Valid signature should have v = 27 or 28, got v = {}",
            signed.signature.v
        );
    }

    #[test]
    fn test_multiple_signatures_all_valid() {
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
            let signed = wallet.sign_message(message).unwrap();
            
            assert!(
                signed.verify().is_ok(),
                "Signature for message '{}' should be valid",
                msg_text
            );
        }
    }

    #[test]
    fn test_signature_components_cannot_be_swapped() {
        let wallet = WalletManager::from_hex_string(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        
        let message = Message("Hello, Ethereum!".to_string());
        let signed = wallet.sign_message(message).unwrap();
        
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
        let wallet1 = WalletManager::from_hex_string(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        let wallet2 = WalletManager::from_hex_string(
            "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        ).unwrap();
        
        let message = Message("Hello, Ethereum!".to_string());
        let signed = wallet1.sign_message(message).unwrap();
        
        let result = SignedMessage::new(
            signed.signature_data.clone(),
            signed.signature.clone(),
            &wallet2.address()
        );
        
        assert!(result.is_err(), "Signature with wrong signer should be rejected");
    }

    #[test]
    fn test_signed_message_guarantees_validity() {
        let wallet = WalletManager::from_hex_string(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        
        let message = Message("Hello, Ethereum!".to_string());
        let signed = wallet.sign_message(message).unwrap();
        assert!(signed.verify().is_ok(), "SignedMessage should always be verifiable");
        let message2 = Message("Another test".to_string());
        let signed2 = wallet.sign_message(message2).unwrap();
        let manual = SignedMessage::new(
            signed2.signature_data.clone(),
            signed2.signature.clone(),
            &wallet.address()
        );
        assert!(manual.is_ok(), "Valid signature should create SignedMessage successfully");
    }
}
