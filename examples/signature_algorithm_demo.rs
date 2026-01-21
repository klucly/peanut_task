use peanut_task::core::wallet_manager::WalletManager;
use peanut_task::core::basic_structs::{Message, SignedMessage};
use peanut_task::SignatureAlgorithm;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Signature Algorithm Demo ===\n");
    
    // Create a wallet
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    )?;
    
    println!("Wallet address: {}\n", wallet.address());
    
    // ========================================
    // EIP-191: Personal Message Signing
    // ========================================
    println!("--- EIP-191: Personal Message Signing ---\n");
    
    let message = Message("Hello, Ethereum!".to_string());
    let signed_eip191 = wallet.sign_message(message);
    
    if let Some(msg) = signed_eip191.signature_data.as_message() {
        println!("Message: {}", msg.0);
    }
    println!("Algorithm: {:?}", signed_eip191.algorithm());
    println!("Signature: {}", signed_eip191.signature.to_hex());
    
    // Verify the signature
    match signed_eip191.verify() {
        Ok(()) => println!("✓ Signature is valid"),
        Err(e) => println!("✗ Signature verification failed: {}", e),
    }
    
    // Recover the signer
    let recovered_address = signed_eip191.recover_signer()?;
    println!("Recovered signer: {}", recovered_address);
    
    // Verify it matches the wallet address
    if recovered_address.0 == wallet.address().0 {
        println!("✓ Recovered address matches wallet address");
    }
    
    // ========================================
    // EIP-712: Typed Structured Data Signing
    // ========================================
    println!("\n--- EIP-712: Typed Structured Data Signing ---\n");
    
    let domain = json!({
        "name": "MyDApp",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0x1234567890123456789012345678901234567890"
    });
    
    let types = json!({
        "Person": [
            {"name": "name", "type": "string"},
            {"name": "wallet", "type": "address"},
            {"name": "age", "type": "uint256"}
        ]
    });
    
    let value = json!({
        "name": "Alice",
        "wallet": "0x1234567890123456789012345678901234567890",
        "age": 30
    });
    
    let signed_eip712 = wallet.sign_typed_data(domain, types, value)?;
    
    println!("Algorithm: {:?}", signed_eip712.algorithm());
    println!("Signature: {}", signed_eip712.signature.to_hex());
    
    // Verify the signature
    match signed_eip712.verify() {
        Ok(()) => println!("✓ Signature is valid"),
        Err(e) => println!("✗ Signature verification failed: {}", e),
    }
    
    // Recover the signer
    let recovered_address_eip712 = signed_eip712.recover_signer()?;
    println!("Recovered signer: {}", recovered_address_eip712);
    
    // Verify it matches the wallet address
    if recovered_address_eip712.0 == wallet.address().0 {
        println!("✓ Recovered address matches wallet address");
    }
    
    // ========================================
    // Manual Verification with Algorithm
    // ========================================
    println!("\n--- Manual Verification ---\n");
    
    // Create a new message and sign it
    let test_message = Message("Test message".to_string());
    let test_signed = wallet.sign_message(test_message.clone());
    
    // Manually verify by creating a new SignedMessage with verification
    let manually_verified = SignedMessage::new(
        test_signed.signature_data.clone(),
        test_signed.signature.clone(),
        &wallet.address()
    );
    
    match manually_verified {
        Ok(_) => println!("✓ Manual verification succeeded"),
        Err(e) => println!("✗ Manual verification failed: {}", e),
    }
    
    // Try with wrong signer (should fail)
    let wrong_wallet = WalletManager::from_hex_string(
        "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    )?;
    
    let failed_verification = SignedMessage::new(
        test_signed.signature_data.clone(),
        test_signed.signature.clone(),
        &wrong_wallet.address()
    );
    
    match failed_verification {
        Ok(_) => println!("✗ Verification should have failed but didn't"),
        Err(e) => println!("✓ Verification correctly failed: {}", e),
    }
    
    // ========================================
    // Demonstrating Algorithm Awareness
    // ========================================
    println!("\n--- Algorithm Awareness ---\n");
    
    println!("EIP-191 signature uses algorithm: {:?}", signed_eip191.algorithm());
    println!("EIP-712 signature uses algorithm: {:?}", signed_eip712.algorithm());
    
    println!("\n✓ Both algorithms are properly tracked and can be verified independently!");
    
    Ok(())
}
