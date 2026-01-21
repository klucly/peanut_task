use peanut_task::core::wallet_manager::WalletManager;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== EIP-712 Typed Data Signing Demo ===\n");
    
    // Create a wallet from a hex string
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    )?;
    
    println!("Wallet address: {}\n", wallet.address());
    
    // Define the domain separator (prevents replay attacks across different domains)
    let domain = json!({
        "name": "MyDApp",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0x1234567890123456789012345678901234567890"
    });
    
    // Define the type structure
    let types = json!({
        "Person": [
            {"name": "name", "type": "string"},
            {"name": "wallet", "type": "address"},
            {"name": "age", "type": "uint256"}
        ]
    });
    
    // Define the actual data to sign
    let value = json!({
        "name": "Alice",
        "wallet": "0x1234567890123456789012345678901234567890",
        "age": 30
    });
    
    println!("Domain:");
    println!("{}\n", serde_json::to_string_pretty(&domain)?);
    
    println!("Types:");
    println!("{}\n", serde_json::to_string_pretty(&types)?);
    
    println!("Value:");
    println!("{}\n", serde_json::to_string_pretty(&value)?);
    
    // Sign the typed data
    println!("Signing typed data...\n");
    let signed = wallet.sign_typed_data(domain, types, value)?;
    
    println!("Signature:");
    println!("  R: 0x{}", hex::encode(&signed.signature.r));
    println!("  S: 0x{}", hex::encode(&signed.signature.s));
    println!("  V: {}", signed.signature.v);
    println!("\nFull signature: {}", signed.signature.to_hex());
    
    // Demonstrate with another example: a token transfer
    println!("\n\n=== Token Transfer Example ===\n");
    
    let transfer_domain = json!({
        "name": "MyToken",
        "version": "1",
        "chainId": 1
    });
    
    let transfer_types = json!({
        "Transfer": [
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"}
        ]
    });
    
    let transfer_value = json!({
        "from": "0x1234567890123456789012345678901234567890",
        "to": "0x0987654321098765432109876543210987654321",
        "amount": "1000000000000000000"
    });
    
    let transfer_signed = wallet.sign_typed_data(transfer_domain, transfer_types, transfer_value)?;
    
    println!("Transfer signature: {}", transfer_signed.signature.to_hex());
    
    Ok(())
}
