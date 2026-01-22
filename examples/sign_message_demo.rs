use peanut_task::core::wallet_manager::WalletManager;
use peanut_task::core::utility::Message;

fn main() {
    // Create a wallet from a hex string
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).expect("Failed to create wallet");

    // Create a message
    let message = Message("Hello, Ethereum!".to_string());
    
    // Sign the message
    let signed = wallet.sign_message(message);
    
    // Display the results
    println!("=== Signed Message ===");
    println!("{}", signed);
    println!();
    
    // Show the debug representation
    println!("=== Debug Output ===");
    println!("{:#?}", signed);
    println!();
    
    // Access individual components
    println!("=== Individual Components ===");
    if let Some(msg) = signed.signature_data.as_message() {
        println!("Message: {}", msg.0);
    }
    println!("Signature (hex): {}", signed.signature.to_hex());
    println!("R: 0x{}", hex::encode(&signed.signature.r));
    println!("S: 0x{}", hex::encode(&signed.signature.s));
    println!("V: {}", signed.signature.v);
    println!();
    
    // Get raw bytes
    println!("=== Raw Representation ===");
    let raw_bytes = signed.signature.to_bytes();
    println!("Raw signature bytes (65 bytes): 0x{}", hex::encode(&raw_bytes));
}
