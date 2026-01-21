# Signature and SignedMessage Implementation

## Overview

This document describes the implementation of the `Signature` and `SignedMessage` structures for Ethereum message signing.

## Error Types

### `SignatureError`

An error type representing various signature validation failures.

**Variants:**
- `InvalidRecoveryId(u8)` - The recovery id (v) is not 27 or 28
- `RecoveryFailed` - Failed to recover a public key from the signature
- `InvalidSignature` - The signature format is invalid

## Structures

### `Signature`

A structure representing an ECDSA signature with recovery id for Ethereum.

**Fields:**
- `r: [u8; 32]` - The x-coordinate of a random point on the elliptic curve
- `s: [u8; 32]` - The signature proof
- `v: u8` - The recovery id (typically 27 or 28 for Ethereum)

**Methods:**
- `new(r, s, v)` - Creates a new Signature
- `to_bytes()` - Returns the raw signature as a 65-byte array (r + s + v)
- `to_hex()` - Returns the signature as a hex string with 0x prefix

**Implementations:**
- `Debug` - Shows raw contents with r, s, v in hex format
- `Display` - Shows the signature as a hex string
- `Clone` - Allows cloning the signature

### `SignedMessage`

A structure representing a message that has been cryptographically signed. This type guarantees that the signature is **100% valid** and was created by a specific signer - it can only be constructed through verification.

**Fields:**
- `message: Message` - The original message that was signed (wrapped in Message struct)
- `signature: Signature` - The cryptographic signature

**Methods:**
- `new(message, signature, expected_signer)` - Creates a new SignedMessage with signer verification (returns `Result<SignedMessage, SignatureError>`)
- `verify()` - Verifies that the signature is cryptographically valid (always succeeds for properly constructed SignedMessage)

**Implementations:**
- `Debug` - Shows message and signature details
- `Display` - Formatted output showing message and signature

**Validation:**

The `new` method validates the signature to ensure it was created by a specific signer:
1. Checks that the recovery id (v) is 27 or 28
2. Verifies the signature is mathematically well-formed
3. Recovers the public key from the signature and message
4. Derives the Ethereum address from the recovered public key
5. Verifies the recovered address matches the expected signer

If validation fails (invalid signature or wrong signer), an error is returned instead of creating the `SignedMessage`. This means **a SignedMessage instance is always 100% valid** - you can trust that the signature was created by the expected signer. The validation happens at construction time, so once you have a `SignedMessage`, you know it came from the right address.

## Usage Example

```rust
use peanut_task::core::wallet_manager::WalletManager;
use peanut_task::core::basic_structs::{Message, Signature, SignedMessage};

// Create a wallet
let wallet = WalletManager::from_hex_string(
    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
).unwrap();

// Sign a message - this creates a SignedMessage that's guaranteed to be valid
// and signed by this specific wallet
let message = Message("Hello, Ethereum!".to_string());
let signed = wallet.sign_message(message);

// The signed message is guaranteed to be 100% valid from this signer
assert!(signed.verify().is_ok());

// Access components
println!("Message: {}", signed.message.0);
println!("Signature: {}", signed.signature.to_hex());
println!("R: 0x{}", hex::encode(&signed.signature.r));
println!("S: 0x{}", hex::encode(&signed.signature.s));
println!("V: {}", signed.signature.v);

// Get raw bytes
let raw_bytes = signed.signature.to_bytes();

// Manually create a SignedMessage (with signer verification)
// This validates the signature was created by the expected signer
let message2 = Message("Another message".to_string());
let sig = Signature::new([0u8; 32], [0u8; 32], 27);
let expected_signer = wallet.address();
match SignedMessage::new(message2, sig, expected_signer) {
    Ok(signed_msg) => println!("Valid signature from correct signer"),
    Err(e) => println!("Invalid signature or wrong signer: {}", e),
}

// Example: Wrong signer is rejected
let wallet2 = WalletManager::generate().unwrap();
let message3 = Message("Test".to_string());
let signed3 = wallet.sign_message(message3.clone());

// This will fail because wallet2 didn't sign the message
match SignedMessage::new(signed3.message, signed3.signature, wallet2.address()) {
    Ok(_) => unreachable!("Should not accept wrong signer"),
    Err(e) => println!("Correctly rejected wrong signer: {}", e),
}
```

## Debug Output Example

```rust
SignedMessage {
    message: "Hello, Ethereum!",
    signature: Signature {
        r: 0x38bf378f82336db7e69446aa36aa54433c9b544ee350b0b6104382b77a4d3b29,
        s: 0x72926edbe968e56920f7db67634b799a3c7c9f9719b9297ac3f00e0c18b66593,
        v: 27,
    },
}
```

## Implementation Details

The `sign_message` method in `WalletManager`:
1. Prefixes the message according to EIP-191: `"\x19Ethereum Signed Message:\n" + message_length + message`
2. Hashes the prefixed message with Keccak-256
3. Signs the hash using ECDSA (secp256k1)
4. Includes the recovery id (v) for public key recovery
5. Gets the wallet's Ethereum address
6. Returns a `SignedMessage` containing the original `Message` and the `Signature`, verified for this signer

The `SignedMessage::new` constructor:
1. Validates the recovery id (v) is 27 or 28
2. Recovers the public key from the signature and message hash
3. Derives the Ethereum address from the recovered public key
4. Verifies the recovered address matches the expected signer
5. Only creates the `SignedMessage` if the signature is valid for the expected signer
6. Returns an error if the signature is invalid or from the wrong signer

This design ensures that:
- **Type Safety**: A `SignedMessage` instance is always 100% valid - no need to check
- **Signer Verification**: The signature was created by the expected signer's private key
- **Validation at Construction**: Invalid signatures or wrong signers cannot create a `SignedMessage`
- **Data Integrity**: The message and signature stay together as a cohesive unit
- **Simplicity**: No need to store the signer address - validation proves it at construction
- **Guaranteed Validity**: If you have a `SignedMessage`, the signature came from the right signer
