//! Secure wrapper around private keys that prevents direct key exposure.
//! 
//! All cryptographic operations are performed through `WalletManager`, ensuring
//! the private key itself is never directly accessible or exposed.

use core::str;
use thiserror::Error;
use std::{env::{self, VarError}, num::ParseIntError, fmt};
use getrandom;
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};

use super::basic_structs::{Address, Message, SignedMessage, UnfinishedType, SignedTransaction, PrivateKey, TypedData};
use super::signature_algorithms::{
    SignatureData, 
    Eip191Hasher, Eip712Hasher, SignatureHasher
};
use serde_json::Value;

/// Wrapper around a `PrivateKey` that handles all key operations.
/// 
/// This design ensures the private key is never directly exposed - all operations
/// (signing, address derivation, etc.) are performed through this interface.
/// The Debug implementation is safe for logging.
pub struct WalletManager {
    private_key: PrivateKey
}

impl fmt::Debug for WalletManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletManager")
            .field("private_key", &self.private_key)
            .finish()
    }
}

#[derive(Error, Debug)]
pub enum KeyLoadError {
    #[error("Couldn't parse a key: {0}")]
    ParseHex(#[from] ParseIntError),

    #[error("Couldn't load a variable: {0}")]
    LoadVar(#[from] VarError),

    #[error("Invalid key length: expected 32 bytes, got {0} bytes")]
    VecConversion(usize),

    #[error("Invalid key format: expected '0x' prefix")]
    MissingHexPrefix,

    #[error("Invalid hex string: {0}")]
    HexDecode(String),

    #[error("Invalid private key: key is not valid for secp256k1 curve")]
    InvalidPrivateKey,
}


impl WalletManager {
    /// Validates that a private key is cryptographically valid for secp256k1.
    /// 
    /// A valid private key must:
    /// - Not be zero
    /// - Be less than the secp256k1 curve order
    /// - Be able to generate a valid signing key
    fn validate_private_key(key: &[u8; 32]) -> Result<(), KeyLoadError> {
        // Attempt to create a signing key - this validates the key is in the valid range
        SigningKey::from_bytes(key.into())
            .map_err(|_| KeyLoadError::InvalidPrivateKey)?;
        Ok(())
    }

    /// Loads a private key from an environment variable.
    /// 
    /// The variable value must be a hex string with '0x' prefix and exactly 64 hex characters (32 bytes).
    /// The key must also be cryptographically valid for secp256k1.
    pub fn from_env(var_name: &str) -> Result<WalletManager, KeyLoadError> {
        let key_hex = env::var(var_name)?;
        Self::from_hex_string(&key_hex)
    }

    /// Parses a private key from a hex string.
    /// 
    /// Expected format: `0x` followed by exactly 64 hexadecimal characters (32 bytes).
    /// The key must be cryptographically valid for secp256k1 (non-zero and less than curve order).
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::wallet_manager::WalletManager;
    /// let wallet = WalletManager::from_hex_string(
    ///     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    /// ).unwrap();
    /// ```
    pub fn from_hex_string(key_hex: &str) -> Result<WalletManager, KeyLoadError> {
        let hex_str = key_hex.strip_prefix("0x")
            .ok_or(KeyLoadError::MissingHexPrefix)?;
        let key_vec = hex::decode(hex_str)
            .map_err(|e| KeyLoadError::HexDecode(e.to_string()))?;
        let key: [u8; 32] = key_vec.try_into().map_err(|v: Vec<u8>| KeyLoadError::VecConversion(v.len()))?;
        
        // Validate the key is cryptographically valid
        Self::validate_private_key(&key)?;
        
        let private_key = PrivateKey(key);
        Ok(WalletManager { private_key })
    }
    
    /// Generates a new wallet with a cryptographically secure random private key.
    /// 
    /// Uses the system's random number generator via `getrandom`.
    /// The generated key is guaranteed to be valid for secp256k1.
    pub fn generate() -> Result<WalletManager, getrandom::Error> {
        let mut raw_key = [0u8; 32];
        
        // Generate random bytes until we get a valid key
        // In practice, the probability of generating an invalid key is negligible (~2^-128)
        loop {
            getrandom::fill(&mut raw_key)?;
            if Self::validate_private_key(&raw_key).is_ok() {
                break;
            }
        }
        
        Ok(WalletManager { private_key: PrivateKey(raw_key) })
    }
    /// Derives the Ethereum address from the private key.
    /// 
    /// The address is computed by:
    /// 1. Deriving the public key from the private key using secp256k1
    /// 2. Hashing the uncompressed public key (64 bytes, without the 0x04 prefix) with Keccak-256
    /// 3. Taking the last 20 bytes of the hash
    /// 4. Formatting as a hex string with '0x' prefix
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::wallet_manager::WalletManager;
    /// let wallet = WalletManager::from_hex_string(
    ///     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    /// ).unwrap();
    /// let address = wallet.address();
    /// ```
    pub fn address(&self) -> Address {
        // Create a signing key from the private key bytes
        let signing_key = SigningKey::from_bytes((&self.private_key.0).into())
            .expect("Must have been validated when creating WalletManager");
        
        // Get the verifying (public) key
        let verifying_key = signing_key.verifying_key();
        
        // Get the uncompressed public key bytes (65 bytes: 0x04 + X + Y coordinates)
        let public_key_bytes = verifying_key.to_encoded_point(false);
        
        // Skip the first byte (0x04 prefix) and hash the remaining 64 bytes with Keccak-256
        let public_key_slice = &public_key_bytes.as_bytes()[1..];
        let mut hasher = Keccak256::new();
        hasher.update(public_key_slice);
        let hash = hasher.finalize();
        
        // Take the last 20 bytes of the hash
        let address_bytes = &hash[12..];
        
        // Format as hex string with 0x prefix
        let address_hex = format!("0x{}", hex::encode(address_bytes));
        
        Address(address_hex)
    }
    /// Signs a message using Ethereum's personal message signing standard (EIP-191).
    /// 
    /// The message is prefixed with "\x19Ethereum Signed Message:\n" + message_length,
    /// then hashed with Keccak-256 before signing. This prevents signed messages from
    /// being valid transactions.
    /// 
    /// Returns a `SignedMessage` containing the original message and signature.
    /// The SignedMessage is guaranteed to be 100% valid - the signature was created
    /// by this wallet and is cryptographically valid for the message.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::wallet_manager::WalletManager;
    /// # use peanut_task::core::basic_structs::Message;
    /// let wallet = WalletManager::from_hex_string(
    ///     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    /// ).unwrap();
    /// let message = Message("Hello, Ethereum!".to_string());
    /// let signed = wallet.sign_message(message);
    /// println!("Signature: {}", signed.signature.to_hex());
    /// ```
    pub fn sign_message(&self, msg: Message) -> SignedMessage {
        let hasher = Eip191Hasher;
        
        let signing_key = SigningKey::from_bytes((&self.private_key.0).into())
            .expect("Must have been validated when creating WalletManager");
        
        let signature = hasher.sign(&signing_key, &msg)
            .expect("Failed to sign message");
        
        let signature_data = SignatureData::from_message(msg);
        
        // Verify the signature matches this wallet's address
        // This should always succeed since we just signed it, but it ensures
        // SignedMessage can only be created through verification
        SignedMessage::new(signature_data, signature, &self.address())
            .expect("Signature verification failed for message we just signed")
    }
    /// Signs typed data using EIP-712 standard.
    /// 
    /// EIP-712 provides a standard for structured data signing that:
    /// - Uses canonical JSON serialization for deterministic hashing
    /// - Includes domain separation to prevent replay attacks
    /// - Supports complex typed data structures
    /// 
    /// The signature is computed by:
    /// 1. Hashing the domain, types, and value separately using canonical serialization
    /// 2. Creating the EIP-712 digest: keccak256("\x19\x01" + domainHash + messageHash)
    /// 3. Signing the digest with ECDSA
    /// 
    /// # Arguments
    /// * `domain` - The domain separator (prevents replay across different domains/contracts)
    /// * `types` - The type definitions for the structured data
    /// * `value` - The actual data to sign
    /// 
    /// # Returns
    /// A `SignedMessage` containing the serialized typed data and signature
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::wallet_manager::WalletManager;
    /// # use serde_json::json;
    /// let wallet = WalletManager::from_hex_string(
    ///     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    /// ).unwrap();
    /// 
    /// let domain = json!({
    ///     "name": "MyApp",
    ///     "version": "1",
    ///     "chainId": 1
    /// });
    /// 
    /// let types = json!({
    ///     "Person": [
    ///         {"name": "name", "type": "string"},
    ///         {"name": "age", "type": "uint256"}
    ///     ]
    /// });
    /// 
    /// let value = json!({
    ///     "name": "Alice",
    ///     "age": 30
    /// });
    /// 
    /// let signed = wallet.sign_typed_data(domain, types, value).unwrap();
    /// ```
    pub fn sign_typed_data(&self, domain: Value, types: Value, value: Value) -> Result<SignedMessage, String> {
        let typed_data = TypedData::new(domain, types, value);
        
        let hasher = Eip712Hasher;
        
        let signing_key = SigningKey::from_bytes((&self.private_key.0).into())
            .expect("Must have been validated when creating WalletManager");
        
        let signature = hasher.sign(&signing_key, &typed_data)
            .map_err(|e| format!("Failed to sign: {}", e))?;
        
        let signature_data = SignatureData::from_typed_data(typed_data);
        
        // Verify the signature matches this wallet's address
        // This should always succeed since we just signed it, but it ensures
        // SignedMessage can only be created through verification
        SignedMessage::new(signature_data, signature, &self.address())
            .map_err(|e| format!("Signature verification failed: {}", e))
    }
    pub fn sign_transaction(_tx: UnfinishedType) -> SignedTransaction {
        todo!()
    }
}
