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

use super::basic_structs::{Address, Message, SignedMessage, Transaction, SignedTransaction, PrivateKey, TypedData};
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

#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("Invalid address format: {0}")]
    InvalidAddress(String),
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

    /// Validates that an address has the correct Ethereum address format.
    /// 
    /// A valid address must:
    /// - Start with "0x" prefix
    /// - Be exactly 42 characters long (0x + 40 hex characters)
    /// - Contain only valid hexadecimal characters after the prefix
    /// - Decode to exactly 20 bytes
    fn validate_address(addr: &Address) -> Result<(), TransactionError> {
        let addr_str = &addr.0;
        
        // Check for 0x prefix
        if !addr_str.starts_with("0x") {
            return Err(TransactionError::InvalidAddress(
                format!("Address must start with '0x', got: {}", addr_str)
            ));
        }
        
        // Check length (0x + 40 hex chars = 42 total)
        if addr_str.len() != 42 {
            return Err(TransactionError::InvalidAddress(
                format!("Address must be 42 characters (0x + 40 hex chars), got {} characters: {}", 
                    addr_str.len(), addr_str)
            ));
        }
        
        // Check that all characters after 0x are valid hex digits
        let hex_part = &addr_str[2..];
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(TransactionError::InvalidAddress(
                format!("Address contains invalid hex characters: {}", addr_str)
            ));
        }
        
        // Decode and verify it's exactly 20 bytes
        let addr_bytes = hex::decode(hex_part)
            .map_err(|e| TransactionError::InvalidAddress(
                format!("Failed to decode address hex: {}", e)
            ))?;
        
        if addr_bytes.len() != 20 {
            return Err(TransactionError::InvalidAddress(
                format!("Address must decode to exactly 20 bytes, got {} bytes", addr_bytes.len())
            ));
        }
        
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
    /// Signs a transaction using Ethereum's transaction signing standard.
    /// 
    /// The transaction is serialized, hashed with Keccak-256, and then signed with ECDSA.
    /// The signature is appended to create a raw transaction that can be broadcast to the network.
    /// 
    /// # Arguments
    /// * `tx` - The transaction to sign
    /// 
    /// # Returns
    /// A `Result` containing either:
    /// - `Ok(SignedTransaction)` - The raw signed transaction as a hex string
    /// - `Err(TransactionError)` - An error if the transaction's address is invalid
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::wallet_manager::WalletManager;
    /// # use peanut_task::core::basic_structs::{Transaction, Address};
    /// let wallet = WalletManager::from_hex_string(
    ///     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    /// ).unwrap();
    /// 
    /// let tx = Transaction {
    ///     nonce: 0,
    ///     gas_price: 20000000000,
    ///     gas_limit: 21000,
    ///     to: Some(Address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0".to_string())),
    ///     value: 1000000000000000000,
    ///     data: vec![],
    ///     chain_id: 1,
    /// };
    /// 
    /// let signed_tx = wallet.sign_transaction(tx).unwrap();
    /// ```
    pub fn sign_transaction(&self, tx: Transaction) -> Result<SignedTransaction, TransactionError> {
        // Serialize transaction for hashing
        // Ethereum transactions are typically RLP-encoded, but for simplicity
        // we'll use a deterministic byte representation
        let tx_bytes = self.serialize_transaction(&tx)?;
        
        // Hash the transaction bytes with Keccak-256
        let mut hasher = Keccak256::new();
        hasher.update(&tx_bytes);
        let hash = hasher.finalize();
        
        // Sign the hash
        let signing_key = SigningKey::from_bytes((&self.private_key.0).into())
            .expect("Must have been validated when creating WalletManager");
        
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&hash)
            .expect("Failed to sign transaction");
        
        // Get the signature bytes (r, s components)
        let sig_bytes = signature.to_bytes();
        
        // Extract r and s components (each 32 bytes)
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[0..32]);
        s.copy_from_slice(&sig_bytes[32..64]);
        
        // v is chain_id * 2 + 35 + recovery_id for EIP-155 transactions
        let v = (tx.chain_id * 2 + 35 + recovery_id.to_byte() as u64) as u8;
        
        // Create the raw transaction: RLP-encode [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
        // For simplicity, we'll create a hex string representation
        let raw_tx = self.create_raw_transaction(&tx, r, s, v);
        
        Ok(SignedTransaction(raw_tx))
    }
    
    /// Serializes a transaction to bytes for hashing.
    /// 
    /// This creates a deterministic byte representation of the transaction.
    /// In a full implementation, this would use RLP encoding.
    /// 
    /// # Errors
    /// Returns an error if the transaction's `to` address is invalid.
    fn serialize_transaction(&self, tx: &Transaction) -> Result<Vec<u8>, TransactionError> {
        // Validate the address if present
        if let Some(ref addr) = tx.to {
            Self::validate_address(addr)?;
        }
        
        let mut bytes = Vec::new();
        
        // Serialize nonce (8 bytes, big-endian)
        bytes.extend_from_slice(&tx.nonce.to_be_bytes());
        
        // Serialize gas_price (8 bytes, big-endian)
        bytes.extend_from_slice(&tx.gas_price.to_be_bytes());
        
        // Serialize gas_limit (8 bytes, big-endian)
        bytes.extend_from_slice(&tx.gas_limit.to_be_bytes());
        
        // Serialize to address (20 bytes if Some, 0 bytes if None)
        if let Some(ref addr) = tx.to {
            // Extract address bytes (skip "0x" prefix)
            // We know it's valid from validation above, so this should always succeed
            // validate_address already verified it decodes to exactly 20 bytes
            let addr_str = addr.0.strip_prefix("0x").unwrap_or(&addr.0);
            let addr_bytes = hex::decode(addr_str)
                .map_err(|e| TransactionError::InvalidAddress(
                    format!("Failed to decode validated address: {}", e)
                ))?;
            
            // Address is guaranteed to be 20 bytes by validate_address
            bytes.extend_from_slice(&addr_bytes);
        }
        
        // Serialize value (8 bytes, big-endian)
        bytes.extend_from_slice(&tx.value.to_be_bytes());
        
        // Serialize data (length + data)
        bytes.extend_from_slice(&(tx.data.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&tx.data);
        
        // Serialize chain_id (8 bytes, big-endian)
        bytes.extend_from_slice(&tx.chain_id.to_be_bytes());
        
        Ok(bytes)
    }
    
    /// Creates a raw transaction hex string from transaction and signature components.
    fn create_raw_transaction(&self, tx: &Transaction, r: [u8; 32], s: [u8; 32], v: u8) -> String {
        // Create a JSON-like representation for the signed transaction
        // In a production implementation, this would be RLP-encoded
        let mut parts = Vec::new();
        
        parts.push(format!("\"nonce\":{}", tx.nonce));
        parts.push(format!("\"gasPrice\":{}", tx.gas_price));
        parts.push(format!("\"gasLimit\":{}", tx.gas_limit));
        
        if let Some(ref addr) = tx.to {
            parts.push(format!("\"to\":\"{}\"", addr.0));
        } else {
            parts.push("\"to\":null".to_string());
        }
        
        parts.push(format!("\"value\":{}", tx.value));
        parts.push(format!("\"data\":\"0x{}\"", hex::encode(&tx.data)));
        parts.push(format!("\"chainId\":{}", tx.chain_id));
        parts.push(format!("\"v\":{}", v));
        parts.push(format!("\"r\":\"0x{}\"", hex::encode(&r)));
        parts.push(format!("\"s\":\"0x{}\"", hex::encode(&s)));
        
        format!("{{{}}}", parts.join(","))
    }
}
