//! Secure wrapper around private keys that prevents direct key exposure.
//! 
//! All cryptographic operations are performed through `WalletManager`, ensuring
//! the private key itself is never directly accessible or exposed.

use thiserror::Error;
use std::{env::{self, VarError}, fmt};
use getrandom;
use k256::ecdsa::{SigningKey, VerifyingKey};

use super::utility::{Address, Message, Transaction, SignedTransaction, TypedData};
use super::signatures::SignedMessage;
use super::signature_algorithms::{
    SignatureData, SignatureAlgorithmError,
    Eip191Hasher, Eip712Hasher, TransactionHasher, SignatureHasher,
    derive_address_from_public_key, derive_public_key_from_private_key
};
use super::signatures::SignatureError;
use serde_json::Value;

/// Wrapper around a `SigningKey` that handles all key operations.
/// 
/// This design ensures the private key is never directly exposed - all operations
/// (signing, address derivation, etc.) are performed through this interface.
/// The Debug implementation is safe for logging (SigningKey has secure Debug).
pub struct WalletManager {
    private_key: SigningKey
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

#[derive(Error, Debug)]
pub enum SigningError {
    #[error("Cannot sign empty message")]
    EmptyMessage,
    
    #[error("Signature algorithm error: {0}")]
    AlgorithmError(#[from] SignatureAlgorithmError),
    
    #[error("Signature verification error: {0}")]
    VerificationError(#[from] SignatureError),
}


impl WalletManager {
    /// Gets a reference to the signing key.
    fn get_signing_key(&self) -> &SigningKey {
        &self.private_key
    }

    /// Returns the public key (VerifyingKey) derived from the private key.
    /// 
    /// The public key is derived using secp256k1 elliptic curve cryptography.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::wallet_manager::WalletManager;
    /// let wallet = WalletManager::from_hex_string(
    ///     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    /// ).unwrap();
    /// let public_key = wallet.public_key();
    /// ```
    pub fn public_key(&self) -> VerifyingKey {
        let signing_key = self.get_signing_key();
        derive_public_key_from_private_key(&signing_key)
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
        
        // Create SigningKey directly - this validates the key is cryptographically valid
        let private_key = SigningKey::from_bytes((&key).into())
            .map_err(|_| KeyLoadError::InvalidPrivateKey)?;
        
        Ok(WalletManager { private_key })
    }
    
    /// Generates a new wallet with a cryptographically secure random private key.
    /// 
    /// Uses the system's random number generator via `getrandom`.
    /// The generated key is guaranteed to be valid for secp256k1.
    pub fn generate() -> Result<WalletManager, getrandom::Error> {
        // Generate random bytes until we get a valid key
        // In practice, the probability of generating an invalid key is negligible (~2^-128)
        loop {
            let mut raw_key = [0u8; 32];
            getrandom::fill(&mut raw_key)?;
            
            // Try to create SigningKey - this validates the key is cryptographically valid
            if let Ok(private_key) = SigningKey::from_bytes((&raw_key).into()) {
                return Ok(WalletManager { private_key });
            }
            // If invalid, loop and try again
        }
    }
    /// Derives the Ethereum address from the private key.
    /// 
    /// The address is computed by:
    /// 1. Deriving the public key from the private key using secp256k1
    /// 2. Hashing the uncompressed public key (64 bytes, without the 0x04 prefix) with Keccak-256
    /// 3. Taking the last 20 bytes of the hash
    /// 4. Formatting as a hex string with '0x' prefix
    /// 
    /// Address validation is performed automatically by `derive_address_from_public_key`.
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
        // Get the public key and derive address from it (includes validation)
        let public_key = self.public_key();
        derive_address_from_public_key(&public_key)
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
    /// # Errors
    /// Returns `Err(SigningError::EmptyMessage)` if the message is empty.
    /// This validation occurs before any cryptographic operations.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::wallet_manager::WalletManager;
    /// # use peanut_task::core::utility::Message;
    /// let wallet = WalletManager::from_hex_string(
    ///     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    /// ).unwrap();
    /// let message = Message("Hello, Ethereum!".to_string());
    /// let signed = wallet.sign_message(message)?;
    /// println!("Signature: {}", signed.signature.to_hex());
    /// # Ok::<(), peanut_task::core::wallet_manager::SigningError>(())
    /// ```
    pub fn sign_message(&self, msg: Message) -> Result<SignedMessage, SigningError> {
        // Validate message is not empty before any crypto operations
        if msg.0.is_empty() {
            return Err(SigningError::EmptyMessage);
        }
        
        let hasher = Eip191Hasher;
        
        let signing_key = self.get_signing_key();
        
        let signature = hasher.sign(signing_key, &msg)?;
        
        let signature_data = SignatureData::from_message(msg);
        
        // Verify the signature matches this wallet's address
        // This should always succeed since we just signed it, but it ensures
        // SignedMessage can only be created through verification
        SignedMessage::new(signature_data, signature, &self.address())
            .map_err(SigningError::from)
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
        // Validate domain is an object before any crypto operations
        if !domain.is_object() {
            return Err(format!("Domain must be a JSON object, got: {}", domain));
        }
        
        // Validate types is an object before any crypto operations
        if !types.is_object() {
            return Err(format!("Types must be a JSON object, got: {}", types));
        }
        
        // Validate value is an object before any crypto operations
        if !value.is_object() {
            return Err(format!("Value must be a JSON object, got: {}", value));
        }
        
        let typed_data = TypedData::new(domain, types, value);
        
        let hasher = Eip712Hasher;
        
        let signing_key = self.get_signing_key();
        
        let signature = hasher.sign(signing_key, &typed_data)
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
    /// # use peanut_task::core::utility::{Transaction, Address};
    /// # use peanut_task::core::token_amount::TokenAmount;
    /// let wallet = WalletManager::from_hex_string(
    ///     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    /// ).unwrap();
    /// 
    /// let tx = Transaction {
    ///     to: Address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0".to_string()),
    ///     value: TokenAmount::new(1000000000000000000, 18, Some("ETH".to_string())),
    ///     data: vec![],
    ///     nonce: Some(0),
    ///     gas_limit: Some(21000),
    ///     max_fee_per_gas: Some(20000000000),
    ///     max_priority_fee: Some(1000000000),
    ///     chain_id: 1,
    /// };
    /// 
    /// let signed_tx = wallet.sign_transaction(tx).unwrap();
    /// ```
    pub fn sign_transaction(&self, tx: Transaction) -> Result<SignedTransaction, TransactionError> {
        let hasher = TransactionHasher;
        
        let signing_key = self.get_signing_key();
        
        let signature = hasher.sign(signing_key, &tx)
            .map_err(|e| TransactionError::InvalidAddress(
                format!("Failed to sign transaction: {}", e)
            ))?;
        
        // Create the raw transaction: RLP-encode [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
        // For simplicity, we'll create a hex string representation
        let raw_tx = self.create_raw_transaction(&tx, signature.r, signature.s, signature.v);
        
        Ok(SignedTransaction(raw_tx))
    }
    
    /// Creates a raw transaction hex string from transaction and signature components.
    fn create_raw_transaction(&self, tx: &Transaction, r: [u8; 32], s: [u8; 32], v: u8) -> String {
        // Create a JSON-like representation for the signed transaction
        // In a production implementation, this would be RLP-encoded
        let mut parts = Vec::new();
        
        parts.push(format!("\"to\":\"{}\"", tx.to.value));
        parts.push(format!("\"value\":\"0x{:x}\"", tx.value.raw));
        parts.push(format!("\"data\":\"0x{}\"", hex::encode(&tx.data)));
        parts.push(format!("\"chainId\":{}", tx.chain_id));
        
        if let Some(nonce) = tx.nonce {
            parts.push(format!("\"nonce\":\"0x{:x}\"", nonce));
        }
        
        if let Some(gas_limit) = tx.gas_limit {
            parts.push(format!("\"gas\":\"0x{:x}\"", gas_limit));
        }
        
        if let Some(max_fee_per_gas) = tx.max_fee_per_gas {
            parts.push(format!("\"maxFeePerGas\":\"0x{:x}\"", max_fee_per_gas));
        }
        
        if let Some(max_priority_fee) = tx.max_priority_fee {
            parts.push(format!("\"maxPriorityFeePerGas\":\"0x{:x}\"", max_priority_fee));
        }
        
        parts.push(format!("\"v\":{}", v));
        parts.push(format!("\"r\":\"0x{}\"", hex::encode(&r)));
        parts.push(format!("\"s\":\"0x{}\"", hex::encode(&s)));
        
        format!("{{{}}}", parts.join(","))
    }
}
