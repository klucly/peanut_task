//! Utility types and structures for wallet operations.
//! 
//! This module contains address validation, private key handling, and other
//! utility types used throughout the wallet system.

use std::fmt;
use sha2::{Sha256, Digest};
use thiserror::Error;

/// Represents an Ethereum address with validation.
#[derive(Clone)]
pub struct Address(pub String);

impl Address {
    /// Validates that the address has the correct Ethereum address format.
    /// 
    /// A valid address must:
    /// - Start with "0x" prefix
    /// - Be exactly 42 characters long (0x + 40 hex characters)
    /// - Contain only valid hexadecimal characters after the prefix
    /// - Decode to exactly 20 bytes
    /// 
    /// # Returns
    /// - `Ok(())` if the address is valid
    /// - `Err(AddressError)` if the address is invalid
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::utility::Address;
    /// let addr = Address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0".to_string());
    /// assert!(addr.validate().is_ok());
    /// ```
    pub fn validate(&self) -> Result<(), AddressError> {
        let addr_str = &self.0;
        
        // Check for 0x prefix
        if !addr_str.starts_with("0x") {
            return Err(AddressError::MissingPrefix(addr_str.clone()));
        }
        
        // Check length (0x + 40 hex chars = 42 total)
        if addr_str.len() != 42 {
            return Err(AddressError::InvalidLength(addr_str.len(), addr_str.clone()));
        }
        
        // Check that all characters after 0x are valid hex digits
        let hex_part = &addr_str[2..];
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AddressError::InvalidHexCharacters(addr_str.clone()));
        }
        
        // Decode and verify it's exactly 20 bytes
        let addr_bytes = hex::decode(hex_part)
            .map_err(|e| AddressError::HexDecodeError(e.to_string()))?;
        
        if addr_bytes.len() != 20 {
            return Err(AddressError::InvalidByteLength(addr_bytes.len()));
        }
        
        Ok(())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address(\"{}\")", self.0)
    }
}

/// Errors that can occur during address validation
#[derive(Error, Debug)]
pub enum AddressError {
    #[error("Address must start with '0x', got: {0}")]
    MissingPrefix(String),
    
    #[error("Address must be 42 characters (0x + 40 hex chars), got {0} characters: {1}")]
    InvalidLength(usize, String),
    
    #[error("Address contains invalid hex characters: {0}")]
    InvalidHexCharacters(String),
    
    #[error("Failed to decode address hex: {0}")]
    HexDecodeError(String),
    
    #[error("Address must decode to exactly 20 bytes, got {0} bytes")]
    InvalidByteLength(usize),
}

/// Trait for types that contain sensitive data and should be hashed for display
pub trait SecureHashable {
    /// Returns the bytes to be hashed for secure display
    fn as_bytes(&self) -> &[u8];
    
    /// Returns the name to use in Debug output
    fn debug_name(&self) -> &'static str {
        "SecureHashable"
    }
    
    /// Computes a SHA-256 hash of the sensitive data
    fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.as_bytes());
        let hash = hasher.finalize();
        format!("{:x}", hash)
    }
    
    /// Returns a shortened hash for display purposes (first 16 hex chars)
    fn short_hash(&self) -> String {
        let hash = self.compute_hash();
        hash[..16].to_string()
    }
    
    /// Formats this value for Debug output
    /// This provides a default Debug implementation for types implementing SecureHashable
    fn fmt_debug(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple(self.debug_name())
            .field(&format_args!("Hash({}...)", self.short_hash()))
            .finish()
    }
}

/// Wrapper around a 32-byte private key that prevents accidental exposure.
/// 
/// The Debug implementation shows only a truncated hash instead of the actual key bytes,
/// protecting against accidental logging of sensitive material.
pub struct PrivateKey(pub [u8; 32]);

impl SecureHashable for PrivateKey {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    
    fn debug_name(&self) -> &'static str {
        "PrivateKey"
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_debug(f)
    }
}

/// Represents a message to be signed.
#[derive(Debug, Clone)]
pub struct Message(pub String);

/// Typed data structure for EIP-712
#[derive(Debug, Clone)]
pub struct TypedData {
    pub domain: serde_json::Value,
    pub types: serde_json::Value,
    pub value: serde_json::Value,
}

impl TypedData {
    /// Creates a new TypedData instance
    pub fn new(domain: serde_json::Value, types: serde_json::Value, value: serde_json::Value) -> Self {
        Self { domain, types, value }
    }
}

/// Represents an Ethereum transaction to be signed.
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Transaction nonce
    pub nonce: u64,
    /// Gas price in wei
    pub gas_price: u64,
    /// Gas limit
    pub gas_limit: u64,
    /// Recipient address (None for contract creation)
    pub to: Option<Address>,
    /// Value to transfer in wei
    pub value: u64,
    /// Transaction data (contract call data or init code)
    pub data: Vec<u8>,
    /// Chain ID for replay protection
    pub chain_id: u64,
}

/// Represents a signed transaction.
pub struct SignedTransaction(pub String);
