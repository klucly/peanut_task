//! Utility types and structures for wallet operations.
//! 
//! This module contains address validation and other utility types used
//! throughout the wallet system.

use std::fmt;
use thiserror::Error;
use sha3::{Digest, Keccak256};

use super::token_amount::TokenAmount;

/// Represents an Ethereum address with validation and checksumming.
#[derive(Clone)]
pub struct Address {
    /// The address value (stored in checksummed format)
    pub value: String,
}

impl Address {
    /// Creates an Address from a string, validating and converting to checksum format.
    /// 
    /// This is equivalent to the Python `from_string` class method and `__post_init__`.
    /// The address is validated and automatically converted to EIP-55 checksummed format.
    /// 
    /// # Arguments
    /// * `s` - Address string (can be any case, will be checksummed)
    /// 
    /// # Returns
    /// - `Ok(Address)` if the address is valid
    /// - `Err(AddressError)` if the address is invalid
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::utility::Address;
    /// let addr = Address::from_string("0x742d35cc6634c0532925a3b844bc9e7595f0beb0")?;
    /// // Address is automatically checksummed
    /// assert_eq!(addr.value, "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0");
    /// # Ok::<(), peanut_task::core::utility::AddressError>(())
    /// ```
    pub fn from_string(s: &str) -> Result<Self, AddressError> {
        // Validate the address format first
        Self::validate_format(s)?;
        
        // Convert to checksummed format
        let checksummed = Self::to_checksum(s);
        
        Ok(Address { value: checksummed })
    }
    
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
    fn validate_format(addr_str: &str) -> Result<(), AddressError> {
        // Check for 0x prefix
        if !addr_str.starts_with("0x") {
            return Err(AddressError::MissingPrefix(addr_str.to_string()));
        }
        
        // Check length (0x + 40 hex chars = 42 total)
        if addr_str.len() != 42 {
            return Err(AddressError::InvalidLength(addr_str.len(), addr_str.to_string()));
        }
        
        // Check that all characters after 0x are valid hex digits
        let hex_part = &addr_str[2..];
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AddressError::InvalidHexCharacters(addr_str.to_string()));
        }
        
        // Decode and verify it's exactly 20 bytes
        let addr_bytes = hex::decode(hex_part)
            .map_err(|e| AddressError::HexDecodeError(e.to_string()))?;
        
        if addr_bytes.len() != 20 {
            return Err(AddressError::InvalidByteLength(addr_bytes.len()));
        }
        
        Ok(())
    }
    
    /// Converts an address to EIP-55 checksummed format.
    /// 
    /// EIP-55 checksumming works by:
    /// 1. Taking the lowercase address
    /// 2. Computing Keccak-256 hash of the lowercase address (without 0x)
    /// 3. For each character in the address (after 0x), if the corresponding hash nibble is >= 8, uppercase that character
    fn to_checksum(addr: &str) -> String {
        // Convert to lowercase for hashing
        let lower = addr.to_lowercase();
        let hex_part = &lower[2..]; // Skip "0x"
        
        // Hash the lowercase address (without 0x) with Keccak-256
        let mut hasher = Keccak256::new();
        hasher.update(hex_part.as_bytes());
        let hash = hasher.finalize();
        
        // Build checksummed address
        let mut result = String::with_capacity(42);
        result.push_str("0x");
        
        for (i, ch) in hex_part.chars().enumerate() {
            let hash_byte = hash[i / 2];
            let hash_nibble = if i % 2 == 0 {
                hash_byte >> 4
            } else {
                hash_byte & 0x0f
            };
            
            // If hash nibble >= 8, uppercase the character
            if hash_nibble >= 8 && ch.is_ascii_alphabetic() {
                result.push(ch.to_ascii_uppercase());
            } else {
                result.push(ch);
            }
        }
        
        result
    }
    
    /// Returns the checksummed address (EIP-55 format).
    /// 
    /// This is equivalent to the Python `checksum` property.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::utility::Address;
    /// let addr = Address::from_string("0x742d35cc6634c0532925a3b844bc9e7595f0beb0")?;
    /// assert_eq!(addr.checksum(), "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0");
    /// # Ok::<(), peanut_task::core::utility::AddressError>(())
    /// ```
    pub fn checksum(&self) -> &str {
        &self.value
    }
    
    /// Returns the lowercase address.
    /// 
    /// This is equivalent to the Python `lower` property.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::utility::Address;
    /// let addr = Address::from_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0")?;
    /// assert_eq!(addr.lower(), "0x742d35cc6634c0532925a3b844bc9e7595f0beb0");
    /// # Ok::<(), peanut_task::core::utility::AddressError>(())
    /// ```
    pub fn lower(&self) -> String {
        self.value.to_lowercase()
    }
    
    /// Validates that the address has the correct Ethereum address format.
    /// 
    /// This is a convenience method that validates the stored address value.
    /// 
    /// # Returns
    /// - `Ok(())` if the address is valid
    /// - `Err(AddressError)` if the address is invalid
    pub fn validate(&self) -> Result<(), AddressError> {
        Self::validate_format(&self.value)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address(\"{}\")", self.value)
    }
}

impl PartialEq for Address {
    /// Compares addresses case-insensitively, as Ethereum addresses are case-insensitive.
    /// 
    /// This is equivalent to the Python `__eq__` method.
    fn eq(&self, other: &Self) -> bool {
        self.value.to_lowercase() == other.value.to_lowercase()
    }
}

impl Eq for Address {}

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
    /// Recipient address
    pub to: Address,
    /// Value to transfer
    pub value: TokenAmount,
    /// Transaction data (contract call data or init code)
    pub data: Vec<u8>,
    /// Transaction nonce (optional)
    pub nonce: Option<u64>,
    /// Gas limit (optional)
    pub gas_limit: Option<u64>,
    /// Maximum fee per gas (EIP-1559, optional)
    pub max_fee_per_gas: Option<u64>,
    /// Maximum priority fee per gas (EIP-1559, optional)
    pub max_priority_fee: Option<u64>,
    /// Chain ID for replay protection (defaults to 1)
    pub chain_id: u64,
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            to: Address::from_string("0x0000000000000000000000000000000000000000")
                .expect("Zero address should always be valid"),
            value: TokenAmount::new(0, 18, Some("ETH".to_string())),
            data: vec![],
            nonce: None,
            gas_limit: None,
            max_fee_per_gas: None,
            max_priority_fee: None,
            chain_id: 1,
        }
    }
}

impl Transaction {
    /// Convert to web3-compatible dict (serde_json::Value).
    /// 
    /// Returns a JSON object compatible with web3.py transaction format.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::utility::{Transaction, Address};
    /// # use peanut_task::core::token_amount::TokenAmount;
    /// let tx = Transaction {
    ///     to: Address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0".to_string()),
    ///     value: TokenAmount::new(1000000000000000000, 18, Some("ETH".to_string())),
    ///     data: vec![0x12, 0x34],
    ///     nonce: Some(0),
    ///     gas_limit: Some(21000),
    ///     max_fee_per_gas: Some(20000000000),
    ///     max_priority_fee: Some(1000000000),
    ///     chain_id: 1,
    /// };
    /// let dict = tx.to_dict();
    /// ```
    pub fn to_dict(&self) -> serde_json::Value {
        use serde_json::json;
        
        let mut dict = json!({
            "to": self.to.value,
            "value": format!("0x{:x}", self.value.raw),
            "data": format!("0x{}", hex::encode(&self.data)),
            "chainId": self.chain_id,
        });
        
        if let Some(nonce) = self.nonce {
            dict["nonce"] = json!(format!("0x{:x}", nonce));
        }
        
        if let Some(gas_limit) = self.gas_limit {
            dict["gas"] = json!(format!("0x{:x}", gas_limit));
        }
        
        if let Some(max_fee_per_gas) = self.max_fee_per_gas {
            dict["maxFeePerGas"] = json!(format!("0x{:x}", max_fee_per_gas));
        }
        
        if let Some(max_priority_fee) = self.max_priority_fee {
            dict["maxPriorityFeePerGas"] = json!(format!("0x{:x}", max_priority_fee));
        }
        
        dict
    }
}

/// Represents a signed transaction.
pub struct SignedTransaction(pub String);
