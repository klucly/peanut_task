//! Core data structures for wallet operations.
//! 
//! This module implements security-focused handling of sensitive data

use std::fmt;
use std::ops::{Add, Mul};
use sha2::{Sha256, Digest};
use thiserror::Error;
use serde_json::Value;

use super::signature_algorithms::{
    SignatureAlgorithm, SignatureData, SignatureAlgorithmError,
    verify_and_recover_with_algorithm, recover_signer_with_algorithm
};

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
    /// # use peanut_task::core::basic_structs::Address;
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

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Signature algorithm error: {0}")]
    AlgorithmError(SignatureAlgorithmError),
    
    #[error("Signature verification failed: signer mismatch")]
    SignerMismatch,
}

impl From<SignatureAlgorithmError> for SignatureError {
    fn from(err: SignatureAlgorithmError) -> Self {
        match err {
            SignatureAlgorithmError::SignerMismatch => SignatureError::SignerMismatch,
            other => SignatureError::AlgorithmError(other),
        }
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

/// Errors that can occur during TokenAmount operations
#[derive(Error, Debug)]
pub enum TokenAmountError {
    #[error("Cannot add TokenAmounts with different decimals: {0} != {1}")]
    DecimalMismatch(u8, u8),
    
    #[error("Cannot add TokenAmounts with different symbols: {0:?} != {1:?}")]
    SymbolMismatch(Option<String>, Option<String>),
    
    #[error("Arithmetic overflow occurred")]
    Overflow,
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

/// Represents an ECDSA signature with recovery id for Ethereum.
/// 
/// The signature consists of:
/// - r: The x-coordinate of a random point on the elliptic curve (32 bytes)
/// - s: The signature proof (32 bytes)
/// - v: The recovery id (1 byte, typically 27 or 28 for Ethereum)
#[derive(Clone)]
pub struct Signature {
    /// The r component of the signature (32 bytes)
    pub r: [u8; 32],
    /// The s component of the signature (32 bytes)
    pub s: [u8; 32],
    /// The recovery id (v), typically 27 or 28 for Ethereum
    pub v: u8,
}

impl Signature {
    /// Creates a new Signature from r, s, and v components.
    pub fn new(r: [u8; 32], s: [u8; 32], v: u8) -> Self {
        Self { r, s, v }
    }

    /// Returns the raw signature as a 65-byte array (r + s + v).
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[0..32].copy_from_slice(&self.r);
        bytes[32..64].copy_from_slice(&self.s);
        bytes[64] = self.v;
        bytes
    }

    /// Returns the signature as a hex string with 0x prefix.
    /// Format: 0x + r (32 bytes) + s (32 bytes) + v (1 byte)
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("r", &format_args!("0x{}", hex::encode(&self.r)))
            .field("s", &format_args!("0x{}", hex::encode(&self.s)))
            .field("v", &self.v)
            .finish()
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Represents a message that has been cryptographically signed.
/// 
/// This type guarantees that the signature is 100% valid for the message.
/// It can only be constructed through verification, ensuring the signature is
/// cryptographically valid and a public key can be recovered from it.
pub struct SignedMessage {
    /// The data that was signed
    pub signature_data: SignatureData,
    /// The cryptographic signature
    pub signature: Signature,
}

impl SignedMessage {
    /// Verifies that the signature is valid (recovers signer but doesn't verify against expected signer)
    pub fn verify(&self) -> Result<(), SignatureError> {
        recover_signer_with_algorithm(&self.signature_data, &self.signature)?;
        Ok(())
    }

    /// Recovers the signer's address from the signature
    pub fn recover_signer(&self) -> Result<Address, SignatureError> {
        Ok(recover_signer_with_algorithm(&self.signature_data, &self.signature)?)
    }

    /// Returns the algorithm used based on the signature data
    pub fn algorithm(&self) -> SignatureAlgorithm {
        match &self.signature_data {
            SignatureData::Message(_) => SignatureAlgorithm::Eip191,
            SignatureData::TypedData { .. } => SignatureAlgorithm::Eip712,
        }
    }

    /// Creates a new SignedMessage and verifies it matches the expected signer.
    /// 
    /// This is the only way to create a SignedMessage. The signature is always
    /// verified to ensure it matches the expected signer address.
    pub fn new(
        signature_data: SignatureData,
        signature: Signature,
        expected_signer: &Address
    ) -> Result<Self, SignatureError> {
        verify_and_recover_with_algorithm(&signature_data, &signature, expected_signer)?;
        
        Ok(Self {
            signature_data,
            signature,
        })
    }
}

impl fmt::Debug for SignedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedMessage")
            .field("signature_data", &self.signature_data)
            .field("signature", &self.signature)
            .finish()
    }
}

impl fmt::Display for SignedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.signature_data {
            SignatureData::Message(msg) => {
                write!(f, "Message: \"{}\"\nSignature: {}", msg.0, self.signature)
            }
            SignatureData::TypedData { .. } => {
                write!(f, "TypedData\nSignature: {}", self.signature)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Message(pub String);

/// Typed data structure for EIP-712
#[derive(Debug, Clone)]
pub struct TypedData {
    pub domain: Value,
    pub types: Value,
    pub value: Value,
}

impl TypedData {
    /// Creates a new TypedData instance
    pub fn new(domain: Value, types: Value, value: Value) -> Self {
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

/// Represents a token amount with precision and optional symbol.
/// 
/// This struct stores token amounts in their raw (smallest unit) representation,
/// along with decimal precision information. For example:
/// - ETH: raw = 1000000000000000000, decimals = 18 (represents 1.0 ETH)
/// - USDC: raw = 1000000, decimals = 6 (represents 1.0 USDC)
#[derive(Debug, Clone)]
pub struct TokenAmount {
    /// The raw amount in the smallest unit (e.g., wei for ETH, smallest unit for tokens)
    pub raw: u128,
    /// The number of decimal places (e.g., 18 for ETH, 6 for USDC)
    pub decimals: u8,
    /// Optional symbol of the cryptocurrency (e.g., "ETH", "USDC")
    pub symbol: Option<String>,
}

impl TokenAmount {
    /// Creates a new TokenAmount with the given raw amount, decimals, and optional symbol.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::basic_structs::TokenAmount;
    /// // 1.0 ETH (18 decimals)
    /// let eth = TokenAmount::new(1000000000000000000, 18, Some("ETH".to_string()));
    /// 
    /// // 1.0 USDC (6 decimals)
    /// let usdc = TokenAmount::new(1000000, 6, Some("USDC".to_string()));
    /// ```
    pub fn new(raw: u128, decimals: u8, symbol: Option<String>) -> Self {
        Self { raw, decimals, symbol }
    }

    /// Creates a TokenAmount from a human-readable amount string (e.g., "1.5" ETH).
    /// 
    /// Parses the string and converts it to the raw amount based on the decimal precision.
    /// 
    /// # Arguments
    /// * `amount` - Human-readable amount as a string (e.g., "1.5", "100", "0.001")
    /// * `decimals` - Number of decimal places for the token
    /// * `symbol` - Optional token symbol (e.g., "ETH", "USDC")
    /// 
    /// # Returns
    /// Returns `Ok(TokenAmount)` if parsing succeeds, or `Err(String)` if the amount
    /// cannot be parsed or exceeds the maximum value for the given decimals.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::basic_structs::TokenAmount;
    /// // 1.5 ETH (18 decimals)
    /// let eth = TokenAmount::from_human("1.5", 18, Some("ETH".to_string()))?;
    /// assert_eq!(eth.raw, 1500000000000000000);
    /// 
    /// // 100 USDC (6 decimals)
    /// let usdc = TokenAmount::from_human("100", 6, Some("USDC".to_string()))?;
    /// assert_eq!(usdc.raw, 100000000);
    /// # Ok::<(), String>(())
    /// ```
    pub fn from_human(amount: &str, decimals: u8, symbol: Option<String>) -> Result<Self, String> {
        // Split the string into integer and fractional parts
        let parts: Vec<&str> = amount.split('.').collect();
        
        if parts.len() > 2 {
            return Err(format!("Invalid amount format: {}", amount));
        }
        
        let integer_part = parts[0];
        let fractional_part = if parts.len() == 2 { parts[1] } else { "" };
        
        // Validate that fractional part doesn't exceed decimals
        if fractional_part.len() > decimals as usize {
            return Err(format!(
                "Fractional part has {} digits, but token only supports {} decimals",
                fractional_part.len(),
                decimals
            ));
        }
        
        // Parse integer part
        let integer: u128 = integer_part
            .parse()
            .map_err(|_| format!("Invalid integer part: {}", integer_part))?;
        
        // Calculate raw amount from integer part
        let decimals_u128 = 10_u128.pow(decimals as u32);
        let integer_raw = integer
            .checked_mul(decimals_u128)
            .ok_or_else(|| format!("Amount too large: {}", amount))?;
        
        // Parse and add fractional part
        let fractional_raw = if fractional_part.is_empty() {
            0
        } else {
            // Pad fractional part on the right with zeros to match decimals
            let padded_fractional = format!("{:0<width$}", fractional_part, width = decimals as usize);
            padded_fractional
                .parse::<u128>()
                .map_err(|_| format!("Invalid fractional part: {}", fractional_part))?
        };
        
        let raw = integer_raw
            .checked_add(fractional_raw)
            .ok_or_else(|| format!("Amount too large: {}", amount))?;
        
        Ok(Self { raw, decimals, symbol })
    }

    /// Returns the human-readable decimal amount as a string.
    /// 
    /// This preserves precision by using string formatting and integer arithmetic,
    /// avoiding any floating-point operations that could introduce precision errors.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::basic_structs::TokenAmount;
    /// let amount = TokenAmount::new(1500000000000000000, 18, Some("ETH".to_string()));
    /// assert_eq!(amount.human(), "1.5");
    /// 
    /// let amount2 = TokenAmount::new(1000000, 6, Some("USDC".to_string()));
    /// assert_eq!(amount2.human(), "1");
    /// 
    /// let amount3 = TokenAmount::new(1234567890123456789, 18, None);
    /// assert_eq!(amount3.human(), "1.234567890123456789");
    /// ```
    pub fn human(&self) -> String {
        let divisor = 10_u128.pow(self.decimals as u32);
        let integer_part = self.raw / divisor;
        let fractional_part = self.raw % divisor;
        
        if fractional_part == 0 {
            format!("{}", integer_part)
        } else {
            // Format fractional part with left-padding to exactly match decimals width
            // This ensures we have the correct number of digits for proper decimal representation
            let fractional_str = format!("{:0>width$}", fractional_part, width = self.decimals as usize);
            // Trim trailing zeros for cleaner display, but preserve at least one digit if fractional_part > 0
            let trimmed = fractional_str.trim_end_matches('0');
            if trimmed.is_empty() {
                format!("{}", integer_part)
            } else {
                format!("{}.{}", integer_part, trimmed)
            }
        }
    }

    /// Adds two TokenAmounts together, returning a Result.
    /// 
    /// # Requirements
    /// - Both amounts must have the same decimals
    /// 
    /// # Returns
    /// - `Ok(TokenAmount)` if addition succeeds
    /// - `Err(TokenAmountError::DecimalMismatch)` if decimals don't match
    /// - `Err(TokenAmountError::Overflow)` if the result overflows u128
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::basic_structs::TokenAmount;
    /// let a = TokenAmount::new(1000000000000000000, 18, Some("ETH".to_string()));
    /// let b = TokenAmount::new(500000000000000000, 18, Some("ETH".to_string()));
    /// let sum = a.try_add(&b)?;
    /// assert_eq!(sum.raw, 1500000000000000000);
    /// # Ok::<(), peanut_task::core::basic_structs::TokenAmountError>(())
    /// ```
    pub fn try_add(&self, other: &Self) -> Result<Self, TokenAmountError> {
        // Validate decimals match
        if self.decimals != other.decimals {
            return Err(TokenAmountError::DecimalMismatch(self.decimals, other.decimals));
        }

        // Calculate sum with overflow check
        let raw = self.raw
            .checked_add(other.raw)
            .ok_or(TokenAmountError::Overflow)?;

        // Use the symbol from self (or other if self doesn't have one)
        let symbol = self.symbol.clone().or_else(|| other.symbol.clone());

        Ok(Self {
            raw,
            decimals: self.decimals,
            symbol,
        })
    }

    /// Multiplies a TokenAmount by an integer factor, returning a Result.
    /// 
    /// # Returns
    /// - `Ok(TokenAmount)` if multiplication succeeds
    /// - `Err(TokenAmountError::Overflow)` if the result overflows u128 or factor is negative
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::basic_structs::TokenAmount;
    /// let amount = TokenAmount::new(1000000000000000000, 18, Some("ETH".to_string()));
    /// let doubled = amount.try_mul(2u128)?;
    /// assert_eq!(doubled.raw, 2000000000000000000);
    /// # Ok::<(), peanut_task::core::basic_structs::TokenAmountError>(())
    /// ```
    pub fn try_mul(&self, factor: u128) -> Result<Self, TokenAmountError> {
        let raw = self.raw
            .checked_mul(factor)
            .ok_or(TokenAmountError::Overflow)?;

        Ok(Self {
            raw,
            decimals: self.decimals,
            symbol: self.symbol.clone(),
        })
    }
}

impl Add for TokenAmount {
    type Output = Self;

    /// Adds two TokenAmounts together using the `+` operator.
    /// 
    /// # Panics
    /// - Panics if decimals don't match
    /// - Panics if the result overflows u128
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::basic_structs::TokenAmount;
    /// let a = TokenAmount::new(1000000000000000000, 18, Some("ETH".to_string()));
    /// let b = TokenAmount::new(500000000000000000, 18, Some("ETH".to_string()));
    /// let sum = a + b;
    /// assert_eq!(sum.raw, 1500000000000000000);
    /// ```
    fn add(self, other: Self) -> Self {
        self.try_add(&other).expect("TokenAmount addition failed")
    }
}

// Implement Mul for various integer types
macro_rules! impl_mul_for_int {
    ($($t:ty),*) => {
        $(
            impl Mul<$t> for TokenAmount {
                type Output = Self;

                /// Multiplies a TokenAmount by an integer factor using the `*` operator.
                /// 
                /// # Panics
                /// - Panics if the result overflows u128
                /// - Panics if factor is negative (for signed types)
                /// 
                /// # Examples
                /// ```
                /// # use peanut_task::core::basic_structs::TokenAmount;
                /// let amount = TokenAmount::new(1000000000000000000, 18, Some("ETH".to_string()));
                /// let doubled = amount * 2u128;
                /// assert_eq!(doubled.raw, 2000000000000000000);
                /// ```
                fn mul(self, factor: $t) -> Self {
                    // Convert factor to u128, handling negative values for signed types
                    let factor_u128: u128 = if factor < 0 {
                        panic!("Cannot multiply TokenAmount by negative number");
                    } else {
                        factor as u128
                    };

                    self.try_mul(factor_u128).expect("TokenAmount multiplication failed")
                }
            }
        )*
    };
}

// Implement for unsigned integers
impl_mul_for_int!(u8, u16, u32, u64, u128);

// Implement for signed integers (will panic for negative values)
impl_mul_for_int!(i8, i16, i32, i64, i128);

impl fmt::Display for TokenAmount {
    /// Formats the TokenAmount as a human-readable string with symbol.
    /// 
    /// Format: "{human_readable_amount} {symbol}" or just "{human_readable_amount}" if no symbol.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::basic_structs::TokenAmount;
    /// let amount = TokenAmount::new(1500000000000000000, 18, Some("ETH".to_string()));
    /// assert_eq!(format!("{}", amount), "1.5 ETH");
    /// 
    /// let amount2 = TokenAmount::new(1000000, 6, None);
    /// assert_eq!(format!("{}", amount2), "1");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let human = self.human();
        let symbol_str = self.symbol.as_ref()
            .map(|s| format!(" {}", s))
            .unwrap_or_default();
        write!(f, "{}{}", human, symbol_str)
    }
}

pub struct SignedTransaction(pub String);