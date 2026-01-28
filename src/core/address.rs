use std::fmt;
use thiserror::Error;
use sha3::{Digest, Keccak256};
use alloy::primitives::Address as AlloyAddress;
use hex;

#[derive(Clone)]
pub struct Address {
    pub value: String,
}

impl Address {
    pub fn zero() -> Self {
        Self::from_string("0x0000000000000000000000000000000000000000")
            .expect("Zero address should always be valid")
    }

    pub fn from_string(s: &str) -> Result<Self, AddressError> {
        Self::validate_format(s)?;
        let checksummed = Self::to_checksum(s);
        Ok(Address { value: checksummed })
    }

    fn validate_format(addr_str: &str) -> Result<(), AddressError> {
        if !addr_str.starts_with("0x") {
            return Err(AddressError::MissingPrefix(addr_str.to_string()));
        }
        if addr_str.len() != 42 {
            return Err(AddressError::InvalidLength(addr_str.len(), addr_str.to_string()));
        }
        let hex_part = &addr_str[2..];
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AddressError::InvalidHexCharacters(addr_str.to_string()));
        }
        let addr_bytes = hex::decode(hex_part)
            .map_err(|e| AddressError::HexDecodeError(e.to_string()))?;
        if addr_bytes.len() != 20 {
            return Err(AddressError::InvalidByteLength(addr_bytes.len()));
        }
        addr_str.parse::<AlloyAddress>()
            .map_err(|e| AddressError::AlloyParseError(addr_str.to_string(), e.to_string()))?;

        Ok(())
    }

    fn to_checksum(addr: &str) -> String {
        let lower = addr.to_lowercase();
        let hex_part = &lower[2..];
        let mut hasher = Keccak256::new();

        hasher.update(hex_part.as_bytes());
        let hash = hasher.finalize();
        let mut result = String::with_capacity(42);

        result.push_str("0x");
        for (i, ch) in hex_part.chars().enumerate() {
            let hash_byte = hash[i / 2];
            let hash_nibble = if i % 2 == 0 { hash_byte >> 4 } else { hash_byte & 0x0f };
            if hash_nibble >= 8 && ch.is_ascii_alphabetic() {
                result.push(ch.to_ascii_uppercase());
            } else {
                result.push(ch);
            }
        }

        result
    }

    pub fn checksum(&self) -> &str {
        &self.value
    }

    pub fn lower(&self) -> String {
        self.value.to_lowercase()
    }

    pub fn validate(&self) -> Result<(), AddressError> {
        Self::validate_format(&self.value)
    }

    pub fn alloy_address(&self) -> AlloyAddress {
        self.value
            .parse::<AlloyAddress>()
            .expect("Address validated at construction, parse should never fail")
    }

    pub fn to_string(&self) -> String {
        self.value.clone()
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
    fn eq(&self, other: &Self) -> bool {
        self.value.to_lowercase() == other.value.to_lowercase()
    }
}

impl Eq for Address {}

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

    #[error("Address cannot be parsed as AlloyAddress: {0} (error: {1})")]
    AlloyParseError(String, String),
}
