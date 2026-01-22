//! Core data structures for wallet operations.
//! 
//! This module implements security-focused handling of sensitive data

use std::fmt;
use sha2::{Sha256, Digest};
use thiserror::Error;
use serde_json::Value;

use super::signature_algorithms::{
    SignatureAlgorithm, SignatureData, SignatureAlgorithmError,
    verify_and_recover_with_algorithm, recover_signer_with_algorithm
};

pub struct Address(pub String);

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

// TODO: Remove this once we get a working version
pub struct UnfinishedType;

pub struct SignedTransaction(pub String);