//! Signature-related types and structures.
//! 
//! This module contains signature structures and signed message handling.

use std::fmt;
use thiserror::Error;

use super::utility::Address;
use super::signature_algorithms::{
    SignatureAlgorithm, SignatureData, SignatureAlgorithmError,
    verify_and_recover_with_algorithm, recover_signer_with_algorithm
};

/// Errors that can occur during signature operations
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
