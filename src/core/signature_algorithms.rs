//! Signature algorithm implementations for different Ethereum signing standards.
//!
//! This module provides a unified interface for different signature algorithms
//! (EIP-191, EIP-712) used in Ethereum for signing messages and typed data.

use sha3::{Digest, Keccak256};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey};
use thiserror::Error;
use serde_json::Value;

use super::basic_structs::{Address, Signature, Message};
use super::serializer::Serializer;

/// Errors that can occur during signature operations
#[derive(Error, Debug)]
pub enum SignatureAlgorithmError {
    #[error("Invalid recovery id: expected 27 or 28, got {0}")]
    InvalidRecoveryId(u8),
    
    #[error("Failed to recover public key from signature")]
    RecoveryFailed,
    
    #[error("Invalid signature format")]
    InvalidSignature,
    
    #[error("Failed to hash data: {0}")]
    HashError(String),
    
    #[error("Failed to sign: {0}")]
    SigningError(String),
    
    #[error("Signature verification failed: signer mismatch")]
    SignerMismatch,
}

/// Enum representing different signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// EIP-191: Personal message signing standard
    /// Uses prefix: "\x19Ethereum Signed Message:\n" + message_length
    Eip191,
    
    /// EIP-712: Typed structured data hashing and signing
    /// Uses prefix: "\x19\x01" + domain_separator_hash + struct_hash
    Eip712,
}

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

/// Trait for signature algorithm implementations with compile-time type safety
pub trait SignatureHasher {
    /// The type of data this hasher accepts
    type Data;
    
    /// Computes the hash that should be signed for the given data
    fn compute_hash(&self, data: &Self::Data) -> Result<[u8; 32], SignatureAlgorithmError>;
    
    /// Signs the data using the provided signing key
    fn sign(&self, signing_key: &SigningKey, data: &Self::Data) -> Result<Signature, SignatureAlgorithmError> {
        // Compute the hash
        let hash = self.compute_hash(data)?;
        
        // Sign with recovery id
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&hash)
            .map_err(|e| SignatureAlgorithmError::SigningError(e.to_string()))?;
        
        // Get the signature bytes (r, s components)
        let sig_bytes = signature.to_bytes();
        
        // Extract r and s components (each 32 bytes)
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[0..32]);
        s.copy_from_slice(&sig_bytes[32..64]);
        
        // v is 27 + recovery_id for Ethereum compatibility
        let v = 27 + recovery_id.to_byte();
        
        Ok(Signature::new(r, s, v))
    }
    
    /// Verifies the signature and recovers the signer's address
    fn verify_and_recover(&self, data: &Self::Data, signature: &Signature) -> Result<Address, SignatureAlgorithmError> {
        // Validate recovery id
        if signature.v != 27 && signature.v != 28 {
            return Err(SignatureAlgorithmError::InvalidRecoveryId(signature.v));
        }

        // Compute the message hash
        let message_hash = self.compute_hash(data)?;

        // Convert v to recovery id (v - 27 gives us 0 or 1)
        let recovery_id = RecoveryId::from_byte(signature.v - 27)
            .ok_or(SignatureAlgorithmError::InvalidRecoveryId(signature.v))?;

        // Construct the signature bytes (r + s)
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0..32].copy_from_slice(&signature.r);
        sig_bytes[32..64].copy_from_slice(&signature.s);

        // Parse the signature
        let k256_sig = K256Signature::from_bytes((&sig_bytes).into())
            .map_err(|_| SignatureAlgorithmError::InvalidSignature)?;

        // Recover the public key from the signature and message hash
        let verifying_key = VerifyingKey::recover_from_prehash(&message_hash, &k256_sig, recovery_id)
            .map_err(|_| SignatureAlgorithmError::RecoveryFailed)?;

        // Derive the Ethereum address from the recovered public key
        Ok(derive_address_from_public_key(&verifying_key))
    }
}

/// Data to be signed - can be either a simple message or typed data
#[derive(Debug, Clone)]
pub enum SignatureData {
    /// Message for EIP-191
    Message(Message),
    
    /// Typed data for EIP-712
    TypedData {
        domain: Value,
        types: Value,
        value: Value,
    },
}

impl SignatureData {
    /// Creates SignatureData from a Message
    pub fn from_message(message: Message) -> Self {
        Self::Message(message)
    }
    
    /// Creates SignatureData from typed data
    pub fn from_typed_data(typed_data: TypedData) -> Self {
        Self::TypedData {
            domain: typed_data.domain,
            types: typed_data.types,
            value: typed_data.value,
        }
    }
    
    /// Returns a reference to the Message if this is a Message variant
    pub fn as_message(&self) -> Option<&Message> {
        match self {
            Self::Message(msg) => Some(msg),
            _ => None,
        }
    }
    
    /// Returns a reference to the typed data if this is a TypedData variant
    pub fn as_typed_data(&self) -> Option<TypedData> {
        match self {
            Self::TypedData { domain, types, value } => Some(TypedData {
                domain: domain.clone(),
                types: types.clone(),
                value: value.clone(),
            }),
            _ => None,
        }
    }
}

/// EIP-191 implementation - uses Message
pub struct Eip191Hasher;

impl SignatureHasher for Eip191Hasher {
    type Data = Message;
    
    fn compute_hash(&self, message: &Message) -> Result<[u8; 32], SignatureAlgorithmError> {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.0.len());
        
        let mut eth_message = prefix.into_bytes();
        eth_message.extend_from_slice(message.0.as_bytes());
        
        let mut hasher = Keccak256::new();
        hasher.update(&eth_message);
        let hash = hasher.finalize();
        
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash);
        Ok(hash_array)
    }
}

/// EIP-712 implementation - uses TypedData
pub struct Eip712Hasher;

impl SignatureHasher for Eip712Hasher {
    type Data = TypedData;
    
    fn compute_hash(&self, data: &TypedData) -> Result<[u8; 32], SignatureAlgorithmError> {
        // No runtime check needed - compiler guarantees data is TypedData!
        
        // Hash each component using canonical serialization
        let domain_hash = Serializer::hash(&data.domain)
            .map_err(|e| SignatureAlgorithmError::HashError(format!("Failed to hash domain: {}", e)))?;
        
        let types_hash = Serializer::hash(&data.types)
            .map_err(|e| SignatureAlgorithmError::HashError(format!("Failed to hash types: {}", e)))?;
        
        let value_hash = Serializer::hash(&data.value)
            .map_err(|e| SignatureAlgorithmError::HashError(format!("Failed to hash value: {}", e)))?;
        
        // Construct the EIP-712 message hash
        // Format: keccak256("\x19\x01" + domainHash + messageHash)
        // where messageHash combines types and value
        let mut eip712_message = Vec::new();
        eip712_message.extend_from_slice(b"\x19\x01");
        eip712_message.extend_from_slice(&domain_hash);
        
        // For the message hash, we combine types and value
        let mut message_data = Vec::new();
        message_data.extend_from_slice(&types_hash);
        message_data.extend_from_slice(&value_hash);
        
        // Hash the combined message data
        let mut hasher = Keccak256::new();
        hasher.update(&message_data);
        let message_hash = hasher.finalize();
        
        // Append to EIP-712 message
        eip712_message.extend_from_slice(&message_hash);
        
        // Hash the final EIP-712 message
        let mut final_hasher = Keccak256::new();
        final_hasher.update(&eip712_message);
        let final_hash = final_hasher.finalize();
        
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&final_hash);
        Ok(hash_array)
    }
}

/// Sign data using the appropriate algorithm (runtime dispatch based on SignatureData)
pub fn sign_with_algorithm(
    signing_key: &SigningKey,
    data: &SignatureData,
) -> Result<Signature, SignatureAlgorithmError> {
    match data {
        SignatureData::Message(msg) => {
            let hasher = Eip191Hasher;
            hasher.sign(signing_key, msg)
        }
        SignatureData::TypedData { domain, types, value } => {
            let hasher = Eip712Hasher;
            let typed_data = TypedData {
                domain: domain.clone(),
                types: types.clone(),
                value: value.clone(),
            };
            hasher.sign(signing_key, &typed_data)
        }
    }
}

/// Verify signature and recover signer (runtime dispatch based on SignatureData)
/// Verifies that the recovered signer matches the expected signer address
pub fn verify_and_recover_with_algorithm(
    data: &SignatureData,
    signature: &Signature,
    expected_signer: &Address,
) -> Result<Address, SignatureAlgorithmError> {
    let recovered_signer = match data {
        SignatureData::Message(msg) => {
            let hasher = Eip191Hasher;
            hasher.verify_and_recover(msg, signature)?
        }
        SignatureData::TypedData { domain, types, value } => {
            let hasher = Eip712Hasher;
            let typed_data = TypedData {
                domain: domain.clone(),
                types: types.clone(),
                value: value.clone(),
            };
            hasher.verify_and_recover(&typed_data, signature)?
        }
    };
    
    // Verify that the recovered signer matches the expected signer
    if recovered_signer.0.to_lowercase() != expected_signer.0.to_lowercase() {
        return Err(SignatureAlgorithmError::SignerMismatch);
    }
    
    Ok(recovered_signer)
}

/// Recover signer address from signature without verification (runtime dispatch based on SignatureData)
pub fn recover_signer_with_algorithm(
    data: &SignatureData,
    signature: &Signature,
) -> Result<Address, SignatureAlgorithmError> {
    match data {
        SignatureData::Message(msg) => {
            let hasher = Eip191Hasher;
            hasher.verify_and_recover(msg, signature)
        }
        SignatureData::TypedData { domain, types, value } => {
            let hasher = Eip712Hasher;
            let typed_data = TypedData {
                domain: domain.clone(),
                types: types.clone(),
                value: value.clone(),
            };
            hasher.verify_and_recover(&typed_data, signature)
        }
    }
}

/// Compute hash using the appropriate algorithm (runtime dispatch based on SignatureData)
pub fn compute_hash_with_algorithm(
    data: &SignatureData,
) -> Result<[u8; 32], SignatureAlgorithmError> {
    match data {
        SignatureData::Message(msg) => {
            let hasher = Eip191Hasher;
            hasher.compute_hash(msg)
        }
        SignatureData::TypedData { domain, types, value } => {
            let hasher = Eip712Hasher;
            let typed_data = TypedData {
                domain: domain.clone(),
                types: types.clone(),
                value: value.clone(),
            };
            hasher.compute_hash(&typed_data)
        }
    }
}

/// Derives an Ethereum address from a public key
fn derive_address_from_public_key(verifying_key: &VerifyingKey) -> Address {
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

