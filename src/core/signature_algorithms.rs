use sha3::{Digest, Keccak256};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey};
use thiserror::Error;
use serde_json::Value;

use super::utility::{Address, Message, TypedData, Transaction};
use super::signatures::Signature;
use super::serializer::DeterministicSerializer;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Eip191,
    Eip712,
}

pub trait SignatureHasher {
    type Data;

    fn compute_hash(&self, data: &Self::Data) -> Result<[u8; 32], SignatureAlgorithmError>;

    fn sign(&self, signing_key: &SigningKey, data: &Self::Data) -> Result<Signature, SignatureAlgorithmError> {
        let hash = self.compute_hash(data)?;

        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&hash)
            .map_err(|e| SignatureAlgorithmError::SigningError(e.to_string()))?;

        let sig_bytes = signature.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];

        r.copy_from_slice(&sig_bytes[0..32]);
        s.copy_from_slice(&sig_bytes[32..64]);
        let v = 27 + recovery_id.to_byte();
        Ok(Signature::new(r, s, v))
    }

    fn verify_and_recover(&self, data: &Self::Data, signature: &Signature) -> Result<Address, SignatureAlgorithmError> {
        if signature.v != 27 && signature.v != 28 {
            return Err(SignatureAlgorithmError::InvalidRecoveryId(signature.v));
        }
        let message_hash = self.compute_hash(data)?;
        let recovery_id = RecoveryId::from_byte(signature.v - 27)
            .ok_or(SignatureAlgorithmError::InvalidRecoveryId(signature.v))?;

        let mut sig_bytes = [0u8; 64];
        sig_bytes[0..32].copy_from_slice(&signature.r);
        sig_bytes[32..64].copy_from_slice(&signature.s);

        let k256_sig = K256Signature::from_bytes((&sig_bytes).into())
            .map_err(|_| SignatureAlgorithmError::InvalidSignature)?;

        let verifying_key = VerifyingKey::recover_from_prehash(&message_hash, &k256_sig, recovery_id)
            .map_err(|_| SignatureAlgorithmError::RecoveryFailed)?;
        Ok(derive_address_from_public_key(&verifying_key))
    }
}

#[derive(Debug, Clone)]
pub enum SignatureData {
    Message(Message),
    TypedData {
        domain: Value,
        types: Value,
        value: Value,
    },
}

impl SignatureData {
    pub fn from_message(message: Message) -> Self {
        Self::Message(message)
    }

    pub fn from_typed_data(typed_data: TypedData) -> Self {
        Self::TypedData {
            domain: typed_data.domain,
            types: typed_data.types,
            value: typed_data.value,
        }
    }

    pub fn as_message(&self) -> Option<&Message> {
        match self {
            Self::Message(msg) => Some(msg),
            _ => None,
        }
    }

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

pub struct Eip712Hasher;

impl SignatureHasher for Eip712Hasher {
    type Data = TypedData;
    
    fn compute_hash(&self, data: &TypedData) -> Result<[u8; 32], SignatureAlgorithmError> {
        let domain_hash = DeterministicSerializer::hash(&data.domain)
            .map_err(|e| SignatureAlgorithmError::HashError(format!("Failed to hash domain: {}", e)))?;
        let types_hash = DeterministicSerializer::hash(&data.types)
            .map_err(|e| SignatureAlgorithmError::HashError(format!("Failed to hash types: {}", e)))?;
        let value_hash = DeterministicSerializer::hash(&data.value)
            .map_err(|e| SignatureAlgorithmError::HashError(format!("Failed to hash value: {}", e)))?;

        let mut eip712_message = Vec::new();
        eip712_message.extend_from_slice(b"\x19\x01");
        eip712_message.extend_from_slice(&domain_hash);

        let mut message_data = Vec::new();
        message_data.extend_from_slice(&types_hash);
        message_data.extend_from_slice(&value_hash);

        let mut hasher = Keccak256::new();
        hasher.update(&message_data);
        let message_hash = hasher.finalize();

        eip712_message.extend_from_slice(&message_hash);

        let mut final_hasher = Keccak256::new();
        final_hasher.update(&eip712_message);

        let final_hash = final_hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&final_hash);
        Ok(hash_array)
    }
}

/// EIP-155; `v = chain_id*2+35+recovery_id`.
pub struct TransactionHasher;

impl TransactionHasher {
    fn serialize_transaction(tx: &Transaction) -> Result<Vec<u8>, SignatureAlgorithmError> {
        tx.to.validate()
            .map_err(|e| SignatureAlgorithmError::HashError(e.to_string()))?;
        let mut bytes = Vec::new();

        let nonce = tx.nonce.unwrap_or(0);
        bytes.extend_from_slice(&nonce.to_be_bytes());

        let max_fee_per_gas = tx.max_fee_per_gas.unwrap_or(0);
        bytes.extend_from_slice(&max_fee_per_gas.to_be_bytes());

        let max_priority_fee = tx.max_priority_fee.unwrap_or(0);
        bytes.extend_from_slice(&max_priority_fee.to_be_bytes());

        let gas_limit = tx.gas_limit.unwrap_or(0);
        bytes.extend_from_slice(&gas_limit.to_be_bytes());

        let addr_str = tx.to.value.strip_prefix("0x").unwrap_or(&tx.to.value);
        
        let addr_bytes = hex::decode(addr_str)
            .map_err(|e| SignatureAlgorithmError::HashError(
                format!("Failed to decode validated address: {}", e)
            ))?;

        bytes.extend_from_slice(&addr_bytes);
        bytes.extend_from_slice(&tx.value.raw.to_be_bytes());
        bytes.extend_from_slice(&(tx.data.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&tx.data);
        bytes.extend_from_slice(&tx.chain_id.to_be_bytes());
        Ok(bytes)
    }
}

impl SignatureHasher for TransactionHasher {
    type Data = Transaction;
    
    fn compute_hash(&self, tx: &Transaction) -> Result<[u8; 32], SignatureAlgorithmError> {
        let tx_bytes = Self::serialize_transaction(tx)?;
        let mut hasher = Keccak256::new();
        hasher.update(&tx_bytes);

        let hash = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash);
        Ok(hash_array)
    }

    fn sign(&self, signing_key: &SigningKey, tx: &Transaction) -> Result<Signature, SignatureAlgorithmError> {
        let hash = self.compute_hash(tx)?;
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&hash)
            .map_err(|e| SignatureAlgorithmError::SigningError(e.to_string()))?;
            
        let sig_bytes = signature.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[0..32]);
        s.copy_from_slice(&sig_bytes[32..64]);
        let v = (tx.chain_id * 2 + 35 + recovery_id.to_byte() as u64) as u8;
        Ok(Signature::new(r, s, v))
    }
}

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
    if recovered_signer.lower() != expected_signer.lower() {
        return Err(SignatureAlgorithmError::SignerMismatch);
    }
    
    Ok(recovered_signer)
}

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

pub fn derive_public_key_from_private_key(signing_key: &SigningKey) -> VerifyingKey {
    *signing_key.verifying_key()
}

pub fn derive_address_from_public_key(public_key: &VerifyingKey) -> Address {
    let public_key_bytes = public_key.to_encoded_point(false);
    let public_key_slice = &public_key_bytes.as_bytes()[1..];
    let mut hasher = Keccak256::new();
    hasher.update(public_key_slice);
    let hash = hasher.finalize();
    let address_bytes = &hash[12..];
    let address_hex = format!("0x{}", hex::encode(address_bytes));
    Address::from_string(&address_hex)
        .expect("Derived address failed validation - this indicates a bug in address derivation")
}

