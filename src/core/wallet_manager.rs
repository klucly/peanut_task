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
    fn get_signing_key(&self) -> &SigningKey {
        &self.private_key
    }

    pub fn public_key(&self) -> VerifyingKey {
        let signing_key = self.get_signing_key();
        derive_public_key_from_private_key(&signing_key)
    }


    pub fn from_env(var_name: &str) -> Result<WalletManager, KeyLoadError> {
        let key_hex = env::var(var_name)?;
        Self::from_hex_string(&key_hex)
    }

    pub fn from_hex_string(key_hex: &str) -> Result<WalletManager, KeyLoadError> {
        let hex_str = key_hex.strip_prefix("0x")
            .ok_or(KeyLoadError::MissingHexPrefix)?;
        let key_vec = hex::decode(hex_str)
            .map_err(|e| KeyLoadError::HexDecode(e.to_string()))?;
        let key: [u8; 32] = key_vec.try_into().map_err(|v: Vec<u8>| KeyLoadError::VecConversion(v.len()))?;

        let private_key = SigningKey::from_bytes((&key).into())
            .map_err(|_| KeyLoadError::InvalidPrivateKey)?;
        
        Ok(WalletManager { private_key })
    }
    
    pub fn generate() -> Result<WalletManager, getrandom::Error> {
        loop {
            let mut raw_key = [0u8; 32];
            getrandom::fill(&mut raw_key)?;
            if let Ok(private_key) = SigningKey::from_bytes((&raw_key).into()) {
                return Ok(WalletManager { private_key });
            }
        }
    }
    pub fn address(&self) -> Address {
        derive_address_from_public_key(&self.public_key())
    }
    pub fn sign_message(&self, msg: Message) -> Result<SignedMessage, SigningError> {
        if msg.0.is_empty() {
            return Err(SigningError::EmptyMessage);
        }
        let signature = Eip191Hasher.sign(self.get_signing_key(), &msg)?;
        let data = SignatureData::from_message(msg);
        SignedMessage::new(data, signature, &self.address()).map_err(SigningError::from)
    }
    pub fn sign_typed_data(&self, domain: Value, types: Value, value: Value) -> Result<SignedMessage, String> {
        if !domain.is_object() {
            return Err(format!("Domain must be a JSON object, got: {}", domain));
        }
        if !types.is_object() {
            return Err(format!("Types must be a JSON object, got: {}", types));
        }
        if !value.is_object() {
            return Err(format!("Value must be a JSON object, got: {}", value));
        }
        let typed_data = TypedData::new(domain, types, value);
        let signature = Eip712Hasher.sign(self.get_signing_key(), &typed_data)
            .map_err(|e| format!("Failed to sign: {}", e))?;
        let data = SignatureData::from_typed_data(typed_data);
        SignedMessage::new(data, signature, &self.address())
            .map_err(|e| format!("Signature verification failed: {}", e))
    }
    pub fn sign_transaction(&self, tx: Transaction) -> Result<SignedTransaction, TransactionError> {
        let signature = TransactionHasher.sign(self.get_signing_key(), &tx)
            .map_err(|e| TransactionError::InvalidAddress(format!("Failed to sign transaction: {}", e)))?;
        Ok(SignedTransaction(self.create_raw_transaction(&tx, signature.r, signature.s, signature.v)))
    }
    
    fn create_raw_transaction(&self, tx: &Transaction, r: [u8; 32], s: [u8; 32], v: u8) -> String {
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
