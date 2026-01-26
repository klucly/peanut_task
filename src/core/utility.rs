use std::fmt;
use thiserror::Error;
use sha3::{Digest, Keccak256};
use alloy::network::TransactionBuilder;
use alloy::consensus::transaction::{SignableTransaction, TxEip1559};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{Address as AlloyAddress, Bytes, B256, Signature as AlloySignature, TxKind, U256};
use alloy::rpc::types::TransactionRequest;

use super::token_amount::TokenAmount;
use super::signatures::Signature;

#[derive(Clone)]
pub struct Address {
    pub value: String,
}

impl Address {
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
        self.value.parse::<AlloyAddress>()
            .expect("Address validated at construction, parse should never fail")
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

/// EIP-191 personal sign message.
#[derive(Debug, Clone)]
pub struct Message(pub String);

/// EIP-712 domain, types, and value (JSON).
#[derive(Debug, Clone)]
pub struct TypedData {
    pub domain: serde_json::Value,
    pub types: serde_json::Value,
    pub value: serde_json::Value,
}

impl TypedData {
    pub fn new(domain: serde_json::Value, types: serde_json::Value, value: serde_json::Value) -> Self {
        Self { domain, types, value }
    }
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub to: Address,
    pub value: TokenAmount,
    pub data: Vec<u8>,
    pub nonce: Option<u64>,
    pub gas_limit: Option<u64>,
    pub max_fee_per_gas: Option<u64>,
    pub max_priority_fee: Option<u64>,
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
    /// Builds an alloy `TransactionRequest` for `eth_call`, `eth_estimateGas`, `eth_sendTransaction`.
    pub fn to_transaction_request(&self) -> TransactionRequest {
        let mut req = TransactionRequest::default()
            .with_to(self.to.alloy_address())
            .with_value(U256::from(self.value.raw))
            .with_input(Bytes::from(self.data.clone()));
        if let Some(n) = self.nonce {
            req = req.with_nonce(n);
        }
        if let Some(g) = self.gas_limit {
            req = req.with_gas_limit(g);
        }
        if let Some(m) = self.max_fee_per_gas {
            req = req.with_max_fee_per_gas(m.into());
        }
        if let Some(m) = self.max_priority_fee {
            req = req.with_max_priority_fee_per_gas(m.into());
        }
        req
    }

    /// Web3-style JSON with hex-encoded values.
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

#[derive(Error, Debug)]
pub enum SignedTransactionError {
    #[error("SignedTransaction hex must start with '0x', got: {0}")]
    MissingPrefix(String),
    
    #[error("Failed to decode SignedTransaction hex: {0}")]
    InvalidHex(String),
}

/// 0x-prefixed hex of EIP-2718 RLP-encoded signed tx. From `WalletManager::sign_transaction`.
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    hex: String,
    raw: Vec<u8>,
}

impl SignedTransaction {
    /// Builds from `Transaction` + `Signature`; RLP-encodes EIP-1559 signed tx.
    pub fn new(tx: &Transaction, sig: &Signature) -> Self {
        // EIP-155: v = chain_id*2+35+recovery_id. y_parity = recovery_id (0 or 1).
        let parity = if sig.v == 27 || sig.v == 28 {
            sig.v == 28
        } else {
            ((sig.v as u64).saturating_sub(35)) % 2 == 1
        };

        let tx_eip = TxEip1559 {
            chain_id: tx.chain_id,
            nonce: tx.nonce.unwrap_or(0),
            gas_limit: tx.gas_limit.unwrap_or(0),
            max_fee_per_gas: tx.max_fee_per_gas.unwrap_or(0) as u128,
            max_priority_fee_per_gas: tx.max_priority_fee.unwrap_or(0) as u128,
            to: TxKind::Call(tx.to.alloy_address()),
            value: U256::from(tx.value.raw),
            access_list: Default::default(),
            input: Bytes::from(tx.data.clone()),
        };
        let alloy_sig = AlloySignature::from_scalars_and_parity(
            B256::from_slice(&sig.r),
            B256::from_slice(&sig.s),
            parity,
        );
        let signed = tx_eip.into_signed(alloy_sig);
        let raw = signed.encoded_2718();
        let hex = format!("0x{}", hex::encode(&raw));
        SignedTransaction { hex, raw }
    }

    /// Validates hex can be decoded to bytes; stores both.
    pub fn from_raw(hex: String) -> Result<Self, SignedTransactionError> {
        if !hex.starts_with("0x") {
            return Err(SignedTransactionError::MissingPrefix(hex));
        }
        let hex_part = hex.trim_start_matches("0x");
        let raw = hex::decode(hex_part)
            .map_err(|e| SignedTransactionError::InvalidHex(format!("{}: {}", hex, e)))?;
        Ok(SignedTransaction { hex, raw })
    }
    
    /// Returns 0x-prefixed hex string.
    pub fn hex(&self) -> &str {
        &self.hex
    }
    
    /// Returns decoded bytes (no validation needed).
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}
