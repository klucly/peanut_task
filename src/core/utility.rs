use std::fmt;
use thiserror::Error;
use sha3::{Digest, Keccak256};
use alloy::network::TransactionBuilder;
use alloy::consensus::transaction::{SignableTransaction, TxEip1559};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{Address as AlloyAddress, Bytes, B256, Signature as AlloySignature, TxKind, U256};
use alloy::rpc::types::TransactionRequest;

pub use super::address::{Address, AddressError};
use super::token_amount::TokenAmount;
use super::signatures::Signature;
use hex;

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
            to: Address::zero(),
            value: TokenAmount::native_eth(0),
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

    /// Numeric fields may be hex or number.
    pub fn from_web3(tx: serde_json::Value) -> Result<Self, TransactionParseError> {
        let obj = tx.as_object()
            .ok_or_else(|| TransactionParseError::InvalidFormat("Transaction must be a JSON object".to_string()))?;

        let to_str = obj.get("to")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TransactionParseError::MissingField("to".to_string()))?;
        let to = Address::from_string(to_str)
            .map_err(|e| TransactionParseError::InvalidFormat(format!("Invalid 'to' address: {}", e)))?;

        let value_raw = parse_hex_or_number_u128(
            obj.get("value")
                .ok_or_else(|| TransactionParseError::MissingField("value".to_string()))?
        )?;
        let value = TokenAmount::native_eth(value_raw);

        let data_str = obj.get("input")
            .or_else(|| obj.get("data"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| TransactionParseError::MissingField("input or data".to_string()))?;
        let data = parse_hex_bytes(data_str)
            .map_err(|e| TransactionParseError::InvalidFormat(format!("Invalid data hex: {}", e)))?;

        let chain_id = parse_hex_or_number_u64(
            obj.get("chainId")
                .ok_or_else(|| TransactionParseError::MissingField("chainId".to_string()))?
        )?;

        let nonce = obj.get("nonce")
            .map(|v| parse_hex_or_number_u64(v))
            .transpose()?;

        let gas_limit = obj.get("gas")
            .or_else(|| obj.get("gasLimit"))
            .map(|v| parse_hex_or_number_u64(v))
            .transpose()?;

        let max_fee_per_gas = obj.get("maxFeePerGas")
            .map(|v| parse_hex_or_number_u64(v))
            .transpose()?;

        let max_priority_fee = obj.get("maxPriorityFeePerGas")
            .map(|v| parse_hex_or_number_u64(v))
            .transpose()?;

        Ok(Transaction {
            to,
            value,
            data,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee,
            chain_id,
        })
    }
}

fn parse_hex_or_number_u64(value: &serde_json::Value) -> Result<u64, TransactionParseError> {
    match value {
        serde_json::Value::String(s) => {
            let hex_str = if s.starts_with("0x") || s.starts_with("0X") {
                &s[2..]
            } else {
                s
            };
            u64::from_str_radix(hex_str, 16)
                .map_err(|e| TransactionParseError::InvalidFormat(
                    format!("Invalid hex string '{}': {}", s, e)
                ))
        }
        serde_json::Value::Number(n) => {
            n.as_u64()
                .ok_or_else(|| TransactionParseError::InvalidFormat(
                    format!("Number too large or negative: {}", n)
                ))
        }
        _ => Err(TransactionParseError::InvalidFormat(
            "Value must be a hex string or number".to_string()
        ))
    }
}

fn parse_hex_or_number_u128(value: &serde_json::Value) -> Result<u128, TransactionParseError> {
    match value {
        serde_json::Value::String(s) => {
            let hex_str = if s.starts_with("0x") || s.starts_with("0X") {
                &s[2..]
            } else {
                s
            };
            u128::from_str_radix(hex_str, 16)
                .map_err(|e| TransactionParseError::InvalidFormat(
                    format!("Invalid hex string '{}': {}", s, e)
                ))
        }
        serde_json::Value::Number(n) => {
            n.as_u64()
                .map(|v| v as u128)
                .ok_or_else(|| TransactionParseError::InvalidFormat(
                    format!("Number too large or negative: {}", n)
                ))
        }
        _ => Err(TransactionParseError::InvalidFormat(
            "Value must be a hex string or number".to_string()
        ))
    }
}

fn parse_hex_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    let hex_part = if hex_str.starts_with("0x") || hex_str.starts_with("0X") {
        &hex_str[2..]
    } else {
        hex_str
    };
    hex::decode(hex_part)
        .map_err(|e| format!("Failed to decode hex: {}", e))
}

#[derive(Error, Debug)]
pub enum TransactionParseError {
    #[error("Missing required field: {0}")]
    MissingField(String),
    
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
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
