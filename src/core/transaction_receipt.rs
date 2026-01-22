//! Transaction receipt parsing and handling.
//! 
//! This module provides parsing of Ethereum transaction receipts from web3 format,
//! including transaction fees calculation and log parsing.

use thiserror::Error;

use super::token_amount::TokenAmount;
use super::utility::Address;

/// Represents an Ethereum transaction log entry.
#[derive(Debug, Clone)]
pub struct Log {
    /// Address that emitted the log
    pub address: Address,
    /// Array of 32-byte log topics
    pub topics: Vec<String>,
    /// Log data (hex-encoded bytes)
    pub data: String,
}

/// Parsed transaction receipt.
#[derive(Debug, Clone)]
pub struct TransactionReceipt {
    /// Transaction hash
    pub tx_hash: String,
    /// Block number where the transaction was included
    pub block_number: u64,
    /// Transaction status (true = success, false = failed)
    pub status: bool,
    /// Gas used by the transaction
    pub gas_used: u64,
    /// Effective gas price in wei
    pub effective_gas_price: u64,
    /// Transaction logs
    pub logs: Vec<Log>,
}

impl TransactionReceipt {
    /// Returns transaction fee as TokenAmount.
    /// 
    /// Calculates the fee as `gas_used * effective_gas_price` in wei (18 decimals).
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::transaction_receipt::TransactionReceipt;
    /// # use peanut_task::core::token_amount::TokenAmount;
    /// let receipt = TransactionReceipt {
    ///     tx_hash: "0x123...".to_string(),
    ///     block_number: 1000,
    ///     status: true,
    ///     gas_used: 21000,
    ///     effective_gas_price: 20000000000, // 20 gwei
    ///     logs: vec![],
    /// };
    /// let fee = receipt.tx_fee();
    /// // fee.raw = 420000000000000 (21000 * 20000000000)
    /// ```
    pub fn tx_fee(&self) -> TokenAmount {
        // Calculate fee: gas_used * effective_gas_price
        // Both are in wei, so the result is also in wei (18 decimals)
        let fee_raw = self.gas_used as u128 * self.effective_gas_price as u128;
        TokenAmount::new(fee_raw, 18, Some("ETH".to_string()))
    }

    /// Parse from web3 receipt dict (serde_json::Value).
    /// 
    /// Expects a JSON object with the following fields:
    /// - `transactionHash`: hex string (required)
    /// - `blockNumber`: hex string or number (required)
    /// - `status`: hex string "0x1" (success) or "0x0" (failed) (required)
    /// - `gasUsed`: hex string or number (required)
    /// - `effectiveGasPrice`: hex string or number (required)
    /// - `logs`: array of log objects (required)
    /// 
    /// Each log object should have:
    /// - `address`: hex string (required)
    /// - `topics`: array of hex strings (required)
    /// - `data`: hex string (required)
    /// 
    /// # Returns
    /// - `Ok(TransactionReceipt)` if parsing succeeds
    /// - `Err(TransactionReceiptError)` if parsing fails
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::transaction_receipt::TransactionReceipt;
    /// # use serde_json::json;
    /// let receipt_json = json!({
    ///     "transactionHash": "0x123...",
    ///     "blockNumber": "0x3e8",
    ///     "status": "0x1",
    ///     "gasUsed": "0x5208",
    ///     "effectiveGasPrice": "0x4a817c800",
    ///     "logs": []
    /// });
    /// let receipt = TransactionReceipt::from_web3(receipt_json)?;
    /// # Ok::<(), peanut_task::core::transaction_receipt::TransactionReceiptError>(())
    /// ```
    pub fn from_web3(receipt: serde_json::Value) -> Result<Self, TransactionReceiptError> {
        let obj = receipt.as_object()
            .ok_or_else(|| TransactionReceiptError::InvalidFormat("Receipt must be a JSON object".to_string()))?;

        // Parse transaction hash
        let tx_hash = obj.get("transactionHash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TransactionReceiptError::MissingField("transactionHash".to_string()))?
            .to_string();

        // Parse block number (can be hex string or number)
        let block_number = parse_hex_or_number(
            obj.get("blockNumber")
                .ok_or_else(|| TransactionReceiptError::MissingField("blockNumber".to_string()))?
        )?;

        // Parse status (hex string "0x1" = success, "0x0" = failed)
        let status = obj.get("status")
            .ok_or_else(|| TransactionReceiptError::MissingField("status".to_string()))?;
        let status = match status {
            serde_json::Value::String(s) => {
                if s == "0x1" || s == "0x01" {
                    true
                } else if s == "0x0" || s == "0x00" {
                    false
                } else {
                    return Err(TransactionReceiptError::InvalidFormat(
                        format!("Invalid status value: {}", s)
                    ));
                }
            }
            serde_json::Value::Number(n) => {
                n.as_u64()
                    .map(|v| v == 1)
                    .unwrap_or(false)
            }
            _ => {
                return Err(TransactionReceiptError::InvalidFormat(
                    "status must be a hex string or number".to_string()
                ));
            }
        };

        // Parse gas used
        let gas_used = parse_hex_or_number(
            obj.get("gasUsed")
                .ok_or_else(|| TransactionReceiptError::MissingField("gasUsed".to_string()))?
        )?;

        // Parse effective gas price
        let effective_gas_price = parse_hex_or_number(
            obj.get("effectiveGasPrice")
                .ok_or_else(|| TransactionReceiptError::MissingField("effectiveGasPrice".to_string()))?
        )?;

        // Parse logs
        let logs_array = obj.get("logs")
            .and_then(|v| v.as_array())
            .ok_or_else(|| TransactionReceiptError::MissingField("logs".to_string()))?;

        let mut logs = Vec::new();
        for (idx, log_value) in logs_array.iter().enumerate() {
            let log_obj = log_value.as_object()
                .ok_or_else(|| TransactionReceiptError::InvalidFormat(
                    format!("Log at index {} must be a JSON object", idx)
                ))?;

            let address_str = log_obj.get("address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| TransactionReceiptError::InvalidFormat(
                    format!("Log at index {} missing 'address' field", idx)
                ))?;
            let address = Address(address_str.to_string());

            let topics_array = log_obj.get("topics")
                .and_then(|v| v.as_array())
                .ok_or_else(|| TransactionReceiptError::InvalidFormat(
                    format!("Log at index {} missing 'topics' field", idx)
                ))?;
            let topics: Result<Vec<String>, _> = topics_array.iter()
                .map(|v| v.as_str()
                    .ok_or_else(|| TransactionReceiptError::InvalidFormat(
                        format!("Log topic must be a string")
                    ))
                    .map(|s| s.to_string()))
                .collect();
            let topics = topics?;

            let data = log_obj.get("data")
                .and_then(|v| v.as_str())
                .ok_or_else(|| TransactionReceiptError::InvalidFormat(
                    format!("Log at index {} missing 'data' field", idx)
                ))?
                .to_string();

            logs.push(Log {
                address,
                topics,
                data,
            });
        }

        Ok(TransactionReceipt {
            tx_hash,
            block_number,
            status,
            gas_used,
            effective_gas_price,
            logs,
        })
    }
}

/// Helper function to parse a hex string or number to u64.
fn parse_hex_or_number(value: &serde_json::Value) -> Result<u64, TransactionReceiptError> {
    match value {
        serde_json::Value::String(s) => {
            // Remove 0x prefix if present
            let hex_str = if s.starts_with("0x") || s.starts_with("0X") {
                &s[2..]
            } else {
                s
            };
            u64::from_str_radix(hex_str, 16)
                .map_err(|e| TransactionReceiptError::InvalidFormat(
                    format!("Invalid hex string '{}': {}", s, e)
                ))
        }
        serde_json::Value::Number(n) => {
            n.as_u64()
                .ok_or_else(|| TransactionReceiptError::InvalidFormat(
                    format!("Number too large or negative: {}", n)
                ))
        }
        _ => Err(TransactionReceiptError::InvalidFormat(
            "Value must be a hex string or number".to_string()
        ))
    }
}

/// Errors that can occur during transaction receipt parsing
#[derive(Error, Debug)]
pub enum TransactionReceiptError {
    #[error("Missing required field: {0}")]
    MissingField(String),
    
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}
