use thiserror::Error;

use super::address::Address;
use super::token_amount::TokenAmount;

#[derive(Debug, Clone)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<String>,
    pub data: String,
}

#[derive(Debug, Clone)]
pub struct TransactionReceipt {
    pub tx_hash: String,
    pub block_number: u64,
    pub status: bool,
    pub gas_used: u64,
    pub effective_gas_price: u64,
    pub logs: Vec<Log>,
}

impl TransactionReceipt {
    pub fn tx_fee(&self) -> TokenAmount {
        let fee_raw = self.gas_used as u128 * self.effective_gas_price as u128;
        TokenAmount::native_eth(fee_raw)
    }

    /// Numeric fields may be hex or number.
    pub fn from_web3(receipt: serde_json::Value) -> Result<Self, TransactionReceiptError> {
        let obj = receipt.as_object()
            .ok_or_else(|| TransactionReceiptError::InvalidFormat("Receipt must be a JSON object".to_string()))?;

        let tx_hash = obj.get("transactionHash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TransactionReceiptError::MissingField("transactionHash".to_string()))?
            .to_string();

        let block_number = parse_hex_or_number(
            obj.get("blockNumber")
                .ok_or_else(|| TransactionReceiptError::MissingField("blockNumber".to_string()))?
        )?;

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

        let gas_used = parse_hex_or_number(
            obj.get("gasUsed")
                .ok_or_else(|| TransactionReceiptError::MissingField("gasUsed".to_string()))?
        )?;

        let effective_gas_price = parse_hex_or_number(
            obj.get("effectiveGasPrice")
                .ok_or_else(|| TransactionReceiptError::MissingField("effectiveGasPrice".to_string()))?
        )?;

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
            let address = Address::from_string(address_str)
                .map_err(|e| TransactionReceiptError::InvalidFormat(
                    format!("Invalid address in log at index {}: {}", idx, e)
                ))?;

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

fn parse_hex_or_number(value: &serde_json::Value) -> Result<u64, TransactionReceiptError> {
    match value {
        serde_json::Value::String(s) => {
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

#[derive(Error, Debug)]
pub enum TransactionReceiptError {
    #[error("Missing required field: {0}")]
    MissingField(String),
    
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}
