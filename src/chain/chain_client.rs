use crate::core::base_types::{
    Address, SignedTransaction, TokenAmount, Transaction, TransactionReceipt
};
use alloy::primitives::{Address as AlloyAddress, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{BlockId, BlockNumberOrTag, TransactionRequest};
use tokio::runtime::Runtime;
use crate::chain::RpcUrl;
use hex;

#[derive(Debug, thiserror::Error)]
pub enum ChainClientCreationError {
    #[error("No RPC URLs provided")]
    NoRpcUrlsProvided,
    
    #[error("Failed to create Tokio runtime: {0}")]
    TokioRuntimeError(String),
}

pub struct ChainClient {
    rpc_urls: Vec<RpcUrl>,
    timeout: u64,
    max_retries: u32,
    runtime: Runtime,
}

impl ChainClient {
    pub fn new(rpc_urls: Vec<RpcUrl>, timeout: u64, max_retries: u32) -> Result<Self, ChainClientCreationError> {
        if rpc_urls.is_empty() {
            return Err(ChainClientCreationError::NoRpcUrlsProvided);
        }

        let runtime = Runtime::new()
            .map_err(|e| ChainClientCreationError::TokioRuntimeError(e.to_string()))?;
        
        Ok(Self {
            rpc_urls,
            timeout,
            max_retries,
            runtime,
        })
    }

    pub fn get_balance(&self, address: Address) -> Result<TokenAmount, ChainClientError> {
        let alloy_address = address.alloy_address();
        let mut last_error = None;

        for rpc_url in &self.rpc_urls {
            match self.try_get_balance_from_url(rpc_url, alloy_address) {
                Ok(balance) => return Ok(balance),
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }
        Err(ChainClientError::all_endpoints_failed(last_error))
    }

    fn try_get_balance_from_url(
        &self,
        rpc_url: &RpcUrl,
        address: AlloyAddress,
    ) -> Result<TokenAmount, ChainClientError> {
        self.runtime.block_on(async {
            let parsed_url = rpc_url.as_url().clone();
            let provider = ProviderBuilder::new().connect_http(parsed_url);
            let balance = provider.get_balance(address).await
                .map_err(|e| ChainClientError::RpcError(format!("RPC call failed: {}", e)))?;
            let balance_u128 = balance.to::<u128>();
            
            Ok(TokenAmount::new(
                balance_u128,
                18,
                Some("ETH".to_string()),
            ))
        })
    }

    /// `block`: `"latest"` | `"pending"` | `"earliest"` or block number.
    pub fn get_nonce(&self, address: Address, block: &str) -> Result<u64, ChainClientError> {
        let alloy_address = address.alloy_address();
        let block_id = parse_block_id(block)?;
        let mut last_error = None;

        for rpc_url in &self.rpc_urls {
            match self.try_get_nonce_from_url(rpc_url, alloy_address, block_id) {
                Ok(nonce) => return Ok(nonce),
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }
        Err(ChainClientError::all_endpoints_failed(last_error))
    }

    fn try_get_nonce_from_url(
        &self,
        rpc_url: &RpcUrl,
        address: AlloyAddress,
        block_id: BlockId,
    ) -> Result<u64, ChainClientError> {
        self.runtime.block_on(async {
            let parsed_url = rpc_url.as_url().clone();
            let provider = ProviderBuilder::new().connect_http(parsed_url);
            let nonce = provider.get_transaction_count(address)
                .block_id(block_id)
                .await
                .map_err(|e| ChainClientError::RpcError(format!("RPC call failed: {}", e)))?;
            
            Ok(nonce)
        })
    }

    pub fn get_gas_price(&self) -> Result<GasPrice, ChainClientError> {
        let mut last_error = None;

        for rpc_url in &self.rpc_urls {
            match self.try_get_gas_price_from_url(rpc_url) {
                Ok(gas_price) => return Ok(gas_price),
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }
        Err(ChainClientError::all_endpoints_failed(last_error))
    }

    fn try_get_gas_price_from_url(
        &self,
        rpc_url: &RpcUrl,
    ) -> Result<GasPrice, ChainClientError> {
        self.runtime.block_on(async {
            let parsed_url = rpc_url.as_url().clone();
            let provider = ProviderBuilder::new().connect_http(parsed_url);
            let fee_history = provider.get_fee_history(1, BlockNumberOrTag::Latest, &[25.0, 50.0, 75.0])
                .await
                .map_err(|e| ChainClientError::RpcError(format!("Failed to get fee history: {}", e)))?;

            let base_fee = fee_history.base_fee_per_gas
                .last()
                .copied()
                .map(|fee: u128| fee as u64)
                .ok_or_else(|| ChainClientError::InvalidResponse("Base fee not found in fee history".to_string()))?;

            let (priority_fee_low, priority_fee_medium, priority_fee_high) =
                if let Some(rewards) = fee_history.reward.as_ref() {
                    if let Some(block_rewards) = rewards.first() {
                        if block_rewards.len() >= 3 {
                            (
                                block_rewards[0] as u64,
                                block_rewards[1] as u64,
                                block_rewards[2] as u64,
                            )
                        } else {
                            return Err(ChainClientError::InvalidResponse(
                                format!("Insufficient reward percentiles: expected 3, got {}", block_rewards.len())
                            ));
                        }
                    } else {
                        return Err(ChainClientError::InvalidResponse(
                            "No block rewards found in fee history".to_string()
                        ));
                    }
                } else {
                    return Err(ChainClientError::InvalidResponse(
                        "Reward data not found in fee history".to_string()
                    ));
                };
            
            Ok(GasPrice::new(
                base_fee,
                priority_fee_low,
                priority_fee_medium,
                priority_fee_high,
            ))
        })
    }

    pub fn estimate_gas(&self, tx: &Transaction) -> Result<u64, ChainClientError> {
        let tx_request = tx.to_transaction_request();
        let mut last_error = None;

        for rpc_url in &self.rpc_urls {
            match self.try_estimate_gas_from_url(rpc_url, &tx_request) {
                Ok(gas_estimate) => return Ok(gas_estimate),
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }
        Err(ChainClientError::all_endpoints_failed(last_error))
    }

    fn try_estimate_gas_from_url(
        &self,
        rpc_url: &RpcUrl,
        tx_request: &TransactionRequest,
    ) -> Result<u64, ChainClientError> {
        self.runtime.block_on(async {
            let parsed_url = rpc_url.as_url().clone();
            let provider = ProviderBuilder::new().connect_http(parsed_url);
            let gas_estimate = provider.estimate_gas(tx_request.clone()).await
                .map_err(|e| ChainClientError::RpcError(format!("Gas estimation failed: {}", e)))?;
            Ok(gas_estimate)
        })
    }

    pub fn send_transaction(&self, signed_tx: &SignedTransaction) -> Result<String, ChainClientError> {
        let mut last_error = None;
        for rpc_url in &self.rpc_urls {
            match self.try_send_raw_transaction_from_url(rpc_url, signed_tx.raw()) {
                Ok(tx_hash) => return Ok(tx_hash),
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }
        Err(ChainClientError::all_endpoints_failed(last_error))
    }

    fn try_send_raw_transaction_from_url(
        &self,
        rpc_url: &RpcUrl,
        signed_tx: &[u8],
    ) -> Result<String, ChainClientError> {
        self.runtime.block_on(async {
            let parsed_url = rpc_url.as_url().clone();
            let provider = ProviderBuilder::new().connect_http(parsed_url);
            let pending = provider
                .send_raw_transaction(signed_tx)
                .await
                .map_err(|e| {
                    ChainClientError::RpcError(format!("eth_sendRawTransaction failed: {}", e))
                })?;
            Ok(format!("0x{:x}", pending.tx_hash()))
        })
    }

    pub fn wait_for_receipt(
        &self,
        _tx_hash: &str,
        _timeout: u64,
        _poll_interval: f64,
    ) -> Result<TransactionReceipt, ChainClientError> {
        todo!()
    }

    /// Returns transaction data; returns `TransactionNotFound` if not found.
    pub fn get_transaction(&self, tx_hash: &str) -> Result<Transaction, ChainClientError> {
        let hash = parse_tx_hash(tx_hash)?;
        let mut last_error = None;

        for rpc_url in &self.rpc_urls {
            match self.try_get_transaction_from_url(rpc_url, hash) {
                Ok(Some(tx)) => return Ok(tx),
                Ok(None) => return Err(ChainClientError::TransactionNotFound(tx_hash.to_string())),
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }
        Err(ChainClientError::all_endpoints_failed(last_error))
    }

    fn try_get_transaction_from_url(
        &self,
        rpc_url: &RpcUrl,
        hash: B256,
    ) -> Result<Option<Transaction>, ChainClientError> {
        self.runtime.block_on(async {
            let parsed_url = rpc_url.as_url().clone();
            let provider = ProviderBuilder::new().connect_http(parsed_url);
            let tx = provider.get_transaction_by_hash(hash).await
                .map_err(|e| ChainClientError::RpcError(format!("RPC call failed: {}", e)))?;
            
            match tx {
                Some(tx) => {
                    let tx_json = serde_json::to_value(tx)
                        .map_err(|e| ChainClientError::InvalidResponse(format!("Failed to serialize transaction: {}", e)))?;
                    Transaction::from_web3(tx_json)
                        .map_err(|e| ChainClientError::InvalidResponse(format!("Failed to parse transaction: {}", e)))
                        .map(Some)
                }
                None => Ok(None),
            }
        })
    }

    pub fn get_receipt(&self, _tx_hash: &str) -> Result<Option<TransactionReceipt>, ChainClientError> {
        todo!()
    }

    pub fn call(&self, tx: &Transaction, block: &str) -> Result<Vec<u8>, ChainClientError> {
        let block_id = parse_block_id(block)?;
        let tx_request = tx.to_transaction_request();
        let mut last_error = None;
        for rpc_url in &self.rpc_urls {
            match self.try_call_from_url(rpc_url, &tx_request, block_id) {
                Ok(data) => return Ok(data),
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }
        Err(ChainClientError::all_endpoints_failed(last_error))
    }

    fn try_call_from_url(
        &self,
        rpc_url: &RpcUrl,
        tx_request: &TransactionRequest,
        block_id: BlockId,
    ) -> Result<Vec<u8>, ChainClientError> {
        self.runtime.block_on(async {
            let parsed_url = rpc_url.as_url().clone();
            let provider = ProviderBuilder::new().connect_http(parsed_url);
            let result = provider
                .call(tx_request.clone())
                .block(block_id)
                .await
                .map_err(|e| ChainClientError::RpcError(format!("eth_call failed: {}", e)))?;
            Ok(result.to_vec())
        })
    }
}

fn parse_tx_hash(tx_hash: &str) -> Result<B256, ChainClientError> {
    if !tx_hash.starts_with("0x") {
        return Err(ChainClientError::InvalidResponse(
            format!("Transaction hash must start with '0x': {}", tx_hash)
        ));
    }
    let hex_part = &tx_hash[2..];
    if hex_part.len() != 64 {
        return Err(ChainClientError::InvalidResponse(
            format!("Transaction hash must be 64 hex characters (32 bytes): got {} characters", hex_part.len())
        ));
    }
    let bytes = hex::decode(hex_part)
        .map_err(|e| ChainClientError::InvalidResponse(
            format!("Invalid transaction hash hex '{}': {}", tx_hash, e)
        ))?;
    if bytes.len() != 32 {
        return Err(ChainClientError::InvalidResponse(
            format!("Transaction hash must be 32 bytes: got {} bytes", bytes.len())
        ));
    }
    Ok(B256::from_slice(&bytes))
}

fn parse_block_id(block: &str) -> Result<BlockId, ChainClientError> {
    match block.to_lowercase().as_str() {
        "latest" => Ok(BlockId::Number(BlockNumberOrTag::Latest)),
        "pending" => Ok(BlockId::Number(BlockNumberOrTag::Pending)),
        "earliest" => Ok(BlockId::Number(BlockNumberOrTag::Earliest)),
        _ => {
            if let Some(hex_str) = block.strip_prefix("0x") {
                u64::from_str_radix(hex_str, 16)
                    .map(|n| BlockId::Number(BlockNumberOrTag::Number(n)))
                    .map_err(|_| ChainClientError::InvalidResponse(
                        format!("Invalid block number (hex): {}", block)
                    ))
            } else {
                block.parse::<u64>()
                    .map(|n| BlockId::Number(BlockNumberOrTag::Number(n)))
                    .map_err(|_| ChainClientError::InvalidResponse(
                        format!("Invalid block identifier: {}", block)
                    ))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct GasPrice {
    pub base_fee: u64,
    pub priority_fee_low: u64,
    pub priority_fee_medium: u64,
    pub priority_fee_high: u64,
}

impl GasPrice {
    pub fn new(
        base_fee: u64,
        priority_fee_low: u64,
        priority_fee_medium: u64,
        priority_fee_high: u64,
    ) -> Self {
        Self {
            base_fee,
            priority_fee_low,
            priority_fee_medium,
            priority_fee_high,
        }
    }

    pub fn get_max_fee(&self, priority: &str, buffer: f64) -> Result<u64, ChainClientError> {
        todo!()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChainClientError {
    #[error("RPC request failed: {0}")]
    RpcError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Timeout error: {0}")]
    TimeoutError(String),
    
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    
    #[error("All RPC endpoints failed: {0}")]
    AllEndpointsFailed(String),
    
    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),
    
    #[error("Invalid priority level: {0}")]
    InvalidPriority(String),
}

impl ChainClientError {
    /// `last_error`: most recent failure from the try loop; uses "No endpoints attempted" if `None`.
    pub fn all_endpoints_failed<E: std::fmt::Display>(last_error: Option<E>) -> Self {
        ChainClientError::AllEndpointsFailed(
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "No endpoints attempted".to_string()),
        )
    }
}
