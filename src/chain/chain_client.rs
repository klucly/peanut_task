use crate::core::base_types::{
    Address, SignedTransaction, TokenAmount, Transaction, TransactionReceipt
};
use alloy::primitives::{Address as AlloyAddress, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{BlockId, BlockNumberOrTag, TransactionRequest};
use tokio::runtime::Runtime;
use crate::chain::{RpcUrl, errors::{ChainClientError, ChainClientCreationError}, gas_price::GasPrice, parsers::{parse_tx_hash, parse_block_id}, receipt_polling::poll_for_receipt};

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

    /// Polls for receipt until found or timeout; `timeout` in seconds, `poll_interval` in seconds.
    pub fn wait_for_receipt(
        &self,
        tx_hash: &str,
        timeout: u64,
        poll_interval: f64,
    ) -> Result<TransactionReceipt, ChainClientError> {
        let hash = parse_tx_hash(tx_hash)?;
        let rpc_urls = self.rpc_urls.clone();
        self.runtime.block_on(async {
            poll_for_receipt(rpc_urls, hash, timeout, poll_interval).await
        })
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

    pub fn get_receipt(&self, tx_hash: &str) -> Result<Option<TransactionReceipt>, ChainClientError> {
        let hash = parse_tx_hash(tx_hash)?;
        let mut last_error = None;

        for rpc_url in &self.rpc_urls {
            match self.try_get_receipt_from_url(rpc_url, hash) {
                Ok(receipt) => return Ok(receipt),
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }
        Err(ChainClientError::all_endpoints_failed(last_error))
    }

    fn try_get_receipt_from_url(
        &self,
        rpc_url: &RpcUrl,
        hash: B256,
    ) -> Result<Option<TransactionReceipt>, ChainClientError> {
        self.runtime.block_on(async {
            crate::chain::receipt_polling::try_get_receipt_from_url_async(rpc_url, hash).await
        })
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
