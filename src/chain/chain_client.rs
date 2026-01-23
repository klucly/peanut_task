//! Ethereum RPC client with reliability features.
//!
//! Features:
//! - Automatic retry with exponential backoff
//! - Multiple RPC endpoint fallback
//! - Request timing/logging
//! - Proper error classification

use crate::core::base_types::{
    Address, TokenAmount, Transaction, TransactionReceipt
};
use alloy::primitives::Address as AlloyAddress;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{BlockId, BlockNumberOrTag, FeeHistory};
use tokio::runtime::Runtime;
use crate::chain::RpcUrl;

/// Errors that can occur during ChainClient creation.
#[derive(Debug, thiserror::Error)]
pub enum ChainClientCreationError {
    #[error("No RPC URLs provided")]
    NoRpcUrlsProvided,
    
    #[error("Failed to create Tokio runtime: {0}")]
    TokioRuntimeError(String),
}

/// Ethereum RPC client with reliability features.
pub struct ChainClient {
    /// List of RPC endpoint URLs to try (with fallback)
    rpc_urls: Vec<RpcUrl>,
    /// Request timeout in seconds
    timeout: u64,
    /// Maximum number of retries per request
    max_retries: u32,
    /// Tokio runtime for async operations
    runtime: Runtime,
}

impl ChainClient {
    /// Creates a new ChainClient with the specified configuration.
    /// 
    /// # Arguments
    /// * `rpc_urls` - List of RPC endpoint URLs (will try in order with fallback)
    /// * `timeout` - Request timeout in seconds
    /// * `max_retries` - Maximum number of retries per request
    /// 
    /// # Returns
    /// Returns `Ok(ChainClient)` if the configuration is valid, or `Err(ChainClientCreationError)`
    /// if the client cannot be created (e.g., no RPC URLs provided or Tokio runtime creation failed).
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::chain::{ChainClient, RpcUrl, ChainClientCreationError};
    /// let rpc_urls = vec![RpcUrl::new("https://eth-sepolia.g.alchemy.com/v2/{}", "demo").unwrap()];
    /// let client = ChainClient::new(rpc_urls, 30, 3)?;
    /// # Ok::<(), ChainClientCreationError>(())
    /// ```
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

    /// Gets the balance of an address.
    /// 
    /// # Arguments
    /// * `address` - The address to query
    /// 
    /// # Returns
    /// The balance as a `TokenAmount` with 18 decimals (native ETH balance)
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::chain::{ChainClient, RpcUrl};
    /// # use peanut_task::core::base_types::Address;
    /// # let client = ChainClient::new(vec![RpcUrl::new("https://eth-sepolia.g.alchemy.com/v2/{}", "demo").unwrap()], 30, 3)?;
    /// # let addr = Address::from_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0").unwrap();
    /// let balance = client.get_balance(addr)?;
    /// # Ok::<(), peanut_task::chain::ChainClientError>(())
    /// ```
    pub fn get_balance(&self, address: Address) -> Result<TokenAmount, ChainClientError> {
        // Convert custom Address to Alloy Address
        let alloy_address = address.value.parse::<AlloyAddress>()
            .map_err(|e| ChainClientError::InvalidResponse(format!("Invalid address format: {}", e)))?;
        
        // Try each RPC URL with fallback
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
        
        // All endpoints failed
        Err(last_error
            .map(|e| ChainClientError::AllEndpointsFailed(e.to_string()))
            .unwrap_or_else(|| ChainClientError::AllEndpointsFailed("No endpoints attempted".to_string())))
    }
    
    /// Attempts to get balance from a specific RPC URL.
    fn try_get_balance_from_url(
        &self,
        rpc_url: &RpcUrl,
        address: AlloyAddress,
    ) -> Result<TokenAmount, ChainClientError> {
        self.runtime.block_on(async {
            // Get the underlying URL with the actual API key (validated at construction time)
            let parsed_url = rpc_url.as_url().clone();
            
            // Create provider using ProviderBuilder
            let provider = ProviderBuilder::new().connect_http(parsed_url);
            
            // Get balance (returns U256) - using latest block
            let balance = provider.get_balance(address).await
                .map_err(|e| ChainClientError::RpcError(format!("RPC call failed: {}", e)))?;
            
            // Convert U256 to u128 (balance in wei)
            // U256::to() converts to the target type, truncating if necessary
            // For balances, u128 is sufficient (can hold up to ~3.4e38 wei)
            let balance_u128 = balance.to::<u128>();
            
            // Create TokenAmount with 18 decimals (native ETH)
            Ok(TokenAmount::new(
                balance_u128,
                18,
                Some("ETH".to_string()),
            ))
        })
    }

    /// Gets the nonce of an address.
    /// 
    /// # Arguments
    /// * `address` - The address to query
    /// * `block` - Block identifier (default: "pending")
    /// 
    /// # Returns
    /// The nonce as a `u64`
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::chain::{ChainClient, RpcUrl};
    /// # use peanut_task::core::base_types::Address;
    /// # let client = ChainClient::new(vec![RpcUrl::new("https://eth-sepolia.g.alchemy.com/v2/{}", "demo").unwrap()], 30, 3)?;
    /// # let addr = Address::from_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0").unwrap();
    /// let nonce = client.get_nonce(addr, "pending")?;
    /// # Ok::<(), peanut_task::chain::ChainClientError>(())
    /// ```
    pub fn get_nonce(&self, address: Address, block: &str) -> Result<u64, ChainClientError> {
        // Convert custom Address to Alloy Address
        let alloy_address = address.value.parse::<AlloyAddress>()
            .map_err(|e| ChainClientError::InvalidResponse(format!("Invalid address format: {}", e)))?;
        
        // Parse block identifier
        let block_id = parse_block_id(block)?;
        
        // Try each RPC URL with fallback
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
        
        // All endpoints failed
        Err(last_error
            .map(|e| ChainClientError::AllEndpointsFailed(e.to_string()))
            .unwrap_or_else(|| ChainClientError::AllEndpointsFailed("No endpoints attempted".to_string())))
    }
    
    /// Attempts to get nonce from a specific RPC URL.
    fn try_get_nonce_from_url(
        &self,
        rpc_url: &RpcUrl,
        address: AlloyAddress,
        block_id: BlockId,
    ) -> Result<u64, ChainClientError> {
        self.runtime.block_on(async {
            // Get the underlying URL with the actual API key (validated at construction time)
            let parsed_url = rpc_url.as_url().clone();
            
            // Create provider using ProviderBuilder
            let provider = ProviderBuilder::new().connect_http(parsed_url);
            
            // Get transaction count (nonce) - returns u64
            let nonce = provider.get_transaction_count(address)
                .block_id(block_id)
                .await
                .map_err(|e| ChainClientError::RpcError(format!("RPC call failed: {}", e)))?;
            
            Ok(nonce)
        })
    }

    /// Returns current gas price info (base fee, priority fee estimates).
    /// 
    /// # Returns
    /// A `GasPrice` struct containing current gas price information
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::chain::{ChainClient, RpcUrl};
    /// # let client = ChainClient::new(vec![RpcUrl::new("https://eth-sepolia.g.alchemy.com/v2/{}", "demo").unwrap()], 30, 3)?;
    /// let gas_price = client.get_gas_price()?;
    /// # Ok::<(), peanut_task::chain::ChainClientError>(())
    /// ```
    pub fn get_gas_price(&self) -> Result<GasPrice, ChainClientError> {
        // Try each RPC URL with fallback
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
        
        // All endpoints failed
        Err(last_error
            .map(|e| ChainClientError::AllEndpointsFailed(e.to_string()))
            .unwrap_or_else(|| ChainClientError::AllEndpointsFailed("No endpoints attempted".to_string())))
    }
    
    /// Attempts to get gas price from a specific RPC URL.
    fn try_get_gas_price_from_url(
        &self,
        rpc_url: &RpcUrl,
    ) -> Result<GasPrice, ChainClientError> {
        self.runtime.block_on(async {
            // Get the underlying URL with the actual API key (validated at construction time)
            let parsed_url = rpc_url.as_url().clone();
            
            // Create provider using ProviderBuilder
            let provider = ProviderBuilder::new().connect_http(parsed_url);
            
            // Get fee history to get base fee and estimate priority fees
            // The reward_percentiles parameter [25.0, 50.0, 75.0] tells the RPC node to calculate
            // what priority fee (tip) was paid at each percentile across all transactions:
            // - 25.0: 25th percentile (25% of transactions paid this or less) -> "low" priority
            // - 50.0: 50th percentile/median (50% paid this or less) -> "medium" priority
            // - 75.0: 75th percentile (75% paid this or less) -> "high" priority
            // Using 1 block for simplicity
            let fee_history = provider.get_fee_history(1, BlockNumberOrTag::Latest, &[25.0, 50.0, 75.0])
                .await
                .map_err(|e| ChainClientError::RpcError(format!("Failed to get fee history: {}", e)))?;
            
            // Extract base fee from the latest block's base fee per gas
            // fee_history.base_fee_per_gas contains base fees, with the last one being the most recent
            let base_fee = fee_history.base_fee_per_gas
                .last()
                .copied()
                .map(|fee: u128| fee as u64)
                .ok_or_else(|| ChainClientError::InvalidResponse("Base fee not found in fee history".to_string()))?;
            
            // Extract priority fee estimates from the most recent block's reward percentiles
            // fee_history.reward is Option<Vec<Vec<u128>>> where each inner vec contains [25th, 50th, 75th] percentiles
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

    /// Estimates the gas required for a transaction.
    /// 
    /// # Arguments
    /// * `tx` - The transaction request to estimate
    /// 
    /// # Returns
    /// The estimated gas amount as a `u64`
    pub fn estimate_gas(&self, tx: &Transaction) -> Result<u64, ChainClientError> {
        todo!()
    }

    /// Sends a signed transaction and returns the transaction hash.
    /// 
    /// Does NOT wait for confirmation.
    /// 
    /// # Arguments
    /// * `signed_tx` - The signed transaction as bytes (RLP-encoded)
    /// 
    /// # Returns
    /// The transaction hash as a hex string
    pub fn send_transaction(&self, signed_tx: &[u8]) -> Result<String, ChainClientError> {
        todo!()
    }

    /// Waits for transaction confirmation.
    /// 
    /// # Arguments
    /// * `tx_hash` - The transaction hash to wait for
    /// * `timeout` - Maximum time to wait in seconds (default: 120)
    /// * `poll_interval` - Interval between polls in seconds (default: 1.0)
    /// 
    /// # Returns
    /// The transaction receipt when confirmed
    pub fn wait_for_receipt(
        &self,
        tx_hash: &str,
        timeout: u64,
        poll_interval: f64,
    ) -> Result<TransactionReceipt, ChainClientError> {
        todo!()
    }

    /// Gets transaction information by hash.
    /// 
    /// # Arguments
    /// * `tx_hash` - The transaction hash
    /// 
    /// # Returns
    /// Transaction information as a dictionary (serde_json::Value)
    pub fn get_transaction(&self, tx_hash: &str) -> Result<serde_json::Value, ChainClientError> {
        todo!()
    }

    /// Gets transaction receipt by hash.
    /// 
    /// # Arguments
    /// * `tx_hash` - The transaction hash
    /// 
    /// # Returns
    /// The transaction receipt, or `None` if not found
    pub fn get_receipt(&self, tx_hash: &str) -> Result<Option<TransactionReceipt>, ChainClientError> {
        todo!()
    }

    /// Simulates a transaction without sending it (eth_call).
    /// 
    /// # Arguments
    /// * `tx` - The transaction request to simulate
    /// * `block` - Block identifier (default: "latest")
    /// 
    /// # Returns
    /// The call result as bytes
    pub fn call(&self, tx: &Transaction, block: &str) -> Result<Vec<u8>, ChainClientError> {
        todo!()
    }
}

/// Parses a block identifier string into Alloy's BlockId.
/// 
/// # Arguments
/// * `block` - Block identifier string ("latest", "pending", "earliest", or block number as hex/dec)
/// 
/// # Returns
/// Returns `Ok(BlockId)` if parsing succeeds, or `Err(ChainClientError)` if the block
/// identifier is invalid.
fn parse_block_id(block: &str) -> Result<BlockId, ChainClientError> {
    match block.to_lowercase().as_str() {
        "latest" => Ok(BlockId::Number(BlockNumberOrTag::Latest)),
        "pending" => Ok(BlockId::Number(BlockNumberOrTag::Pending)),
        "earliest" => Ok(BlockId::Number(BlockNumberOrTag::Earliest)),
        _ => {
            // Try to parse as block number (hex or decimal)
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

/// Current gas price information.
#[derive(Debug, Clone)]
pub struct GasPrice {
    /// Base fee per gas (in wei)
    pub base_fee: u64,
    /// Low priority fee estimate (in wei)
    pub priority_fee_low: u64,
    /// Medium priority fee estimate (in wei)
    pub priority_fee_medium: u64,
    /// High priority fee estimate (in wei)
    pub priority_fee_high: u64,
}

impl GasPrice {
    /// Creates a new GasPrice instance.
    /// 
    /// # Arguments
    /// * `base_fee` - Base fee per gas (in wei)
    /// * `priority_fee_low` - Low priority fee estimate (in wei)
    /// * `priority_fee_medium` - Medium priority fee estimate (in wei)
    /// * `priority_fee_high` - High priority fee estimate (in wei)
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

    /// Calculates maxFeePerGas with buffer for base fee increase.
    /// 
    /// # Arguments
    /// * `priority` - Priority level: "low", "medium", or "high" (default: "medium")
    /// * `buffer` - Buffer multiplier for base fee increase (default: 1.2)
    /// 
    /// # Returns
    /// The calculated maxFeePerGas in wei
    pub fn get_max_fee(&self, priority: &str, buffer: f64) -> Result<u64, ChainClientError> {
        todo!()
    }
}

/// Errors that can occur during ChainClient operations.
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
