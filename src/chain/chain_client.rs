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
use tokio::runtime::Runtime;

/// Ethereum RPC client with reliability features.
pub struct ChainClient {
    /// List of RPC endpoint URLs to try (with fallback)
    rpc_urls: Vec<String>,
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
    /// # Panics
    /// Panics if the Tokio runtime cannot be created
    pub fn new(rpc_urls: Vec<String>, timeout: u64, max_retries: u32) -> Self {
        let runtime = Runtime::new()
            .expect("Failed to create Tokio runtime");
        
        Self {
            rpc_urls,
            timeout,
            max_retries,
            runtime,
        }
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
    /// # use peanut_task::chain::ChainClient;
    /// # use peanut_task::core::base_types::Address;
    /// # let client = ChainClient::new(vec!["https://eth-sepolia.g.alchemy.com/v2/demo".to_string()], 30, 3);
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
        Err(last_error.unwrap_or(ChainClientError::AllEndpointsFailed))
    }
    
    /// Attempts to get balance from a specific RPC URL.
    fn try_get_balance_from_url(
        &self,
        rpc_url: &str,
        address: AlloyAddress,
    ) -> Result<TokenAmount, ChainClientError> {
        self.runtime.block_on(async {
            // Parse RPC URL - ProviderBuilder expects a parsed URL
            let url = rpc_url.parse::<url::Url>()
                .map_err(|e| ChainClientError::InvalidResponse(format!("Invalid RPC URL: {}", e)))?;
            
            // Create provider using ProviderBuilder
            let provider = ProviderBuilder::new().connect_http(url);
            
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
    pub fn get_nonce(&self, address: Address, block: &str) -> Result<u64, ChainClientError> {
        todo!()
    }

    /// Returns current gas price info (base fee, priority fee estimates).
    /// 
    /// # Returns
    /// A `GasPrice` struct containing current gas price information
    pub fn get_gas_price(&self) -> Result<GasPrice, ChainClientError> {
        todo!()
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
    
    #[error("All RPC endpoints failed")]
    AllEndpointsFailed,
    
    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),
    
    #[error("Invalid priority level: {0}")]
    InvalidPriority(String),
}
