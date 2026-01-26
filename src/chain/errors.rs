#[derive(Debug, thiserror::Error)]
pub enum ChainClientCreationError {
    #[error("No RPC URLs provided")]
    NoRpcUrlsProvided,
    
    #[error("Failed to create Tokio runtime: {0}")]
    TokioRuntimeError(String),
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
