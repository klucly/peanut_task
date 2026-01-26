use url::Url;
use thiserror::Error;
use alloy::providers::{Provider, ProviderBuilder};

#[derive(Error, Debug)]
pub enum RpcUrlError {
    #[error("URL template must contain exactly one {{}} placeholder, found {0}")]
    InvalidPlaceholderCount(usize),
    
    #[error("Invalid URL after formatting: {0}")]
    InvalidUrl(#[from] url::ParseError),
}

#[derive(Debug, thiserror::Error)]
pub enum RpcUrlValidationError {
    #[error("RPC endpoint {url} is unreachable: {error}")]
    UrlUnreachable {
        url: String,
        error: String,
    },
    
    #[error("RPC endpoint {url} returned an error during validation: {error}")]
    UrlRpcError {
        url: String,
        error: String,
    },
}

/// Template with exactly one `{}`; key stored separately; Display/Debug use `****`.
#[derive(Clone)]
pub struct RpcUrl {
    url_template: String,
    api_key: String,
    parsed_url: Url,
}

impl RpcUrl {
    /// Template must have exactly one `{}`; URL validated at construction.
    pub fn new(url_template: &str, api_key: &str) -> Result<Self, RpcUrlError> {
        // Validate that template contains exactly one placeholder
        let placeholder_count = url_template.matches("{}").count();
        if placeholder_count != 1 {
            return Err(RpcUrlError::InvalidPlaceholderCount(placeholder_count));
        }

        // Validate and parse the formatted URL
        let formatted_url = url_template.replace("{}", api_key);
        let parsed_url = formatted_url.parse::<Url>()?;

        Ok(Self {
            url_template: url_template.to_string(),
            api_key: api_key.to_string(),
            parsed_url,
        })
    }

    pub fn as_url(&self) -> &Url {
        &self.parsed_url
    }

    pub fn redacted(&self) -> String {
        self.url_template.replace("{}", "****")
    }

    /// Connectivity check via `get_chain_id`.
    pub async fn validate(&self) -> Result<(), RpcUrlValidationError> {
        // Create provider using ProviderBuilder
        let provider = ProviderBuilder::new().connect_http(self.as_url().clone());
        
        // Make a lightweight RPC call to validate the connection
        // Using get_chain_id() as it's a simple, fast call that validates the endpoint
        provider.get_chain_id()
            .await
            .map_err(|e| {
                // Check if it's a network/connection error or an RPC error
                let error_str = e.to_string().to_lowercase();
                if error_str.contains("connection") || error_str.contains("network") || 
                   error_str.contains("timeout") || error_str.contains("unreachable") {
                    RpcUrlValidationError::UrlUnreachable {
                        url: self.redacted(),
                        error: e.to_string(),
                    }
                } else {
                    RpcUrlValidationError::UrlRpcError {
                        url: self.redacted(),
                        error: e.to_string(),
                    }
                }
            })?;
        
        Ok(())
    }
}

impl std::fmt::Display for RpcUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.redacted())
    }
}

impl std::fmt::Debug for RpcUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcUrl")
            .field("url_template", &self.url_template)
            .field("api_key", &"****")
            .finish()
    }
}
