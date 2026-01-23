//! RPC URL wrapper that prevents accidental exposure of sensitive information.
//! 
//! This module provides a `RpcUrl` wrapper that stores a URL template with a placeholder
//! for the API key and the API key separately. When displayed or logged, the API key is
//! replaced with `****` to prevent accidental exposure.

use url::Url;
use thiserror::Error;
use alloy::providers::{Provider, ProviderBuilder};

/// Errors that can occur during RpcUrl operations.
#[derive(Error, Debug)]
pub enum RpcUrlError {
    #[error("URL template must contain exactly one {{}} placeholder, found {0}")]
    InvalidPlaceholderCount(usize),
    
    #[error("Invalid URL after formatting: {0}")]
    InvalidUrl(#[from] url::ParseError),
}

/// Errors that can occur during RPC URL validation.
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

/// A safe wrapper that stores a URL template and API key separately.
/// 
/// When displayed or debugged, the API key is replaced with `****` to prevent accidental
/// exposure. The full URL with the actual API key can be accessed explicitly via
/// `as_url()`. The URL is validated at construction time, so `as_url()` always succeeds.
/// 
/// # Examples
/// ```
/// # use peanut_task::chain::url_wrapper::RpcUrl;
/// let url = RpcUrl::new("https://api.example.com/v1?key={}", "secret123")?;
/// // Display shows redacted version
/// assert_eq!(format!("{}", url), "https://api.example.com/v1?key=****");
/// // Full URL accessible explicitly (no Result needed since it's validated at construction)
/// assert_eq!(url.as_url().as_str(), "https://api.example.com/v1?key=secret123");
/// # Ok::<(), peanut_task::chain::url_wrapper::RpcUrlError>(())
/// ```
pub struct RpcUrl {
    /// URL template with `{}` placeholder for the API key
    url_template: String,
    /// The API key (kept private to prevent accidental exposure)
    api_key: String,
    /// The parsed URL with the API key inserted (validated at construction time)
    parsed_url: Url,
}

impl RpcUrl {
    /// Creates a new `RpcUrl` from a URL template and API key.
    /// 
    /// The URL template should contain exactly one `{}` placeholder where the API key
    /// will be inserted. The URL is validated at construction time, ensuring that
    /// `as_url()` will always succeed.
    /// 
    /// # Arguments
    /// * `url_template` - URL template with `{}` placeholder (e.g., "https://api.example.com/v1?key={}")
    /// * `api_key` - The API key to insert into the template
    /// 
    /// # Returns
    /// Returns `Ok(RpcUrl)` if the template can be formatted and parsed as a valid URL,
    /// or `Err(RpcUrlError)` if the template is invalid or cannot be parsed as a URL.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::chain::url_wrapper::RpcUrl;
    /// let rpc_url = RpcUrl::new("https://api.example.com/v1?key={}", "my-secret-key")?;
    /// # Ok::<(), peanut_task::chain::url_wrapper::RpcUrlError>(())
    /// ```
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

    /// Returns a reference to the underlying `Url` with the actual API key.
    /// 
    /// Use this method when you need explicit access to the full URL with the real API key.
    /// Since the URL is validated at construction time, this method always succeeds.
    /// 
    /// # Returns
    /// A reference to the underlying `url::Url` with the API key inserted
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::chain::url_wrapper::RpcUrl;
    /// let rpc_url = RpcUrl::new("https://api.example.com/v1?key={}", "secret")?;
    /// let url = rpc_url.as_url();
    /// assert_eq!(url.as_str(), "https://api.example.com/v1?key=secret");
    /// # Ok::<(), peanut_task::chain::url_wrapper::RpcUrlError>(())
    /// ```
    pub fn as_url(&self) -> &Url {
        &self.parsed_url
    }

    /// Returns a redacted version of the URL for safe display.
    /// 
    /// Replaces the API key with `****` in the formatted URL.
    /// 
    /// # Returns
    /// A redacted URL string with `****` instead of the API key
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::chain::url_wrapper::RpcUrl;
    /// let rpc_url = RpcUrl::new("https://api.example.com/v1?key={}", "secret")?;
    /// assert_eq!(rpc_url.redacted(), "https://api.example.com/v1?key=****");
    /// # Ok::<(), peanut_task::chain::url_wrapper::RpcUrlError>(())
    /// ```
    pub fn redacted(&self) -> String {
        self.url_template.replace("{}", "****")
    }

    /// Validates the RPC URL by attempting to connect and make a test RPC call.
    /// 
    /// This method verifies that the RPC endpoint is reachable and responds correctly
    /// by making a lightweight RPC call (get_chain_id).
    /// 
    /// # Returns
    /// Returns `Ok(())` if the URL is valid and reachable, or `Err(RpcUrlValidationError)` 
    /// indicating the specific type of validation failure.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::chain::url_wrapper::RpcUrl;
    /// # tokio_test::block_on(async {
    /// let rpc_url = RpcUrl::new("https://eth-sepolia.g.alchemy.com/v2/{}", "demo")?;
    /// rpc_url.validate().await?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// # })
    /// ```
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
