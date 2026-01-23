//! Safe URL wrapper that prevents accidental exposure of sensitive information.
//! 
//! This module provides a `SafeUrl` wrapper that stores a URL template with a placeholder
//! for the API key and the API key separately. When displayed or logged, the API key is
//! replaced with `****` to prevent accidental exposure.

use url::Url;
use thiserror::Error;

/// Errors that can occur during SafeUrl operations.
#[derive(Error, Debug)]
pub enum SafeUrlError {
    #[error("URL template must contain exactly one {{}} placeholder, found {0}")]
    InvalidPlaceholderCount(usize),
    
    #[error("Invalid URL after formatting: {0}")]
    InvalidUrl(#[from] url::ParseError),
}

/// A safe wrapper that stores a URL template and API key separately.
/// 
/// When displayed or debugged, the API key is replaced with `****` to prevent accidental
/// exposure. The full URL with the actual API key can be accessed explicitly via
/// `as_url()`.
/// 
    /// # Examples
    /// ```
    /// # use peanut_task::chain::url_wrapper::SafeUrl;
    /// let url = SafeUrl::new("https://api.example.com/v1?key={}", "secret123")?;
    /// // Display shows redacted version
    /// assert_eq!(format!("{}", url), "https://api.example.com/v1?key=****");
    /// // Full URL accessible explicitly
    /// assert_eq!(url.as_url()?.as_str(), "https://api.example.com/v1?key=secret123");
    /// # Ok::<(), peanut_task::chain::url_wrapper::SafeUrlError>(())
    /// ```
pub struct SafeUrl {
    /// URL template with `{}` placeholder for the API key
    url_template: String,
    /// The API key (kept private to prevent accidental exposure)
    api_key: String,
}

impl SafeUrl {
    /// Creates a new `SafeUrl` from a URL template and API key.
    /// 
    /// The URL template should contain exactly one `{}` placeholder where the API key
    /// will be inserted.
    /// 
    /// # Arguments
    /// * `url_template` - URL template with `{}` placeholder (e.g., "https://api.example.com/v1?key={}")
    /// * `api_key` - The API key to insert into the template
    /// 
    /// # Returns
    /// Returns `Ok(SafeUrl)` if the template can be formatted, or `Err(SafeUrlError)` if
    /// the template is invalid or cannot be parsed as a URL after formatting.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::chain::url_wrapper::SafeUrl;
    /// let safe_url = SafeUrl::new("https://api.example.com/v1?key={}", "my-secret-key")?;
    /// # Ok::<(), peanut_task::chain::url_wrapper::SafeUrlError>(())
    /// ```
    pub fn new(url_template: &str, api_key: &str) -> Result<Self, SafeUrlError> {
        // Validate that template contains exactly one placeholder
        let placeholder_count = url_template.matches("{}").count();
        if placeholder_count != 1 {
            return Err(SafeUrlError::InvalidPlaceholderCount(placeholder_count));
        }

        // Validate that the formatted URL is valid
        let formatted_url = url_template.replace("{}", api_key);
        formatted_url.parse::<Url>()?;

        Ok(Self {
            url_template: url_template.to_string(),
            api_key: api_key.to_string(),
        })
    }

    /// Returns a reference to the underlying `Url` with the actual API key.
    /// 
    /// Use this method when you need explicit access to the full URL with the real API key.
    /// 
    /// # Returns
    /// A reference to the underlying `url::Url` with the API key inserted
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::chain::url_wrapper::SafeUrl;
    /// let safe_url = SafeUrl::new("https://api.example.com/v1?key={}", "secret")?;
    /// let url = safe_url.as_url()?;
    /// assert_eq!(url.as_str(), "https://api.example.com/v1?key=secret");
    /// # Ok::<(), peanut_task::chain::url_wrapper::SafeUrlError>(())
    /// ```
    pub fn as_url(&self) -> Result<Url, SafeUrlError> {
        let formatted = self.url_template.replace("{}", &self.api_key);
        Ok(formatted.parse()?)
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
    /// # use peanut_task::chain::url_wrapper::SafeUrl;
    /// let safe_url = SafeUrl::new("https://api.example.com/v1?key={}", "secret")?;
    /// assert_eq!(safe_url.redacted(), "https://api.example.com/v1?key=****");
    /// # Ok::<(), peanut_task::chain::url_wrapper::SafeUrlError>(())
    /// ```
    pub fn redacted(&self) -> String {
        self.url_template.replace("{}", "****")
    }
}

impl std::fmt::Display for SafeUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.redacted())
    }
}

impl std::fmt::Debug for SafeUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafeUrl")
            .field("url_template", &self.url_template)
            .field("api_key", &"****")
            .finish()
    }
}
