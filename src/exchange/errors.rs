#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    #[error("Exchange API error: {0}")]
    Exchange(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}
