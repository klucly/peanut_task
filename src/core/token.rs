/// Currency identity: decimals and optional symbol. No address in core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub decimals: u8,
    pub symbol: Option<String>,
}

impl Token {
    pub fn new(decimals: u8, symbol: Option<String>) -> Self {
        Self { decimals, symbol }
    }

    pub fn native_eth() -> Self {
        Self::new(18, Some("ETH".to_string()))
    }

    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    /// Returns the symbol as `&str` when present.
    pub fn symbol(&self) -> Option<&str> {
        self.symbol.as_deref()
    }
}
