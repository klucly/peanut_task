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

    pub fn symbol(&self) -> Option<&String> {
        self.symbol.as_ref()
    }
}
