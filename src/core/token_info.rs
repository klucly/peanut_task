use super::utility::Address;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    pub address: Address,
    pub decimals: u8,
    pub symbol: Option<String>,
}

impl TokenInfo {
    pub fn new(address: Address, decimals: u8, symbol: Option<String>) -> Self {
        Self {
            address,
            decimals,
            symbol,
        }
    }
}

