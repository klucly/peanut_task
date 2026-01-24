use std::fmt;
use std::ops::{Add, Mul};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenAmountError {
    #[error("Cannot add TokenAmounts with different decimals: {0} != {1}")]
    DecimalMismatch(u8, u8),
    
    #[error("Cannot add TokenAmounts with different symbols: {0:?} != {1:?}")]
    SymbolMismatch(Option<String>, Option<String>),
    
    #[error("Arithmetic overflow occurred")]
    Overflow,
}

#[derive(Debug, Clone)]
pub struct TokenAmount {
    pub raw: u128,
    pub decimals: u8,
    pub symbol: Option<String>,
}

impl TokenAmount {
    pub fn new(raw: u128, decimals: u8, symbol: Option<String>) -> Self {
        Self { raw, decimals, symbol }
    }

    /// Decimal string (e.g. `"1.5"`) → raw units.
    pub fn from_human(amount: &str, decimals: u8, symbol: Option<String>) -> Result<Self, String> {
        let parts: Vec<&str> = amount.split('.').collect();
        if parts.len() > 2 {
            return Err(format!("Invalid amount format: {}", amount));
        }
        let integer_part = parts[0];
        let fractional_part = if parts.len() == 2 { parts[1] } else { "" };
        if fractional_part.len() > decimals as usize {
            return Err(format!(
                "Fractional part has {} digits, but token only supports {} decimals",
                fractional_part.len(),
                decimals
            ));
        }
        let integer: u128 = integer_part
            .parse()
            .map_err(|_| format!("Invalid integer part: {}", integer_part))?;
        let decimals_u128 = 10_u128.pow(decimals as u32);
        let integer_raw = integer
            .checked_mul(decimals_u128)
            .ok_or_else(|| format!("Amount too large: {}", amount))?;
        let fractional_raw = if fractional_part.is_empty() {
            0
        } else {
            let padded_fractional = format!("{:0<width$}", fractional_part, width = decimals as usize);
            padded_fractional
                .parse::<u128>()
                .map_err(|_| format!("Invalid fractional part: {}", fractional_part))?
        };
        let raw = integer_raw
            .checked_add(fractional_raw)
            .ok_or_else(|| format!("Amount too large: {}", amount))?;
        Ok(Self { raw, decimals, symbol })
    }

    /// Raw → decimal string (no floats).
    pub fn human(&self) -> String {
        let divisor = 10_u128.pow(self.decimals as u32);
        let integer_part = self.raw / divisor;
        let fractional_part = self.raw % divisor;
        if fractional_part == 0 {
            format!("{}", integer_part)
        } else {
            let fractional_str = format!("{:0>width$}", fractional_part, width = self.decimals as usize);
            let trimmed = fractional_str.trim_end_matches('0');
            if trimmed.is_empty() {
                format!("{}", integer_part)
            } else {
                format!("{}.{}", integer_part, trimmed)
            }
        }
    }

    pub fn try_add(&self, other: &Self) -> Result<Self, TokenAmountError> {
        if self.decimals != other.decimals {
            return Err(TokenAmountError::DecimalMismatch(self.decimals, other.decimals));
        }
        let raw = self.raw
            .checked_add(other.raw)
            .ok_or(TokenAmountError::Overflow)?;
        let symbol = self.symbol.clone().or_else(|| other.symbol.clone());

        Ok(Self {
            raw,
            decimals: self.decimals,
            symbol,
        })
    }

    pub fn try_mul(&self, factor: u128) -> Result<Self, TokenAmountError> {
        let raw = self.raw
            .checked_mul(factor)
            .ok_or(TokenAmountError::Overflow)?;

        Ok(Self {
            raw,
            decimals: self.decimals,
            symbol: self.symbol.clone(),
        })
    }
}

impl Add for TokenAmount {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        self.try_add(&other).expect("TokenAmount addition failed")
    }
}

macro_rules! impl_mul_for_int {
    ($($t:ty),*) => {
        $(
            impl Mul<$t> for TokenAmount {
                type Output = Self;

                fn mul(self, factor: $t) -> Self {
                    let factor_u128: u128 = if factor < 0 {
                        panic!("Cannot multiply TokenAmount by negative number");
                    } else {
                        factor as u128
                    };

                    self.try_mul(factor_u128).expect("TokenAmount multiplication failed")
                }
            }
        )*
    };
}

impl_mul_for_int!(u8, u16, u32, u64, u128);
impl_mul_for_int!(i8, i16, i32, i64, i128);

impl fmt::Display for TokenAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let human = self.human();
        let symbol_str = self.symbol.as_ref()
            .map(|s| format!(" {}", s))
            .unwrap_or_default();
        write!(f, "{}{}", human, symbol_str)
    }
}
