use std::fmt;
use std::ops::{Add, Mul};
use thiserror::Error;

use super::token::Token;

#[derive(Error, Debug)]
pub enum TokenAmountError {
    #[error("Cannot add TokenAmounts with different tokens")]
    TokenMismatch,

    #[error("Arithmetic overflow occurred")]
    Overflow,
}

#[derive(Debug, Clone)]
pub struct TokenAmount {
    pub raw: u128,
    pub token: Token,
}

impl TokenAmount {
    pub fn new(raw: u128, token: Token) -> Self {
        Self { raw, token }
    }

    pub fn native_eth(raw: u128) -> Self {
        Self::new(raw, Token::native_eth())
    }

    pub fn from_human_native_eth(amount: &str) -> Result<Self, String> {
        Self::from_human(amount, Token::native_eth())
    }

    pub fn decimals(&self) -> u8 {
        self.token.decimals()
    }

    pub fn symbol(&self) -> Option<&str> {
        self.token.symbol()
    }

    pub fn from_human(amount: &str, token: Token) -> Result<Self, String> {
        let decimals = token.decimals();
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
        Ok(Self { raw, token })
    }

    pub fn human(&self) -> String {
        let decimals = self.token.decimals();
        let divisor = 10_u128.pow(decimals as u32);
        let integer_part = self.raw / divisor;
        let fractional_part = self.raw % divisor;
        if fractional_part == 0 {
            format!("{}", integer_part)
        } else {
            let fractional_str = format!("{:0>width$}", fractional_part, width = decimals as usize);
            let trimmed = fractional_str.trim_end_matches('0');
            if trimmed.is_empty() {
                format!("{}", integer_part)
            } else {
                format!("{}.{}", integer_part, trimmed)
            }
        }
    }

    pub fn try_add(&self, other: &Self) -> Result<Self, TokenAmountError> {
        if self.token != other.token {
            return Err(TokenAmountError::TokenMismatch);
        }
        let raw = self
            .raw
            .checked_add(other.raw)
            .ok_or(TokenAmountError::Overflow)?;
        Ok(Self {
            raw,
            token: self.token.clone(),
        })
    }

    pub fn try_mul(&self, factor: u128) -> Result<Self, TokenAmountError> {
        let raw = self
            .raw
            .checked_mul(factor)
            .ok_or(TokenAmountError::Overflow)?;
        Ok(Self {
            raw,
            token: self.token.clone(),
        })
    }
}

impl Add for TokenAmount {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        self.try_add(&other).expect("TokenAmount addition failed")
    }
}

macro_rules! impl_mul_for_unsigned {
    ($($t:ty),*) => {
        $(
            impl Mul<$t> for TokenAmount {
                type Output = Self;

                fn mul(self, factor: $t) -> Self {
                    self.try_mul(factor as u128).expect("TokenAmount multiplication failed")
                }
            }
        )*
    };
}

macro_rules! impl_mul_for_signed {
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

impl_mul_for_unsigned!(u8, u16, u32, u64, u128);
impl_mul_for_signed!(i8, i16, i32, i64, i128);

impl fmt::Display for TokenAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let human = self.human();
        let symbol_str = self
            .token
            .symbol()
            .map(|s| format!(" {}", s))
            .unwrap_or_default();
        write!(f, "{}{}", human, symbol_str)
    }
}
