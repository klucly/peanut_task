//! Token amount handling with precision and arithmetic operations.
//! 
//! This module provides secure handling of token amounts with decimal precision,
//! avoiding floating-point arithmetic to prevent precision errors.

use std::fmt;
use std::ops::{Add, Mul};
use thiserror::Error;

/// Errors that can occur during TokenAmount operations
#[derive(Error, Debug)]
pub enum TokenAmountError {
    #[error("Cannot add TokenAmounts with different decimals: {0} != {1}")]
    DecimalMismatch(u8, u8),
    
    #[error("Cannot add TokenAmounts with different symbols: {0:?} != {1:?}")]
    SymbolMismatch(Option<String>, Option<String>),
    
    #[error("Arithmetic overflow occurred")]
    Overflow,
}

/// Represents a token amount with precision and optional symbol.
/// 
/// This struct stores token amounts in their raw (smallest unit) representation,
/// along with decimal precision information. For example:
/// - ETH: raw = 1000000000000000000, decimals = 18 (represents 1.0 ETH)
/// - USDC: raw = 1000000, decimals = 6 (represents 1.0 USDC)
#[derive(Debug, Clone)]
pub struct TokenAmount {
    /// The raw amount in the smallest unit (e.g., wei for ETH, smallest unit for tokens)
    pub raw: u128,
    /// The number of decimal places (e.g., 18 for ETH, 6 for USDC)
    pub decimals: u8,
    /// Optional symbol of the cryptocurrency (e.g., "ETH", "USDC")
    pub symbol: Option<String>,
}

impl TokenAmount {
    /// Creates a new TokenAmount with the given raw amount, decimals, and optional symbol.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::token_amount::TokenAmount;
    /// // 1.0 ETH (18 decimals)
    /// let eth = TokenAmount::new(1000000000000000000, 18, Some("ETH".to_string()));
    /// 
    /// // 1.0 USDC (6 decimals)
    /// let usdc = TokenAmount::new(1000000, 6, Some("USDC".to_string()));
    /// ```
    pub fn new(raw: u128, decimals: u8, symbol: Option<String>) -> Self {
        Self { raw, decimals, symbol }
    }

    /// Creates a TokenAmount from a human-readable amount string (e.g., "1.5" ETH).
    /// 
    /// Parses the string and converts it to the raw amount based on the decimal precision.
    /// 
    /// # Arguments
    /// * `amount` - Human-readable amount as a string (e.g., "1.5", "100", "0.001")
    /// * `decimals` - Number of decimal places for the token
    /// * `symbol` - Optional token symbol (e.g., "ETH", "USDC")
    /// 
    /// # Returns
    /// Returns `Ok(TokenAmount)` if parsing succeeds, or `Err(String)` if the amount
    /// cannot be parsed or exceeds the maximum value for the given decimals.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::token_amount::TokenAmount;
    /// // 1.5 ETH (18 decimals)
    /// let eth = TokenAmount::from_human("1.5", 18, Some("ETH".to_string()))?;
    /// assert_eq!(eth.raw, 1500000000000000000);
    /// 
    /// // 100 USDC (6 decimals)
    /// let usdc = TokenAmount::from_human("100", 6, Some("USDC".to_string()))?;
    /// assert_eq!(usdc.raw, 100000000);
    /// # Ok::<(), String>(())
    /// ```
    pub fn from_human(amount: &str, decimals: u8, symbol: Option<String>) -> Result<Self, String> {
        // Split the string into integer and fractional parts
        let parts: Vec<&str> = amount.split('.').collect();
        
        if parts.len() > 2 {
            return Err(format!("Invalid amount format: {}", amount));
        }
        
        let integer_part = parts[0];
        let fractional_part = if parts.len() == 2 { parts[1] } else { "" };
        
        // Validate that fractional part doesn't exceed decimals
        if fractional_part.len() > decimals as usize {
            return Err(format!(
                "Fractional part has {} digits, but token only supports {} decimals",
                fractional_part.len(),
                decimals
            ));
        }
        
        // Parse integer part
        let integer: u128 = integer_part
            .parse()
            .map_err(|_| format!("Invalid integer part: {}", integer_part))?;
        
        // Calculate raw amount from integer part
        let decimals_u128 = 10_u128.pow(decimals as u32);
        let integer_raw = integer
            .checked_mul(decimals_u128)
            .ok_or_else(|| format!("Amount too large: {}", amount))?;
        
        // Parse and add fractional part
        let fractional_raw = if fractional_part.is_empty() {
            0
        } else {
            // Pad fractional part on the right with zeros to match decimals
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

    /// Returns the human-readable decimal amount as a string.
    /// 
    /// This preserves precision by using string formatting and integer arithmetic,
    /// avoiding any floating-point operations that could introduce precision errors.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::token_amount::TokenAmount;
    /// let amount = TokenAmount::new(1500000000000000000, 18, Some("ETH".to_string()));
    /// assert_eq!(amount.human(), "1.5");
    /// 
    /// let amount2 = TokenAmount::new(1000000, 6, Some("USDC".to_string()));
    /// assert_eq!(amount2.human(), "1");
    /// 
    /// let amount3 = TokenAmount::new(1234567890123456789, 18, None);
    /// assert_eq!(amount3.human(), "1.234567890123456789");
    /// ```
    pub fn human(&self) -> String {
        let divisor = 10_u128.pow(self.decimals as u32);
        let integer_part = self.raw / divisor;
        let fractional_part = self.raw % divisor;
        
        if fractional_part == 0 {
            format!("{}", integer_part)
        } else {
            // Format fractional part with left-padding to exactly match decimals width
            // This ensures we have the correct number of digits for proper decimal representation
            let fractional_str = format!("{:0>width$}", fractional_part, width = self.decimals as usize);
            // Trim trailing zeros for cleaner display, but preserve at least one digit if fractional_part > 0
            let trimmed = fractional_str.trim_end_matches('0');
            if trimmed.is_empty() {
                format!("{}", integer_part)
            } else {
                format!("{}.{}", integer_part, trimmed)
            }
        }
    }

    /// Adds two TokenAmounts together, returning a Result.
    /// 
    /// # Requirements
    /// - Both amounts must have the same decimals
    /// 
    /// # Returns
    /// - `Ok(TokenAmount)` if addition succeeds
    /// - `Err(TokenAmountError::DecimalMismatch)` if decimals don't match
    /// - `Err(TokenAmountError::Overflow)` if the result overflows u128
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::token_amount::TokenAmount;
    /// let a = TokenAmount::new(1000000000000000000, 18, Some("ETH".to_string()));
    /// let b = TokenAmount::new(500000000000000000, 18, Some("ETH".to_string()));
    /// let sum = a.try_add(&b)?;
    /// assert_eq!(sum.raw, 1500000000000000000);
    /// # Ok::<(), peanut_task::core::token_amount::TokenAmountError>(())
    /// ```
    pub fn try_add(&self, other: &Self) -> Result<Self, TokenAmountError> {
        // Validate decimals match
        if self.decimals != other.decimals {
            return Err(TokenAmountError::DecimalMismatch(self.decimals, other.decimals));
        }

        // Calculate sum with overflow check
        let raw = self.raw
            .checked_add(other.raw)
            .ok_or(TokenAmountError::Overflow)?;

        // Use the symbol from self (or other if self doesn't have one)
        let symbol = self.symbol.clone().or_else(|| other.symbol.clone());

        Ok(Self {
            raw,
            decimals: self.decimals,
            symbol,
        })
    }

    /// Multiplies a TokenAmount by an integer factor, returning a Result.
    /// 
    /// # Returns
    /// - `Ok(TokenAmount)` if multiplication succeeds
    /// - `Err(TokenAmountError::Overflow)` if the result overflows u128 or factor is negative
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::token_amount::TokenAmount;
    /// let amount = TokenAmount::new(1000000000000000000, 18, Some("ETH".to_string()));
    /// let doubled = amount.try_mul(2u128)?;
    /// assert_eq!(doubled.raw, 2000000000000000000);
    /// # Ok::<(), peanut_task::core::token_amount::TokenAmountError>(())
    /// ```
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

    /// Adds two TokenAmounts together using the `+` operator.
    /// 
    /// # Panics
    /// - Panics if decimals don't match
    /// - Panics if the result overflows u128
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::token_amount::TokenAmount;
    /// let a = TokenAmount::new(1000000000000000000, 18, Some("ETH".to_string()));
    /// let b = TokenAmount::new(500000000000000000, 18, Some("ETH".to_string()));
    /// let sum = a + b;
    /// assert_eq!(sum.raw, 1500000000000000000);
    /// ```
    fn add(self, other: Self) -> Self {
        self.try_add(&other).expect("TokenAmount addition failed")
    }
}

// Implement Mul for various integer types
macro_rules! impl_mul_for_int {
    ($($t:ty),*) => {
        $(
            impl Mul<$t> for TokenAmount {
                type Output = Self;

                /// Multiplies a TokenAmount by an integer factor using the `*` operator.
                /// 
                /// # Panics
                /// - Panics if the result overflows u128
                /// - Panics if factor is negative (for signed types)
                /// 
                /// # Examples
                /// ```
                /// # use peanut_task::core::token_amount::TokenAmount;
                /// let amount = TokenAmount::new(1000000000000000000, 18, Some("ETH".to_string()));
                /// let doubled = amount * 2u128;
                /// assert_eq!(doubled.raw, 2000000000000000000);
                /// ```
                fn mul(self, factor: $t) -> Self {
                    // Convert factor to u128, handling negative values for signed types
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

// Implement for unsigned integers
impl_mul_for_int!(u8, u16, u32, u64, u128);

// Implement for signed integers (will panic for negative values)
impl_mul_for_int!(i8, i16, i32, i64, i128);

impl fmt::Display for TokenAmount {
    /// Formats the TokenAmount as a human-readable string with symbol.
    /// 
    /// Format: "{human_readable_amount} {symbol}" or just "{human_readable_amount}" if no symbol.
    /// 
    /// # Examples
    /// ```
    /// # use peanut_task::core::token_amount::TokenAmount;
    /// let amount = TokenAmount::new(1500000000000000000, 18, Some("ETH".to_string()));
    /// assert_eq!(format!("{}", amount), "1.5 ETH");
    /// 
    /// let amount2 = TokenAmount::new(1000000, 6, None);
    /// assert_eq!(format!("{}", amount2), "1");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let human = self.human();
        let symbol_str = self.symbol.as_ref()
            .map(|s| format!(" {}", s))
            .unwrap_or_default();
        write!(f, "{}{}", human, symbol_str)
    }
}
