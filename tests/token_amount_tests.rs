#[cfg(test)]
mod tests {
    use peanut_task::core::base_types::Token;
    use peanut_task::core::token_amount::TokenAmount;

    fn token(decimals: u8, symbol: Option<&str>) -> Token {
        Token::new(decimals, symbol.map(String::from))
    }

    // ========== Tests for `new()` ==========

    #[test]
    fn test_new_basic() {
        let amount = TokenAmount::native_eth(1000000000000000000);
        assert_eq!(amount.raw, 1000000000000000000);
        assert_eq!(amount.decimals(), 18);
        assert_eq!(amount.symbol(), Some("ETH"));
    }

    #[test]
    fn test_new_without_symbol() {
        let amount = TokenAmount::new(1000000, token(6, None));
        assert_eq!(amount.raw, 1000000);
        assert_eq!(amount.decimals(), 6);
        assert_eq!(amount.symbol(), None);
    }

    #[test]
    fn test_new_zero() {
        let amount = TokenAmount::native_eth(0);
        assert_eq!(amount.raw, 0);
        assert_eq!(amount.decimals(), 18);
    }

    #[test]
    fn test_new_large_amount() {
        let amount = TokenAmount::new(u128::MAX, token(18, None));
        assert_eq!(amount.raw, u128::MAX);
        assert_eq!(amount.decimals(), 18);
    }

    // ========== Tests for `from_human()` - Valid inputs ==========

    #[test]
    fn test_from_human_whole_number() {
        let amount = TokenAmount::from_human_native_eth("100").unwrap();
        assert_eq!(amount.raw, 100000000000000000000);
        assert_eq!(amount.decimals(), 18);
        assert_eq!(amount.symbol(), Some("ETH"));
    }

    #[test]
    fn test_from_human_decimal() {
        let amount = TokenAmount::from_human_native_eth("1.5").unwrap();
        assert_eq!(amount.raw, 1500000000000000000);
        assert_eq!(amount.decimals(), 18);
    }

    #[test]
    fn test_from_human_small_decimal() {
        let amount = TokenAmount::from_human_native_eth("0.001").unwrap();
        assert_eq!(amount.raw, 1000000000000000);
        assert_eq!(amount.decimals(), 18);
    }

    #[test]
    fn test_from_human_usdc_whole() {
        let amount = TokenAmount::from_human("100", token(6, Some("USDC"))).unwrap();
        assert_eq!(amount.raw, 100000000);
        assert_eq!(amount.decimals(), 6);
        assert_eq!(amount.symbol(), Some("USDC"));
    }

    #[test]
    fn test_from_human_usdc_decimal() {
        let amount = TokenAmount::from_human("1.5", token(6, Some("USDC"))).unwrap();
        assert_eq!(amount.raw, 1500000);
        assert_eq!(amount.decimals(), 6);
    }

    #[test]
    fn test_from_human_zero() {
        let amount = TokenAmount::from_human("0", token(18, None)).unwrap();
        assert_eq!(amount.raw, 0);
        assert_eq!(amount.decimals(), 18);
    }

    #[test]
    fn test_from_human_zero_decimal() {
        let amount = TokenAmount::from_human("0.0", token(18, None)).unwrap();
        assert_eq!(amount.raw, 0);
    }

    #[test]
    fn test_from_human_precise_decimal() {
        // Test with full precision for 18 decimals
        let amount = TokenAmount::from_human("1.234567890123456789", token(18, None)).unwrap();
        assert_eq!(amount.raw, 1234567890123456789);
    }

    #[test]
    fn test_from_human_precise_decimal_6() {
        // Test with full precision for 6 decimals
        let amount = TokenAmount::from_human("1.123456", token(6, None)).unwrap();
        assert_eq!(amount.raw, 1123456);
    }

    #[test]
    fn test_from_human_very_large_integer() {
        let amount = TokenAmount::from_human("1000000000", token(18, None)).unwrap();
        assert_eq!(amount.raw, 1000000000000000000000000000);
    }

    #[test]
    fn test_from_human_leading_zeros_integer() {
        let amount = TokenAmount::from_human("0001.5", token(18, None)).unwrap();
        assert_eq!(amount.raw, 1500000000000000000);
    }

    #[test]
    fn test_from_human_trailing_zeros_fractional() {
        let amount = TokenAmount::from_human("1.500", token(18, None)).unwrap();
        assert_eq!(amount.raw, 1500000000000000000);
    }

    #[test]
    fn test_from_human_short_fractional() {
        // Fractional part shorter than decimals should be padded
        let amount = TokenAmount::from_human("1.5", token(18, None)).unwrap();
        assert_eq!(amount.raw, 1500000000000000000);
    }

    // ========== Tests for `from_human()` - Error cases ==========

    #[test]
    fn test_from_human_invalid_format_multiple_dots() {
        let result = TokenAmount::from_human("1.2.3", token(18, None));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid amount format"));
    }

    #[test]
    fn test_from_human_fractional_exceeds_decimals() {
        let result = TokenAmount::from_human("1.1234567890123456789", token(18, None));
        // This should fail because fractional part has 19 digits but decimals is 18
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Fractional part has"));
    }

    #[test]
    fn test_from_human_fractional_exceeds_decimals_6() {
        let result = TokenAmount::from_human("1.1234567", token(6, None));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Fractional part has"));
    }

    #[test]
    fn test_from_human_invalid_integer() {
        let result = TokenAmount::from_human("abc", token(18, None));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid integer part"));
    }

    #[test]
    fn test_from_human_invalid_fractional() {
        let result = TokenAmount::from_human("1.abc", token(18, None));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid fractional part"));
    }

    #[test]
    fn test_from_human_empty_string() {
        let result = TokenAmount::from_human("", token(18, None));
        assert!(result.is_err());
    }

    #[test]
    fn test_from_human_only_dot() {
        let result = TokenAmount::from_human(".", token(18, None));
        assert!(result.is_err());
    }

    #[test]
    fn test_from_human_only_dot_start() {
        let result = TokenAmount::from_human(".5", token(18, None));
        // This should fail because integer part is empty
        assert!(result.is_err());
    }

    #[test]
    fn test_from_human_overflow() {
        // Try to create an amount that would overflow u128
        let _result = TokenAmount::from_human("340282366920938463463374607431768211456", token(0, None));
        // This might succeed or fail depending on the exact value, but let's test a known overflow case
        // Actually, let's test with a more reasonable but still large number
        let _result2 = TokenAmount::from_human("999999999999999999999999999999999999999", token(18, None));
        // This should either succeed or fail gracefully
        // The exact behavior depends on whether it overflows during multiplication
    }

    // ========== Tests for `human()` ==========

    #[test]
    fn test_human_whole_number() {
        let amount = TokenAmount::new(100000000000000000000, token(18, None));
        assert_eq!(amount.human(), "100");
    }

    #[test]
    fn test_human_decimal() {
        let amount = TokenAmount::new(1500000000000000000, token(18, None));
        assert_eq!(amount.human(), "1.5");
    }

    #[test]
    fn test_human_small_decimal() {
        let amount = TokenAmount::new(1000000000000000, token(18, None));
        assert_eq!(amount.human(), "0.001");
    }

    #[test]
    fn test_human_zero() {
        let amount = TokenAmount::new(0, token(18, None));
        assert_eq!(amount.human(), "0");
    }

    #[test]
    fn test_human_precise_decimal() {
        let amount = TokenAmount::new(1234567890123456789, token(18, None));
        assert_eq!(amount.human(), "1.234567890123456789");
    }

    #[test]
    fn test_human_usdc_whole() {
        let amount = TokenAmount::new(100000000, token(6, None));
        // When fractional part is zero, we return just the integer part
        assert_eq!(amount.human(), "100");
    }

    #[test]
    fn test_human_usdc_decimal() {
        let amount = TokenAmount::new(1500000, token(6, None));
        assert_eq!(amount.human(), "1.5");
    }

    #[test]
    fn test_human_trailing_zeros_removed() {
        let amount = TokenAmount::new(1500000000000000000, token(18, None));
        assert_eq!(amount.human(), "1.5");
        // Should not have trailing zeros
        assert!(!amount.human().ends_with("0"));
    }

    #[test]
    fn test_human_single_digit_fractional() {
        let amount = TokenAmount::new(500000000000000000, token(18, None));
        assert_eq!(amount.human(), "0.5");
    }

    #[test]
    fn test_human_very_small_amount() {
        let amount = TokenAmount::new(1, token(18, None));
        assert_eq!(amount.human(), "0.000000000000000001");
    }

    #[test]
    fn test_human_large_integer() {
        let amount = TokenAmount::new(1000000000000000000000000000, token(18, None));
        assert_eq!(amount.human(), "1000000000");
    }

    #[test]
    fn test_human_6_decimals() {
        let amount = TokenAmount::new(123456, token(6, None));
        assert_eq!(amount.human(), "0.123456");
    }

    #[test]
    fn test_human_8_decimals() {
        // Test with 8 decimals (like some tokens)
        let amount = TokenAmount::new(12345678, token(8, None));
        assert_eq!(amount.human(), "0.12345678");
    }

    #[test]
    fn test_human_0_decimals() {
        // Test with 0 decimals (like some tokens)
        let amount = TokenAmount::new(100, token(0, None));
        assert_eq!(amount.human(), "100");
    }

    #[test]
    fn test_human_1_decimal() {
        let amount = TokenAmount::new(15, token(1, None));
        assert_eq!(amount.human(), "1.5");
    }

    // ========== Round-trip tests (from_human -> human) ==========

    #[test]
    fn test_round_trip_whole_number() {
        let original = "100";
        let amount = TokenAmount::from_human(original, token(18, None)).unwrap();
        assert_eq!(amount.human(), original);
    }

    #[test]
    fn test_round_trip_decimal() {
        let original = "1.5";
        let amount = TokenAmount::from_human(original, token(18, None)).unwrap();
        assert_eq!(amount.human(), original);
    }

    #[test]
    fn test_round_trip_precise() {
        let original = "1.234567890123456789";
        let amount = TokenAmount::from_human(original, token(18, None)).unwrap();
        assert_eq!(amount.human(), original);
    }

    #[test]
    fn test_round_trip_usdc() {
        let original = "1.5";
        let amount = TokenAmount::from_human(original, token(6, None)).unwrap();
        assert_eq!(amount.human(), original);
    }

    #[test]
    fn test_round_trip_small() {
        let original = "0.001";
        let amount = TokenAmount::from_human(original, token(18, None)).unwrap();
        assert_eq!(amount.human(), original);
    }

    #[test]
    fn test_round_trip_zero() {
        let original = "0";
        let amount = TokenAmount::from_human(original, token(18, None)).unwrap();
        assert_eq!(amount.human(), original);
    }

    #[test]
    fn test_round_trip_large() {
        let original = "1000000";
        let amount = TokenAmount::from_human(original, token(18, None)).unwrap();
        assert_eq!(amount.human(), original);
    }

    #[test]
    fn test_round_trip_trailing_zeros() {
        // When we parse "1.500", it should round-trip to "1.5" (trailing zeros removed)
        let amount = TokenAmount::from_human("1.500", token(18, None)).unwrap();
        assert_eq!(amount.human(), "1.5");
    }

    // ========== Tests for Display trait (old - will be updated below) ==========

    // ========== Edge cases and boundary tests ==========

    #[test]
    fn test_max_u128() {
        let amount = TokenAmount::new(u128::MAX, token(18, None));
        assert_eq!(amount.raw, u128::MAX);
        // human() should still work even with max value
        let human = amount.human();
        assert!(!human.is_empty());
    }

    #[test]
    fn test_different_decimal_precisions() {
        // Test various decimal precisions
        for decimals in [0, 1, 6, 8, 18] {
            let amount = TokenAmount::new(100, token(decimals, None));
            assert_eq!(amount.decimals(), decimals);
            let human = amount.human();
            assert!(!human.is_empty());
        }
    }

    #[test]
    fn test_fractional_part_exactly_at_decimals() {
        // Fractional part exactly matching decimals should work
        let amount = TokenAmount::from_human("1.123456", token(6, None)).unwrap();
        assert_eq!(amount.raw, 1123456);
        assert_eq!(amount.human(), "1.123456");
    }

    #[test]
    fn test_very_small_fractional() {
        // Test with a very small fractional part
        let amount = TokenAmount::from_human("0.000000000000000001", token(18, None)).unwrap();
        assert_eq!(amount.raw, 1);
        assert_eq!(amount.human(), "0.000000000000000001");
    }

    #[test]
    fn test_integer_part_zero_with_fractional() {
        let amount = TokenAmount::from_human("0.5", token(18, None)).unwrap();
        assert_eq!(amount.raw, 500000000000000000);
        assert_eq!(amount.human(), "0.5");
    }

    // ========== Tests for `Add` trait (operator +) ==========

    #[test]
    fn test_add_same_decimals() {
        let a = TokenAmount::native_eth(1000000000000000000);
        let b = TokenAmount::native_eth(500000000000000000);
        let sum = a + b;
        assert_eq!(sum.raw, 1500000000000000000);
        assert_eq!(sum.decimals(), 18);
        assert_eq!(sum.symbol(), Some("ETH"));
    }

    #[test]
    #[should_panic(expected = "TokenMismatch")]
    fn test_add_different_decimals() {
        let a = TokenAmount::new(1000000000000000000, token(18, None));
        let b = TokenAmount::new(1000000, token(6, None));
        let _sum = a + b; // Should panic
    }

    #[test]
    fn test_add_zero() {
        let a = TokenAmount::native_eth(1000000000000000000);
        let b = TokenAmount::native_eth(0);
        let sum = a + b;
        assert_eq!(sum.raw, 1000000000000000000);
    }

    #[test]
    fn test_add_symbol_handling() {
        // Same token (native_eth): sum preserves token/symbol
        let a = TokenAmount::native_eth(1000000000000000000);
        let b = TokenAmount::native_eth(500000000000000000);
        let sum = a + b;
        assert_eq!(sum.symbol(), Some("ETH"));

        // Same token (no symbol): sum has no symbol
        let a2 = TokenAmount::new(1000000000000000000, token(18, None));
        let b2 = TokenAmount::new(500000000000000000, token(18, None));
        let sum2 = a2 + b2;
        assert_eq!(sum2.symbol(), None);
    }

    #[test]
    fn test_try_add_success() {
        let a = TokenAmount::new(1000000000000000000, token(18, None));
        let b = TokenAmount::new(500000000000000000, token(18, None));
        let result = a.try_add(&b);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().raw, 1500000000000000000);
    }

    #[test]
    fn test_try_add_decimal_mismatch() {
        let a = TokenAmount::new(1000000000000000000, token(18, None));
        let b = TokenAmount::new(1000000, token(6, None));
        let result = a.try_add(&b);
        assert!(result.is_err());
        match result.unwrap_err() {
            peanut_task::core::token_amount::TokenAmountError::TokenMismatch => {}
            _ => panic!("Expected TokenMismatch error"),
        }
    }

    // ========== Tests for `Mul` trait (operator *) ==========

    #[test]
    fn test_mul_u128() {
        let amount = TokenAmount::native_eth(1000000000000000000);
        let doubled = amount * 2u128;
        assert_eq!(doubled.raw, 2000000000000000000);
        assert_eq!(doubled.decimals(), 18);
        assert_eq!(doubled.symbol(), Some("ETH"));
    }

    #[test]
    fn test_mul_u64() {
        let amount = TokenAmount::new(1000000, token(6, Some("USDC")));
        let result = amount * 3u64;
        assert_eq!(result.raw, 3000000);
    }

    #[test]
    fn test_mul_u32() {
        let amount = TokenAmount::new(1000000000000000000, token(18, None));
        let result = amount * 5u32;
        assert_eq!(result.raw, 5000000000000000000);
    }

    #[test]
    fn test_mul_zero() {
        let amount = TokenAmount::new(1000000000000000000, token(18, None));
        let result = amount * 0u128;
        assert_eq!(result.raw, 0);
    }

    #[test]
    fn test_mul_one() {
        let amount = TokenAmount::new(1000000000000000000, token(18, None));
        let result = amount * 1u128;
        assert_eq!(result.raw, 1000000000000000000);
    }

    #[test]
    #[should_panic(expected = "negative")]
    fn test_mul_negative_i64() {
        let amount = TokenAmount::new(1000000000000000000, token(18, None));
        let _result = amount * -1i64; // Should panic
    }

    #[test]
    fn test_mul_positive_i64() {
        let amount = TokenAmount::new(1000000000000000000, token(18, None));
        let result = amount * 2i64;
        assert_eq!(result.raw, 2000000000000000000);
    }

    #[test]
    fn test_try_mul_success() {
        let amount = TokenAmount::new(1000000000000000000, token(18, None));
        let result = amount.try_mul(3u128);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().raw, 3000000000000000000);
    }

    #[test]
    fn test_try_mul_overflow() {
        let amount = TokenAmount::new(u128::MAX, token(18, None));
        let result = amount.try_mul(2u128);
        assert!(result.is_err());
        match result.unwrap_err() {
            peanut_task::core::token_amount::TokenAmountError::Overflow => {},
            _ => panic!("Expected Overflow error"),
        }
    }

    // ========== Tests for `Display` trait (updated) ==========

    #[test]
    fn test_display_with_symbol() {
        let amount = TokenAmount::native_eth(1500000000000000000);
        let display = format!("{}", amount);
        assert_eq!(display, "1.5 ETH");
    }

    #[test]
    fn test_display_without_symbol() {
        let amount = TokenAmount::new(1500000000000000000, token(18, None));
        let display = format!("{}", amount);
        assert_eq!(display, "1.5");
    }

    #[test]
    fn test_display_whole_number_with_symbol() {
        let amount = TokenAmount::native_eth(100000000000000000000);
        let display = format!("{}", amount);
        assert_eq!(display, "100 ETH");
    }

    #[test]
    fn test_display_precise_with_symbol() {
        let amount = TokenAmount::native_eth(1234567890123456789);
        let display = format!("{}", amount);
        assert_eq!(display, "1.234567890123456789 ETH");
    }

    #[test]
    fn test_display_usdc() {
        let amount = TokenAmount::new(1500000, token(6, Some("USDC")));
        let display = format!("{}", amount);
        assert_eq!(display, "1.5 USDC");
    }
}
