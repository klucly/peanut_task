//! Specification compliance tests.

use peanut_task::core::wallet_manager::WalletManager;
use peanut_task::core::utility::{Address, Message};
use peanut_task::core::base_types::Token;
use peanut_task::core::token_amount::TokenAmount;
use peanut_task::core::serializer::DeterministicSerializer;
use serde_json::json;

#[test]
fn test_wallet_display_debug_never_shows_private_key() {
    let test_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let wallet = WalletManager::from_hex_string(test_key).expect("Valid key should load");

    let debug_output = format!("{:?}", wallet);

    assert!(!debug_output.contains("1234567890abcdef"),
        "Debug output should not contain the actual private key: {}", debug_output);
    assert!(debug_output.contains("WalletManager"),
        "Debug output should contain struct name");
    assert!(debug_output.contains("address"),
        "Debug should show address: {}", debug_output);
    assert!(debug_output.contains(wallet.address().checksum()),
        "Debug should show derived address: {}", debug_output);

    let display_output = format!("{}", wallet);
    let to_string_output = wallet.to_string();
    assert!(!display_output.contains("1234567890abcdef"), "Display must not contain private key: {}", display_output);
    assert!(!to_string_output.contains("1234567890abcdef"), "ToString must not contain private key: {}", to_string_output);
}

#[test]
fn test_signing_empty_message_raises_explicit_error() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let empty_message = Message("".to_string());
    let result = wallet.sign_message(empty_message);

    assert!(result.is_err(), "Empty message should raise explicit error");
    let error = result.unwrap_err();
    let error_msg = error.to_string();

    assert!(error_msg.contains("empty") || error_msg.contains("Empty"),
        "Error message should mention empty message: {}", error_msg);
    assert!(!error_msg.contains("cryptographic") && !error_msg.contains("signature"),
        "Error should be explicit validation error, not cryptographic: {}", error_msg);
}

#[test]
fn test_signing_with_invalid_types_raises_before_crypto() {
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();

    let invalid_domain = json!("not an object");
    let types = json!({});
    let value = json!({});

    let result = wallet.sign_typed_data(invalid_domain, types, value);

    assert!(result.is_err(), "Invalid typed data should fail before crypto operations");
    let error_msg = result.unwrap_err();
    assert!(!error_msg.contains("cryptographic") && !error_msg.contains("signature"),
        "Error should be about format/structure, not cryptography: {}", error_msg);
}

#[test]
fn test_serializer_nested_objects_mixed_key_orders() {
    let data1 = json!({
        "z": {
            "c": 3,
            "a": 1,
            "b": 2
        },
        "x": {
            "f": 6,
            "d": 4,
            "e": 5
        }
    });

    let data2 = json!({
        "x": {
            "e": 5,
            "d": 4,
            "f": 6
        },
        "z": {
            "b": 2,
            "a": 1,
            "c": 3
        }
    });

    let result1 = DeterministicSerializer::serialize(&data1).unwrap();
    let result2 = DeterministicSerializer::serialize(&data2).unwrap();

    assert_eq!(result1, result2, "Nested objects with mixed key orders should serialize identically");

    let result_str = String::from_utf8(result1).unwrap();
    assert!(result_str.contains("\"x\""), "Should contain outer key x");
    assert!(result_str.contains("\"z\""), "Should contain outer key z");
}

#[test]
fn test_serializer_unicode_strings() {
    let data = json!({
        "emoji": "🚀",
        "chinese": "你好",
        "arabic": "مرحبا",
        "japanese": "こんにちは",
        "russian": "Привет",
        "mixed": "Hello 世界 🌍",
        "special_chars": "Café résumé naïve"
    });

    let result = DeterministicSerializer::serialize(&data).unwrap();
    let result_str = String::from_utf8(result).unwrap();

    assert!(result_str.contains("🚀"), "Should contain emoji");
    assert!(result_str.contains("你好"), "Should contain Chinese characters");
    assert!(result_str.contains("مرحبا"), "Should contain Arabic characters");
    assert!(result_str.contains("こんにちは"), "Should contain Japanese characters");
    assert!(result_str.contains("Привет"), "Should contain Russian characters");
    assert!(result_str.contains("Hello 世界 🌍"), "Should contain mixed unicode");
    assert!(result_str.contains("Café résumé naïve"), "Should contain special characters");
}

#[test]
fn test_serializer_very_large_integers() {
    let js_unsafe_int: u64 = 9007199254740992;
    let larger_int: u64 = 18446744073709551615;
    let safe_int: u64 = 9007199254740991;

    let data = json!({
        "js_unsafe": js_unsafe_int,
        "very_large": larger_int,
        "safe": safe_int,
    });

    let result = DeterministicSerializer::serialize(&data).unwrap();
    let result_str = String::from_utf8(result).unwrap();

    assert!(result_str.contains("9007199254740992"), "Should contain js_unsafe integer");
    assert!(result_str.contains("18446744073709551615"), "Should contain very large integer");
    assert!(result_str.contains("9007199254740991"), "Should contain safe integer");
    assert!(!result_str.contains("\"9007199254740992\""), "Large integers should not be quoted");
    assert!(!result_str.contains("\"18446744073709551615\""), "Very large integers should not be quoted");
}

#[test]
fn test_serializer_null_values() {
    let data = json!({
        "null_field": null,
        "string": "value",
        "nested": {
            "inner_null": null,
            "inner_value": 42
        },
        "array_with_null": [1, null, 3]
    });

    let result = DeterministicSerializer::serialize(&data).unwrap();
    let result_str = String::from_utf8(result).unwrap();

    assert!(result_str.contains("null"), "Should contain null values");
    assert!(result_str.contains("\"null_field\":null"), "Should serialize null field");
    assert!(result_str.contains("\"inner_null\":null"), "Should serialize nested null");
    assert!(result_str.contains("[1,null,3]") || result_str.contains("[1,null,3]"),
        "Should serialize array with null");
}

#[test]
fn test_serializer_empty_objects_arrays() {
    let data = json!({
        "empty_object": {},
        "empty_array": [],
        "nested": {
            "empty_obj": {},
            "empty_arr": []
        },
        "mixed": {
            "obj": {},
            "arr": []
        }
    });

    let result = DeterministicSerializer::serialize(&data).unwrap();
    let result_str = String::from_utf8(result).unwrap();

    assert!(result_str.contains("\"empty_object\":{}"), "Should serialize empty object");
    assert!(result_str.contains("\"empty_array\":[]"), "Should serialize empty array");
    assert!(result_str.contains("\"empty_obj\":{}"), "Should serialize nested empty object");
    assert!(result_str.contains("\"empty_arr\":[]"), "Should serialize nested empty array");
}

#[test]
fn test_serializer_floating_point_handling() {
    let data_with_float = json!({
        "float": 3.14159,
        "integer": 42
    });

    let result = DeterministicSerializer::serialize(&data_with_float);

    assert!(result.is_err(), "Floating point numbers should be rejected");
    let error = result.unwrap_err();
    let error_msg = error.to_string();
    assert!(error_msg.contains("float") || error_msg.contains("Floating"),
        "Error message should mention floating point: {}", error_msg);

    let data_with_integers = json!({
        "positive": 42,
        "negative": -123,
        "zero": 0,
        "large": 18446744073709551615u64
    });

    let result_int = DeterministicSerializer::serialize(&data_with_integers);
    assert!(result_int.is_ok(), "Integer numbers should be allowed");

    let data_zero_float = json!({
        "zero_float": 0.0
    });

    let result_zero = DeterministicSerializer::serialize(&data_zero_float);
    assert!(result_zero.is_err(), "Zero as float should be rejected");
}

#[test]
fn test_address_invalid_raises_clear_error() {
    let invalid_addresses = vec![
        ("invalid", "Missing 0x prefix"),
        ("0x", "Too short"),
        ("0x123", "Too short"),
        ("0x1234567890abcdef1234567890abcdef1234567", "Too short (39 chars)"),
        ("0x1234567890abcdef1234567890abcdef123456789", "Too short (41 chars)"),
        ("0x1234567890abcdef1234567890abcdef12345678901", "Too long (43 chars)"),
        ("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG", "Invalid hex characters"),
        ("not_an_address", "No prefix and invalid"),
    ];

    for (addr_str, description) in invalid_addresses {
        let result = Address::from_string(addr_str);
        let addr = match result {
            Ok(addr) => addr,
            Err(e) => {
                let error_msg = e.to_string();
                assert!(!error_msg.is_empty(),
                    "Error message should not be empty for '{}'", addr_str);
                assert!(error_msg.len() > 10,
                    "Error message should be descriptive for '{}': {}", addr_str, error_msg);
                continue;
            }
        };
        let result = addr.validate();

        assert!(result.is_err(),
            "Address '{}' should fail validation ({})", addr_str, description);

        let error = result.unwrap_err();
        let error_msg = error.to_string();
        assert!(!error_msg.is_empty(),
            "Error message should not be empty for '{}'", addr_str);
        assert!(error_msg.len() > 10,
            "Error message should be descriptive for '{}': {}", addr_str, error_msg);
    }
}

#[test]
fn test_address_case_insensitive_equality() {
    let addr_lower = Address::from_string("0x742d35cc6634c0532925a3b844bc9e7595f0beb0").unwrap();
    let addr_upper = Address::from_string("0x742D35CC6634C0532925A3B844BC9E7595F0BEB0").unwrap();
    let addr_mixed = Address::from_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0").unwrap();

    assert!(addr_lower.validate().is_ok(), "Lowercase address should be valid");
    assert!(addr_upper.validate().is_ok(), "Uppercase address should be valid");
    assert!(addr_mixed.validate().is_ok(), "Mixed case address should be valid");

    assert_eq!(addr_lower, addr_upper,
        "Addresses should be equal case-insensitively using == operator");
    assert_eq!(addr_lower, addr_mixed,
        "Addresses should be equal case-insensitively using == operator");
    assert_eq!(addr_upper, addr_mixed,
        "Addresses should be equal case-insensitively using == operator");
    assert!(addr_lower == addr_upper, "PartialEq should work case-insensitively");
}

#[test]
fn test_token_amount_from_human_decimal() {
    let amount = TokenAmount::from_human_native_eth("1.5").unwrap();
    assert_eq!(amount.raw, 1500000000000000000,
        "TokenAmount.from_human(\"1.5\", 18) should produce raw value 1500000000000000000");
    assert_eq!(amount.decimals(), 18, "Decimals should be preserved");
}

#[test]
fn test_token_amount_adding_different_decimals_raises_error() {
    let amount1 = TokenAmount::native_eth(1000000000000000000);
    let amount2 = TokenAmount::new(1000000, Token::new(6, Some("USDC".to_string())));
    let result = amount1.try_add(&amount2);
    assert!(result.is_err(), "Adding amounts with different tokens should fail");
    let error = result.unwrap_err();
    let error_msg = error.to_string();
    assert!(error_msg.contains("token") || error_msg.contains("TokenMismatch"),
        "Error message should mention token mismatch: {}", error_msg);
}
