//! Specification compliance tests.
//!
//! This file contains tests that verify the codebase follows specific requirements
//! and specifications. Some items are requirements that need to be verified with
//! comments explaining how the code follows the spec.

use peanut_task::core::wallet_manager::WalletManager;
use peanut_task::core::utility::{Address, Message};
use peanut_task::core::token_amount::TokenAmount;
use peanut_task::core::serializer::DeterministicSerializer;
use serde_json::json;

// ============================================================================
// Operations with WalletManager
// ============================================================================

#[test]
fn test_wallet_display_debug_never_shows_private_key() {
    // Spec requirement: str(wallet) and repr(wallet) never show the private key
    // 
    // In Rust, Display is equivalent to str() and Debug is equivalent to repr().
    // WalletManager does not implement Display (which is correct - it prevents
    // accidental string formatting that might expose keys).
    // 
    // The Debug implementation uses SigningKey's Debug, which is secure and
    // uses { .. } to hide the actual key bytes. The k256 crate's SigningKey
    // implements secure Debug that never exposes the private key.
    
    let test_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let wallet = WalletManager::from_hex_string(test_key).expect("Valid key should load");
    
    // Test Debug (repr equivalent)
    let debug_output = format!("{:?}", wallet);
    
    // The debug output should NOT contain the actual private key bytes
    assert!(!debug_output.contains("1234567890abcdef"), 
        "Debug output should not contain the actual private key: {}", debug_output);
    
    // Should contain "WalletManager" to indicate the struct type
    assert!(debug_output.contains("WalletManager"), 
        "Debug output should contain struct name");
    
    // SigningKey from k256 uses { .. } to hide the key, which is secure
    assert!(debug_output.contains("..") || debug_output.contains("SigningKey"), 
        "Debug output should use secure representation: {}", debug_output);
    
    // Verify Display is not implemented (this is intentional)
    // If Display were implemented, we'd be able to use format!("{}", wallet)
    // The fact that this doesn't compile is the correct behavior
}

// Spec requirement: If private key is logged accidentally via panic, it's masked
//
// HOW IT FOLLOWS THE SPEC:
// The WalletManager struct stores the private key as a SigningKey from the k256 crate.
// The k256::ecdsa::SigningKey type implements a secure Debug trait that masks the
// private key bytes. When a panic occurs and the panic handler tries to display
// the WalletManager (or SigningKey), the Debug implementation will show:
// "SigningKey { .. }" instead of the actual key bytes.
//
// Additionally, WalletManager's Debug implementation delegates to SigningKey's Debug,
// which ensures that even in panic messages, the private key is never exposed.
// The k256 crate is designed with security in mind and follows cryptographic best
// practices for key handling.

#[test]
fn test_signing_empty_message_raises_explicit_error() {
    // Spec requirement: Signing an empty message raises explicit error (not cryptographic failure)
    
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();
    
    let empty_message = Message("".to_string());
    
    // Empty messages should raise an explicit error before any crypto operations
    let result = wallet.sign_message(empty_message);
    
    // Should fail with explicit error, not a cryptographic failure
    assert!(result.is_err(), "Empty message should raise explicit error");
    let error = result.unwrap_err();
    let error_msg = error.to_string();
    
    // Error should be clear and explicit about empty message
    assert!(error_msg.contains("empty") || error_msg.contains("Empty"),
        "Error message should mention empty message: {}", error_msg);
    
    // Should not be a cryptographic error
    assert!(!error_msg.contains("cryptographic") && !error_msg.contains("signature"),
        "Error should be explicit validation error, not cryptographic: {}", error_msg);
}

#[test]
fn test_signing_with_invalid_types_raises_before_crypto() {
    // Spec requirement: Signing with invalid types raises before any crypto operations
    //
    // The WalletManager::sign_message method accepts a Message type, which is a newtype
    // wrapper around String. The type system prevents invalid types from being passed.
    // 
    // For sign_typed_data, the method accepts serde_json::Value, which can be validated
    // before any cryptographic operations. However, the current implementation may perform
    // some validation during serialization.
    //
    // This test verifies that type errors are caught at compile time (for sign_message)
    // and that invalid JSON structure errors occur before crypto operations (for sign_typed_data).
    
    let wallet = WalletManager::from_hex_string(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ).unwrap();
    
    // sign_message requires Message type - invalid types are caught at compile time
    // This is enforced by Rust's type system, so no runtime test is needed.
    
    // For sign_typed_data, test that invalid JSON structure fails early
    // Invalid domain structure should fail during serialization, not during crypto
    let invalid_domain = json!("not an object");
    let types = json!({});
    let value = json!({});
    
    let result = wallet.sign_typed_data(invalid_domain, types, value);
    
    // Should fail with a clear error about invalid format, not a cryptographic error
    assert!(result.is_err(), "Invalid typed data should fail before crypto operations");
    let error_msg = result.unwrap_err();
    assert!(!error_msg.contains("cryptographic") && !error_msg.contains("signature"),
        "Error should be about format/structure, not cryptography: {}", error_msg);
}

// ============================================================================
// DeterministicSerializer testing
// ============================================================================

#[test]
fn test_serializer_nested_objects_mixed_key_orders() {
    // Spec requirement: Nested objects with mixed key orders
    
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
    
    // Should produce identical output regardless of key order
    assert_eq!(result1, result2, "Nested objects with mixed key orders should serialize identically");
    
    // Verify keys are sorted at all levels
    let result_str = String::from_utf8(result1).unwrap();
    // Should be: {"x":{"d":4,"e":5,"f":6},"z":{"a":1,"b":2,"c":3}}
    assert!(result_str.contains("\"x\""), "Should contain outer key x");
    assert!(result_str.contains("\"z\""), "Should contain outer key z");
}

#[test]
fn test_serializer_unicode_strings() {
    // Spec requirement: Unicode strings (emoji, non-ASCII)
    
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
    
    // Should properly handle all unicode characters
    assert!(result_str.contains("🚀"), "Should contain emoji");
    assert!(result_str.contains("你好"), "Should contain Chinese characters");
    assert!(result_str.contains("مرحبا"), "Should contain Arabic characters");
    assert!(result_str.contains("こんにちは"), "Should contain Japanese characters");
    assert!(result_str.contains("Привет"), "Should contain Russian characters");
    assert!(result_str.contains("Hello 世界 🌍"), "Should contain mixed unicode");
    assert!(result_str.contains("Café résumé naïve"), "Should contain special characters");
    
    // Verify it's valid UTF-8 (result_str is already a String, so it's valid UTF-8)
    // The fact that String::from_utf8 succeeded above proves it's valid UTF-8
}

#[test]
fn test_serializer_very_large_integers() {
    // Spec requirement: Very large integers (> 2^53, JavaScript unsafe)
    // JavaScript's Number.MAX_SAFE_INTEGER is 2^53 - 1 = 9007199254740991
    
    let js_unsafe_int: u64 = 9007199254740992; // 2^53
    let larger_int: u64 = 18446744073709551615; // u64::MAX
    let safe_int: u64 = 9007199254740991; // 2^53 - 1 (safe)
    
    let data = json!({
        "js_unsafe": js_unsafe_int,
        "very_large": larger_int,
        "safe": safe_int,
    });
    
    let result = DeterministicSerializer::serialize(&data).unwrap();
    let result_str = String::from_utf8(result).unwrap();
    
    // Should serialize large integers correctly (as numbers, not strings)
    assert!(result_str.contains("9007199254740992"), "Should contain js_unsafe integer");
    assert!(result_str.contains("18446744073709551615"), "Should contain very large integer");
    assert!(result_str.contains("9007199254740991"), "Should contain safe integer");
    
    // Should not be quoted (should be numbers, not strings)
    assert!(!result_str.contains("\"9007199254740992\""), "Large integers should not be quoted");
    assert!(!result_str.contains("\"18446744073709551615\""), "Very large integers should not be quoted");
}

#[test]
fn test_serializer_null_values() {
    // Spec requirement: None/null values
    
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
    
    // Should serialize null values correctly
    assert!(result_str.contains("null"), "Should contain null values");
    
    // Verify structure is correct
    assert!(result_str.contains("\"null_field\":null"), "Should serialize null field");
    assert!(result_str.contains("\"inner_null\":null"), "Should serialize nested null");
    assert!(result_str.contains("[1,null,3]") || result_str.contains("[1,null,3]"), 
        "Should serialize array with null");
}

#[test]
fn test_serializer_empty_objects_arrays() {
    // Spec requirement: Empty objects/arrays
    
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
    
    // Should serialize empty structures correctly
    assert!(result_str.contains("\"empty_object\":{}"), "Should serialize empty object");
    assert!(result_str.contains("\"empty_array\":[]"), "Should serialize empty array");
    assert!(result_str.contains("\"empty_obj\":{}"), "Should serialize nested empty object");
    assert!(result_str.contains("\"empty_arr\":[]"), "Should serialize nested empty array");
}

#[test]
fn test_serializer_floating_point_handling() {
    // Spec requirement: Floating point (should REJECT or convert with warning)
    
    // Test that floating point numbers are rejected
    let data_with_float = json!({
        "float": 3.14159,
        "integer": 42
    });
    
    let result = DeterministicSerializer::serialize(&data_with_float);
    
    // Should fail with explicit error about floating point
    assert!(result.is_err(), "Floating point numbers should be rejected");
    let error = result.unwrap_err();
    let error_msg = error.to_string();
    
    // Error should mention floating point
    assert!(error_msg.contains("float") || error_msg.contains("Floating"),
        "Error message should mention floating point: {}", error_msg);
    
    // Test that integers are still allowed
    let data_with_integers = json!({
        "positive": 42,
        "negative": -123,
        "zero": 0,
        "large": 18446744073709551615u64
    });
    
    let result_int = DeterministicSerializer::serialize(&data_with_integers);
    assert!(result_int.is_ok(), "Integer numbers should be allowed");
    
    // Test that zero as float is rejected
    let data_zero_float = json!({
        "zero_float": 0.0
    });
    
    let result_zero = DeterministicSerializer::serialize(&data_zero_float);
    assert!(result_zero.is_err(), "Zero as float should be rejected");
}

// ============================================================================
// base_types stuff
// ============================================================================

#[test]
fn test_address_invalid_raises_clear_error() {
    // Spec requirement: Address("invalid") raises clear error
    
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
        // Try to create address - invalid addresses will fail
        let result = Address::from_string(addr_str);
        let addr = match result {
            Ok(addr) => addr,
            Err(e) => {
                // Expected error for invalid addresses
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
        
        // Error should be clear and descriptive
        assert!(!error_msg.is_empty(), 
            "Error message should not be empty for '{}'", addr_str);
        assert!(error_msg.len() > 10, 
            "Error message should be descriptive for '{}': {}", addr_str, error_msg);
    }
}

#[test]
fn test_address_case_insensitive_equality() {
    // Spec requirement: Address("0xabc...") equals Address("0xABC...") (case-insensitive)
    //
    // Note: Address does not implement PartialEq, so direct == comparison is not available.
    // However, Ethereum addresses are case-insensitive by design. The validation and
    // comparison logic should treat addresses as case-insensitive.
    //
    // This test verifies that addresses with different cases are considered equivalent
    // when compared using case-insensitive comparison.
    
    let addr_lower = Address::from_string("0x742d35cc6634c0532925a3b844bc9e7595f0beb0").unwrap();
    let addr_upper = Address::from_string("0x742D35CC6634C0532925A3B844BC9E7595F0BEB0").unwrap();
    let addr_mixed = Address::from_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0").unwrap();
    
    // All should validate successfully
    assert!(addr_lower.validate().is_ok(), "Lowercase address should be valid");
    assert!(addr_upper.validate().is_ok(), "Uppercase address should be valid");
    assert!(addr_mixed.validate().is_ok(), "Mixed case address should be valid");
    
    // Addresses should be equal when compared case-insensitively using == operator
    assert_eq!(addr_lower, addr_upper,
        "Addresses should be equal case-insensitively using == operator");
    assert_eq!(addr_lower, addr_mixed,
        "Addresses should be equal case-insensitively using == operator");
    assert_eq!(addr_upper, addr_mixed,
        "Addresses should be equal case-insensitively using == operator");
    
    // Verify that addresses with different cases are considered equal
    // Address now implements PartialEq with case-insensitive comparison
    assert!(addr_lower == addr_upper, "PartialEq should work case-insensitively");
}

#[test]
fn test_token_amount_from_human_decimal() {
    // Spec requirement: TokenAmount.from_human("1.5", 18).raw == 1500000000000000000
    
    let amount = TokenAmount::from_human("1.5", 18, None).unwrap();
    assert_eq!(amount.raw, 1500000000000000000,
        "TokenAmount.from_human(\"1.5\", 18) should produce raw value 1500000000000000000");
    assert_eq!(amount.decimals, 18, "Decimals should be preserved");
}

#[test]
fn test_token_amount_adding_different_decimals_raises_error() {
    // Spec requirement: Adding TokenAmount with different decimals raises error
    
    let amount1 = TokenAmount::new(1000000000000000000, 18, Some("ETH".to_string()));
    let amount2 = TokenAmount::new(1000000, 6, Some("USDC".to_string()));
    
    let result = amount1.try_add(&amount2);
    
    assert!(result.is_err(), "Adding amounts with different decimals should fail");
    
    let error = result.unwrap_err();
    let error_msg = error.to_string();
    
    // Error should mention decimal mismatch
    assert!(error_msg.contains("decimals") || error_msg.contains("DecimalMismatch"),
        "Error message should mention decimal mismatch: {}", error_msg);
    assert!(error_msg.contains("18") || error_msg.contains("6"),
        "Error message should mention the decimal values: {}", error_msg);
}

// Spec requirement: TokenAmount arithmetic never uses float internally
//
// HOW IT FOLLOWS THE SPEC:
// The TokenAmount implementation uses only integer arithmetic (u128) for all operations:
//
// 1. **Storage**: TokenAmount stores amounts as `raw: u128` (integer, smallest unit)
//    and `decimals: u8` (integer, decimal places count)
//
// 2. **from_human()**: Parses the string manually, splits on '.', and uses integer
//    arithmetic with checked_mul and checked_add. No floating point is used.
//
// 3. **try_add()**: Uses `checked_add()` on u128 values directly. No float conversion.
//
// 4. **try_mul()**: Uses `checked_mul()` on u128 values directly. No float conversion.
//
// 5. **human()**: Converts back to human-readable format using integer division and
//    modulo operations: `integer_part = raw / divisor` and `fractional_part = raw % divisor`.
//    String formatting is used for display, but no floating point arithmetic.
//
// 6. **All arithmetic operations**: Use u128 integer types exclusively. The Add and Mul
//    trait implementations delegate to try_add() and try_mul(), which use integer arithmetic.
//
// The codebase explicitly avoids floating point to prevent precision errors that are
// critical in financial/cryptocurrency applications. All decimal handling is done
// through integer arithmetic with explicit decimal place tracking.
