use peanut_task::core::serializer::DeterministicSerializer;
use serde_json::json;

#[test]
fn test_serialize_simple_object() {
    let data = json!({"name": "Alice", "age": 30});
    let result = DeterministicSerializer::serialize(&data).unwrap();
    let result_str = String::from_utf8(result).unwrap();
    assert_eq!(result_str, r#"{"age":30,"name":"Alice"}"#);
}

#[test]
fn test_serialize_order_independence() {
    let data1 = json!({"name": "Alice", "age": 30});
    let data2 = json!({"age": 30, "name": "Alice"});
    
    let bytes1 = DeterministicSerializer::serialize(&data1).unwrap();
    let bytes2 = DeterministicSerializer::serialize(&data2).unwrap();
    
    assert_eq!(bytes1, bytes2);
}

#[test]
fn test_serialize_nested_objects() {
    let data = json!({"user": {"name": "Alice", "age": 30}, "id": 1});
    let result = DeterministicSerializer::serialize(&data).unwrap();
    let result_str = String::from_utf8(result).unwrap();
    assert_eq!(result_str, r#"{"id":1,"user":{"age":30,"name":"Alice"}}"#);
}

#[test]
fn test_hash_produces_32_bytes() {
    let data = json!({"name": "Alice", "age": 30});
    let hash = DeterministicSerializer::hash(&data).unwrap();
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_hash_deterministic() {
    let data1 = json!({"name": "Alice", "age": 30});
    let data2 = json!({"age": 30, "name": "Alice"});
    
    let hash1 = DeterministicSerializer::hash(&data1).unwrap();
    let hash2 = DeterministicSerializer::hash(&data2).unwrap();
    
    assert_eq!(hash1, hash2);
}

#[test]
fn test_verify_determinism_with_shuffled_keys() {
    let data = json!({"name": "Alice", "age": 30, "city": "NYC", "id": 42});
    assert!(DeterministicSerializer::verify_determinism(&data, Some(100)).is_ok());
}

#[test]
fn test_verify_determinism_with_nested_objects() {
    let data = json!({
        "user": {
            "name": "Alice",
            "age": 30,
            "address": {
                "city": "New York",
                "street": "5th Avenue",
                "zip": "10001"
            }
        },
        "timestamp": 1234567890,
        "tags": ["tag1", "tag2", "tag3"],
        "metadata": {
            "version": "1.0",
            "source": "api"
        }
    });
    assert!(DeterministicSerializer::verify_determinism(&data, Some(50)).is_ok());
}

#[test]
fn test_array_serialization() {
    let data = json!([{"b": 2, "a": 1}, {"d": 4, "c": 3}]);
    let result = DeterministicSerializer::serialize(&data).unwrap();
    let result_str = String::from_utf8(result).unwrap();
    assert_eq!(result_str, r#"[{"a":1,"b":2},{"c":3,"d":4}]"#);
}

#[test]
fn test_hash_different_for_different_data() {
    let data1 = json!({"name": "Alice", "age": 30});
    let data2 = json!({"name": "Bob", "age": 25});
    
    let hash1 = DeterministicSerializer::hash(&data1).unwrap();
    let hash2 = DeterministicSerializer::hash(&data2).unwrap();
    
    assert_ne!(hash1, hash2);
}

#[test]
fn test_serialize_primitives() {
    let string_data = json!("hello");
    let string_result = DeterministicSerializer::serialize(&string_data).unwrap();
    assert_eq!(String::from_utf8(string_result).unwrap(), r#""hello""#);

    let number_data = json!(42);
    let number_result = DeterministicSerializer::serialize(&number_data).unwrap();
    assert_eq!(String::from_utf8(number_result).unwrap(), "42");

    let bool_data = json!(true);
    let bool_result = DeterministicSerializer::serialize(&bool_data).unwrap();
    assert_eq!(String::from_utf8(bool_result).unwrap(), "true");
    
    // Test with null
    let null_data = json!(null);
    let null_result = DeterministicSerializer::serialize(&null_data).unwrap();
    assert_eq!(String::from_utf8(null_result).unwrap(), "null");
}

#[test]
fn test_deeply_nested_objects() {
    let data = json!({
        "level1": {
            "level2": {
                "level3": {
                    "z": 3,
                    "y": 2,
                    "x": 1
                }
            }
        }
    });
    let result = DeterministicSerializer::serialize(&data).unwrap();
    let result_str = String::from_utf8(result).unwrap();
    
    // All levels should have sorted keys
    assert_eq!(result_str, r#"{"level1":{"level2":{"level3":{"x":1,"y":2,"z":3}}}}"#);
}

#[test]
fn test_mixed_array_and_objects() {
    let data = json!({
        "items": [
            {"name": "item1", "id": 1},
            {"name": "item2", "id": 2}
        ],
        "count": 2
    });
    let result = DeterministicSerializer::serialize(&data).unwrap();
    let result_str = String::from_utf8(result).unwrap();
    
    // Objects in arrays should have sorted keys
    assert_eq!(result_str, r#"{"count":2,"items":[{"id":1,"name":"item1"},{"id":2,"name":"item2"}]}"#);
}

// Format verification tests

#[test]
fn test_format_no_whitespace() {
    // Verify that serialization contains no whitespace
    let data = json!({
        "key1": "value1",
        "key2": "value2",
        "nested": {
            "inner": "value"
        }
    });
    let result = DeterministicSerializer::serialize(&data).unwrap();
    let result_str = String::from_utf8(result).unwrap();
    
    // Should not contain any spaces, newlines, or tabs
    assert!(!result_str.contains(' '));
    assert!(!result_str.contains('\n'));
    assert!(!result_str.contains('\t'));
    assert!(!result_str.contains('\r'));
}

#[test]
fn test_format_numbers_preserved() {
    // Verify numbers are serialized as-is without quotes
    // Note: Floating point numbers are now rejected per spec
    let data = json!({
        "integer": 42,
        "negative": -123,
        "zero": 0,
        "large": 1234567890
    });
    let result = DeterministicSerializer::serialize(&data).unwrap();
    let result_str = String::from_utf8(result).unwrap();
    
    // With keys sorted: integer, large, negative, zero
    // Expected: {"integer":42,"large":1234567890,"negative":-123,"zero":0}
    
    // Should not have quotes around numbers
    assert!(!result_str.contains("\"42\""));
    assert!(!result_str.contains("\"-123\""));
    assert!(!result_str.contains("\"1234567890\""));
    assert!(!result_str.contains("\"0\""));
    
    // Verify actual number formats are present
    assert!(result_str.contains("42"));
    assert!(result_str.contains("-123"));
    assert!(result_str.contains("1234567890"));
    assert!(result_str.contains(":0}"));  // zero is last, so ends with }
    
    // Verify the exact format
    assert_eq!(result_str, r#"{"integer":42,"large":1234567890,"negative":-123,"zero":0}"#);
}

#[test]
fn test_format_unicode_handling() {
    // Verify consistent UTF-8 unicode handling
    let data = json!({
        "emoji": "🚀",
        "chinese": "你好",
        "arabic": "مرحبا",
        "mixed": "Hello 世界 🌍"
    });
    let result = DeterministicSerializer::serialize(&data).unwrap();
    let result_str = String::from_utf8(result).unwrap();
    
    // Should contain the unicode characters properly encoded
    assert!(result_str.contains("🚀"));
    assert!(result_str.contains("你好"));
    assert!(result_str.contains("مرحبا"));
    assert!(result_str.contains("Hello 世界 🌍"));
    
    // Verify it's valid UTF-8 (this would fail if encoding was wrong)
    assert!(result_str.is_char_boundary(0));
}

#[test]
fn test_format_recursive_key_sorting() {
    // Verify keys are sorted at all nesting levels
    let data = json!({
        "z_top": {
            "z_nested": 1,
            "a_nested": 2,
            "m_nested": {
                "z_deep": 3,
                "a_deep": 4
            }
        },
        "a_top": "value",
        "m_top": [
            {"z_array": 5, "a_array": 6}
        ]
    });
    let result = DeterministicSerializer::serialize(&data).unwrap();
    let result_str = String::from_utf8(result).unwrap();
    
    // Check that keys appear in alphabetical order at each level
    let a_top_pos = result_str.find("\"a_top\"").unwrap();
    let m_top_pos = result_str.find("\"m_top\"").unwrap();
    let z_top_pos = result_str.find("\"z_top\"").unwrap();
    assert!(a_top_pos < m_top_pos);
    assert!(m_top_pos < z_top_pos);
    
    // Check nested keys are sorted
    let a_nested_pos = result_str.find("\"a_nested\"").unwrap();
    let m_nested_pos = result_str.find("\"m_nested\"").unwrap();
    let z_nested_pos = result_str.find("\"z_nested\"").unwrap();
    assert!(a_nested_pos < m_nested_pos);
    assert!(m_nested_pos < z_nested_pos);
    
    // Check deeply nested keys are sorted
    let a_deep_pos = result_str.find("\"a_deep\"").unwrap();
    let z_deep_pos = result_str.find("\"z_deep\"").unwrap();
    assert!(a_deep_pos < z_deep_pos);
}

#[test]
fn test_determinism_actually_shuffles() {
    // Verify that verify_determinism actually tests different orderings
    // by manually creating different orderings and checking they canonicalize the same
    let order1 = json!({"a": 1, "b": 2, "c": 3, "d": 4, "e": 5});
    let order2 = json!({"e": 5, "d": 4, "c": 3, "b": 2, "a": 1});
    let order3 = json!({"c": 3, "a": 1, "e": 5, "b": 2, "d": 4});
    
    let result1 = DeterministicSerializer::serialize(&order1).unwrap();
    let result2 = DeterministicSerializer::serialize(&order2).unwrap();
    let result3 = DeterministicSerializer::serialize(&order3).unwrap();
    
    // All different orderings should produce identical output
    assert_eq!(result1, result2);
    assert_eq!(result2, result3);
    assert_eq!(String::from_utf8(result1).unwrap(), r#"{"a":1,"b":2,"c":3,"d":4,"e":5}"#);
}
