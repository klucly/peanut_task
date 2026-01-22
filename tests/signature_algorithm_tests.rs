use peanut_task::core::signature_algorithms::{
    Eip191Hasher, Eip712Hasher, SignatureHasher, SignatureData,
    compute_hash_with_algorithm
};
use peanut_task::core::utility::{Message, TypedData};
use serde_json::json;

#[test]
fn test_eip191_hash_consistency() {
    let hasher = Eip191Hasher;
    let message = Message("Hello, Ethereum!".to_string());
    
    let hash1 = hasher.compute_hash(&message).unwrap();
    let hash2 = hasher.compute_hash(&message).unwrap();
    
    assert_eq!(hash1, hash2, "Hashes should be deterministic");
}

#[test]
fn test_eip712_hash_consistency() {
    let hasher = Eip712Hasher;
    let typed_data = TypedData::new(
        json!({"name": "Test"}),
        json!({"Person": [{"name": "name", "type": "string"}]}),
        json!({"name": "Alice"})
    );
    
    let hash1 = hasher.compute_hash(&typed_data).unwrap();
    let hash2 = hasher.compute_hash(&typed_data).unwrap();
    
    assert_eq!(hash1, hash2, "Hashes should be deterministic");
}

#[test]
fn test_signature_data_dispatch() {
    let message_data = SignatureData::from_message(Message("Hello".to_string()));
    let hash1 = compute_hash_with_algorithm(&message_data).unwrap();
    
    assert_eq!(hash1.len(), 32, "Hash should be 32 bytes");
    
    let typed_data = SignatureData::from_typed_data(TypedData::new(
        json!({}),
        json!({}),
        json!({})
    ));
    let hash2 = compute_hash_with_algorithm(&typed_data).unwrap();
    
    assert_eq!(hash2.len(), 32, "Hash should be 32 bytes");
    assert_ne!(hash1, hash2, "Different data should produce different hashes");
}
