//! Canonical JSON serialization for cryptographic operations.
//!
//! This module provides deterministic JSON serialization that ensures the same
//! data always produces the same byte representation, which is critical for
//! cryptographic operations like signing and hashing.

use serde_json::{Map, Value};
use sha3::{Digest, Keccak256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SerializationError {
    #[error("Failed to serialize JSON: {0}")]
    JsonSerialize(#[from] serde_json::Error),

    #[error("Serialization produced different results across iterations")]
    NonDeterministic,
}

/// Provides deterministic, canonical JSON serialization for cryptographic operations.
///
/// The serializer ensures the following format:
/// - **Keys sorted alphabetically** (recursively for nested objects)
/// - **No whitespace** (compact JSON format)
/// - **Numbers as-is** (preserved in their original numeric form)
/// - **Consistent unicode handling** (UTF-8 encoded)
/// - The same input always produces the same output
/// - Output is suitable for cryptographic hashing and signing
pub struct Serializer;

impl Serializer {
    /// Serializes JSON data into a canonical byte representation.
    ///
    /// The serialization is deterministic: the same JSON data will always produce
    /// the same byte sequence, regardless of the order keys appear in the input.
    ///
    /// Object keys are sorted alphabetically, and the output uses compact JSON
    /// formatting (no extra whitespace).
    ///
    /// # Arguments
    /// * `data` - A JSON value to serialize
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The canonical byte representation of the JSON
    /// * `Err(SerializationError)` - If the JSON cannot be serialized
    ///
    /// # Examples
    /// ```
    /// # use peanut_task::core::serializer::Serializer;
    /// # use serde_json::json;
    /// let data = json!({"name": "Alice", "age": 30});
    /// let bytes = Serializer::serialize(&data).unwrap();
    /// ```
    pub fn serialize(data: &Value) -> Result<Vec<u8>, SerializationError> {
        // Canonicalize the JSON (sort keys recursively)
        let canonical_value = Self::canonicalize_value(data.clone());
        
        // Serialize to compact JSON string
        let canonical_json = serde_json::to_string(&canonical_value)?;
        
        // Convert to bytes
        Ok(canonical_json.into_bytes())
    }

    /// Computes the Keccak-256 hash of the canonical JSON serialization.
    ///
    /// This is useful for cryptographic operations where you need a fixed-size
    /// digest of JSON data. The hash is deterministic: the same JSON data
    /// (regardless of key order) will always produce the same hash.
    ///
    /// # Arguments
    /// * `data` - A JSON value to hash
    ///
    /// # Returns
    /// * `Ok([u8; 32])` - The 32-byte Keccak-256 hash
    /// * `Err(SerializationError)` - If the JSON cannot be serialized
    ///
    /// # Examples
    /// ```
    /// # use peanut_task::core::serializer::Serializer;
    /// # use serde_json::json;
    /// let data = json!({"name": "Alice", "age": 30});
    /// let hash = Serializer::hash(&data).unwrap();
    /// assert_eq!(hash.len(), 32);
    /// ```
    pub fn hash(data: &Value) -> Result<[u8; 32], SerializationError> {
        // Get the canonical serialization
        let canonical_bytes = Self::serialize(data)?;
        
        // Hash with Keccak-256
        let mut hasher = Keccak256::new();
        hasher.update(&canonical_bytes);
        let hash = hasher.finalize();
        
        // Convert to fixed-size array
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash);
        
        Ok(hash_array)
    }

    /// Verifies that serialization is deterministic by creating variations of the same data.
    ///
    /// This function tests that different representations of semantically identical data
    /// (e.g., same object with keys in different orders) all produce the same canonical
    /// serialization. This ensures the serializer is truly deterministic.
    ///
    /// For objects, this method creates N variations with randomly shuffled key orders
    /// and verifies they all serialize to the same bytes.
    ///
    /// # Arguments
    /// * `data` - A JSON value to test
    /// * `iterations` - Number of variations to create and test (default: 100)
    ///
    /// # Returns
    /// * `Ok(())` - If all variations produce identical output
    /// * `Err(SerializationError)` - If any variation differs or serialization fails
    ///
    /// # Examples
    /// ```
    /// # use peanut_task::core::serializer::Serializer;
    /// # use serde_json::json;
    /// let data = json!({"name": "Alice", "age": 30, "city": "NYC"});
    /// // Creates 100 variations with different key orders, verifies all serialize identically
    /// Serializer::verify_determinism(&data, Some(100)).unwrap();
    /// ```
    pub fn verify_determinism(data: &Value, iterations: Option<usize>) -> Result<(), SerializationError> {
        let n = iterations.unwrap_or(100);
        
        // Get the canonical serialization as reference
        let reference = Self::serialize(data)?;
        
        // Create variations of the data and verify they all serialize the same
        for _ in 0..n {
            // Create a variation (shuffled keys for objects)
            let variation = Self::create_variation(data);
            let serialized = Self::serialize(&variation)?;
            
            if serialized != reference {
                return Err(SerializationError::NonDeterministic);
            }
        }
        
        Ok(())
    }

    /// Creates a structural variation of the data by shuffling object keys.
    ///
    /// This produces semantically identical data with potentially different key orders,
    /// which is useful for testing determinism.
    fn create_variation(value: &Value) -> Value {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hash, Hasher};
        
        match value {
            Value::Object(map) => {
                // Collect entries and shuffle using a random seed
                let mut entries: Vec<(String, Value)> = map
                    .iter()
                    .map(|(k, v)| (k.clone(), Self::create_variation(v)))
                    .collect();
                
                // Pseudo-shuffle by sorting with a random-ish comparator
                // This creates different orderings while being deterministic enough for testing
                let random_state = RandomState::new();
                entries.sort_by(|a, b| {
                    let mut hasher_a = random_state.build_hasher();
                    let mut hasher_b = random_state.build_hasher();
                    a.0.hash(&mut hasher_a);
                    b.0.hash(&mut hasher_b);
                    hasher_a.finish().cmp(&hasher_b.finish())
                });
                
                // Build new object with shuffled keys
                let mut new_map = Map::new();
                for (k, v) in entries {
                    new_map.insert(k, v);
                }
                Value::Object(new_map)
            }
            Value::Array(arr) => {
                // Recursively create variations for array elements
                Value::Array(arr.iter().map(Self::create_variation).collect())
            }
            // Primitive types are returned as-is
            other => other.clone(),
        }
    }

    /// Recursively canonicalizes a JSON value by sorting all object keys.
    ///
    /// This ensures that two JSON objects with the same content but different
    /// key orders will produce identical canonical representations.
    fn canonicalize_value(value: Value) -> Value {
        match value {
            Value::Object(map) => {
                // Create a new map with sorted keys
                let mut sorted_map = Map::new();
                
                // Collect and sort keys
                let mut keys: Vec<String> = map.keys().cloned().collect();
                keys.sort();
                
                // Insert values in sorted order, recursively canonicalizing nested values
                for key in keys {
                    if let Some(val) = map.get(&key) {
                        sorted_map.insert(key, Self::canonicalize_value(val.clone()));
                    }
                }
                
                Value::Object(sorted_map)
            }
            Value::Array(arr) => {
                // Recursively canonicalize array elements
                Value::Array(arr.into_iter().map(Self::canonicalize_value).collect())
            }
            // Primitive types are already canonical
            other => other,
        }
    }
}
