use serde_json::{Map, Value};
use sha3::{Digest, Keccak256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SerializationError {
    #[error("Failed to serialize JSON: {0}")]
    JsonSerialize(#[from] serde_json::Error),

    #[error("Serialization produced different results across iterations")]
    NonDeterministic,
    
    #[error("Floating point numbers are not allowed in cryptographic serialization: {0}")]
    FloatingPointNotAllowed(f64),
}

/// Canonical JSON (sorted keys, no whitespace) and Keccak-256; for EIP-712.
pub struct DeterministicSerializer;

impl DeterministicSerializer {
    pub fn serialize(data: &Value) -> Result<Vec<u8>, SerializationError> {
        let canonical_value = Self::canonicalize_value(data.clone())?;
        let canonical_json = serde_json::to_string(&canonical_value)?;
        Ok(canonical_json.into_bytes())
    }

    pub fn hash(data: &Value) -> Result<[u8; 32], SerializationError> {
        let canonical_bytes = Self::serialize(data)?;

        let mut hasher = Keccak256::new();
        hasher.update(&canonical_bytes);
        let hash = hasher.finalize();

        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash);
        Ok(hash_array)
    }

    pub fn verify_determinism(data: &Value, iterations: Option<usize>) -> Result<(), SerializationError> {
        let n = iterations.unwrap_or(1000);
        let reference = Self::serialize(data)?;

        for _ in 0..n {
            let variation = Self::create_variation(data);
            let serialized = Self::serialize(&variation)?;
            if serialized != reference {
                return Err(SerializationError::NonDeterministic);
            }
        }
        Ok(())
    }

    fn create_variation(value: &Value) -> Value {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hash, Hasher};

        match value {
            Value::Object(map) => {
                let mut entries: Vec<(String, Value)> = map
                    .iter()
                    .map(|(k, v)| (k.clone(), Self::create_variation(v)))
                    .collect();

                let random_state = RandomState::new();
                entries.sort_by(|a, b| {
                    let mut hasher_a = random_state.build_hasher();
                    let mut hasher_b = random_state.build_hasher();
                    a.0.hash(&mut hasher_a);
                    b.0.hash(&mut hasher_b);
                    hasher_a.finish().cmp(&hasher_b.finish())
                });
                
                let mut new_map = Map::new();
                for (k, v) in entries {
                    new_map.insert(k, v);
                }
                Value::Object(new_map)
            }
            Value::Array(arr) => Value::Array(arr.iter().map(Self::create_variation).collect()),
            other => other.clone(),
        }
    }

    fn canonicalize_value(value: Value) -> Result<Value, SerializationError> {
        match value {
            Value::Object(map) => {
                let mut sorted_map = Map::new();
                let mut keys: Vec<String> = map.keys().cloned().collect();
                keys.sort();
                for key in keys {
                    if let Some(val) = map.get(&key) {
                        sorted_map.insert(key, Self::canonicalize_value(val.clone())?);
                    }
                }
                Ok(Value::Object(sorted_map))
            }
            Value::Array(arr) => {
                let canonicalized: Result<Vec<Value>, SerializationError> = arr
                    .into_iter()
                    .map(Self::canonicalize_value)
                    .collect();
                Ok(Value::Array(canonicalized?))
            }
            Value::Number(n) => {
                if !n.is_i64() && !n.is_u64() {
                    let f = n.as_f64().unwrap_or(0.0);
                    return Err(SerializationError::FloatingPointNotAllowed(f));
                }
                Ok(Value::Number(n))
            }
            other => Ok(other),
        }
    }
}
