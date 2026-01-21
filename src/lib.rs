pub mod core;

// Re-export commonly used types for convenience
pub use core::signature_algorithms::{
    SignatureAlgorithm, SignatureData, TypedData, SignatureAlgorithmError
};