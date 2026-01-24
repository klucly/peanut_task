use std::fmt;
use thiserror::Error;

use super::utility::Address;
use super::signature_algorithms::{
    SignatureAlgorithm, SignatureData, SignatureAlgorithmError,
    verify_and_recover_with_algorithm, recover_signer_with_algorithm
};

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Signature algorithm error: {0}")]
    AlgorithmError(SignatureAlgorithmError),
    
    #[error("Signature verification failed: signer mismatch")]
    SignerMismatch,
}

impl From<SignatureAlgorithmError> for SignatureError {
    fn from(err: SignatureAlgorithmError) -> Self {
        match err {
            SignatureAlgorithmError::SignerMismatch => SignatureError::SignerMismatch,
            other => SignatureError::AlgorithmError(other),
        }
    }
}

#[derive(Clone)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

impl Signature {
    pub fn new(r: [u8; 32], s: [u8; 32], v: u8) -> Self {
        Self { r, s, v }
    }

    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[0..32].copy_from_slice(&self.r);
        bytes[32..64].copy_from_slice(&self.s);
        bytes[64] = self.v;
        bytes
    }

    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("r", &format_args!("0x{}", hex::encode(&self.r)))
            .field("s", &format_args!("0x{}", hex::encode(&self.s)))
            .field("v", &self.v)
            .finish()
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

pub struct SignedMessage {
    pub signature_data: SignatureData,
    pub signature: Signature,
}

impl SignedMessage {
    pub fn verify(&self) -> Result<(), SignatureError> {
        recover_signer_with_algorithm(&self.signature_data, &self.signature)?;
        Ok(())
    }

    pub fn recover_signer(&self) -> Result<Address, SignatureError> {
        Ok(recover_signer_with_algorithm(&self.signature_data, &self.signature)?)
    }

    pub fn algorithm(&self) -> SignatureAlgorithm {
        match &self.signature_data {
            SignatureData::Message(_) => SignatureAlgorithm::Eip191,
            SignatureData::TypedData { .. } => SignatureAlgorithm::Eip712,
        }
    }

    pub fn new(
        signature_data: SignatureData,
        signature: Signature,
        expected_signer: &Address
    ) -> Result<Self, SignatureError> {
        verify_and_recover_with_algorithm(&signature_data, &signature, expected_signer)?;
        
        Ok(Self {
            signature_data,
            signature,
        })
    }
}

impl fmt::Debug for SignedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedMessage")
            .field("signature_data", &self.signature_data)
            .field("signature", &self.signature)
            .finish()
    }
}

impl fmt::Display for SignedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.signature_data {
            SignatureData::Message(msg) => {
                write!(f, "Message: \"{}\"\nSignature: {}", msg.0, self.signature)
            }
            SignatureData::TypedData { .. } => {
                write!(f, "TypedData\nSignature: {}", self.signature)
            }
        }
    }
}
