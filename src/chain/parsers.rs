use alloy::primitives::B256;
use alloy::rpc::types::{BlockId, BlockNumberOrTag};
use crate::chain::errors::ChainClientError;
use hex;

pub fn parse_tx_hash(tx_hash: &str) -> Result<B256, ChainClientError> {
    if !tx_hash.starts_with("0x") {
        return Err(ChainClientError::InvalidResponse(
            format!("Transaction hash must start with '0x': {}", tx_hash)
        ));
    }
    let hex_part = &tx_hash[2..];
    if hex_part.len() != 64 {
        return Err(ChainClientError::InvalidResponse(
            format!("Transaction hash must be 64 hex characters (32 bytes): got {} characters", hex_part.len())
        ));
    }
    let bytes = hex::decode(hex_part)
        .map_err(|e| ChainClientError::InvalidResponse(
            format!("Invalid transaction hash hex '{}': {}", tx_hash, e)
        ))?;
    if bytes.len() != 32 {
        return Err(ChainClientError::InvalidResponse(
            format!("Transaction hash must be 32 bytes: got {} bytes", bytes.len())
        ));
    }
    Ok(B256::from_slice(&bytes))
}

pub fn parse_block_id(block: &str) -> Result<BlockId, ChainClientError> {
    match block.to_lowercase().as_str() {
        "latest" => Ok(BlockId::Number(BlockNumberOrTag::Latest)),
        "pending" => Ok(BlockId::Number(BlockNumberOrTag::Pending)),
        "earliest" => Ok(BlockId::Number(BlockNumberOrTag::Earliest)),
        _ => {
            if let Some(hex_str) = block.strip_prefix("0x") {
                u64::from_str_radix(hex_str, 16)
                    .map(|n| BlockId::Number(BlockNumberOrTag::Number(n)))
                    .map_err(|_| ChainClientError::InvalidResponse(
                        format!("Invalid block number (hex): {}", block)
                    ))
            } else {
                block.parse::<u64>()
                    .map(|n| BlockId::Number(BlockNumberOrTag::Number(n)))
                    .map_err(|_| ChainClientError::InvalidResponse(
                        format!("Invalid block identifier: {}", block)
                    ))
            }
        }
    }
}
