//! Mempool monitor for detecting pending DEX swap transactions.

use crate::core::base_types::{Address, Transaction};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use futures_util::StreamExt;
use rust_decimal::prelude::FromPrimitive;
use rust_decimal::Decimal;
use std::sync::Arc;
use thiserror::Error;

/// Parsed swap transaction from mempool.
#[derive(Debug, Clone)]
pub struct ParsedSwap {
    pub tx_hash: String,
    pub router: String,
    pub dex: String,
    pub method: String,
    pub token_in: Option<Address>,
    pub token_out: Option<Address>,
    pub amount_in: u128,
    pub min_amount_out: u128,
    pub deadline: u64,
    pub sender: Address,
    pub gas_price: u64,
}

impl ParsedSwap {
    /// Returns `None` without expected output. Use `slippage_tolerance_with_expected` when caller has price context.
    pub fn slippage_tolerance(&self) -> Option<Decimal> {
        None
    }

    /// Calculate implied slippage tolerance when expected output is known.
    /// Returns `1 - (min_amount_out / expected_out)` as Decimal.
    pub fn slippage_tolerance_with_expected(&self, expected_out: u128) -> Option<Decimal> {
        if expected_out == 0 {
            return None;
        }
        let min = Decimal::from_u128(self.min_amount_out)?;
        let expected = Decimal::from_u128(expected_out)?;
        let ratio = min / expected;
        Some(Decimal::ONE - ratio)
    }
}

fn selector_info(sel: &[u8]) -> Option<(&'static str, &'static str)> {
    if sel.len() < 4 {
        return None;
    }
    match (sel[0], sel[1], sel[2], sel[3]) {
        (0x38, 0xed, 0x17, 0x39) => Some(("UniswapV2", "swapExactTokensForTokens")),
        (0x7f, 0xf3, 0x6a, 0xb5) => Some(("UniswapV2", "swapExactETHForTokens")),
        (0x18, 0xcb, 0xaf, 0xe5) => Some(("UniswapV2", "swapExactTokensForETH")),
        _ => None,
    }
}

fn decode_u256(data: &[u8], offset: usize) -> Option<u128> {
    if offset + 32 > data.len() {
        return None;
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&data[offset..offset + 32]);
    let mut v: u128 = 0;
    for b in &raw {
        v = v.wrapping_mul(256).wrapping_add(*b as u128);
    }
    Some(v)
}

fn decode_address(data: &[u8], offset: usize) -> Option<Address> {
    if offset + 32 > data.len() {
        return None;
    }
    let addr = &data[offset + 12..offset + 32];
    let s = format!("0x{}", hex::encode(addr));
    Address::from_string(&s).ok()
}

#[derive(Debug)]
struct SwapParams {
    amount_in: u128,
    min_amount_out: u128,
    token_in: Option<Address>,
    token_out: Option<Address>,
    deadline: u64,
}

/// Decode ABI-encoded address[] path: returns (path[0], path[last]).
fn decode_path(data: &[u8], path_offset: usize) -> Result<(Option<Address>, Option<Address>), DecodeError> {
    let path_base = 4 + path_offset;
    if path_base + 32 > data.len() {
        return Err(DecodeError::TruncatedData);
    }
    let path_len = decode_u256(data, path_base).ok_or(DecodeError::InvalidCalldata)? as usize;
    if path_len < 2 {
        return Err(DecodeError::InvalidCalldata);
    }
    let token_in = decode_address(data, path_base + 32);
    let token_out = decode_address(data, path_base + 32 + (path_len - 1) * 32);
    Ok((token_in, token_out))
}

fn decode_swap_exact_tokens_for_tokens(data: &[u8]) -> Result<SwapParams, DecodeError> {
    if data.len() < 4 + 32 * 5 {
        return Err(DecodeError::TruncatedData);
    }
    let amount_in = decode_u256(data, 4).ok_or(DecodeError::InvalidCalldata)?;
    let amount_out_min = decode_u256(data, 4 + 32).ok_or(DecodeError::InvalidCalldata)?;
    let path_offset = decode_u256(data, 4 + 64).ok_or(DecodeError::InvalidCalldata)? as usize;
    let deadline = decode_u256(data, 4 + 128).ok_or(DecodeError::InvalidCalldata)? as u64;

    let (token_in, token_out) = decode_path(data, path_offset)?;

    Ok(SwapParams {
        amount_in,
        min_amount_out: amount_out_min,
        token_in,
        token_out,
        deadline,
    })
}

fn decode_swap_exact_eth_for_tokens(data: &[u8], tx_value: u128) -> Result<SwapParams, DecodeError> {
    if data.len() < 4 + 32 * 4 {
        return Err(DecodeError::TruncatedData);
    }
    let amount_out_min = decode_u256(data, 4).ok_or(DecodeError::InvalidCalldata)?;
    let path_offset = decode_u256(data, 4 + 32).ok_or(DecodeError::InvalidCalldata)? as usize;
    let deadline = decode_u256(data, 4 + 96).ok_or(DecodeError::InvalidCalldata)? as u64;

    let (_, token_out) = decode_path(data, path_offset)?;

    Ok(SwapParams {
        amount_in: tx_value,
        min_amount_out: amount_out_min,
        token_in: None,
        token_out,
        deadline,
    })
}

fn decode_swap_params(
    method: &str,
    data: &[u8],
    tx_value: u128,
) -> Result<SwapParams, DecodeError> {
    match method {
        "swapExactTokensForTokens" | "swapExactTokensForETH" => decode_swap_exact_tokens_for_tokens(data),
        "swapExactETHForTokens" => decode_swap_exact_eth_for_tokens(data, tx_value),
        _ => Err(DecodeError::UnknownSelector),
    }
}

#[derive(Debug, Error)]
enum DecodeError {
    #[error("Unknown selector")]
    UnknownSelector,
    #[error("Invalid calldata")]
    InvalidCalldata,
    #[error("Truncated data")]
    TruncatedData,
}

/// Parse transaction to extract swap details. Returns `None` if not a known swap.
pub fn parse_transaction(tx: &Transaction, tx_hash: &str) -> Option<ParsedSwap> {
    if tx.data.len() < 4 {
        return None;
    }
    let selector = &tx.data[0..4];
    let (dex, method) = selector_info(selector)?;
    let params = decode_swap_params(method, &tx.data, tx.value.raw).ok()?;

    let gas_price = tx.max_fee_per_gas.unwrap_or(0);
    let sender = tx.from.clone().unwrap_or_else(Address::zero);

    Some(ParsedSwap {
        tx_hash: tx_hash.to_string(),
        router: dex.to_string(),
        dex: dex.to_string(),
        method: method.to_string(),
        token_in: params.token_in,
        token_out: params.token_out,
        amount_in: params.amount_in,
        min_amount_out: params.min_amount_out,
        deadline: params.deadline,
        sender,
        gas_price,
    })
}

/// Monitors pending transactions for swap activity.
pub struct MempoolMonitor {
    ws_url: String,
    callback: Arc<dyn Fn(ParsedSwap) + Send + Sync>,
}

#[derive(Debug, Error)]
pub enum MempoolMonitorError {
    #[error("WebSocket connection failed: {0}")]
    Connection(String),

    #[error("Subscription failed: {0}")]
    Subscription(String),

    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Parse error: {0}")]
    Parse(String),
}

impl MempoolMonitor {
    pub fn new(
        ws_url: impl Into<String>,
        callback: impl Fn(ParsedSwap) + Send + Sync + 'static,
    ) -> Self {
        Self {
            ws_url: ws_url.into(),
            callback: Arc::new(callback),
        }
    }

    /// Start monitoring pending transactions. Runs until connection error.
    pub async fn start(&self) -> Result<(), MempoolMonitorError> {
        let ws = WsConnect::new(&self.ws_url);
        let provider = ProviderBuilder::new()
            .connect_ws(ws)
            .await
            .map_err(|e| MempoolMonitorError::Connection(e.to_string()))?;

        let callback = Arc::clone(&self.callback);

        let sub_result = provider.subscribe_full_pending_transactions().await;

        if let Ok(sub) = sub_result {
            let mut stream = sub.into_stream();
            while let Some(tx) = stream.next().await {
                if let Some(swap) = Self::process_full_tx(&tx) {
                    let cb = Arc::clone(&callback);
                    tokio::spawn(async move {
                        cb(swap);
                    });
                }
            }
            return Ok(());
        }

        let sub = provider
            .subscribe_pending_transactions()
            .await
            .map_err(|e| MempoolMonitorError::Subscription(e.to_string()))?;
        let mut stream = sub.into_stream();
        while let Some(tx_hash) = stream.next().await {
            if let Some(swap) = Self::process_hash(tx_hash, &provider).await {
                let cb = Arc::clone(&callback);
                tokio::spawn(async move {
                    cb(swap);
                });
            }
        }
        Ok(())
    }

    fn process_full_tx(tx: &alloy::rpc::types::Transaction) -> Option<ParsedSwap> {
        let tx_json = serde_json::to_value(tx).ok()?;
        let hash = tx_json
            .get("hash")
            .or_else(|| tx_json.get("transactionHash"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())?;
        let our_tx = Transaction::from_web3(tx_json).ok()?;
        parse_transaction(&our_tx, &hash)
    }

    async fn process_hash<P: Provider>(
        tx_hash: alloy::primitives::B256,
        provider: &P,
    ) -> Option<ParsedSwap> {
        let tx = provider.get_transaction_by_hash(tx_hash).await.ok()??;
        let hash = format!("0x{:x}", tx_hash);
        let tx_json = serde_json::to_value(&tx).ok()?;
        let our_tx = Transaction::from_web3(tx_json).ok()?;
        parse_transaction(&our_tx, &hash)
    }
}
