use tokio::time::{sleep, Duration, Instant};
use alloy::primitives::B256;
use alloy::providers::{Provider, ProviderBuilder};
use serde_json;
use crate::chain::{RpcUrl, errors::ChainClientError};
use crate::core::base_types::TransactionReceipt;

enum PollResult {
    Found(TransactionReceipt),
    NotFound,
    AllFailed,
}

pub async fn poll_for_receipt(
    rpc_urls: Vec<RpcUrl>,
    hash: B256,
    timeout: u64,
    poll_interval: f64,
) -> Result<TransactionReceipt, ChainClientError> {
    let timeout_duration = Duration::from_secs(timeout);
    let poll_duration = Duration::from_secs_f64(poll_interval);
    let start = Instant::now();

    loop {
        check_timeout_exceeded(start, timeout_duration, timeout)?;

        match try_all_rpc_urls_for_receipt(&rpc_urls, hash).await {
            PollResult::Found(receipt) => return Ok(receipt),
            PollResult::NotFound => {
                match wait_before_next_poll_when_not_found(
                    start,
                    timeout_duration,
                    poll_duration,
                    timeout,
                    &rpc_urls,
                    hash,
                ).await {
                    Ok(Some(receipt)) => return Ok(receipt),
                    Ok(None) => continue,
                    Err(e) => return Err(e),
                }
            }
            PollResult::AllFailed => {
                wait_and_retry_after_all_failed(
                    start,
                    timeout_duration,
                    poll_duration,
                    timeout,
                ).await?;
            }
        }
    }
}

fn check_timeout_exceeded(
    start: Instant,
    timeout_duration: Duration,
    timeout: u64,
) -> Result<(), ChainClientError> {
    if start.elapsed() >= timeout_duration {
        return Err(ChainClientError::TimeoutError(
            format!("Timeout waiting for receipt after {} seconds", timeout)
        ));
    }
    Ok(())
}

async fn try_all_rpc_urls_for_receipt(
    rpc_urls: &[RpcUrl],
    hash: B256,
) -> PollResult {
    let mut found_none = false;
    for rpc_url in rpc_urls {
        match try_get_receipt_from_url_async(rpc_url, hash).await {
            Ok(Some(receipt)) => return PollResult::Found(receipt),
            Ok(None) => {
                found_none = true;
            }
            Err(_) => {
                continue;
            }
        }
    }
    if found_none {
        PollResult::NotFound
    } else {
        PollResult::AllFailed
    }
}

async fn wait_before_next_poll_when_not_found(
    start: Instant,
    timeout_duration: Duration,
    poll_duration: Duration,
    timeout: u64,
    rpc_urls: &[RpcUrl],
    hash: B256,
) -> Result<Option<TransactionReceipt>, ChainClientError> {
    let elapsed = start.elapsed();
    let remaining = timeout_duration.saturating_sub(elapsed);
    if remaining > poll_duration {
        sleep(poll_duration).await;
        Ok(None)
    } else if remaining.is_zero() {
        Err(ChainClientError::TimeoutError(
            format!("Timeout waiting for receipt after {} seconds", timeout)
        ))
    } else {
        wait_and_final_check(remaining, timeout, rpc_urls, hash).await.map(Some)
    }
}

async fn wait_and_final_check(
    remaining: Duration,
    timeout: u64,
    rpc_urls: &[RpcUrl],
    hash: B256,
) -> Result<TransactionReceipt, ChainClientError> {
    sleep(remaining).await;
    for rpc_url in rpc_urls {
        match try_get_receipt_from_url_async(rpc_url, hash).await {
            Ok(Some(receipt)) => return Ok(receipt),
            Ok(None) | Err(_) => continue,
        }
    }
    Err(ChainClientError::TimeoutError(
        format!("Timeout waiting for receipt after {} seconds", timeout)
    ))
}

async fn wait_and_retry_after_all_failed(
    start: Instant,
    timeout_duration: Duration,
    poll_duration: Duration,
    timeout: u64,
) -> Result<(), ChainClientError> {
    let elapsed = start.elapsed();
    let remaining = timeout_duration.saturating_sub(elapsed);
    if remaining > poll_duration {
        sleep(poll_duration).await;
    } else {
        return Err(ChainClientError::TimeoutError(
            format!("Timeout waiting for receipt after {} seconds", timeout)
        ));
    }
    Ok(())
}

pub async fn try_get_receipt_from_url_async(
    rpc_url: &RpcUrl,
    hash: B256,
) -> Result<Option<TransactionReceipt>, ChainClientError> {
    let parsed_url = rpc_url.as_url().clone();
    let provider = ProviderBuilder::new().connect_http(parsed_url);
    let receipt = provider.get_transaction_receipt(hash).await
        .map_err(|e| ChainClientError::RpcError(format!("RPC call failed: {}", e)))?;
    
    match receipt {
        Some(receipt) => {
            let receipt_json = serde_json::to_value(receipt)
                .map_err(|e| ChainClientError::InvalidResponse(format!("Failed to serialize receipt: {}", e)))?;
            TransactionReceipt::from_web3(receipt_json)
                .map_err(|e| ChainClientError::InvalidResponse(format!("Failed to parse receipt: {}", e)))
                .map(Some)
        }
        None => Ok(None),
    }
}
