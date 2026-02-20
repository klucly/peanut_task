//! DEX executor: builds and submits Uniswap V2 swap transactions.

use crate::chain::{
    swap_calldata::{build_get_amounts_out_calldata, build_swap_calldata, decode_get_amounts_out_return},
    transaction_builder::TransactionBuilder,
    ChainClient,
};
use crate::core::base_types::{Address, TokenAmount, Transaction};
use crate::core::wallet_manager::WalletManager;
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Result of a DEX swap execution.
#[derive(Debug, Clone)]
pub struct DexSwapResult {
    pub success: bool,
    pub tx_hash: Option<String>,
    pub amount_in: u128,
    pub amount_out: u128,
    pub fill_price_approx: Option<Decimal>,
}

#[derive(Error, Debug)]
pub enum DexSwapError {
    #[error("Missing token in map: {0}")]
    MissingToken(String),

    #[error("Invalid pair format: {0}")]
    InvalidPair(String),

    #[error("Chain/client error: {0}")]
    Chain(String),

    #[error("Transaction build/send error: {0}")]
    Transaction(String),
}

/// DEX swap side: sell base for quote, or buy base with quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DexSwapDirection {
    /// Sell base token for quote token (path = [base, quote]).
    SellBase,
    /// Buy base token with quote token (path = [quote, base]).
    BuyBase,
}

/// Chain config for DEX (router and WETH addresses).
#[derive(Debug, Clone)]
pub struct DexChainConfig {
    pub router: Address,
    pub weth: Address,
}

impl DexChainConfig {
    pub fn ethereum_mainnet() -> Self {
        Self {
            router: Address::from_string("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap(),
            weth: Address::from_string("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
        }
    }
}

/// Executes Uniswap V2 swaps on-chain.
pub struct DexExecutor {
    chain_client: Arc<ChainClient>,
    wallet: Arc<WalletManager>,
    config: DexChainConfig,
    /// Symbol (e.g. "ETH", "WETH", "USDC") -> contract address.
    token_map: HashMap<String, Address>,
}

impl DexExecutor {
    pub fn new(
        chain_client: Arc<ChainClient>,
        wallet: Arc<WalletManager>,
        config: DexChainConfig,
        token_map: HashMap<String, Address>,
    ) -> Self {
        Self {
            chain_client,
            wallet,
            config,
            token_map,
        }
    }

    /// Resolve pair "BASE/QUOTE" to (base_addr, quote_addr). Uses WETH for "ETH".
    fn resolve_pair(&self, pair: &str) -> Result<(Address, Address), DexSwapError> {
        let (base_sym, quote_sym) = pair
            .split_once('/')
            .ok_or_else(|| DexSwapError::InvalidPair(pair.to_string()))?;
        let base_addr = self
            .token_map
            .get(base_sym)
            .or_else(|| self.token_map.get("WETH"))
            .cloned()
            .ok_or_else(|| DexSwapError::MissingToken(base_sym.to_string()))?;
        let quote_addr = self
            .token_map
            .get(quote_sym)
            .ok_or_else(|| DexSwapError::MissingToken(quote_sym.to_string()))?
            .clone();
        Ok((base_addr, quote_addr))
    }

    /// Execute a DEX swap. size is in base asset; direction determines path and side.
    pub fn execute_swap(
        &self,
        pair: &str,
        direction: DexSwapDirection,
        size: Decimal,
        dex_price: Decimal,
        slippage_bps: u16,
        timeout_secs: u64,
    ) -> Result<DexSwapResult, DexSwapError> {
        let (base_addr, quote_addr) = self.resolve_pair(pair)?;
        let to = self.wallet.address();

        // Path and amount_in: sell base -> [base, quote], buy base -> [quote, base]
        let (path, amount_in_u128) = match direction {
            DexSwapDirection::SellBase => {
                let path = vec![base_addr.clone(), quote_addr.clone()];
                let amount_in = size
                    .to_f64()
                    .ok_or_else(|| DexSwapError::Transaction("size to f64".to_string()))?;
                let amount_in_u128 = (amount_in * 1e18) as u128;
                (path, amount_in_u128)
            }
            DexSwapDirection::BuyBase => {
                let path = vec![quote_addr.clone(), base_addr.clone()];
                let quote_amount = (size * dex_price)
                    .to_f64()
                    .ok_or_else(|| DexSwapError::Transaction("quote amount to f64".to_string()))?;
                let amount_in_u128 = (quote_amount * 1e6) as u128; // USDC 6 decimals
                (path, amount_in_u128)
            }
        };

        if amount_in_u128 == 0 {
            return Err(DexSwapError::Transaction("amount_in is zero".to_string()));
        }

        // getAmountsOut for amount_out_min
        let get_amounts_out_data = build_get_amounts_out_calldata(&path, amount_in_u128);
        let tx_view = Transaction {
            from: None,
            to: self.config.router.clone(),
            value: TokenAmount::native_eth(0),
            data: get_amounts_out_data,
            nonce: None,
            gas_limit: None,
            max_fee_per_gas: None,
            max_priority_fee: None,
            chain_id: 1,
        };
        let call_result = self
            .chain_client
            .call(&tx_view, "latest")
            .map_err(|e| DexSwapError::Chain(e.to_string()))?;
        let expected_out = decode_get_amounts_out_return(&call_result)
            .ok_or_else(|| DexSwapError::Chain("getAmountsOut decode failed".to_string()))?;
        let amount_out_min = expected_out
            .saturating_mul((10000 - slippage_bps as u128).max(1))
            / 10000;

        let deadline = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs())
            .saturating_add(300);

        let (calldata, value) = build_swap_calldata(
            &path,
            amount_in_u128,
            amount_out_min,
            &to,
            deadline,
            &self.config.weth,
        );

        let value_token = TokenAmount::native_eth(value);
        let builder = TransactionBuilder::new(self.chain_client.as_ref(), self.wallet.as_ref())
            .to(self.config.router.clone())
            .value(value_token)
            .data(calldata)
            .with_gas_estimate(1.2)
            .map_err(|e| DexSwapError::Transaction(e.to_string()))?
            .with_gas_price(crate::chain::gas_price::Priority::High)
            .map_err(|e| DexSwapError::Transaction(e.to_string()))?;

        let tx_hash = builder
            .send()
            .map_err(|e| DexSwapError::Transaction(e.to_string()))?;

        let receipt = self
            .chain_client
            .wait_for_receipt(&tx_hash, timeout_secs, 1.0)
            .map_err(|e| DexSwapError::Chain(e.to_string()))?;

        let success = receipt.status;
        let amount_out = if success { expected_out } else { 0 };
        let fill_price_approx = if success && amount_out > 0 {
            let out_dec = Decimal::from(amount_out);
            let in_dec = Decimal::from(amount_in_u128);
            Some(out_dec / in_dec)
        } else {
            None
        };

        Ok(DexSwapResult {
            success,
            tx_hash: Some(tx_hash),
            amount_in: amount_in_u128,
            amount_out,
            fill_price_approx,
        })
    }
}
