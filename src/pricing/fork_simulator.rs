//! Fork simulator for Uniswap V2–compatible swaps on local Anvil/Hardhat forks.

use crate::chain::{
    ChainClient, ChainClientCreationError, ChainClientError, RpcUrl, RpcUrlError,
};
use crate::core::base_types::{Address, Token, TokenAmount, Transaction};
use super::route::Route;
use crate::pricing::uniswap_v2_pair::{UniswapV2Pair, UniswapV2PairError};
use alloy::primitives::{Address as AlloyAddress, B256, U256};
use alloy::sol;
use alloy::sol_types::SolCall;
use thiserror::Error;

sol!(
    #[allow(missing_docs)]
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
);

sol!(
    #[allow(missing_docs)]
    function swapExactETHForTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable returns (uint256[] memory amounts);
);

sol!(
    #[allow(missing_docs)]
    function getAmountsOut(
        uint256 amountIn,
        address[] calldata path
    ) external view returns (uint256[] memory amounts);
);

/// Chain-specific addresses for Uniswap V2–compatible DEXes.
#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub router: Address,
    pub weth: Address,
    pub chain_id: u64,
}

/// Predefined chain configs. Use `ChainConfig::custom` for others.
#[derive(Debug, Clone, Copy)]
pub enum Chain {
    EthereumMainnet,
    Polygon,
    ArbitrumOne,
    Base,
}

impl Chain {
    pub fn config(&self) -> ChainConfig {
        match self {
            Chain::EthereumMainnet => ChainConfig {
                router: Address::from_string("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap(),
                weth: Address::from_string("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
                chain_id: 1,
            },
            Chain::Polygon => ChainConfig {
                router: Address::from_string("0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff").unwrap(),
                weth: Address::from_string("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270").unwrap(),
                chain_id: 137,
            },
            Chain::ArbitrumOne => ChainConfig {
                router: Address::from_string("0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24").unwrap(),
                weth: Address::from_string("0x82aF49447D8a07e3bd95BD0d56f35241523fBab1").unwrap(),
                chain_id: 42161,
            },
            Chain::Base => ChainConfig {
                router: Address::from_string("0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24").unwrap(),
                weth: Address::from_string("0x4200000000000000000000000000000000000006").unwrap(),
                chain_id: 8453,
            },
        }
    }
}

impl From<Chain> for ChainConfig {
    fn from(c: Chain) -> Self {
        c.config()
    }
}

impl ChainConfig {
    pub fn custom(router: Address, weth: Address, chain_id: u64) -> Self {
        Self {
            router,
            weth,
            chain_id,
        }
    }
}

/// Result of a simulated swap.
#[derive(Debug, Clone)]
pub struct SimulationResult {
    pub success: bool,
    pub amount_out: u128,
    pub gas_used: u64,
    pub error: Option<String>,
    pub logs: Vec<DecodedLog>,
}

/// Placeholder for decoded event logs (eth_call does not return logs).
#[derive(Debug, Clone)]
pub struct DecodedLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
}

/// Parameters for a swap simulation.
#[derive(Debug, Clone)]
pub struct SwapParams {
    pub amount_in: u128,
    pub amount_out_min: u128,
    pub path: Vec<Address>,
    pub to: Address,
    pub deadline: u64,
}

/// Result of comparing AMM math vs fork simulation.
#[derive(Debug, Clone)]
pub struct ComparisonResult {
    pub calculated: u128,
    pub simulated: u128,
    pub difference: u128,
    pub matches: bool,
}

#[derive(Error, Debug)]
pub enum ForkSimulatorError {
    #[error(transparent)]
    Chain(#[from] ChainClientError),
    #[error(transparent)]
    ChainCreation(#[from] ChainClientCreationError),
    #[error(transparent)]
    RpcUrl(#[from] RpcUrlError),
    #[error(transparent)]
    Pair(#[from] UniswapV2PairError),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Encoding error: {0}")]
    Encoding(String),
    #[error("Invalid params: {0}")]
    InvalidParams(String),
}

/// Simulates Uniswap V2 swaps on a local Anvil/Hardhat fork.
pub struct ForkSimulator {
    client: ChainClient,
    chain: ChainConfig,
}

impl ForkSimulator {
    pub fn new(
        fork_url: &str,
        chain: impl Into<ChainConfig>,
    ) -> Result<Self, ForkSimulatorError> {
        let rpc = RpcUrl::new("{}", fork_url)?;
        let client = ChainClient::new(vec![rpc], 30, 3)?;
        Ok(Self {
            client,
            chain: chain.into(),
        })
    }

    pub fn simulate_swap(
        &self,
        router: &Address,
        swap_params: &SwapParams,
        sender: &Address,
    ) -> Result<SimulationResult, ForkSimulatorError> {
        if swap_params.path.len() < 2 {
            return Err(ForkSimulatorError::InvalidParams(
                "path must have at least 2 tokens".to_string(),
            ));
        }

        let path_alloy: Vec<AlloyAddress> = swap_params
            .path
            .iter()
            .map(|a| a.alloy_address())
            .collect();

        let is_eth_in = swap_params.path[0] == self.chain.weth;

        let (calldata, value) = if is_eth_in {
            let call = swapExactETHForTokensCall::new((
                U256::from(swap_params.amount_out_min),
                path_alloy.clone(),
                swap_params.to.alloy_address(),
                U256::from(swap_params.deadline),
            ));
            (swapExactETHForTokensCall::abi_encode(&call), swap_params.amount_in)
        } else {
            let call = swapExactTokensForTokensCall::new((
                U256::from(swap_params.amount_in),
                U256::from(swap_params.amount_out_min),
                path_alloy.clone(),
                swap_params.to.alloy_address(),
                U256::from(swap_params.deadline),
            ));
            (swapExactTokensForTokensCall::abi_encode(&call), 0u128)
        };

        let tx = Transaction {
            from: Some(sender.clone()),
            to: router.clone(),
            value: TokenAmount::native_eth(value),
            data: calldata,
            nonce: None,
            gas_limit: None,
            max_fee_per_gas: None,
            max_priority_fee: None,
            chain_id: self.chain.chain_id,
        };

        let call_result = self.client.call(&tx, "latest");

        let (amount_out, gas_used) = match call_result {
            Err(e) => {
                return Ok(SimulationResult {
                    success: false,
                    amount_out: 0,
                    gas_used: 0,
                    error: Some(e.to_string()),
                    logs: vec![],
                });
            }
            Ok(data) => {
                let amounts: Vec<U256> =
                    swapExactTokensForTokensCall::abi_decode_returns(&data)
                        .map_err(|e| ForkSimulatorError::InvalidResponse(format!(
                            "failed to decode swap return: {}",
                            e
                        )))?;
                let amount_out = amounts
                    .last()
                    .map(|u| u.to::<u128>())
                    .unwrap_or(0);

                let gas_used = self
                    .client
                    .estimate_gas(&tx)
                    .unwrap_or(0);

                (amount_out, gas_used)
            }
        };

        Ok(SimulationResult {
            success: true,
            amount_out,
            gas_used,
            error: None,
            logs: vec![],
        })
    }

    pub fn simulate_route(
        &self,
        route: &Route,
        amount_in: u128,
        sender: &Address,
    ) -> Result<SimulationResult, ForkSimulatorError> {
        let path = route.path_addresses();
        let swap_params = SwapParams {
            amount_in,
            amount_out_min: 0,
            path,
            to: sender.clone(),
            deadline: u64::MAX,
        };
        self.simulate_swap(&self.chain.router, &swap_params, sender)
    }

    pub fn compare_simulation_vs_calculation(
        &self,
        pair: &UniswapV2Pair,
        amount_in: u128,
        token_in: &Token,
    ) -> Result<ComparisonResult, ForkSimulatorError> {
        let amount_in_ta = TokenAmount::new(amount_in, token_in.clone());
        let calculated = pair.get_amount_out(&amount_in_ta)?.raw;

        let path = if token_in == &pair.token0.token {
            vec![pair.token0.address.clone(), pair.token1.address.clone()]
        } else if token_in == &pair.token1.token {
            vec![pair.token1.address.clone(), pair.token0.address.clone()]
        } else {
            return Err(ForkSimulatorError::Pair(
                UniswapV2PairError::TokenNotInPair(format!("{:?}", token_in)),
            ));
        };

        let path_alloy: Vec<AlloyAddress> =
            path.iter().map(|a| a.alloy_address()).collect();

        let call = getAmountsOutCall::new((
            U256::from(amount_in),
            path_alloy,
        ));

        let tx = Transaction {
            from: None,
            to: self.chain.router.clone(),
            value: TokenAmount::native_eth(0),
            data: getAmountsOutCall::abi_encode(&call),
            nonce: None,
            gas_limit: None,
            max_fee_per_gas: None,
            max_priority_fee: None,
            chain_id: self.chain.chain_id,
        };

        let data = self.client.call(&tx, "latest")?;
        let amounts: Vec<U256> = getAmountsOutCall::abi_decode_returns(&data)
            .map_err(|e| ForkSimulatorError::InvalidResponse(format!(
                "failed to decode getAmountsOut return: {}",
                e
            )))?;

        let simulated = amounts
            .last()
            .map(|u| u.to::<u128>())
            .unwrap_or(0);

        let difference = calculated.abs_diff(simulated);
        let matches = calculated == simulated;

        Ok(ComparisonResult {
            calculated,
            simulated,
            difference,
            matches,
        })
    }
}
