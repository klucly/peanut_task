//! PricingEngine: unified interface for AMM math, routing, simulation, and mempool monitoring.

use crate::chain::ChainClient;
use crate::core::base_types::{Address, Token};
use crate::pricing::fork_simulator::{ChainConfig, ForkSimulator, ForkSimulatorError};
use crate::pricing::mempool_monitor::{MempoolMonitor, ParsedSwap};
use crate::pricing::route::{Route, RouteError, RouteFinder};
use crate::pricing::uniswap_v2_pair::{UniswapV2Pair, UniswapV2PairError};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Default simulation sender (Anvil first account).
const DEFAULT_SIMULATION_SENDER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

/// Quote for a swap with expected and simulated output.
#[derive(Debug, Clone)]
pub struct Quote {
    pub route: Route,
    pub amount_in: u128,
    pub expected_output: u128,
    pub simulated_output: u128,
    pub gas_estimate: u64,
    pub timestamp: f64,
}

impl Quote {
    /// Quote valid if simulation output exactly matches our calculation.
    /// No tolerance: we require exact equality to be sure our operations are correct.
    pub fn is_valid(&self) -> bool {
        self.expected_output != 0 && self.expected_output == self.simulated_output
    }
}

#[derive(Error, Debug)]
pub enum QuoteError {
    #[error("No pools loaded")]
    NoPoolsLoaded,
    #[error("No route found")]
    NoRoute,
    #[error("Pool not found: {0}")]
    PoolNotFound(Address),
    #[error("Simulation failed: {0}")]
    SimulationFailed(String),
    #[error(transparent)]
    Route(#[from] RouteError),
    #[error(transparent)]
    Fork(#[from] ForkSimulatorError),
    #[error(transparent)]
    Pair(#[from] UniswapV2PairError),
}

#[derive(Error, Debug)]
pub enum PricingEngineError {
    #[error(transparent)]
    Fork(#[from] ForkSimulatorError),
}

/// Main interface for the pricing module.
/// Integrates AMM math, routing, simulation, and mempool monitoring.
pub struct PricingEngine {
    client: ChainClient,
    simulator: ForkSimulator,
    monitor: MempoolMonitor,
    pools: HashMap<Address, UniswapV2Pair>,
    router: Option<RouteFinder>,
    simulation_sender: Address,
    pool_token_addresses: Arc<RwLock<HashSet<Address>>>,
}

impl PricingEngine {
    /// Create a new PricingEngine.
    pub fn new(
        chain_client: ChainClient,
        fork_url: &str,
        ws_url: impl Into<String>,
        chain: impl Into<ChainConfig>,
        simulation_sender: Option<Address>,
    ) -> Result<Self, PricingEngineError> {
        let simulator = ForkSimulator::new(fork_url, chain)?;
        let pool_token_addresses = Arc::new(RwLock::new(HashSet::new()));
        let pool_token_addresses_clone = Arc::clone(&pool_token_addresses);
        let monitor = MempoolMonitor::new(ws_url, move |swap: ParsedSwap| {
            let set = match pool_token_addresses_clone.read() {
                Ok(guard) => guard,
                Err(_) => return,
            };
            let affects = swap
                .token_in
                .as_ref()
                .map(|t| set.contains(t))
                .unwrap_or(false)
                || swap
                    .token_out
                    .as_ref()
                    .map(|t| set.contains(t))
                    .unwrap_or(false);
            if affects {
                // Could trigger re-quote or alert; no-op for now
            }
        });
        let sender = simulation_sender.unwrap_or_else(|| {
            Address::from_string(DEFAULT_SIMULATION_SENDER)
                .expect("default simulation sender is valid")
        });
        Ok(Self {
            client: chain_client,
            simulator,
            monitor,
            pools: HashMap::new(),
            router: None,
            simulation_sender: sender,
            pool_token_addresses,
        })
    }

    /// Load pool data from chain. Replaces existing pools atomically.
    pub fn load_pools(&mut self, pool_addresses: &[Address]) -> Result<(), QuoteError> {
        let mut new_pools = HashMap::new();
        let mut token_addrs = HashSet::new();
        for addr in pool_addresses {
            let pair = UniswapV2Pair::from_chain(addr.clone(), &self.client)?;
            token_addrs.insert(pair.token0.address.clone());
            token_addrs.insert(pair.token1.address.clone());
            new_pools.insert(pair.address.clone(), pair);
        }
        self.pools = new_pools;
        *self.pool_token_addresses.write().unwrap() = token_addrs;
        self.router = Some(RouteFinder::new(self.pools.values().cloned().collect()));
        Ok(())
    }

    /// Refresh a single pool's reserves from chain.
    pub fn refresh_pool(&mut self, address: &Address) -> Result<(), QuoteError> {
        self.refresh_pools(&[address.clone()])
    }

    /// Refresh multiple pools' reserves from chain.
    pub fn refresh_pools(&mut self, addresses: &[Address]) -> Result<(), QuoteError> {
        for address in addresses {
            if let Some(pool) = self.pools.get_mut(address) {
                if let Err(e) = pool.refresh_reserves(&self.client) {
                    // Log error but continue refreshing others? or fail?
                    // For now, let's log and continue to be robust.
                    log::warn!("Failed to refresh pool {}: {}", address, e);
                }
            } else {
                return Err(QuoteError::PoolNotFound(address.clone()));
            }
        }
        self.router = Some(RouteFinder::new(self.pools.values().cloned().collect()));
        Ok(())
    }

    /// Get best quote for a swap.
    pub fn get_quote(
        &self,
        token_in: &Token,
        token_out: &Token,
        amount_in: u128,
        gas_price_gwei: u64,
        max_hops: u32,
    ) -> Result<Quote, QuoteError> {
        let router = self.router.as_ref().ok_or(QuoteError::NoPoolsLoaded)?;
        let (route, net_output) = router
            .find_best_route(token_in, token_out, amount_in, gas_price_gwei, max_hops)?
            .ok_or(QuoteError::NoRoute)?;
        let sim_result =
            self.simulator
                .simulate_route(&route, amount_in, &self.simulation_sender)?;
        if !sim_result.success {
            return Err(QuoteError::SimulationFailed(
                sim_result.error.unwrap_or_else(|| "unknown".to_string()),
            ));
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        Ok(Quote {
            route,
            amount_in,
            expected_output: net_output,
            simulated_output: sim_result.amount_out,
            gas_estimate: sim_result.gas_used,
            timestamp,
        })
    }

    /// Access the mempool monitor (e.g. to call `start()`).
    pub fn monitor(&self) -> &MempoolMonitor {
        &self.monitor
    }

    /// Number of loaded pools.
    pub fn pool_count(&self) -> usize {
        self.pools.len()
    }

    /// Returns unique tokens from all loaded pools. Use these tokens for `get_quote`
    /// so they match the pool's token metadata (e.g. WETH has symbol "WETH", not "ETH").
    pub fn pool_tokens(&self) -> Vec<Token> {
        let mut seen = HashSet::new();
        let mut tokens = Vec::new();
        for pool in self.pools.values() {
            if seen.insert(pool.token0.token.clone()) {
                tokens.push(pool.token0.token.clone());
            }
            if seen.insert(pool.token1.token.clone()) {
                tokens.push(pool.token1.token.clone());
            }
        }
        tokens
    }

    pub fn get_tokens_with_addresses(&self) -> Vec<(Token, Address)> {
        let mut seen = HashSet::new();
        let mut tokens = Vec::new();
        for pool in self.pools.values() {
            if seen.insert(pool.token0.address.clone()) {
                tokens.push((pool.token0.token.clone(), pool.token0.address.clone()));
            }
            if seen.insert(pool.token1.address.clone()) {
                tokens.push((pool.token1.token.clone(), pool.token1.address.clone()));
            }
        }
        tokens
    }

    pub fn get_token_by_symbol(&self, symbol: &str) -> Option<Token> {
        for token in self.pool_tokens() {
            if token.symbol().unwrap_or_default() == symbol {
                return Some(token);
            }
        }
        None
    }

    pub fn get_pair_by_symbols(&self, symbol0: &str, symbol1: &str) -> Option<&UniswapV2Pair> {
        for pair in self.pools.values() {
            let token0_symbol = pair.token0.token.symbol().unwrap_or_default();
            let token1_symbol = pair.token1.token.symbol().unwrap_or_default();
            if token0_symbol == symbol0 && token1_symbol == symbol1
                || token0_symbol == symbol1 && token1_symbol == symbol0
            {
                return Some(pair);
            }
        }
        None
    }

    pub fn get_pair_by_address(&self, address: &Address) -> Option<&UniswapV2Pair> {
        self.pools.get(address)
    }
}
