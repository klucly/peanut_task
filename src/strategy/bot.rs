//! Main arbitrage bot loop for continuous opportunity monitoring and execution.

use rust_decimal::Decimal;
use rust_decimal::prelude::FromPrimitive;
use rust_decimal_macros::dec;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::exchange::ExchangeClient;
use crate::inventory::InventoryTracker;
use crate::pricing::PricingEngine;

use super::executor::{Executor, ExecutorConfig, ExecutorState};
use super::fees::FeeStructure;
use super::generator::{GeneratorConfig, SignalGenerator};
use super::scorer::{ScorerConfig, SignalScorer};
use super::signal::Direction;

/// Configuration for the arbitrage bot.
#[derive(Debug, Clone)]
pub struct BotConfig {
    /// Trading pairs to monitor (e.g., ["ETH/USDT", "BTC/USDT"])
    pub pairs: Vec<String>,

    /// Time between ticks in seconds
    pub tick_interval_secs: u64,

    /// Minimum score threshold to execute a signal
    pub min_score_threshold: Decimal,

    /// Run in simulation mode (no real orders)
    pub simulation_mode: bool,

    /// Signal generator configuration
    pub generator_config: GeneratorConfig,

    /// Signal scorer configuration
    pub scorer_config: ScorerConfig,

    /// Executor configuration
    pub executor_config: ExecutorConfig,
}

impl Default for BotConfig {
    fn default() -> Self {
        Self {
            pairs: vec!["ETH/USDT".to_string()],
            tick_interval_secs: 1,
            min_score_threshold: dec!(60),
            simulation_mode: true,
            generator_config: GeneratorConfig::default(),
            scorer_config: ScorerConfig::default(),
            executor_config: ExecutorConfig::default(),
        }
    }
}

impl BotConfig {
    pub fn new(
        pairs: Vec<String>,
        tick_interval_secs: u64,
        min_score_threshold: Decimal,
        simulation_mode: bool,
        generator_config: GeneratorConfig,
        scorer_config: ScorerConfig,
        executor_config: ExecutorConfig,
    ) -> Self {
        Self {
            pairs,
            tick_interval_secs,
            min_score_threshold,
            simulation_mode,
            generator_config,
            scorer_config,
            executor_config,
        }
    }
}

/// Main arbitrage bot that monitors opportunities and executes trades.
use crate::chain::ChainClient;
use crate::core::base_types::Address;
use crate::core::base_types::TokenAmount;
use crate::core::base_types::Transaction;
use std::collections::HashMap;

/// Main arbitrage bot that monitors opportunities and executes trades.
pub struct ArbBot {
    exchange: Arc<Mutex<ExchangeClient>>,
    pricing: Arc<Mutex<PricingEngine>>,
    inventory: Arc<Mutex<InventoryTracker>>,
    fee_structure: FeeStructure,
    generator: SignalGenerator,
    scorer: SignalScorer,
    executor: Executor,
    config: BotConfig,
    running: Arc<AtomicBool>,
    chain_client: ChainClient,
    wallet_address: Address,
}

impl ArbBot {
    /// Create a new arbitrage bot.
    pub fn new(
        exchange: ExchangeClient,
        pricing_engine: PricingEngine,
        inventory: InventoryTracker,
        fee_structure: FeeStructure,
        config: BotConfig,
        chain_client: ChainClient,
        wallet_address: Address,
    ) -> Self {
        // Wrap in Arc<Mutex<>> for shared ownership
        let exchange = Arc::new(Mutex::new(exchange));
        let pricing_engine = Arc::new(Mutex::new(pricing_engine));
        let inventory = Arc::new(Mutex::new(inventory));

        // Create ArbChecker with shared references
        let arb_checker = crate::integration::ArbChecker::new(
            Arc::clone(&pricing_engine),
            Arc::clone(&exchange),
            Arc::clone(&inventory),
            crate::inventory::PnLEngine::new(),
        );

        // Create signal generator
        let generator = SignalGenerator::new(
            arb_checker,
            fee_structure.clone(),
            config.generator_config.clone(),
        );

        // Create signal scorer
        let scorer = SignalScorer::new(Some(config.scorer_config.clone()));

        // Create executor with shared references
        let executor = Executor::new(
            Arc::clone(&exchange),
            Arc::clone(&pricing_engine),
            Arc::clone(&inventory),
            Some(config.executor_config.clone()),
        );

        Self {
            exchange,
            pricing: pricing_engine,
            inventory,
            fee_structure,
            generator,
            scorer,
            executor,
            config,
            running: Arc::new(AtomicBool::new(false)),
            chain_client,
            wallet_address,
        }
    }

    /// Run the bot loop continuously.
    pub fn run(&mut self) {
        self.running.store(true, Ordering::SeqCst);
        tracing::info!("Bot starting...");

        // Sync balances initially
        self._sync_balances();

        while self.running.load(Ordering::SeqCst) {
            match self._tick() {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("Tick error: {}", e);
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    continue;
                }
            }

            std::thread::sleep(std::time::Duration::from_secs(
                self.config.tick_interval_secs,
            ));
        }

        tracing::info!("Bot stopped");
    }

    /// Execute a single tick of the bot loop.
    fn _tick(&mut self) -> Result<(), String> {
        // Check circuit breaker
        if self.executor.circuit_breaker.is_open() {
            tracing::warn!("Circuit breaker open - skipping tick");
            return Ok(());
        }

        // Process each pair
        for pair in self.config.pairs.clone() {
            tracing::debug!("Checking {}...", pair);

            // Refresh DEX pool data
            if let Some((base, quote)) = pair.split_once('/') {
                // Map ETH to WETH for DEX lookup if needed
                let dex_base = if base == "ETH" { "WETH" } else { base };
                let dex_quote = if quote == "ETH" { "WETH" } else { quote };

                let mut pricing = self.pricing.lock().unwrap();
                if let Some(pool) = pricing.get_pair_by_symbols(dex_base, dex_quote) {
                    let pool_address = pool.address.clone();
                    if let Err(e) = pricing.refresh_pool(&pool_address) {
                        tracing::error!("Failed to refresh pool for {}: {}", pair, e);
                    } else {
                        tracing::trace!("Refreshed pool for {}", pair);
                    }
                }
                drop(pricing);
            }

            // Generate signal
            let signal = match self.generator.generate(&pair) {
                Some(s) => s,
                None => {
                    tracing::debug!("No profitable path found for {}", pair);
                    continue;
                }
            };

            // Score signal (pass empty slice since scorer handles inventory internally if needed)
            let score = self.scorer.score(&signal, &[]);
            let mut signal = signal;
            signal.score = score;

            // Check score threshold
            if signal.score < self.config.min_score_threshold {
                tracing::debug!(
                    "Signal skipped: {} spread={:.1}bps score={:.0} < threshold {}",
                    pair,
                    signal.spread_bps,
                    signal.score,
                    self.config.min_score_threshold
                );
                continue;
            }

            // Log signal
            tracing::info!(
                "Signal: {} spread={:.1}bps score={:.0}",
                pair,
                signal.spread_bps,
                signal.score
            );

            // Log execution intent
            let direction_str = match signal.direction {
                Direction::BuyCexSellDex => "BUY_CEX_SELL_DEX",
                Direction::BuyDexSellCex => "BUY_DEX_SELL_CEX",
            };
            tracing::info!("Executing: {} {:.4} ETH", direction_str, signal.size);

            // Execute
            let ctx = self.executor.execute(signal.clone());

            // Record result
            let success = ctx.state == ExecutorState::Done;
            self.scorer.record_result(pair.clone(), success);

            // Log result
            if success {
                let pnl = ctx.actual_net_pnl.unwrap_or(dec!(0));
                tracing::info!("SUCCESS: PnL=${:.2}", pnl);
            } else {
                tracing::error!(
                    "FAILED: {}",
                    ctx.error.unwrap_or_else(|| "unknown error".to_string())
                );

                // Log circuit breaker status if tripped
                if self.executor.circuit_breaker.is_open() {
                    tracing::error!("Circuit breaker tripped due to failure");
                }
            }

            // Sync balances after execution
            self._sync_balances();
        }

        Ok(())
    }

    /// Synchronize balances from all venues.
    fn _sync_balances(&mut self) {
        self._sync_cex_balances();
        self._sync_wallet_balances();
    }

    /// Synchronize balances from exchange.
    fn _sync_cex_balances(&mut self) {
        let exchange = self.exchange.lock().unwrap();
        match exchange.fetch_balance() {
            Ok(balances) => {
                drop(exchange); // Release lock before acquiring inventory lock
                let mut inventory = self.inventory.lock().unwrap();
                if let Err(e) =
                    inventory.update_from_cex(crate::inventory::Venue::Binance, balances)
                {
                    tracing::error!("Failed to sync CEX balances: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to fetch CEX balances: {}", e);
            }
        }
    }

    /// Synchronize balances from wallet.
    fn _sync_wallet_balances(&mut self) {
        tracing::warn!("Starting wallet balance sync...");
        let pricing = self.pricing.lock().unwrap();
        let tokens_with_addr = pricing.get_tokens_with_addresses();
        drop(pricing);

        let mut wallet_balances = HashMap::new();

        // 1. ETH Balance
        match self.chain_client.get_balance(self.wallet_address.clone()) {
            Ok(balance) => {
                // Convert u128 to Decimal (assuming 18 decimals for ETH)
                if let Some(dec_bal) = Decimal::from_u128(balance.raw) {
                    let eth_val = dec_bal / Decimal::from(1_000_000_000_000_000_000u128);
                    wallet_balances.insert("ETH".to_string(), eth_val);
                    wallet_balances.insert("WETH".to_string(), eth_val); // Treat WETH in inventory as ETH for simplicity if needed, or track separate
                }
            }
            Err(e) => tracing::error!("Failed to fetch ETH balance: {}", e),
        }

        // 2. ERC20 Balances
        for (token, address) in tokens_with_addr {
            let symbol = token.symbol().unwrap_or("UNKNOWN").to_string();
            if symbol == "ETH" || symbol == "WETH" {
                continue;
            } // Already handled or native

            // balanceOf(address) -> 70a08231 + padded address
            let mut data = Vec::with_capacity(4 + 32);
            data.extend_from_slice(&hex::decode("70a08231").unwrap());

            // Pad address to 32 bytes
            let mut addr_pad = [0u8; 32];
            let addr_bytes = hex::decode(&self.wallet_address.value[2..]).unwrap();
            addr_pad[12..32].copy_from_slice(&addr_bytes);
            data.extend_from_slice(&addr_pad);

            let tx = Transaction {
                from: None,
                to: address.clone(),
                value: TokenAmount::native_eth(0),
                data,
                nonce: None,
                gas_limit: None,
                max_fee_per_gas: None,
                max_priority_fee: None,
                chain_id: 1, // Mainnet/Fork
            };

            match self.chain_client.call(&tx, "latest") {
                Ok(result) => {
                    if result.len() >= 32 {
                        let balance_bytes = &result[0..32];
                        let balance_u256 = alloy::primitives::U256::from_be_slice(balance_bytes);
                        // Convert to u128 (unsafe if too large, but for arb testing okay)
                        let balance_u128 = balance_u256.to::<u128>();

                        if let Some(dec_bal_raw) = Decimal::from_u128(balance_u128) {
                            let divisor = Decimal::from(10_u128.pow(token.decimals() as u32));
                            let val = dec_bal_raw / divisor;
                            tracing::warn!("Synced Wallet Balance: {} = {}", symbol, val);
                            wallet_balances.insert(symbol, val);
                        }
                    }
                }
                Err(e) => tracing::warn!("Failed to fetch balance for {}: {}", symbol, e),
            }
        }

        let eth_bal = wallet_balances.get("ETH").cloned().unwrap_or(Decimal::ZERO);
        tracing::warn!("Synced Wallet Balance: ETH = {}", eth_bal);

        // Update inventory
        let mut inventory = self.inventory.lock().unwrap();
        if let Err(e) =
            inventory.update_from_wallet(crate::inventory::Venue::Wallet, wallet_balances)
        {
            tracing::error!("Failed to update wallet inventory: {}", e);
        }
    }

    /// Stop the bot gracefully.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Get a handle to stop the bot from another thread.
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }
}
