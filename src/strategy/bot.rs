//! Main arbitrage bot loop for continuous opportunity monitoring and execution.

use rust_decimal::Decimal;
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
pub struct ArbBot {
    exchange: Arc<Mutex<ExchangeClient>>,
    inventory: Arc<Mutex<InventoryTracker>>,
    fee_structure: FeeStructure,
    generator: SignalGenerator,
    scorer: SignalScorer,
    executor: Executor,
    config: BotConfig,
    running: Arc<AtomicBool>,
}

impl ArbBot {
    /// Create a new arbitrage bot.
    pub fn new(
        exchange: ExchangeClient,
        pricing_engine: PricingEngine,
        inventory: InventoryTracker,
        fee_structure: FeeStructure,
        config: BotConfig,
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
            inventory,
            fee_structure,
            generator,
            scorer,
            executor,
            config,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Run the bot loop continuously.
    pub fn run(&mut self) {
        self.running.store(true, Ordering::SeqCst);
        println!("Bot starting...");
        
        // Sync balances initially
        self._sync_balances();

        while self.running.load(Ordering::SeqCst) {
            match self._tick() {
                Ok(_) => {},
                Err(e) => {
                    eprintln!("Tick error: {}", e);
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    continue;
                }
            }

            std::thread::sleep(std::time::Duration::from_secs(self.config.tick_interval_secs));
        }

        println!("Bot stopped");
    }

    /// Execute a single tick of the bot loop.
    fn _tick(&mut self) -> Result<(), String> {
        // Check circuit breaker
        if self.executor.circuit_breaker.is_open() {
            println!("Circuit breaker open");
            return Ok(());
        }

        // Process each pair
        for pair in self.config.pairs.clone() {
            // Generate signal
            let signal = match self.generator.generate(&pair) {
                Some(s) => s,
                None => continue,
            };

            // Score signal (pass empty slice since scorer handles inventory internally if needed)
            let score = self.scorer.score(&signal, &[]);
            let mut signal = signal;
            signal.score = score;

            // Check score threshold
            if signal.score < self.config.min_score_threshold {
                println!(
                    "Signal: {} spread={:.1}bps score={:.0}",
                    pair,
                    signal.spread_bps,
                    signal.score
                );
                println!("Skipped: score below threshold");
                continue;
            }

            // Log signal
            println!(
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
            println!("Executing: {} {:.4} ETH", direction_str, signal.size);

            // Execute
            let ctx = self.executor.execute(signal.clone());

            // Record result
            let success = ctx.state == ExecutorState::Done;
            self.scorer.record_result(pair.clone(), success);

            // Log result
            if success {
                let pnl = ctx.actual_net_pnl.unwrap_or(dec!(0));
                println!("SUCCESS: PnL=${:.2}", pnl);
            } else {
                eprintln!("FAILED: {}", ctx.error.unwrap_or_else(|| "unknown error".to_string()));
                
                // Log circuit breaker status if tripped
                if self.executor.circuit_breaker.is_open() {
                    eprintln!("Circuit breaker tripped");
                }
            }

            // Sync balances after execution
            self._sync_balances();
        }

        Ok(())
    }

    /// Synchronize balances from exchange.
    fn _sync_balances(&mut self) {
        let exchange = self.exchange.lock().unwrap();
        match exchange.fetch_balance() {
            Ok(balances) => {
                drop(exchange); // Release lock before acquiring inventory lock
                let mut inventory = self.inventory.lock().unwrap();
                if let Err(e) = inventory.update_from_cex(crate::inventory::Venue::Binance, balances) {
                    eprintln!("Failed to sync balances: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Failed to fetch balances: {}", e);
            }
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
