//! Main arbitrage bot loop for continuous opportunity monitoring and execution.

use rust_decimal::Decimal;
use rust_decimal::prelude::FromPrimitive;
use rust_decimal_macros::dec;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::exchange::ExchangeClient;
use crate::inventory::{InventoryTracker, Venue};
use crate::pricing::PricingEngine;

use super::executor::{Executor, ExecutorConfig, ExecutorState};
use super::fees::FeeStructure;
use super::generator::{GeneratorConfig, SignalGenerator};
use super::scorer::{ScorerConfig, SignalScorer};
use super::signal::Direction;

/// Exit code when the circuit breaker has tripped (process exits for operator investigation).
/// Public so that subprocess tests can assert the bot exits with this code when the circuit trips.
pub const EXIT_CODE_CIRCUIT_TRIPPED: i32 = 1;

/// Configuration for the arbitrage bot.
#[derive(Debug, Clone)]
pub struct BotConfig {
    /// Trading pairs to monitor (e.g., ["ETH/USDT", "BTC/USDT"])
    pub pairs: Vec<String>,

    /// Time between ticks in milliseconds
    pub tick_interval_millis: u64,

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

    /// Path to the JSONL stats history file (appended after every trade)
    pub stats_file: PathBuf,
}

impl Default for BotConfig {
    fn default() -> Self {
        Self {
            pairs: vec!["ETH/USDT".to_string()],
            tick_interval_millis: 1,
            min_score_threshold: dec!(60),
            simulation_mode: true,
            generator_config: GeneratorConfig::default(),
            scorer_config: ScorerConfig::default(),
            executor_config: ExecutorConfig::default(),
            stats_file: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".peanut_bot_stats.jsonl"),
        }
    }
}

impl BotConfig {
    pub fn new(
        pairs: Vec<String>,
        tick_interval_millis: u64,
        min_score_threshold: Decimal,
        simulation_mode: bool,
        generator_config: GeneratorConfig,
        scorer_config: ScorerConfig,
        executor_config: ExecutorConfig,
    ) -> Self {
        Self {
            pairs,
            tick_interval_millis,
            min_score_threshold,
            simulation_mode,
            generator_config,
            scorer_config,
            executor_config,
            stats_file: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".peanut_bot_stats.jsonl"),
        }
    }
}

// ---------------------------------------------------------------------------
// BotStats: running trade counter + persistent JSONL history
// ---------------------------------------------------------------------------

/// Tracks cumulative trade statistics for the current session.
/// Loaded from `stats_file` at startup; appended after every execution.
#[derive(Debug, Default)]
pub struct BotStats {
    pub trades: u64,
    pub wins: u64,
    pub losses: u64,
    pub total_pnl: Decimal,
}

impl BotStats {
    /// Load cumulative totals by replaying a JSONL file.
    pub fn load(path: &PathBuf) -> Self {
        let mut s = Self::default();
        let Ok(content) = std::fs::read_to_string(path) else {
            return s;
        };
        for line in content.lines() {
            // Minimal parse — look for ok/actual_pnl fields without pulling in serde
            let ok = line.contains("\"ok\":true");
            let pnl: Decimal = Self::extract_decimal(line, "actual_pnl").unwrap_or(Decimal::ZERO);
            s.trades += 1;
            if ok {
                s.wins += 1;
                s.total_pnl += pnl;
            } else {
                s.losses += 1;
                s.total_pnl += pnl; // may be negative for failed
            }
        }
        s
    }

    /// Append one record to the JSONL file and update in-memory counters.
    pub fn record(
        &mut self,
        path: &PathBuf,
        id: &str,
        pair: &str,
        dir: &str,
        size: Decimal,
        actual_pnl: Decimal,
        ok: bool,
    ) {
        self.trades += 1;
        if ok {
            self.wins += 1;
        } else {
            self.losses += 1;
        }
        self.total_pnl += actual_pnl;

        let ts = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "?".to_string());
        let ok_str = if ok { "true" } else { "false" };
        let line = format!(
            "{{\"ts\":\"{ts}\",\"id\":\"{id}\",\"pair\":\"{pair}\",\"dir\":\"{dir}\",\"size\":{size:.4},\"actual_pnl\":{actual_pnl:.4},\"ok\":{ok_str}}}\n"
        );

        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = f.write_all(line.as_bytes());
        } else {
            tracing::warn!("Failed to write stats to {:?}", path);
        }
    }

    fn extract_decimal(line: &str, key: &str) -> Option<Decimal> {
        let needle = format!("\"{key}\":");
        let start = line.find(&needle)? + needle.len();
        let rest = &line[start..];
        let end = rest
            .find(|c: char| c == ',' || c == '}')
            .unwrap_or(rest.len());
        rest[..end].trim().parse().ok()
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
    pub executor: Executor,
    config: BotConfig,
    running: Arc<AtomicBool>,
    chain_client: ChainClient,
    wallet_address: Address,
    stats: BotStats,
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

        // Propagate simulation_mode from BotConfig into ExecutorConfig
        let mut executor_config = config.executor_config.clone();
        executor_config.simulation_mode = config.simulation_mode;

        // Create executor with shared references
        let chain_client_arc = Arc::new(chain_client.clone());
        let executor = Executor::new(
            Arc::clone(&exchange),
            Arc::clone(&pricing_engine),
            Arc::clone(&inventory),
            chain_client_arc,
            fee_structure.clone(),
            Some(executor_config),
        );

        let stats = BotStats::load(&config.stats_file);
        tracing::info!(
            "[STATS] Loaded history: trades={} wins={} losses={} total_pnl=${:.2}",
            stats.trades,
            stats.wins,
            stats.losses,
            stats.total_pnl
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
            stats,
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

            std::thread::sleep(std::time::Duration::from_millis(
                self.config.tick_interval_millis,
            ));
        }

        tracing::info!("Bot stopped");
    }

    pub fn _tick(&mut self) -> Result<(), String> {
        if self.executor.circuit_breaker.is_open() {
            tracing::warn!("Circuit breaker open - skipping tick");
            return Ok(());
        }

        for pair in self.config.pairs.clone() {
            // Hoist base/quote to outer scope so both inventory logs can use them
            let (base, quote) = match pair.split_once('/') {
                Some((b, q)) => (b.to_string(), q.to_string()),
                None => {
                    tracing::error!("Invalid pair format (expected BASE/QUOTE): {}", pair);
                    continue;
                }
            };

            // Refresh DEX pool reserves for this pair
            {
                let dex_base = if base == "ETH" { "WETH" } else { &base };
                let dex_quote = if quote == "ETH" { "WETH" } else { &quote };

                let mut pricing = self.pricing.lock()
                    .unwrap_or_else(|e| {
                        tracing::error!("Mutex poisoned in bot: {}", e);
                        e.into_inner()
                    });
                if let Some(pool) = pricing.get_pair_by_symbols(dex_base, dex_quote) {
                    let pool_address = pool.address.clone();
                    if let Err(e) = pricing.refresh_pool(&pool_address) {
                        tracing::error!(
                            "Failed to refresh pool for {}. Skipping pair. Error: {}.",
                            pair,
                            e
                        );
                        continue;
                    }
                }
                drop(pricing);
            }

            let signal = match self.generator.generate(&pair) {
                Some(s) => s,
                None => {
                    tracing::debug!("No profitable path found for {}", pair);
                    continue;
                }
            };

            let score = self.scorer.score(&signal, &[]);
            let mut signal = signal;
            signal.score = score;
            if signal.score < self.config.min_score_threshold {
                tracing::info!(
                    "[GENERATOR] {}  LOW_SCORE  score={:.0} < threshold={}",
                    pair,
                    signal.score,
                    self.config.min_score_threshold
                );
                continue;
            }

            // Direction string used in several log lines below
            let direction_str = match signal.direction {
                Direction::BuyCexSellDex => "BUY_CEX_SELL_DEX",
                Direction::BuyDexSellCex => "BUY_DEX_SELL_CEX",
            };

            // Pre-execution inventory snapshot
            let (cex_asset, cex_bal, wallet_asset, wallet_bal) = {
                let inventory = self.inventory.lock()
                    .unwrap_or_else(|e| {
                        tracing::error!("Mutex poisoned in bot: {}", e);
                        e.into_inner()
                    });
                match signal.direction {
                    Direction::BuyCexSellDex => (
                        quote.clone(),
                        inventory.get_available(Venue::Binance, &quote),
                        base.clone(),
                        inventory.get_available(Venue::Wallet, &base),
                    ),
                    Direction::BuyDexSellCex => (
                        base.clone(),
                        inventory.get_available(Venue::Binance, &base),
                        quote.clone(),
                        inventory.get_available(Venue::Wallet, &quote),
                    ),
                }
            };

            // Detailed [SIGNAL] log — one line capturing everything relevant
            tracing::info!(
                "[SIGNAL] id={}  {}  {}\n         size={:.4}  spread={:+.0}bps  score={:.0}  exp_gross=${:.2}  exp_fees=${:.2}  exp_net=${:.2}\n         cex={:.2}  dex={:.2}\n         inv: {}(cex)={:.4}  {}(wallet)={:.4}",
                signal.signal_id,
                pair,
                direction_str,
                signal.size,
                signal.spread_bps,
                signal.score,
                signal.expected_gross_pnl,
                signal.expected_fees,
                signal.expected_net_pnl,
                signal.cex_price,
                signal.dex_price,
                cex_asset,
                cex_bal,
                wallet_asset,
                wallet_bal,
            );

            // Execute and time the trade
            let exec_start = Instant::now();
            let ctx = self.executor.execute(signal.clone());
            let duration_ms = exec_start.elapsed().as_millis();

            // Record scorer result
            let success = ctx.state == ExecutorState::Done;
            self.scorer.record_result(pair.clone(), success);

            // Detailed result log
            if success {
                let actual_pnl = ctx.actual_net_pnl.unwrap_or(dec!(0));
                let leg1_price = ctx.leg1_fill_price.unwrap_or(dec!(0));
                let leg2_price = ctx.leg2_fill_price.unwrap_or(dec!(0));
                tracing::info!(
                    "[DONE] id={}  {}  leg1={}@{:.4}  leg2={}@{:.4}  actual_pnl=${:.2}  exp_pnl=${:.2}  duration={}ms",
                    signal.signal_id,
                    pair,
                    ctx.leg1_venue,
                    leg1_price,
                    ctx.leg2_venue,
                    leg2_price,
                    actual_pnl,
                    signal.expected_net_pnl,
                    duration_ms,
                );

                // Persist to stats file
                self.stats.record(
                    &self.config.stats_file.clone(),
                    &signal.signal_id,
                    &pair,
                    direction_str,
                    signal.size,
                    actual_pnl,
                    true,
                );
            } else {
                let reason = ctx.error.as_deref().unwrap_or("unknown error");
                tracing::error!(
                    "[FAIL] id={}  {}  reason=\"{}\"  duration={}ms",
                    signal.signal_id,
                    pair,
                    reason,
                    duration_ms,
                );

                self.stats.record(
                    &self.config.stats_file.clone(),
                    &signal.signal_id,
                    &pair,
                    direction_str,
                    signal.size,
                    dec!(0),
                    false,
                );
            }

            if self.executor.circuit_breaker.is_open() {
                tracing::error!("Circuit breaker tripped — exiting for operator investigation");
                std::process::exit(EXIT_CODE_CIRCUIT_TRIPPED);
            }

            // Running stats summary
            let win_rate = if self.stats.trades > 0 {
                (self.stats.wins as f64 / self.stats.trades as f64) * 100.0
            } else {
                0.0
            };
            tracing::info!(
                "[STATS] trades={}  wins={}  losses={}  win_rate={:.0}%  total_pnl=${:.2}",
                self.stats.trades,
                self.stats.wins,
                self.stats.losses,
                win_rate,
                self.stats.total_pnl,
            );

            // Update inventory to reflect the trade.
            // In simulation mode the real chain/exchange balances don't change, so syncing
            // from them would wipe the deltas. Instead apply them directly via record_trade().
            // In real mode do the normal sync.
            if success && self.config.simulation_mode {
                let fill_size = ctx.leg1_fill_size.unwrap_or(signal.size);
                let leg1_price = ctx.leg1_fill_price.unwrap_or(signal.cex_price);
                let leg2_price = ctx.leg2_fill_price.unwrap_or(signal.dex_price);

                let mut inventory = self.inventory.lock()
                    .unwrap_or_else(|e| {
                        tracing::error!("Mutex poisoned in bot: {}", e);
                        e.into_inner()
                    });
                match signal.direction {
                    Direction::BuyCexSellDex => {
                        // CEX leg: buy base with quote
                        let quote_spent = fill_size * leg1_price;
                        let _ = inventory.record_trade(
                            Venue::Binance,
                            "buy",
                            &base,
                            &quote,
                            fill_size,
                            quote_spent,
                            dec!(0),
                            &quote,
                        );
                        // DEX leg: sell base for quote (wallet sends base, receives quote)
                        let quote_received = fill_size * leg2_price;
                        let _ = inventory.record_trade(
                            Venue::Wallet,
                            "sell",
                            &base,
                            &quote,
                            fill_size,
                            quote_received,
                            dec!(0),
                            &quote,
                        );
                    }
                    Direction::BuyDexSellCex => {
                        // CEX leg: sell base for quote
                        let quote_received = fill_size * leg1_price;
                        let _ = inventory.record_trade(
                            Venue::Binance,
                            "sell",
                            &base,
                            &quote,
                            fill_size,
                            quote_received,
                            dec!(0),
                            &quote,
                        );
                        // DEX leg: buy base with quote (wallet spends quote, receives base)
                        let quote_spent = fill_size * leg2_price;
                        let _ = inventory.record_trade(
                            Venue::Wallet,
                            "buy",
                            &base,
                            &quote,
                            fill_size,
                            quote_spent,
                            dec!(0),
                            &quote,
                        );
                    }
                }
            } else {
                // Real mode: sync from live sources
                self._sync_balances();
            }

            // Post-swap inventory (concise; pre-swap already in [SIGNAL])
            {
                let inventory = self.inventory.lock()
                    .unwrap_or_else(|e| {
                        tracing::error!("Mutex poisoned in bot: {}", e);
                        e.into_inner()
                    });
                let (cex_asset2, cex_bal2, wallet_asset2, wallet_bal2) = match signal.direction {
                    Direction::BuyCexSellDex => (
                        quote.as_str(),
                        inventory.get_available(Venue::Binance, &quote),
                        base.as_str(),
                        inventory.get_available(Venue::Wallet, &base),
                    ),
                    Direction::BuyDexSellCex => (
                        base.as_str(),
                        inventory.get_available(Venue::Binance, &base),
                        quote.as_str(),
                        inventory.get_available(Venue::Wallet, &quote),
                    ),
                };
                tracing::info!(
                    "[INV-POST] {}  {}(cex)={:.4}  {}(wallet)={:.4}",
                    pair,
                    cex_asset2,
                    cex_bal2,
                    wallet_asset2,
                    wallet_bal2
                );
            }
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
        let exchange = self.exchange.lock()
                    .unwrap_or_else(|e| {
                        tracing::error!("Mutex poisoned in bot: {}", e);
                        e.into_inner()
                    });
        match exchange.fetch_balance() {
            Ok(balances) => {
                drop(exchange); // Release lock before acquiring inventory lock
                let mut inventory = self.inventory.lock()
                    .unwrap_or_else(|e| {
                        tracing::error!("Mutex poisoned in bot: {}", e);
                        e.into_inner()
                    });
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
        tracing::debug!("Starting wallet balance sync...");
        let pricing = self.pricing.lock()
                    .unwrap_or_else(|e| {
                        tracing::error!("Mutex poisoned in bot: {}", e);
                        e.into_inner()
                    });
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
                            tracing::debug!("Synced Wallet Balance: {} = {}", symbol, val);
                            wallet_balances.insert(symbol, val);
                        }
                    }
                }
                Err(e) => tracing::warn!("Failed to fetch balance for {}: {}", symbol, e),
            }
        }

        let eth_bal = wallet_balances.get("ETH").cloned().unwrap_or(Decimal::ZERO);
        tracing::debug!("Synced Wallet Balance: ETH = {}", eth_bal);

        // Update inventory
        let mut inventory = self.inventory.lock()
                    .unwrap_or_else(|e| {
                        tracing::error!("Mutex poisoned in bot: {}", e);
                        e.into_inner()
                    });
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
