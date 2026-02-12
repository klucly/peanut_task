//! Executor module for multi-leg arbitrage execution.

use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::collections::HashSet;
use time::{Duration, OffsetDateTime};
use tokio::time::timeout;

use super::signal::{Direction, Signal};
use crate::exchange::ExchangeClient;
use crate::inventory::InventoryTracker;
use crate::pricing::PricingEngine;

/// Executor state tracking execution progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorState {
    Idle,
    Validating,
    Leg1Pending,
    Leg1Filled,
    Leg2Pending,
    Done,
    Failed,
    Unwinding,
}

/// Execution context tracking full execution lifecycle.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub signal: Signal,
    pub state: ExecutorState,

    pub leg1_venue: String,
    pub leg1_order_id: Option<String>,
    pub leg1_fill_price: Option<Decimal>,
    pub leg1_fill_size: Option<Decimal>,

    pub leg2_venue: String,
    pub leg2_tx_hash: Option<String>,
    pub leg2_fill_price: Option<Decimal>,
    pub leg2_fill_size: Option<Decimal>,

    pub started_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
    pub actual_net_pnl: Option<Decimal>,
    pub error: Option<String>,
}

impl ExecutionContext {
    pub fn new(signal: Signal) -> Self {
        Self {
            signal,
            state: ExecutorState::Idle,
            leg1_venue: String::new(),
            leg1_order_id: None,
            leg1_fill_price: None,
            leg1_fill_size: None,
            leg2_venue: String::new(),
            leg2_tx_hash: None,
            leg2_fill_price: None,
            leg2_fill_size: None,
            started_at: OffsetDateTime::now_utc(),
            finished_at: None,
            actual_net_pnl: None,
            error: None,
        }
    }
}

/// Executor configuration.
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    pub leg1_timeout_secs: u64,
    pub leg2_timeout_secs: u64,
    pub min_fill_ratio: Decimal,
    pub use_flashbots: bool,
    pub simulation_mode: bool,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            leg1_timeout_secs: 5,
            leg2_timeout_secs: 60,
            min_fill_ratio: dec!(0.8),
            use_flashbots: true,
            simulation_mode: true,
        }
    }
}

impl ExecutorConfig {
    pub fn new(
        leg1_timeout_secs: u64,
        leg2_timeout_secs: u64,
        min_fill_ratio: Decimal,
        use_flashbots: bool,
        simulation_mode: bool,
    ) -> Self {
        Self {
            leg1_timeout_secs,
            leg2_timeout_secs,
            min_fill_ratio,
            use_flashbots,
            simulation_mode,
        }
    }
}

/// Circuit breaker to prevent cascading failures.
#[derive(Debug)]
pub struct CircuitBreaker {
    consecutive_failures: u32,
    failure_threshold: u32,
    last_failure_time: Option<OffsetDateTime>,
    cooldown_duration: Duration,
    total_successes: u64,
    total_failures: u64,
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self {
            consecutive_failures: 0,
            failure_threshold: 5,
            last_failure_time: None,
            cooldown_duration: Duration::seconds(60),
            total_successes: 0,
            total_failures: 0,
        }
    }

    pub fn is_open(&self) -> bool {
        if self.consecutive_failures >= self.failure_threshold {
            if let Some(last_failure) = self.last_failure_time {
                let now = OffsetDateTime::now_utc();
                let elapsed = now - last_failure;
                return elapsed < self.cooldown_duration;
            }
            return true;
        }
        false
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.total_successes += 1;
    }

    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        self.last_failure_time = Some(OffsetDateTime::now_utc());
        self.total_failures += 1;
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

/// Replay protection to prevent duplicate executions.
#[derive(Debug)]
pub struct ReplayProtection {
    executed_signals: HashSet<String>,
}

impl ReplayProtection {
    pub fn new() -> Self {
        Self {
            executed_signals: HashSet::new(),
        }
    }

    pub fn is_duplicate(&self, signal: &Signal) -> bool {
        self.executed_signals.contains(&signal.signal_id)
    }

    pub fn mark_executed(&mut self, signal: &Signal) {
        self.executed_signals.insert(signal.signal_id.clone());
        
        // Clean up old entries if set grows too large
        if self.executed_signals.len() > 1000 {
            // Keep only most recent 500
            let to_remove: Vec<String> = self.executed_signals
                .iter()
                .take(500)
                .cloned()
                .collect();
            for id in to_remove {
                self.executed_signals.remove(&id);
            }
        }
    }
}

impl Default for ReplayProtection {
    fn default() -> Self {
        Self::new()
    }
}

/// Result from executing a single leg.
#[derive(Debug)]
struct LegResult {
    success: bool,
    price: Decimal,
    filled: Decimal,
    error: Option<String>,
}

/// Execute arbitrage trades across CEX and DEX.
pub struct Executor {
    exchange: ExchangeClient,
    pricing: PricingEngine,
    inventory: InventoryTracker,
    config: ExecutorConfig,
    pub circuit_breaker: CircuitBreaker,
    pub replay_protection: ReplayProtection,
}

impl Executor {
    pub fn new(
        exchange_client: ExchangeClient,
        pricing_module: PricingEngine,
        inventory_tracker: InventoryTracker,
        config: Option<ExecutorConfig>,
    ) -> Self {
        Self {
            exchange: exchange_client,
            pricing: pricing_module,
            inventory: inventory_tracker,
            config: config.unwrap_or_default(),
            circuit_breaker: CircuitBreaker::new(),
            replay_protection: ReplayProtection::new(),
        }
    }

    /// Execute arbitrage trade based on signal.
    pub async fn execute(&mut self, signal: Signal) -> ExecutionContext {
        let mut ctx = ExecutionContext::new(signal.clone());

        // Pre-flight checks
        if self.circuit_breaker.is_open() {
            ctx.state = ExecutorState::Failed;
            ctx.error = Some("Circuit breaker open".to_string());
            ctx.finished_at = Some(OffsetDateTime::now_utc());
            self.circuit_breaker.record_failure();
            return ctx;
        }

        if self.replay_protection.is_duplicate(&signal) {
            ctx.state = ExecutorState::Failed;
            ctx.error = Some("Duplicate signal".to_string());
            ctx.finished_at = Some(OffsetDateTime::now_utc());
            self.replay_protection.mark_executed(&signal);
            self.circuit_breaker.record_failure();
            return ctx;
        }

        ctx.state = ExecutorState::Validating;
        if !signal.is_valid() {
            ctx.state = ExecutorState::Failed;
            ctx.error = Some("Signal invalid".to_string());
            ctx.finished_at = Some(OffsetDateTime::now_utc());
            self.replay_protection.mark_executed(&signal);
            self.circuit_breaker.record_failure();
            return ctx;
        }

        // Execute based on leg order strategy
        ctx = if self.config.use_flashbots {
            self._execute_dex_first(ctx).await
        } else {
            self._execute_cex_first(ctx).await
        };

        // Record result
        self.replay_protection.mark_executed(&signal);
        if ctx.state == ExecutorState::Done {
            self.circuit_breaker.record_success();
        } else {
            self.circuit_breaker.record_failure();
        }

        ctx.finished_at = Some(OffsetDateTime::now_utc());
        ctx
    }

    /// CEX leg first (default for non-Flashbots).
    async fn _execute_cex_first(&mut self, mut ctx: ExecutionContext) -> ExecutionContext {
        let signal = &ctx.signal;

        // Leg 1: CEX
        ctx.state = ExecutorState::Leg1Pending;
        ctx.leg1_venue = "cex".to_string();

        let leg1_future = self._execute_cex_leg(signal, signal.size);
        let timeout_duration = std::time::Duration::from_secs(self.config.leg1_timeout_secs);
        
        let leg1 = match timeout(timeout_duration, leg1_future).await {
            Ok(result) => result,
            Err(_) => {
                ctx.state = ExecutorState::Failed;
                ctx.error = Some("CEX timeout".to_string());
                return ctx;
            }
        };

        if !leg1.success {
            ctx.state = ExecutorState::Failed;
            ctx.error = Some(leg1.error.unwrap_or_else(|| "CEX rejected".to_string()));
            return ctx;
        }

        if leg1.filled / signal.size < self.config.min_fill_ratio {
            ctx.state = ExecutorState::Failed;
            ctx.error = Some("Partial fill below threshold".to_string());
            return ctx;
        }

        ctx.leg1_fill_price = Some(leg1.price);
        ctx.leg1_fill_size = Some(leg1.filled);
        ctx.state = ExecutorState::Leg1Filled;

        // Leg 2: DEX
        ctx.state = ExecutorState::Leg2Pending;
        ctx.leg2_venue = "dex".to_string();

        let leg2_future = self._execute_dex_leg(signal, ctx.leg1_fill_size.unwrap());
        let timeout_duration = std::time::Duration::from_secs(self.config.leg2_timeout_secs);
        
        let leg2 = match timeout(timeout_duration, leg2_future).await {
            Ok(result) => result,
            Err(_) => {
                ctx.state = ExecutorState::Unwinding;
                self._unwind(&ctx).await;
                ctx.state = ExecutorState::Failed;
                ctx.error = Some("DEX timeout - unwound".to_string());
                return ctx;
            }
        };

        if !leg2.success {
            ctx.state = ExecutorState::Unwinding;
            self._unwind(&ctx).await;
            ctx.state = ExecutorState::Failed;
            ctx.error = Some("DEX failed - unwound".to_string());
            return ctx;
        }

        ctx.leg2_fill_price = Some(leg2.price);
        ctx.leg2_fill_size = Some(leg2.filled);
        ctx.actual_net_pnl = Some(self._calculate_pnl(&ctx));
        ctx.state = ExecutorState::Done;
        ctx
    }

    /// DEX leg first (when using Flashbots - failed tx = no cost).
    async fn _execute_dex_first(&mut self, mut ctx: ExecutionContext) -> ExecutionContext {
        let signal = &ctx.signal;

        // Leg 1: DEX
        ctx.state = ExecutorState::Leg1Pending;
        ctx.leg1_venue = "dex".to_string();

        let leg1_future = self._execute_dex_leg(signal, signal.size);
        let timeout_duration = std::time::Duration::from_secs(self.config.leg2_timeout_secs);
        
        let leg1 = match timeout(timeout_duration, leg1_future).await {
            Ok(result) => result,
            Err(_) => {
                ctx.state = ExecutorState::Failed;
                ctx.error = Some("DEX timeout".to_string());
                return ctx;
            }
        };

        if !leg1.success {
            ctx.state = ExecutorState::Failed;
            ctx.error = Some("DEX failed (no cost via Flashbots)".to_string());
            return ctx;
        }

        ctx.leg1_fill_price = Some(leg1.price);
        ctx.leg1_fill_size = Some(leg1.filled);
        ctx.state = ExecutorState::Leg1Filled;

        // Leg 2: CEX
        ctx.state = ExecutorState::Leg2Pending;
        ctx.leg2_venue = "cex".to_string();

        let leg2_future = self._execute_cex_leg(signal, ctx.leg1_fill_size.unwrap());
        let timeout_duration = std::time::Duration::from_secs(self.config.leg1_timeout_secs);
        
        let leg2 = match timeout(timeout_duration, leg2_future).await {
            Ok(result) => result,
            Err(_) => {
                ctx.state = ExecutorState::Unwinding;
                self._unwind(&ctx).await;
                ctx.state = ExecutorState::Failed;
                ctx.error = Some("CEX timeout after DEX - unwound".to_string());
                return ctx;
            }
        };

        if !leg2.success {
            ctx.state = ExecutorState::Unwinding;
            self._unwind(&ctx).await;
            ctx.state = ExecutorState::Failed;
            ctx.error = Some("CEX failed after DEX - unwound".to_string());
            return ctx;
        }

        ctx.leg2_fill_price = Some(leg2.price);
        ctx.leg2_fill_size = Some(leg2.filled);
        ctx.actual_net_pnl = Some(self._calculate_pnl(&ctx));
        ctx.state = ExecutorState::Done;
        ctx
    }

    /// Execute CEX leg.
    async fn _execute_cex_leg(&self, signal: &Signal, size: Decimal) -> LegResult {
        if self.config.simulation_mode {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            return LegResult {
                success: true,
                price: signal.cex_price * dec!(1.0001),
                filled: size,
                error: None,
            };
        }

        // Real execution via exchange client
        let side = match signal.direction {
            Direction::BuyCexSellDex => "buy",
            Direction::BuyDexSellCex => "sell",
        };

        let amount_f64 = size.to_string().parse::<f64>().unwrap_or(0.0);
        let price_f64 = (signal.cex_price * dec!(1.001)).to_string().parse::<f64>().unwrap_or(0.0);

        match self.exchange.create_limit_ioc_order(&signal.pair, side, amount_f64, price_f64) {
            Ok(result) => LegResult {
                success: result.status == "filled",
                price: result.avg_fill_price,
                filled: result.amount_filled,
                error: if result.status != "filled" {
                    Some(result.status.clone())
                } else {
                    None
                },
            },
            Err(e) => LegResult {
                success: false,
                price: Decimal::ZERO,
                filled: Decimal::ZERO,
                error: Some(format!("Exchange error: {:?}", e)),
            },
        }
    }

    /// Execute DEX leg (simulation stub).
    async fn _execute_dex_leg(&self, signal: &Signal, size: Decimal) -> LegResult {
        if self.config.simulation_mode {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            return LegResult {
                success: true,
                price: signal.dex_price * dec!(0.9998),
                filled: size,
                error: None,
            };
        }

        tracing::warn!("Real DEX execution requires Week 2 integration");
        LegResult {
            success: false,
            price: Decimal::ZERO,
            filled: Decimal::ZERO,
            error: Some("DEX execution not implemented".to_string()),
        }
    }

    /// Unwind position (simulation stub).
    async fn _unwind(&self, _ctx: &ExecutionContext) {
        if self.config.simulation_mode {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            return;
        }

        tracing::warn!("Real unwind not implemented");
    }

    /// Calculate actual PnL from execution.
    fn _calculate_pnl(&self, ctx: &ExecutionContext) -> Decimal {
        let signal = &ctx.signal;
        let leg1_price = ctx.leg1_fill_price.unwrap_or(Decimal::ZERO);
        let leg1_size = ctx.leg1_fill_size.unwrap_or(Decimal::ZERO);
        let leg2_price = ctx.leg2_fill_price.unwrap_or(Decimal::ZERO);

        let gross = match signal.direction {
            Direction::BuyCexSellDex => (leg2_price - leg1_price) * leg1_size,
            Direction::BuyDexSellCex => (leg1_price - leg2_price) * leg1_size,
        };

        // ~40 bps fee assumption
        let fees = leg1_size * leg1_price * dec!(0.004);
        gross - fees
    }
}
