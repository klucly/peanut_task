use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

use super::recovery::{CircuitBreaker, ReplayProtection};
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
    exchange: Arc<Mutex<ExchangeClient>>,
    pricing: Arc<Mutex<PricingEngine>>,
    inventory: Arc<Mutex<InventoryTracker>>,
    config: ExecutorConfig,
    pub circuit_breaker: CircuitBreaker,
    pub replay_protection: ReplayProtection,
}

impl Executor {
    pub fn new(
        exchange_client: Arc<Mutex<ExchangeClient>>,
        pricing_module: Arc<Mutex<PricingEngine>>,
        inventory_tracker: Arc<Mutex<InventoryTracker>>,
        config: Option<ExecutorConfig>,
    ) -> Self {
        Self {
            exchange: exchange_client,
            pricing: pricing_module,
            inventory: inventory_tracker,
            config: config.unwrap_or_default(),
            circuit_breaker: CircuitBreaker::default(),
            replay_protection: ReplayProtection::default(),
        }
    }

    /// Execute arbitrage trade based on signal.
    #[tracing::instrument(skip(self, signal), fields(pair = %signal.pair, direction = ?signal.direction, score = %signal.score))]
    pub fn execute(&mut self, signal: Signal) -> ExecutionContext {
        let mut ctx = ExecutionContext::new(signal.clone());
        tracing::info!(
            "Starting execution for {} (Score: {})",
            signal.pair,
            signal.score
        );

        // Pre-flight checks
        if self.circuit_breaker.is_open() {
            tracing::warn!("Circuit breaker open - rejecting execution");
            ctx.state = ExecutorState::Failed;
            ctx.error = Some("Circuit breaker open".to_string());
            ctx.finished_at = Some(OffsetDateTime::now_utc());
            self.circuit_breaker.record_failure();
            return ctx;
        }

        if self.replay_protection.is_duplicate(&signal) {
            tracing::warn!("Duplicate signal detected - rejecting execution");
            ctx.state = ExecutorState::Failed;
            ctx.error = Some("Duplicate signal".to_string());
            ctx.finished_at = Some(OffsetDateTime::now_utc());
            self.replay_protection.mark_executed(&signal);
            self.circuit_breaker.record_failure();
            return ctx;
        }

        ctx.state = ExecutorState::Validating;
        if !signal.is_valid() {
            tracing::warn!("Signal validation failed");
            ctx.state = ExecutorState::Failed;
            ctx.error = Some("Signal invalid".to_string());
            ctx.finished_at = Some(OffsetDateTime::now_utc());
            self.replay_protection.mark_executed(&signal);
            self.circuit_breaker.record_failure();
            return ctx;
        }

        // Additional validation: Price sanity check
        if signal.cex_price <= Decimal::ZERO {
            tracing::error!("Invalid CEX price in signal: {}", signal.cex_price);
            ctx.state = ExecutorState::Failed;
            ctx.error = Some("Invalid CEX price".to_string());
            ctx.finished_at = Some(OffsetDateTime::now_utc());
            self.circuit_breaker.record_failure();
            return ctx;
        }

        tracing::debug!(
            "Validation passed. Strategy: {}",
            if self.config.use_flashbots {
                "Flashbots (DEX first)"
            } else {
                "Standard (CEX first)"
            }
        );

        // Execute based on leg order strategy
        ctx = if self.config.use_flashbots {
            self._execute_dex_first(ctx)
        } else {
            self._execute_cex_first(ctx)
        };

        // Record result
        self.replay_protection.mark_executed(&signal);
        if ctx.state == ExecutorState::Done {
            tracing::info!("Execution successful. Net PnL: {:?}", ctx.actual_net_pnl);
            self.circuit_breaker.record_success();
        } else {
            tracing::error!("Execution failed: {:?}", ctx.error);
            self.circuit_breaker.record_failure();
        }

        ctx.finished_at = Some(OffsetDateTime::now_utc());
        ctx
    }

    /// CEX leg first (default for non-Flashbots).
    fn _execute_cex_first(&mut self, mut ctx: ExecutionContext) -> ExecutionContext {
        let signal = &ctx.signal;

        // Leg 1: CEX
        ctx.state = ExecutorState::Leg1Pending;
        ctx.leg1_venue = "cex".to_string();

        let leg1 = self._execute_cex_leg(signal, signal.size);

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

        let leg2 = self._execute_dex_leg(signal, ctx.leg1_fill_size.unwrap());

        if !leg2.success {
            ctx.state = ExecutorState::Unwinding;
            self._unwind(&ctx);
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
    fn _execute_dex_first(&mut self, mut ctx: ExecutionContext) -> ExecutionContext {
        let signal = &ctx.signal;

        // Leg 1: DEX
        ctx.state = ExecutorState::Leg1Pending;
        ctx.leg1_venue = "dex".to_string();

        let leg1 = self._execute_dex_leg(signal, signal.size);

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

        let leg2 = self._execute_cex_leg(signal, ctx.leg1_fill_size.unwrap());

        if !leg2.success {
            ctx.state = ExecutorState::Unwinding;
            self._unwind(&ctx);
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
    fn _execute_cex_leg(&self, signal: &Signal, size: Decimal) -> LegResult {
        if self.config.simulation_mode {
            tracing::info!(
                "Simulating CEX Leg: {} {} @ {}",
                if signal.direction == Direction::BuyCexSellDex {
                    "Buy"
                } else {
                    "Sell"
                },
                size,
                signal.cex_price
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
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
        let price_f64 = (signal.cex_price * dec!(1.001))
            .to_string()
            .parse::<f64>()
            .unwrap_or(0.0);

        tracing::info!("Placing CEX Order: {} {} @ {}", side, amount_f64, price_f64);

        let exchange = self.exchange.lock().unwrap();
        match exchange.create_limit_ioc_order(&signal.pair, side, amount_f64, price_f64) {
            Ok(result) => {
                tracing::info!(
                    "CEX Order Result: Status={}, Filled={}, AvgPrice={}",
                    result.status,
                    result.amount_filled,
                    result.avg_fill_price
                );
                LegResult {
                    success: result.status == "filled",
                    price: result.avg_fill_price,
                    filled: result.amount_filled,
                    error: if result.status != "filled" {
                        Some(result.status.clone())
                    } else {
                        None
                    },
                }
            }
            Err(e) => {
                tracing::error!("CEX Order Failed: {:?}", e);
                LegResult {
                    success: false,
                    price: Decimal::ZERO,
                    filled: Decimal::ZERO,
                    error: Some(format!("Exchange error: {:?}", e)),
                }
            }
        }
    }

    /// Execute DEX leg (simulation stub).
    fn _execute_dex_leg(&self, signal: &Signal, size: Decimal) -> LegResult {
        if self.config.simulation_mode {
            tracing::info!(
                "Simulating DEX Leg: {} {} @ {}",
                if signal.direction == Direction::BuyDexSellCex {
                    "Buy"
                } else {
                    "Sell"
                },
                size,
                signal.dex_price
            );
            std::thread::sleep(std::time::Duration::from_millis(500));
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
    fn _unwind(&self, _ctx: &ExecutionContext) {
        if self.config.simulation_mode {
            std::thread::sleep(std::time::Duration::from_millis(100));
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
