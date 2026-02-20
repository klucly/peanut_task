use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

use super::fees::FeeStructure;
use super::recovery::{CircuitBreaker, CircuitBreakerConfig, ReplayProtection};
use super::signal::{Direction, Signal};
use crate::chain::ChainClient;
use crate::exchange::ExchangeClient;
use crate::inventory::InventoryTracker;
use crate::pricing::PricingEngine;

/// Whether the first leg of an execution is a buy or a sell.
/// Used to correctly compute PnL regardless of execution order (CEX-first vs DEX-first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegSide {
    /// Spending quote to obtain base (buying)
    Buy,
    /// Spending base to obtain quote (selling)
    Sell,
}

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
    pub leg1_side: LegSide,
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
            leg1_side: LegSide::Buy, // default; overwritten before use
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
    pub circuit_breaker: Option<CircuitBreakerConfig>,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            leg1_timeout_secs: 5,
            leg2_timeout_secs: 60,
            min_fill_ratio: dec!(0.8),
            use_flashbots: true,
            simulation_mode: true,
            circuit_breaker: None,
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
        circuit_breaker: Option<CircuitBreakerConfig>,
    ) -> Self {
        Self {
            leg1_timeout_secs,
            leg2_timeout_secs,
            min_fill_ratio,
            use_flashbots,
            simulation_mode,
            circuit_breaker,
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
    /// True when failure is critical (e.g. real-mode DEX unimplemented); caller must record_critical_failure().
    critical: bool,
}

/// Execute arbitrage trades across CEX and DEX.
#[allow(dead_code)] // pricing, inventory, chain_client reserved for real DEX execution implementation
pub struct Executor {
    exchange: Arc<Mutex<ExchangeClient>>,
    pricing: Arc<Mutex<PricingEngine>>,
    inventory: Arc<Mutex<InventoryTracker>>,
    chain_client: Arc<ChainClient>,
    fee_structure: FeeStructure,
    config: ExecutorConfig,
    pub circuit_breaker: CircuitBreaker,
    pub replay_protection: ReplayProtection,
}

impl Executor {
    pub fn new(
        exchange_client: Arc<Mutex<ExchangeClient>>,
        pricing_module: Arc<Mutex<PricingEngine>>,
        inventory_tracker: Arc<Mutex<InventoryTracker>>,
        chain_client: Arc<ChainClient>,
        fee_structure: FeeStructure,
        config: Option<ExecutorConfig>,
    ) -> Self {
        let cfg = config.unwrap_or_default();
        Self {
            exchange: exchange_client,
            pricing: pricing_module,
            inventory: inventory_tracker,
            chain_client,
            fee_structure,
            config: cfg.clone(),
            circuit_breaker: CircuitBreaker::new(cfg.circuit_breaker),
            replay_protection: ReplayProtection::default(),
        }
    }

    /// Execute arbitrage trade based on signal.
    #[tracing::instrument(skip(self, signal), fields(pair = %signal.pair, direction = ?signal.direction, score = %signal.score))]
    pub fn execute(&mut self, signal: Signal) -> ExecutionContext {
        let mut ctx = ExecutionContext::new(signal.clone());

        // Pre-flight checks — these are protective guards, not genuine trade failures.
        // Only record_failure() when an actual execution attempt fails.
        if self.circuit_breaker.is_open() {
            tracing::warn!("Circuit breaker open - rejecting execution");
            ctx.state = ExecutorState::Failed;
            ctx.error = Some("Circuit breaker open".to_string());
            ctx.finished_at = Some(OffsetDateTime::now_utc());
            return ctx;
        }

        if self.replay_protection.is_duplicate(&signal) {
            tracing::warn!("Duplicate signal detected - rejecting execution");
            ctx.state = ExecutorState::Failed;
            ctx.error = Some("Duplicate signal".to_string());
            ctx.finished_at = Some(OffsetDateTime::now_utc());
            self.replay_protection.mark_executed(&signal);
            return ctx;
        }

        ctx.state = ExecutorState::Validating;
        if !signal.is_valid() {
            tracing::warn!(
                "Signal invalid (expired or negative PnL): {}",
                signal.signal_id
            );
            ctx.state = ExecutorState::Failed;
            ctx.error = Some("Signal invalid".to_string());
            ctx.finished_at = Some(OffsetDateTime::now_utc());
            self.replay_protection.mark_executed(&signal);
            return ctx;
        }

        // Additional validation: Price sanity check
        if signal.cex_price <= Decimal::ZERO {
            tracing::warn!(
                "Signal has invalid CEX price ({}): {}",
                signal.cex_price,
                signal.signal_id
            );
            ctx.state = ExecutorState::Failed;
            ctx.error = Some("Invalid CEX price".to_string());
            ctx.finished_at = Some(OffsetDateTime::now_utc());
            return ctx;
        }

        // Execute based on leg order strategy
        ctx = if self.config.use_flashbots {
            self._execute_dex_first(ctx)
        } else {
            self._execute_cex_first(ctx)
        };

        // Only execution attempts (past pre-flight) count; pre-flight returns above do not reach here.
        self.replay_protection.mark_executed(&signal);
        if ctx.state == ExecutorState::Done {
            self.circuit_breaker.record_success();
        } else {
            // Only actual execution failures count toward tripping the circuit breaker
            self.circuit_breaker.record_failure();
        }

        ctx.finished_at = Some(OffsetDateTime::now_utc());
        ctx
    }

    /// CEX leg first (default for non-Flashbots).
    fn _execute_cex_first(&mut self, mut ctx: ExecutionContext) -> ExecutionContext {
        let signal = &ctx.signal;

        // leg1 = CEX. Direction determines if CEX is buy or sell.
        let leg1_side = match signal.direction {
            Direction::BuyCexSellDex => LegSide::Buy,
            Direction::BuyDexSellCex => LegSide::Sell,
        };

        ctx.state = ExecutorState::Leg1Pending;
        ctx.leg1_venue = "cex".to_string();
        ctx.leg1_side = leg1_side;

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
            if leg2.critical {
                self.circuit_breaker.record_critical_failure();
            }
            ctx.state = ExecutorState::Unwinding;
            let unwind_critical = self._unwind(&ctx);
            if unwind_critical {
                self.circuit_breaker.record_critical_failure();
            }
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

        // leg1 = DEX. Direction determines if DEX is buy or sell.
        let leg1_side = match signal.direction {
            Direction::BuyCexSellDex => LegSide::Sell, // selling base on DEX
            Direction::BuyDexSellCex => LegSide::Buy,  // buying base on DEX
        };

        ctx.state = ExecutorState::Leg1Pending;
        ctx.leg1_venue = "dex".to_string();
        ctx.leg1_side = leg1_side;

        let leg1 = self._execute_dex_leg(signal, signal.size);

        if !leg1.success {
            if leg1.critical {
                self.circuit_breaker.record_critical_failure();
            }
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
            let unwind_critical = self._unwind(&ctx);
            if unwind_critical {
                self.circuit_breaker.record_critical_failure();
            }
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
            std::thread::sleep(std::time::Duration::from_millis(100));
            return LegResult {
                success: true,
                price: signal.cex_price * dec!(1.0001),
                filled: size,
                error: None,
                critical: false,
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

        if amount_f64 <= 0.0
            || !amount_f64.is_finite()
            || price_f64 <= 0.0
            || !price_f64.is_finite()
        {
            return LegResult {
                success: false,
                price: Decimal::ZERO,
                filled: Decimal::ZERO,
                error: Some("invalid amount or price (parse error)".to_string()),
                critical: false,
            };
        }

        let exchange = self
            .exchange
            .lock()
            .unwrap_or_else(|e| {
                tracing::error!("Mutex poisoned in executor (exchange): {}", e);
                e.into_inner()
            });
        match exchange.create_limit_ioc_order(&signal.pair, side, amount_f64, price_f64) {
            Ok(result) => LegResult {
                success: result.status == "filled",
                price: result.avg_fill_price,
                filled: result.amount_filled,
                error: if result.status != "filled" {
                    Some(result.status.clone())
                } else {
                    None
                },
                critical: false,
            },
            Err(e) => {
                tracing::error!("CEX Order Failed: {:?}", e);
                LegResult {
                    success: false,
                    price: Decimal::ZERO,
                    filled: Decimal::ZERO,
                    error: Some(format!("Exchange error: {:?}", e)),
                    critical: false,
                }
            }
        }
    }

    /// Execute DEX leg.
    fn _execute_dex_leg(&self, signal: &Signal, size: Decimal) -> LegResult {
        if self.config.simulation_mode {
            std::thread::sleep(std::time::Duration::from_millis(500));
            return LegResult {
                success: true,
                price: signal.dex_price * dec!(0.9998),
                filled: size,
                error: None,
                critical: false,
            };
        }

        // Real DEX execution requires submitting an on-chain swap transaction.
        // ChainClient is available via self.chain_client but swap transaction
        // construction is not yet implemented.
        tracing::error!(
            "DEX execution not implemented for real mode. pair={}, size={}",
            signal.pair,
            size
        );
        LegResult {
            success: false,
            price: Decimal::ZERO,
            filled: Decimal::ZERO,
            error: Some("DEX execution not implemented — real mode".to_string()),
            critical: true,
        }
    }

    /// Unwind position after a partial execution failure.
    /// Returns true if real mode and unwind was required but not implemented (critical).
    fn _unwind(&self, _ctx: &ExecutionContext) -> bool {
        if self.config.simulation_mode {
            std::thread::sleep(std::time::Duration::from_millis(100));
            return false;
        }

        tracing::error!("Real unwind not implemented — manual intervention required");
        true
    }

    /// Calculate actual PnL from execution.
    /// Uses leg1_side to correctly identify which leg was the sell (revenue) and buy (cost),
    /// regardless of whether we went CEX-first or DEX-first.
    fn _calculate_pnl(&self, ctx: &ExecutionContext) -> Decimal {
        let leg1_price = ctx.leg1_fill_price.unwrap_or(Decimal::ZERO);
        let leg1_size = ctx.leg1_fill_size.unwrap_or(Decimal::ZERO);
        let leg2_price = ctx.leg2_fill_price.unwrap_or(Decimal::ZERO);

        // Sell leg generates revenue; buy leg is the cost
        let (sell_price, buy_price) = match ctx.leg1_side {
            LegSide::Sell => (leg1_price, leg2_price),
            LegSide::Buy => (leg2_price, leg1_price),
        };

        let gross = (sell_price - buy_price) * leg1_size;

        // Use configured fee structure instead of hardcoded assumptions
        let trade_value_usd = buy_price * leg1_size;
        let fee_bps = self.fee_structure.cex_taker_bps + self.fee_structure.dex_swap_bps;
        let fees = if trade_value_usd > Decimal::ZERO {
            (fee_bps / Decimal::from(10_000)) * trade_value_usd
        } else {
            Decimal::ZERO
        };

        gross - fees
    }
}
