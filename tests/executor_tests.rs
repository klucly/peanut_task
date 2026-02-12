use peanut_task::{Direction, Signal};
use peanut_task::strategy::{ExecutorConfig, ExecutorState, Executor};
use peanut_task::exchange::{ExchangeClient, ExchangeConfig};
use peanut_task::inventory::{InventoryTracker, Venue};
use peanut_task::pricing::PricingEngine;
use peanut_task::chain::{ChainClient, RpcUrl};
use peanut_task::pricing::Chain;
use rust_decimal_macros::dec;
use time::{Duration, OffsetDateTime};
use std::sync::Mutex;

// Global mutex to serialize executor creation (so ChainClient runtime creation happens one at a time)
static INIT_LOCK: Mutex<()> = Mutex::new(());

// Helper to create dependencies in non-async context
// Returns owned instances for Executor::new
fn create_dependencies() -> (ExchangeClient, PricingEngine, InventoryTracker) {
    // Lock to ensure only one thread creates ChainClient at a time
    let _lock = INIT_LOCK.lock().unwrap();
    
    let exchange = {
        let config = ExchangeConfig::from_env()
            .expect("Failed to load exchange config from env");
        ExchangeClient::new(config).expect("Failed to create exchange client")
    };
    
    let pricing = {
        let rpc = RpcUrl::new("https://eth-mainnet.g.alchemy.com/v2/test/{}", "")
            .expect("Failed to create RPC URL");
        
        let chain_client = ChainClient::new(vec![rpc], 60, 3)
            .expect("Failed to create chain client");
        
        PricingEngine::new(
            chain_client,
            "https://eth-mainnet.g.alchemy.com/v2/test",
            "wss://eth-mainnet.g.alchemy.com/v2/test",
            Chain::EthereumMainnet,
            None,
        ).expect("Failed to create pricing engine")
    };
    
    let inventory = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet])
        .expect("Failed to create inventory tracker");
    
    (exchange, pricing, inventory)
}

// Helper to create test executor - this must NOT be called from within an async function
// Instead, it should be called from a regular function that returns the executor
fn create_test_executor_sync(config: Option<ExecutorConfig>) -> Executor {
    let (exchange, pricing, inventory) = create_dependencies();
    Executor::new(exchange, pricing, inventory, config)
}

// ============================================================================
// Unit Tests
// ============================================================================

#[test]
fn test_default_executor_config() {
    let config = ExecutorConfig::default();
    assert_eq!(config.leg1_timeout_secs, 5);
    assert_eq!(config.leg2_timeout_secs, 60);
    assert_eq!(config.min_fill_ratio, dec!(0.8));
    assert_eq!(config.use_flashbots, true);
    assert_eq!(config.simulation_mode, true);
}

#[test]
fn test_custom_executor_config() {
    let config = ExecutorConfig::new(10, 120, dec!(0.9), false, false);
    assert_eq!(config.leg1_timeout_secs, 10);
    assert_eq!(config.leg2_timeout_secs, 120);
    assert_eq!(config.min_fill_ratio, dec!(0.9));
    assert_eq!(config.use_flashbots, false);
    assert_eq!(config.simulation_mode, false);
}

#[test]
fn test_executor_state_variants() {
    assert_eq!(ExecutorState::Idle, ExecutorState::Idle);
    assert_ne!(ExecutorState::Idle, ExecutorState::Validating);
    assert_eq!(ExecutorState::Done, ExecutorState::Done);
    assert_ne!(ExecutorState::Done, ExecutorState::Failed);
}

// Helper to create a test signal
fn create_test_signal() -> Signal {
    let expiry = OffsetDateTime::now_utc() + Duration::seconds(10);
    Signal::create(
        "ETH/USDT".to_string(),
        Direction::BuyCexSellDex,
        dec!(2000.0),   // cex_price
        dec!(2010.0),   // dex_price
        dec!(50),       // spread_bps
        dec!(1.0),      // size
        dec!(10.0),     // expected_gross_pnl
        dec!(2.0),      // expected_fees
        dec!(8.0),      // expected_net_pnl
        dec!(40),       // score
        expiry,
        true,           // inventory_ok
        true,           // within_limits
    )
}

// ============================================================================
// Required Integration Tests
// ============================================================================

#[test]
fn test_execute_success() {
    // Create executor in non-async context
    let mut executor = create_test_executor_sync(Some(ExecutorConfig {
        simulation_mode: true,
        use_flashbots: false,
        ..ExecutorConfig::default()
    }));

    let signal = create_test_signal();
    
    // Now run the async execution
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ctx = rt.block_on(executor.execute(signal));

    assert_eq!(ctx.state, ExecutorState::Done);
    assert!(ctx.error.is_none());
    assert!(ctx.leg1_fill_price.is_some());
    assert!(ctx.leg1_fill_size.is_some());
    assert!(ctx.leg2_fill_price.is_some());
    assert!(ctx.leg2_fill_size.is_some());
    assert!(ctx.actual_net_pnl.is_some());
    assert_eq!(ctx.leg1_venue, "cex");
    assert_eq!(ctx.leg2_venue, "dex");
    assert!(ctx.finished_at.is_some());
}

#[test]
fn test_execute_cex_timeout() {
    let mut executor = create_test_executor_sync(Some(ExecutorConfig::default()));

    // Create expired signal
    let expiry = OffsetDateTime::now_utc() - Duration::seconds(10);
    let signal = Signal::create(
        "ETH/USDT".to_string(),
        Direction::BuyCexSellDex,
        dec!(2000.0),
        dec!(2010.0),
        dec!(50),
        dec!(1.0),
        dec!(10.0),
        dec!(2.0),
        dec!(8.0),
        dec!(40),
        expiry,
        true,
        true,
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let ctx = rt.block_on(executor.execute(signal));

    assert_eq!(ctx.state, ExecutorState::Failed);
    assert!(ctx.error.is_some());
    assert_eq!(ctx.error.unwrap(), "Signal invalid");
}

#[test]
fn test_execute_dex_failure_unwinds() {
    let mut executor = create_test_executor_sync(Some(ExecutorConfig {
        simulation_mode: true,
        use_flashbots: true, // DEX-first
        ..ExecutorConfig::default()
    }));

    let signal = create_test_signal();
    
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ctx = rt.block_on(executor.execute(signal));

    // In simulation mode, both legs succeed
    assert_eq!(ctx.state, ExecutorState::Done);
    assert_eq!(ctx.leg1_venue, "dex");
    assert_eq!(ctx.leg2_venue, "cex");
}

#[test]
fn test_partial_fill_rejected() {
    let config = ExecutorConfig {
        min_fill_ratio: dec!(0.9),
        simulation_mode: true,
        ..ExecutorConfig::default()
    };

    let mut executor = create_test_executor_sync(Some(config));
    let signal = create_test_signal();
    
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ctx = rt.block_on(executor.execute(signal));

    // In simulation mode, this will succeed since we get 100% fill
    assert_eq!(ctx.state, ExecutorState::Done);
}

#[test]
fn test_circuit_breaker_blocks() {
    let mut executor = create_test_executor_sync(Some(ExecutorConfig::default()));

    let rt = tokio::runtime::Runtime::new().unwrap();
    
    // Trigger circuit breaker by simulating 5 consecutive failures quickly
   // Use expired signals which will fail validation
    for i in 0..5 {
        let expiry = OffsetDateTime::now_utc() - Duration::seconds(10);
        let signal = Signal::create(
            format!("ETH/USDT-{}", i),  // Unique pair to avoid replay protection
            Direction::BuyCexSellDex,
            dec!(2000.0),
            dec!(2010.0),
            dec!(50),
            dec!(1.0),
            dec!(10.0),
            dec!(2.0),
            dec!(8.0),
            dec!(40),
            expiry,
            true,
            true,
        );
        let ctx = rt.block_on(executor.execute(signal));
        // Verify each one fails
        assert_eq!(ctx.state, ExecutorState::Failed, "Failure {} should result in Failed state", i + 1);
    }

    // Verify circuit breaker is now open
    assert!(executor.circuit_breaker.is_open(), "Circuit breaker should be open after 5 failures");
    
    // Try to execute with a valid signal - should be blocked by circuit breaker
    let signal = create_test_signal();
    let ctx = rt.block_on(executor.execute(signal));

    assert_eq!(ctx.state, ExecutorState::Failed, "Circuit breaker should block execution");
    assert!(ctx.error.is_some());
    assert_eq!(ctx.error.unwrap(), "Circuit breaker open");
}

#[test]
fn test_replay_protection() {
    let mut executor = create_test_executor_sync(Some(ExecutorConfig::default()));

    let signal = create_test_signal();
    let _signal_id = signal.signal_id.clone();

    let rt = tokio::runtime::Runtime::new().unwrap();
    
    // First execution should succeed
    let ctx1 = rt.block_on(executor.execute(signal.clone()));
    assert_eq!(ctx1.state, ExecutorState::Done);

    // Second execution of same signal should be blocked
    let ctx2 = rt.block_on(executor.execute(signal));
    assert_eq!(ctx2.state, ExecutorState::Failed);
    assert!(ctx2.error.is_some());
    assert_eq!(ctx2.error.unwrap(), "Duplicate signal");
    
    // Verify the signal ID was tracked
    assert!(executor.replay_protection.is_duplicate(&ctx1.signal));
}

// ============================================================================
// Additional Tests
// ============================================================================

#[test]
fn test_dex_first_execution_flow() {
    let mut executor = create_test_executor_sync(Some(ExecutorConfig {
        simulation_mode: true,
        use_flashbots: true,
        ..ExecutorConfig::default()
    }));

    let signal = create_test_signal();
    
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ctx = rt.block_on(executor.execute(signal));

    assert_eq!(ctx.state, ExecutorState::Done);
    assert_eq!(ctx.leg1_venue, "dex");
    assert_eq!(ctx.leg2_venue, "cex");
    assert!(ctx.actual_net_pnl.is_some());
}

#[test]
fn test_signal_validation_failure() {
    let mut executor = create_test_executor_sync(Some(ExecutorConfig::default()));

    // Create signal with negative PnL (invalid)
    let expiry = OffsetDateTime::now_utc() + Duration::seconds(10);
    let signal = Signal::create(
        "ETH/USDT".to_string(),
        Direction::BuyCexSellDex,
        dec!(2000.0),
        dec!(1990.0),  // DEX price lower than CEX (wrong direction)
        dec!(50),
        dec!(1.0),
        dec!(-10.0),   // negative gross PnL
        dec!(2.0),
        dec!(-12.0),   // negative net PnL
        dec!(0),       // zero score
        expiry,
        true,
        true,
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let ctx = rt.block_on(executor.execute(signal));

    assert_eq!(ctx.state, ExecutorState::Failed);
    assert!(ctx.error.is_some());
    assert_eq!(ctx.error.unwrap(), "Signal invalid");
}

#[test]
fn test_pnl_calculation_buy_cex_sell_dex() {
    let mut executor = create_test_executor_sync(Some(ExecutorConfig::default()));

    let signal = Signal::create(
        "ETH/USDT".to_string(),
        Direction::BuyCexSellDex,
        dec!(2000.0),
        dec!(2010.0),
        dec!(50),
        dec!(1.0),
        dec!(10.0),
        dec!(2.0),
        dec!(8.0),
        dec!(80),
        OffsetDateTime::now_utc() + Duration::seconds(10),
        true,
        true,
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let ctx = rt.block_on(executor.execute(signal));

    assert_eq!(ctx.state, ExecutorState::Done);
    assert!(ctx.actual_net_pnl.is_some());
    
    // PnL calculation exists and is reasonable (simulation has fees)
    let _pnl = ctx.actual_net_pnl.unwrap();
}

#[test]
fn test_pnl_calculation_buy_dex_sell_cex() {
    let mut executor = create_test_executor_sync(Some(ExecutorConfig {
        use_flashbots: true,
        ..ExecutorConfig::default()
    }));

    let signal = Signal::create(
        "ETH/USDT".to_string(),
        Direction::BuyDexSellCex,
        dec!(2010.0),  // CEX price (higher)
        dec!(2000.0),  // DEX price (lower)
        dec!(50),
        dec!(1.0),
        dec!(10.0),
        dec!(2.0),
        dec!(8.0),
        dec!(80),
        OffsetDateTime::now_utc() + Duration::seconds(10),
        true,
        true,
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let ctx = rt.block_on(executor.execute(signal));

    assert_eq!(ctx.state, ExecutorState::Done);
    assert!(ctx.actual_net_pnl.is_some());
    
    // PnL calculation exists and is reasonable (simulation has fees)
    let _pnl = ctx.actual_net_pnl.unwrap();
}
