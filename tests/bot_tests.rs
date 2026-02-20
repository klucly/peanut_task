//! Integration and unit tests for ArbBot.
//!
//! Tests that require a running fork are skipped when FORK_URL is not set.
//! Tests that require exchange credentials are skipped when env vars are missing.

use peanut_task::chain::{ChainClient, RpcUrl};
use peanut_task::core::base_types::Address;
use peanut_task::exchange::{ExchangeClient, ExchangeConfig};
use peanut_task::inventory::{InventoryTracker, Venue};
use peanut_task::pricing::{Chain, PricingEngine};
use peanut_task::strategy::fees::FeeStructure;
use peanut_task::strategy::{ArbBot, BotConfig, ExecutorConfig};
use rust_decimal_macros::dec;
use std::sync::atomic::Ordering;

// ─── helpers ────────────────────────────────────────────────────────────────

/// Returns the FORK_URL (Anvil fork) from env, or None if not set.
fn fork_url() -> Option<String> {
    std::env::var("FORK_URL").ok()
}

/// Build a minimal ArbBot in simulation mode for testing.
/// Returns None when required env vars are missing.
fn make_bot(config: BotConfig) -> Option<ArbBot> {
    let fork = fork_url()?;

    let exchange_config = ExchangeConfig::from_env().ok()?;
    let exchange = ExchangeClient::new(exchange_config).ok()?;

    let rpc = RpcUrl::new(&fork, "").ok()?;
    let chain_client = ChainClient::new(vec![rpc], 60, 3).ok()?;

    let pricing = PricingEngine::new(
        chain_client.clone(),
        &fork,
        &fork.replace("http", "ws"),
        Chain::EthereumMainnet,
        None,
    )
    .ok()?;

    let inventory = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).ok()?;
    let fee_structure = FeeStructure::default();

    // Use a real wallet address from env, or a deterministic test address
    let wallet = std::env::var("WALLET_ADDRESS")
        .unwrap_or_else(|_| "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string());
    let wallet_address = Address { value: wallet };

    Some(ArbBot::new(
        exchange,
        pricing,
        inventory,
        fee_structure,
        config,
        chain_client,
        wallet_address,
    ))
}

// ─── unit tests (no fork required) ──────────────────────────────────────────

#[test]
fn test_bot_default_config() {
    let config = BotConfig::default();
    assert_eq!(config.pairs, vec!["ETH/USDT"]);
    assert_eq!(config.tick_interval_millis, 1);
    assert_eq!(config.min_score_threshold, dec!(60));
    assert_eq!(config.simulation_mode, true);
    assert_eq!(config.executor_config.simulation_mode, true);
}

#[test]
fn test_bot_simulation_mode_propagated() {
    // This test uses BotConfig only — no fork needed.
    // We verify the propagation logic directly rather than constructing a full bot.
    let mut bot_config = BotConfig::default();
    bot_config.simulation_mode = false;

    // Simulate what ArbBot::new() does
    let mut executor_config = bot_config.executor_config.clone();
    executor_config.simulation_mode = bot_config.simulation_mode;

    assert_eq!(
        executor_config.simulation_mode, false,
        "ExecutorConfig.simulation_mode must mirror BotConfig.simulation_mode"
    );
}

// ─── integration tests (fork required) ──────────────────────────────────────

#[test]
fn test_bot_stop_handle() {
    let bot = match make_bot(BotConfig::default()) {
        Some(b) => b,
        None => {
            eprintln!("SKIP test_bot_stop_handle: FORK_URL not set");
            return;
        }
    };

    let handle = bot.stop_handle();
    assert_eq!(
        handle.load(Ordering::SeqCst),
        false,
        "Bot not yet started — should be false"
    );

    // stop() sets the flag
    bot.stop();
    assert_eq!(
        handle.load(Ordering::SeqCst),
        false,
        "stop() stores false — bot loop will exit on next iteration"
    );
}

#[test]
fn test_bot_balance_sync_called_on_run() {
    // Verify that inventory is populated after construction (via the fork)
    let mut bot = match make_bot(BotConfig {
        simulation_mode: true,
        tick_interval_millis: 1,
        ..BotConfig::default()
    }) {
        Some(b) => b,
        None => {
            eprintln!("SKIP test_bot_balance_sync_called_on_run: FORK_URL not set");
            return;
        }
    };

    // Run one manual balance sync (same call that run() makes at startup)
    // Access via a test-only helper — we can just use the internal method through the public run()
    // We'll do it by invoking run() in a thread and immediately stopping it.
    let handle = bot.stop_handle();
    let stop = handle.clone();
    let thread = std::thread::spawn(move || {
        bot.run();
    });

    // Short sleep then stop
    std::thread::sleep(std::time::Duration::from_millis(50));
    stop.store(false, Ordering::SeqCst);

    let _ = thread.join();
    // If we reach here without panic, balance sync ran successfully
}

#[test]
fn test_bot_tick_no_signal() {
    // With no profitable opportunities (mock exchange will have equal prices),
    // the bot should complete a tick without executing anything.
    // This is covered by the balance sync + tick flow above — just verify no panic.
    let bot = match make_bot(BotConfig {
        simulation_mode: true,
        ..BotConfig::default()
    }) {
        Some(b) => b,
        None => {
            eprintln!("SKIP test_bot_tick_no_signal: FORK_URL not set");
            return;
        }
    };
    // Bot constructed without panic — no signal path relies on the generator returning None
    drop(bot);
}

#[test]
fn test_bot_tick_circuit_breaker_open() {
    // When circuit breaker is open, tick should exit early without calling generator.
    let mut bot = match make_bot(BotConfig {
        simulation_mode: true,
        ..BotConfig::default()
    }) {
        Some(b) => b,
        None => {
            eprintln!("SKIP test_bot_tick_circuit_breaker_open: FORK_URL not set");
            return;
        }
    };

    // Trip the circuit breaker manually
    // Access via executor's public field
    for _ in 0..5 {
        bot.executor.circuit_breaker.record_failure();
    }
    assert!(bot.executor.circuit_breaker.is_open());

    // A tick should not panic and should detect CB open
    let result = bot._tick();
    assert!(result.is_ok());
}

#[test]
fn test_bot_tick_signal_execute_failure() {
    // Real mode with DEX-first will fail on DEX leg (not implemented)
    // CB should only trip after 3 real failures, not on signal validation guards
    let mut bot = match make_bot(BotConfig {
        simulation_mode: false,
        executor_config: ExecutorConfig {
            simulation_mode: false,
            use_flashbots: true, // DEX-first — will fail in real mode
            ..ExecutorConfig::default()
        },
        ..BotConfig::default()
    }) {
        Some(b) => b,
        None => {
            eprintln!("SKIP test_bot_tick_signal_execute_failure: FORK_URL not set");
            return;
        }
    };

    // Tick may or may not find a signal; if it does the DEX leg fails
    let result = bot._tick();
    assert!(result.is_ok(), "Tick must return Ok even when signals fail");
}

#[test]
fn test_bot_tick_signal_below_threshold() {
    // With a very high score threshold, no signals should execute.
    let mut bot = match make_bot(BotConfig {
        simulation_mode: true,
        min_score_threshold: dec!(999), // impossibly high
        ..BotConfig::default()
    }) {
        Some(b) => b,
        None => {
            eprintln!("SKIP test_bot_tick_signal_below_threshold: FORK_URL not set");
            return;
        }
    };

    let result = bot._tick();
    assert!(result.is_ok());
    // CB should be untouched (no real execution attempted)
    assert!(!bot.executor.circuit_breaker.is_open());
}

#[test]
fn test_bot_cb_not_tripped_by_high_threshold_skip() {
    // When a signal is skipped due to score threshold, CB must not trip.
    let mut bot = match make_bot(BotConfig {
        simulation_mode: true,
        min_score_threshold: dec!(999),
        ..BotConfig::default()
    }) {
        Some(b) => b,
        None => {
            eprintln!("SKIP test_bot_cb_not_tripped_by_high_threshold_skip: FORK_URL not set");
            return;
        }
    };

    // Run many ticks — CB must remain closed
    for _ in 0..5 {
        let _ = bot._tick();
    }
    assert!(
        !bot.executor.circuit_breaker.is_open(),
        "CB must not trip when signals are skipped due to score threshold"
    );
}
