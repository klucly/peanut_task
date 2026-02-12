//! Tests for circuit breaker and replay protection.

use peanut_task::strategy::recovery::{CircuitBreaker, CircuitBreakerConfig, ReplayProtection};
use peanut_task::strategy::signal::{Direction, Signal};
use rust_decimal_macros::dec;
use std::thread;
use std::time::Duration;
use time::OffsetDateTime;

fn create_test_signal(id_suffix: &str) -> Signal {
    let pair = format!("ETH{}", id_suffix);
    Signal::create(
        pair,
        Direction::BuyCexSellDex,
        dec!(2000),
        dec!(2010),
        dec!(50),
        dec!(1.0),
        dec!(10),
        dec!(0.5),
        dec!(9.5),
        dec!(100),
        OffsetDateTime::now_utc() + time::Duration::seconds(60),
        true,
        true,
    )
}

// ============================================================================
// Circuit Breaker Tests
// ============================================================================

#[test]
fn test_circuit_breaker_trips() {
    // Test: 3 failures in window trips breaker
    let config = CircuitBreakerConfig::new(3, 300.0, 600.0);
    let mut cb = CircuitBreaker::new(Some(config));

    assert!(!cb.is_open(), "Breaker should start closed");

    // Record 3 failures
    cb.record_failure();
    assert!(!cb.is_open(), "Breaker should remain closed after 1 failure");

    cb.record_failure();
    assert!(!cb.is_open(), "Breaker should remain closed after 2 failures");

    cb.record_failure();
    assert!(cb.is_open(), "Breaker should trip after 3 failures");
}

#[test]
fn test_circuit_breaker_resets() {
    // Test: Breaker resets after cooldown
    let config = CircuitBreakerConfig::new(2, 300.0, 1.0); // 1 second cooldown
    let mut cb = CircuitBreaker::new(Some(config));

    // Trip the breaker
    cb.record_failure();
    cb.record_failure();
    assert!(cb.is_open(), "Breaker should be open");

    // Check time until reset
    let remaining = cb.time_until_reset();
    assert!(remaining > 0.0 && remaining <= 1.0, "Time remaining should be in range");

    // Wait for cooldown
    thread::sleep(Duration::from_millis(1100));

    // Breaker should auto-reset
    assert!(!cb.is_open(), "Breaker should reset after cooldown");
    assert_eq!(cb.time_until_reset(), 0.0, "No time remaining after reset");
}

#[test]
fn test_circuit_breaker_window_behavior() {
    // Test: Failures outside window don't count
    let config = CircuitBreakerConfig::new(3, 1.0, 600.0); // 1 second window
    let mut cb = CircuitBreaker::new(Some(config));

    // Record 2 failures
    cb.record_failure();
    cb.record_failure();
    assert!(!cb.is_open(), "Breaker should not trip with 2 failures");

    // Wait for window to expire
    thread::sleep(Duration::from_millis(1100));

    // Old failures should be cleaned up, new failure shouldn't trip
    cb.record_failure();
    assert!(!cb.is_open(), "Breaker should not trip - old failures expired");
}

#[test]
fn test_time_until_reset() {
    let config = CircuitBreakerConfig::new(1, 300.0, 2.0); // 2 second cooldown
    let mut cb = CircuitBreaker::new(Some(config));

    // Not tripped - no time remaining
    assert_eq!(cb.time_until_reset(), 0.0);

    // Trip the breaker
    cb.record_failure();
    assert!(cb.is_open());

    // Should have time remaining
    let remaining = cb.time_until_reset();
    assert!(remaining > 0.0 && remaining <= 2.0, "Should have time remaining");

    // Wait a bit
    thread::sleep(Duration::from_millis(500));

    // Time should decrease
    let new_remaining = cb.time_until_reset();
    assert!(new_remaining < remaining, "Time remaining should decrease");
}

// ============================================================================
// Replay Protection Tests
// ============================================================================

#[test]
fn test_replay_blocks_duplicate() {
    // Test: Same signal_id blocked
    let mut rp = ReplayProtection::new(Some(60.0));
    let signal = create_test_signal("/USDT");

    // First execution should be allowed
    assert!(!rp.is_duplicate(&signal), "First execution should not be duplicate");

    // Mark as executed
    rp.mark_executed(&signal);

    // Second execution should be blocked
    assert!(rp.is_duplicate(&signal), "Second execution should be duplicate");
}

#[test]
fn test_replay_allows_new() {
    // Test: Different signal_id allowed
    let mut rp = ReplayProtection::new(Some(60.0));
    let signal1 = create_test_signal("/USDT");
    let signal2 = create_test_signal("/DAI"); // Different pair = different signal_id

    // Mark first signal as executed
    rp.mark_executed(&signal1);
    assert!(rp.is_duplicate(&signal1), "First signal should be duplicate");

    // Second signal should be allowed
    assert!(!rp.is_duplicate(&signal2), "Different signal should not be duplicate");
}

#[test]
fn test_replay_ttl_expiry() {
    // Test: Signals allowed after TTL expires
    let mut rp = ReplayProtection::new(Some(1.0)); // 1 second TTL
    let signal = create_test_signal("/USDT");

    // Mark as executed
    rp.mark_executed(&signal);
    assert!(rp.is_duplicate(&signal), "Should be duplicate immediately");

    // Wait for TTL to expire
    thread::sleep(Duration::from_millis(1100));

    // Should be allowed again after cleanup
    assert!(!rp.is_duplicate(&signal), "Should not be duplicate after TTL");
}

#[test]
fn test_replay_cleanup() {
    // Test: Automatic cleanup of old entries
    let mut rp = ReplayProtection::new(Some(1.0)); // 1 second TTL

    // Add multiple signals
    for i in 0..5 {
        let signal = create_test_signal(&format!("/TOKEN{}", i));
        rp.mark_executed(&signal);
    }

    // Wait for TTL
    thread::sleep(Duration::from_millis(1100));

    // Add a new signal (triggers cleanup)
    let new_signal = create_test_signal("/NEW");
    assert!(!rp.is_duplicate(&new_signal), "New signal triggers cleanup");

    // Old signals should be cleaned up
    let old_signal = create_test_signal("/TOKEN0");
    assert!(!rp.is_duplicate(&old_signal), "Old signals should be removed");
}

#[test]
fn test_circuit_breaker_default_config() {
    let mut cb = CircuitBreaker::default();
    // Should use default config values
    assert!(!cb.is_open(), "Default breaker should be closed");
}

#[test]
fn test_replay_protection_default_ttl() {
    let rp = ReplayProtection::default();
    // Should use default TTL (60 seconds)
    // We can't easily test the actual TTL value without exposing it,
    // but we can verify it works
    let signal = create_test_signal("/USDT");
    let mut rp_mut = rp;
    rp_mut.mark_executed(&signal);
    assert!(rp_mut.is_duplicate(&signal));
}
