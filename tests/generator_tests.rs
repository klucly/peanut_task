use peanut_task::GeneratorConfig;
use rust_decimal_macros::dec;

#[test]
fn test_default_generator_config() {
    let config = GeneratorConfig::default();
    assert_eq!(config.min_profit_usd, dec!(5));
    assert_eq!(config.max_position_usd, dec!(10_000));
    assert_eq!(config.signal_ttl_seconds, 5);
    assert_eq!(config.cooldown_seconds, 2);
}

#[test]
fn test_custom_generator_config() {
    let config = GeneratorConfig::new(
        dec!(10.0),
        dec!(5000.0),
        10,
        3,
    );
    assert_eq!(config.min_profit_usd, dec!(10.0));
    assert_eq!(config.max_position_usd, dec!(5000.0));
    assert_eq!(config.signal_ttl_seconds, 10);
    assert_eq!(config.cooldown_seconds, 3);
}

#[test]
fn test_generator_config_methods() {
    let config = GeneratorConfig::new(
        dec!(7.5),
        dec!(15000.0),
        8,
        4,
    );
    
    // Verify all fields are set correctly
    assert_eq!(config.min_profit_usd, dec!(7.5));
    assert_eq!(config.max_position_usd, dec!(15000.0));
    assert_eq!(config.signal_ttl_seconds, 8);
    assert_eq!(config.cooldown_seconds, 4);
}

#[test]
fn test_config_with_zero_cooldown() {
    let config = GeneratorConfig::new(
        dec!(5.0),
        dec!(10000.0),
        5,
        0, // No cooldown
    );
    assert_eq!(config.cooldown_seconds, 0);
}

#[test]
fn test_config_with_very_short_ttl() {
    let config = GeneratorConfig::new(
        dec!(5.0),
        dec!(10000.0),
        1, // Very short TTL
        2,
    );
    assert_eq!(config.signal_ttl_seconds, 1);
}

#[test]
fn test_config_high_min_profit() {
    // Config with high profit threshold
    let config = GeneratorConfig::new(
        dec!(100.0), // $100 minimum profit
        dec!(50000.0),
        10,
        5,
    );
    assert_eq!(config.min_profit_usd, dec!(100.0));
}

#[test]
fn test_config_realistic_values() {
    // Test with realistic production values
    let config = GeneratorConfig::new(
        dec!(15.0),    // $15 min profit
        dec!(25000.0), // $25k max position
        3,             // 3 second TTL
        5,             // 5 second cooldown
    );
    
    assert_eq!(config.min_profit_usd, dec!(15.0));
    assert_eq!(config.max_position_usd, dec!(25000.0));
    assert_eq!(config.signal_ttl_seconds, 3);
    assert_eq!(config.cooldown_seconds, 5);
}

// Note: Full integration tests for SignalGenerator would require:
// 1. Mocking ArbChecker (complex - needs ExchangeClient, PricingEngine, InventoryTracker, PnLEngine)
// 2. Setting up test fixtures for orderbooks and pricing data
// 3. Running against a forked blockchain for DEX pricing
//
// These tests focus on configuration validation. The actual signal generation
// logic depends on ArbChecker.check() which is tested separately in arb_checker_tests.rs.
//
// Cooldown behavior is tested implicitly through the in_cooldown() method,
// which is called by generate(). To fully test cooldown, we would need to:
// - Create a real ArbChecker instance (requires extensive setup)
// - Call generate() twice in succession
// - Verify second call returns None due to cooldown
//
// For now, the configuration tests verify that cooldown values are correctly stored,
// and the SignalGenerator implementation uses these values in its logic.
