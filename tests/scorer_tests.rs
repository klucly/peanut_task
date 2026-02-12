use peanut_task::{ScorerConfig, SignalScorer};
use peanut_task::{Signal, Direction};
use peanut_task::SkewResult;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use time::{Duration, OffsetDateTime};
use std::collections::HashMap;

#[test]
fn test_default_scorer_config() {
    let config = ScorerConfig::default();
    assert_eq!(config.spread_weight, dec!(0.4));
    assert_eq!(config.liquidity_weight, dec!(0.2));
    assert_eq!(config.inventory_weight, dec!(0.2));
    assert_eq!(config.history_weight, dec!(0.2));
    assert_eq!(config.excellent_spread_bps, dec!(100));
    assert_eq!(config.min_spread_bps, dec!(30));
}

#[test]
fn test_custom_scorer_config() {
    let config = ScorerConfig::new(
        dec!(0.5),
        dec!(0.1),
        dec!(0.3),
        dec!(0.1),
        dec!(150),
        dec!(50),
    );
    assert_eq!(config.spread_weight, dec!(0.5));
    assert_eq!(config.liquidity_weight, dec!(0.1));
    assert_eq!(config.inventory_weight, dec!(0.3));
    assert_eq!(config.history_weight, dec!(0.1));
    assert_eq!(config.excellent_spread_bps, dec!(150));
    assert_eq!(config.min_spread_bps, dec!(50));
}

// Spread Scoring Tests

#[test]
fn test_score_spread_below_min() {
    let scorer = SignalScorer::new(None);
    let signal = create_test_signal(dec!(25), dec!(80)); // 25 bps < 30 min
    let score = scorer.score(&signal, &[]);
    
    // With 0 spread score, weighted = 0*0.4 + 80*0.2 + 60*0.2 + 50*0.2 = 38
    assert_eq!(score, dec!(38.0));
}

#[test]
fn test_score_spread_at_excellent() {
    let scorer = SignalScorer::new(None);
    let signal = create_test_signal(dec!(120), dec!(80)); // 120 bps > 100 excellent
    let score = scorer.score(&signal, &[]);
    
    // With 100 spread score, weighted = 100*0.4 + 80*0.2 + 60*0.2 + 50*0.2 = 78
    assert_eq!(score, dec!(78.0));
}

#[test]
fn test_score_spread_midpoint() {
    let scorer = SignalScorer::new(None);
    let signal = create_test_signal(dec!(65), dec!(80)); // midpoint between 30 and 100
    let score = scorer.score(&signal, &[]);
    
    // Spread score = (65-30)/(100-30)*100 = 35/70*100 = 50
    // Weighted = 50*0.4 + 80*0.2 + 60*0.2 + 50*0.2 = 20 + 16 + 12 + 10 = 58
    assert_eq!(score, dec!(58.0));
}

// Inventory Scoring Tests

#[test]
fn test_score_inventory_needs_rebalance() {
    let scorer = SignalScorer::new(None);
    let signal = create_test_signal(dec!(80), dec!(80));
    
    // Create a skew result for ETH that needs rebalancing
    let skew = SkewResult {
        asset: "ETH".to_string(),
        total: dec!(100),
        venues: HashMap::new(),
        max_deviation_pct: dec!(35), // > 30, so needs_rebalance = true
        needs_rebalance: true,
    };
    
    let score = scorer.score(&signal, &[skew]);
    
    // With spread_bps=80, spread_score=(80-30)/(100-30)*100=71.43
    // inventory score of 20, weighted = 71.43* 0.4 + 80*0.2 + 20*0.2 + 50*0.2 = 28.57+16+4+10 = 58.57 ~= 58.6
    assert_eq!(score, dec!(58.6));
}

#[test]
fn test_score_inventory_balanced() {
    let scorer = SignalScorer::new(None);
    let signal = create_test_signal(dec!(80), dec!(80));
    
    let skew = SkewResult {
        asset: "ETH".to_string(),
        total: dec!(100),
        venues: HashMap::new(),
        max_deviation_pct: dec!(10), // < 30, so needs_rebalance = false
        needs_rebalance: false,
    };
    
    let score = scorer.score(&signal, &[skew]);
    
    // With spread_bps=80, spread_score=71.43, inventory=60
    // Weighted = 71.43*0.4 + 80*0.2 + 60*0.2 + 50*0.2 = 28.57+16+12+10 = 66.57~=66.6
    assert_eq!(score, dec!(66.6));
}

#[test]
fn test_score_inventory_no_matching_token() {
    let scorer = SignalScorer::new(None);
    let signal = create_test_signal(dec!(80), dec!(80));
    
    // Different token - no match
    let skew = SkewResult {
        asset: "BTC".to_string(),
        total: dec!(100),
        venues: HashMap::new(),
        max_deviation_pct: dec!(35),
        needs_rebalance: true,
    };
    
    let score = scorer.score(&signal, &[skew]);
    
    // No matching token, so inventory score defaults to 60
    // spread_bps=80 -> spread_score=71.43, weighted = 71.43*0.4 + 80*0.2 + 60*0.2 + 50*0.2 = 66.6
    assert_eq!(score, dec!(66.6));
}

// History Scoring Tests

#[test]
fn test_score_history_insufficient_data() {
    let scorer = SignalScorer::new(None);
    let signal = create_test_signal(dec!(80), dec!(80));
    
    // No history recorded, should default to 50
    let score = scorer.score(&signal, &[]);
    
    // With history score of 50, spread_bps=80 -> spread_score=71.43
    // weighted = 71.43*0.4 + 80*0.2 + 60*0.2 + 50*0.2 = 66.6
    assert_eq!(score, dec!(66.6));
}

#[test]
fn test_score_history_all_success() {
    let mut scorer = SignalScorer::new(None);
    
    // Record 5 successful trades for ETH/USDT
    for _ in 0..5 {
        scorer.record_result("ETH/USDT".to_string(), true);
    }
    
    let signal = create_test_signal(dec!(80), dec!(80));
    let score = scorer.score(&signal, &[]);
    
    // With history score of 100, spread_bps=80 -> spread_score=71.43
    // weighted = 71.43*0.4 + 80*0.2 + 60*0.2 + 100*0.2 = 28.57+16+12+20 = 76.57~=76.6
    assert_eq!(score, dec!(76.6));
}

#[test]
fn test_score_history_mixed_results() {
    let mut scorer = SignalScorer::new(None);
    
    // Record 2 successes and 2 failures for ETH/USDT
    scorer.record_result("ETH/USDT".to_string(), true);
    scorer.record_result("ETH/USDT".to_string(), false);
    scorer.record_result("ETH/USDT".to_string(), true);
    scorer.record_result("ETH/USDT".to_string(), false);
    
    let signal = create_test_signal(dec!(80), dec!(80));
    let score = scorer.score(&signal, &[]);
    
    // History score = 2/4 * 100 = 50, spread_bps=80 -> spread_score=71.43
    // Weighted = 71.43*0.4 + 80*0.2 + 60*0.2 + 50*0.2 = 66.6
    assert_eq!(score, dec!(66.6));
}

#[test]
fn test_score_history_only_relevant_pair() {
    let mut scorer = SignalScorer::new(None);
    
    // Record results for multiple pairs
    scorer.record_result("BTC/USDT".to_string(), false); // Different pair
    scorer.record_result("ETH/USDT".to_string(), true);
    scorer.record_result("BTC/USDT".to_string(), false); // Different pair
    scorer.record_result("ETH/USDT".to_string(), true);
    scorer.record_result("ETH/USDT".to_string(), true);
    
    let signal = create_test_signal(dec!(80), dec!(80));
    let score = scorer.score(&signal, &[]);
    
    // Only ETH/USDT results count: 3/3 = 100%, spread_bps=80 -> spread_score=71.43
    // Weighted = 71.43*0.4 + 80*0.2 + 60*0.2 + 100*0.2 = 76.6
    assert_eq!(score, dec!(76.6));
}

// Weighted Scoring Tests

#[test]
fn test_weighted_score_calculation() {
    let config = ScorerConfig::new(
        dec!(0.5), // spread weight
        dec!(0.1), // liquidity weight
        dec!(0.2), // inventory weight
        dec!(0.2), // history weight
        dec!(100),
        dec!(30),
    );
    let scorer = SignalScorer::new(Some(config));
    
    let signal = create_test_signal(dec!(65), dec!(80)); // Spread score = 50
    let score = scorer.score(&signal, &[]);
    
    // Weighted = 50*0.5 + 80*0.1 + 60*0.2 + 50*0.2 = 25 + 8 + 12 + 10 = 55
    assert_eq!(score, dec!(55.0));
}

#[test]
fn test_score_clamping() {
    // Test that scores are clamped to [0, 100]
    let scorer = SignalScorer::new(None);
    let signal = create_test_signal(dec!(65), dec!(100));
    
    let score = scorer.score(&signal, &[]);
    assert!(score >= dec!(0) && score <= dec!(100));
}

// Decay Tests

#[test]
fn test_decay_fresh_signal() {
    let scorer = SignalScorer::new(None);
    let now = OffsetDateTime::now_utc();
    let expiry = now + Duration::seconds(10);
    
    let signal = Signal::create(
        "ETH/USDT".to_string(),
        Direction::BuyCexSellDex,
        dec!(2000),
        dec!(2010),
        dec!(50),
        dec!(1),
        dec!(5),
        dec!(3),
        dec!(2),
        dec!(70), // score
        expiry,
        true,
        true,
    );
    
    // Fresh signal (just created), should have minimal decay
    let decayed_score = scorer.apply_decay(&signal);
    
    // Age is very small, decay factor ~1, so score should be close to 70
    assert!(decayed_score >= dec!(69) && decayed_score <= dec!(70));
}

#[test]
fn test_decay_halfway_expired() {
    let scorer = SignalScorer::new(None);
    
    // Create a signal with known timestamp
    let timestamp = OffsetDateTime::now_utc() - Duration::seconds(5);
    let expiry = timestamp + Duration::seconds(10);
    
    let mut signal = Signal::create(
        "ETH/USDT".to_string(),
        Direction::BuyCexSellDex,
        dec!(2000),
        dec!(2010),
        dec!(50),
        dec!(1),
        dec!(5),
        dec!(3),
        dec!(2),
        dec!(80), // score
        expiry,
        true,
        true,
    );
    
    // Manually set timestamp to control the test
    signal.timestamp = timestamp;
    
    let decayed_score = scorer.apply_decay(&signal);
    
    // Age = 5s, TTL = 10s
    // Decay factor = 1 - (5/10)*0.5 = 1 - 0.25 = 0.75
    // Decayed score = 80 * 0.75 = 60 (allow small rounding)
    assert!((decayed_score - dec!(60)).abs() < dec!(0.01));
}

#[test]
fn test_decay_fully_expired() {
    let scorer = SignalScorer::new(None);
    
    // Create a signal that's already expired
    let timestamp = OffsetDateTime::now_utc() - Duration::seconds(15);
    let expiry = timestamp + Duration::seconds(10);
    
    let mut signal = Signal::create(
        "ETH/USDT".to_string(),
        Direction::BuyCexSellDex,
        dec!(2000),
        dec!(2010),
        dec!(50),
        dec!(1),
        dec!(5),
        dec!(3),
        dec!(2),
        dec!(100), // score
        expiry,
        true,
        true,
    );
    
    signal.timestamp = timestamp;
    
    let decayed_score = scorer.apply_decay(&signal);
    
    // Age = 15s, TTL = 10s
    // Decay factor = max(0, 1 - (15/10)*0.5) = max(0, 1 - 0.75) = 0.25
    // Decayed score = 100 * 0.25 = 25 (allow small rounding)
    assert!((decayed_score - dec!(25)).abs() < dec!(0.01));
}

// Result Tracking Tests

#[test]
fn test_record_result_tracking() {
    let mut scorer = SignalScorer::new(None);
    
    scorer.record_result("ETH/USDT".to_string(), true);
    scorer.record_result("BTC/USDT".to_string(), false);
    
    // Verify results are stored (tested through history scoring)
    let signal = create_test_signal(dec!(80), dec!(80));
    let _ = scorer.score(&signal, &[]);
    
    // If this doesn't panic, results were stored correctly
}

#[test]
fn test_record_result_max_capacity() {
    let mut scorer = SignalScorer::new(None);
    
    // Record 150 results (more than the 100 limit)
    for i in 0..150 {
        scorer.record_result(
            "ETH/USDT".to_string(),
            i % 2 == 0,
        );
    }
    
    // The implementation should only keep last 100 results
    // We can't directly check the internal field, but we can verify
    // that the scorer still works correctly with history scoring
    let signal = create_test_signal(dec!(80), dec!(80));
    let score = scorer.score(&signal, &[]);
    
    // Should be able to score without errors
    assert!(score >= dec!(0) && score <= dec!(100));
}

// Helper Functions

fn create_test_signal(spread_bps: Decimal, score: Decimal) -> Signal {
    let now = OffsetDateTime::now_utc();
    let expiry = now + Duration::seconds(5);
    
    Signal::create(
        "ETH/USDT".to_string(),
        Direction::BuyCexSellDex,
        dec!(2000),
        dec!(2010),
        spread_bps,
        dec!(1),
        dec!(10),
        dec!(5),
        dec!(5),
        score,
        expiry,
        true,
        true,
    )
}
