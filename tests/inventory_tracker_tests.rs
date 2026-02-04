//! Inventory tracker tests.
//!
//! All tests use in-memory mock data (no network).

use peanut_task::exchange::AssetBalance;
use peanut_task::inventory::{InventoryTracker, InventoryTrackerError, Venue};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::collections::HashMap;

fn asset_balance(free: Decimal, locked: Decimal) -> AssetBalance {
    AssetBalance {
        free,
        locked,
        total: free + locked,
    }
}

#[test]
fn test_new_rejects_empty_venues() {
    let result = InventoryTracker::new(vec![]);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), InventoryTrackerError::EmptyVenues));
}

#[test]
fn test_snapshot_aggregates_across_venues() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();

    let mut binance = HashMap::new();
    binance.insert(
        "ETH".to_string(),
        asset_balance(dec!(10), dec!(0)),
    );
    tracker.update_from_cex(Venue::Binance, binance).unwrap();

    let mut wallet = HashMap::new();
    wallet.insert("ETH".to_string(), dec!(10));
    tracker.update_from_wallet(Venue::Wallet, wallet).unwrap();

    let snapshot = tracker.snapshot(None);
    assert_eq!(snapshot.totals.get("ETH"), Some(&dec!(20)));
}

#[test]
fn test_snapshot_includes_empty_venues() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();

    let mut binance = HashMap::new();
    binance.insert("ETH".to_string(), asset_balance(dec!(10), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();

    let snapshot = tracker.snapshot(None);
    assert!(snapshot.venues.contains_key("binance"));
    assert!(snapshot.venues.contains_key("wallet"));
    assert!(snapshot.venues.get("wallet").unwrap().is_empty());
}

#[test]
fn test_can_execute_passes_when_sufficient() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();

    let mut binance = HashMap::new();
    binance.insert("USDT".to_string(), asset_balance(dec!(10000), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();

    let mut wallet = HashMap::new();
    wallet.insert("ETH".to_string(), dec!(5));
    tracker.update_from_wallet(Venue::Wallet, wallet).unwrap();

    let result = tracker.can_execute(
        Venue::Binance,
        "USDT",
        dec!(100),
        Venue::Wallet,
        "ETH",
        dec!(1),
    );
    assert!(result.can_execute);
    assert!(result.reason.is_none());
}

#[test]
fn test_can_execute_fails_insufficient_buy() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();

    let mut binance = HashMap::new();
    binance.insert("USDT".to_string(), asset_balance(dec!(50), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();

    let mut wallet = HashMap::new();
    wallet.insert("ETH".to_string(), dec!(5));
    tracker.update_from_wallet(Venue::Wallet, wallet).unwrap();

    let result = tracker.can_execute(
        Venue::Binance,
        "USDT",
        dec!(100),
        Venue::Wallet,
        "ETH",
        dec!(1),
    );
    assert!(!result.can_execute);
    assert!(result.reason.is_some());
    let reason = result.reason.unwrap();
    assert!(reason.contains("buy"));
    assert!(reason.contains("USDT"));
}

#[test]
fn test_can_execute_fails_insufficient_sell() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();

    let mut binance = HashMap::new();
    binance.insert("USDT".to_string(), asset_balance(dec!(10000), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();

    let mut wallet = HashMap::new();
    wallet.insert("ETH".to_string(), dec!(0.5));
    tracker.update_from_wallet(Venue::Wallet, wallet).unwrap();

    let result = tracker.can_execute(
        Venue::Binance,
        "USDT",
        dec!(100),
        Venue::Wallet,
        "ETH",
        dec!(1),
    );
    assert!(!result.can_execute);
    assert!(result.reason.is_some());
    let reason = result.reason.unwrap();
    assert!(reason.contains("sell"));
    assert!(reason.contains("ETH"));
}

#[test]
fn test_record_trade_updates_balances() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance]).unwrap();

    let mut binance = HashMap::new();
    binance.insert("ETH".to_string(), asset_balance(dec!(0), dec!(0)));
    binance.insert("USDT".to_string(), asset_balance(dec!(10000), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();

    tracker
        .record_trade(
            Venue::Binance,
            "buy",
            "ETH",
            "USDT",
            dec!(1),
            dec!(2000),
            dec!(2),
            "USDT",
        )
        .unwrap();

    assert_eq!(tracker.get_available(Venue::Binance, "ETH"), dec!(1));
    assert_eq!(tracker.get_available(Venue::Binance, "USDT"), dec!(7998)); // 10000 - 2000 - 2
}

#[test]
fn test_record_trade_rejects_untracked_venue() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance]).unwrap();

    let mut binance = HashMap::new();
    binance.insert("ETH".to_string(), asset_balance(dec!(5), dec!(0)));
    binance.insert("USDT".to_string(), asset_balance(dec!(10000), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();

    let result = tracker.record_trade(
        Venue::Wallet,
        "sell",
        "ETH",
        "USDT",
        dec!(1),
        dec!(2000),
        dec!(2),
        "USDT",
    );
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        InventoryTrackerError::VenueNotTracked(Venue::Wallet)
    ));
}

#[test]
fn test_record_trade_overflow_returns_error() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance]).unwrap();

    let mut binance = HashMap::new();
    binance.insert("ETH".to_string(), asset_balance(dec!(0.5), dec!(0)));
    binance.insert("USDT".to_string(), asset_balance(dec!(10000), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();

    let result = tracker.record_trade(
        Venue::Binance,
        "sell",
        "ETH",
        "USDT",
        dec!(1),
        dec!(2000),
        dec!(2),
        "USDT",
    );
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        InventoryTrackerError::ArithmeticOverflow
    ));
}

#[test]
fn test_update_from_cex_rejects_wallet() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();

    let mut balances = HashMap::new();
    balances.insert("ETH".to_string(), asset_balance(dec!(10), dec!(0)));

    let result = tracker.update_from_cex(Venue::Wallet, balances);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), InventoryTrackerError::InvalidVenue(_)));
}

#[test]
fn test_update_from_wallet_rejects_binance() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();

    let mut balances = HashMap::new();
    balances.insert("ETH".to_string(), dec!(10));

    let result = tracker.update_from_wallet(Venue::Binance, balances);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), InventoryTrackerError::InvalidVenue(_)));
}

#[test]
fn test_skew_detects_imbalance() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();

    let mut binance = HashMap::new();
    binance.insert("ETH".to_string(), asset_balance(dec!(85), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();

    let mut wallet = HashMap::new();
    wallet.insert("ETH".to_string(), dec!(15));
    tracker.update_from_wallet(Venue::Wallet, wallet).unwrap();

    let skew = tracker.skew("ETH");
    assert_eq!(skew.total, dec!(100));
    assert!(skew.max_deviation_pct > dec!(30));
    assert!(skew.needs_rebalance);
}

#[test]
fn test_skew_balanced() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();

    let mut binance = HashMap::new();
    binance.insert("ETH".to_string(), asset_balance(dec!(50), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();

    let mut wallet = HashMap::new();
    wallet.insert("ETH".to_string(), dec!(50));
    tracker.update_from_wallet(Venue::Wallet, wallet).unwrap();

    let skew = tracker.skew("ETH");
    assert_eq!(skew.total, dec!(100));
    assert!(skew.max_deviation_pct <= dec!(1));
    assert!(!skew.needs_rebalance);
}

#[test]
fn test_skew_zero_total() {
    let tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();

    let skew = tracker.skew("ETH");
    assert_eq!(skew.total, dec!(0));
    assert!(!skew.needs_rebalance);
}
