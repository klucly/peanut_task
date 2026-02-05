//! Rebalance planner tests

use peanut_task::exchange::AssetBalance;
use peanut_task::inventory::{InventoryTracker, RebalancePlanner, Venue};
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
fn test_check_detects_skewed_asset() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();
    let mut binance = HashMap::new();
    binance.insert("ETH".to_string(), asset_balance(dec!(2), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();
    let mut wallet = HashMap::new();
    wallet.insert("ETH".to_string(), dec!(8));
    tracker.update_from_wallet(Venue::Wallet, wallet).unwrap();

    let planner = RebalancePlanner::new(&tracker, 30.0, None);
    let checks = planner.check_all();
    let eth_check = checks.iter().find(|c| c.asset == "ETH").unwrap();
    assert!(eth_check.needs_rebalance);
    assert!(eth_check.max_deviation_pct >= dec!(30));
}

#[test]
fn test_check_passes_balanced_asset() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();
    let mut binance = HashMap::new();
    binance.insert("ETH".to_string(), asset_balance(dec!(5.5), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();
    let mut wallet = HashMap::new();
    wallet.insert("ETH".to_string(), dec!(4.5));
    tracker.update_from_wallet(Venue::Wallet, wallet).unwrap();

    let planner = RebalancePlanner::new(&tracker, 30.0, None);
    let checks = planner.check_all();
    let eth_check = checks.iter().find(|c| c.asset == "ETH").unwrap();
    assert!(!eth_check.needs_rebalance);
    assert!(eth_check.max_deviation_pct < dec!(30));
}

#[test]
fn test_plan_generates_correct_transfer() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();
    let mut binance = HashMap::new();
    binance.insert("ETH".to_string(), asset_balance(dec!(2), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();
    let mut wallet = HashMap::new();
    wallet.insert("ETH".to_string(), dec!(8));
    tracker.update_from_wallet(Venue::Wallet, wallet).unwrap();

    let planner = RebalancePlanner::new(&tracker, 30.0, None);
    let plans = planner.plan("ETH");
    assert_eq!(plans.len(), 1);
    let p = &plans[0];
    assert_eq!(p.from_venue, Venue::Wallet);
    assert_eq!(p.to_venue, Venue::Binance);
    assert_eq!(p.asset, "ETH");
    assert!(p.net_amount() >= dec!(3));
    assert!(p.amount > p.estimated_fee);
}

#[test]
fn test_plan_respects_min_operating_balance() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();
    let mut binance = HashMap::new();
    binance.insert("ETH".to_string(), asset_balance(dec!(2), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();
    let mut wallet = HashMap::new();
    wallet.insert("ETH".to_string(), dec!(8));
    tracker.update_from_wallet(Venue::Wallet, wallet).unwrap();

    let planner = RebalancePlanner::new(&tracker, 30.0, None);
    let plans = planner.plan("ETH");
    assert!(!plans.is_empty());
    let p = &plans[0];
    let from_after = if p.from_venue == Venue::Wallet {
        dec!(8) - p.amount
    } else {
        dec!(2) - p.amount
    };
    assert!(from_after >= dec!(0.5), "sender must keep >= min_operating");
}

#[test]
fn test_plan_accounts_for_fees() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();
    let mut binance = HashMap::new();
    binance.insert("ETH".to_string(), asset_balance(dec!(2), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();
    let mut wallet = HashMap::new();
    wallet.insert("ETH".to_string(), dec!(8));
    tracker.update_from_wallet(Venue::Wallet, wallet).unwrap();

    let planner = RebalancePlanner::new(&tracker, 30.0, None);
    let plans = planner.plan("ETH");
    assert!(!plans.is_empty());
    for p in &plans {
        assert_eq!(p.net_amount(), p.amount - p.estimated_fee);
    }
}

#[test]
fn test_plan_empty_when_balanced() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();
    let mut binance = HashMap::new();
    binance.insert("ETH".to_string(), asset_balance(dec!(5), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();
    let mut wallet = HashMap::new();
    wallet.insert("ETH".to_string(), dec!(5));
    tracker.update_from_wallet(Venue::Wallet, wallet).unwrap();

    let planner = RebalancePlanner::new(&tracker, 30.0, None);
    let plans = planner.plan("ETH");
    assert!(plans.is_empty());
}

#[test]
fn test_estimate_cost_sums_correctly() {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();
    let mut binance = HashMap::new();
    binance.insert("ETH".to_string(), asset_balance(dec!(2), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();
    let mut wallet = HashMap::new();
    wallet.insert("ETH".to_string(), dec!(8));
    tracker.update_from_wallet(Venue::Wallet, wallet).unwrap();

    let planner = RebalancePlanner::new(&tracker, 30.0, None);
    let plans = planner.plan("ETH");
    assert!(!plans.is_empty());

    let cost = planner.estimate_cost(&plans);
    assert_eq!(cost.total_transfers, plans.len());
    assert!(cost.total_fees_usd > Decimal::ZERO);
    assert!(cost.total_time_min >= 15);
    assert!(cost.assets_affected.contains(&"ETH".to_string()));
}
