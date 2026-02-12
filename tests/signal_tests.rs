use peanut_task::{Direction, Signal};
use rust_decimal_macros::dec;
use time::{Duration, OffsetDateTime};

#[test]
fn test_signal_creation() {
    let expiry = OffsetDateTime::now_utc() + Duration::seconds(60);
    let signal = Signal::create(
        "ETH/USDT".to_string(),
        Direction::BuyCexSellDex,
        dec!(2000.0),
        dec!(2010.0),
        dec!(50.0),
        dec!(1.0),
        dec!(10.0),
        dec!(2.0),
        dec!(8.0),
        dec!(5.0),
        expiry,
        true,
        true,
    );

    assert_eq!(signal.pair, "ETH/USDT");
    assert_eq!(signal.direction, Direction::BuyCexSellDex);
    assert!(signal.signal_id.starts_with("ETHUSDT_"));
    assert_eq!(signal.cex_price, dec!(2000.0));
    assert_eq!(signal.dex_price, dec!(2010.0));
}

#[test]
fn test_signal_validation() {
    let expiry = OffsetDateTime::now_utc() + Duration::seconds(60);
    let signal = Signal::create(
        "ETH/USDT".to_string(),
        Direction::BuyCexSellDex,
        dec!(2000.0),
        dec!(2010.0),
        dec!(50.0),
        dec!(1.0),
        dec!(10.0),
        dec!(2.0),
        dec!(8.0),
        dec!(5.0),
        expiry,
        true,
        true,
    );

    assert!(signal.is_valid());
}

#[test]
fn test_signal_invalid_when_expired() {
    let expiry = OffsetDateTime::now_utc() - Duration::seconds(60);
    let signal = Signal::create(
        "ETH/USDT".to_string(),
        Direction::BuyCexSellDex,
        dec!(2000.0),
        dec!(2010.0),
        dec!(50.0),
        dec!(1.0),
        dec!(10.0),
        dec!(2.0),
        dec!(8.0),
        dec!(5.0),
        expiry,
        true,
        true,
    );

    assert!(!signal.is_valid());
}

#[test]
fn test_signal_invalid_when_negative_pnl() {
    let expiry = OffsetDateTime::now_utc() + Duration::seconds(60);
    let signal = Signal::create(
        "ETH/USDT".to_string(),
        Direction::BuyCexSellDex,
        dec!(2000.0),
        dec!(2010.0),
        dec!(50.0),
        dec!(1.0),
        dec!(10.0),
        dec!(2.0),
        dec!(-5.0), // Negative net PnL
        dec!(5.0),
        expiry,
        true,
        true,
    );

    assert!(!signal.is_valid());
}

#[test]
fn test_signal_age() {
    let expiry = OffsetDateTime::now_utc() + Duration::seconds(60);
    let signal = Signal::create(
        "ETH/USDT".to_string(),
        Direction::BuyCexSellDex,
        dec!(2000.0),
        dec!(2010.0),
        dec!(50.0),
        dec!(1.0),
        dec!(10.0),
        dec!(2.0),
        dec!(8.0),
        dec!(5.0),
        expiry,
        true,
        true,
    );

    let age = signal.age_seconds();
    assert!(age >= 0.0 && age < 1.0);
}
