use peanut_task::FeeStructure;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

#[test]
fn test_default_fee_structure() {
    let fees = FeeStructure::default();
    assert_eq!(fees.cex_taker_bps, dec!(10.0));
    assert_eq!(fees.dex_swap_bps, dec!(30.0));
    assert_eq!(fees.gas_cost_usd, dec!(5.0));
}

#[test]
fn test_custom_fee_structure() {
    let fees = FeeStructure::new(dec!(15.0), dec!(25.0), dec!(3.0));
    assert_eq!(fees.cex_taker_bps, dec!(15.0));
    assert_eq!(fees.dex_swap_bps, dec!(25.0));
    assert_eq!(fees.gas_cost_usd, dec!(3.0));
}

#[test]
fn test_total_fee_bps() {
    let fees = FeeStructure::default();
    let trade_value = dec!(1000.0);
    
    // gas_bps = (5.0 / 1000.0) * 10000 = 50.0
    // total = 10.0 + 30.0 + 50.0 = 90.0
    let total = fees.total_fee_bps(trade_value);
    assert_eq!(total, dec!(90.0));
}

#[test]
fn test_total_fee_bps_small_trade() {
    let fees = FeeStructure::default();
    let trade_value = dec!(100.0);
    
    // gas_bps = (5.0 / 100.0) * 10000 = 500.0
    // total = 10.0 + 30.0 + 500.0 = 540.0
    let total = fees.total_fee_bps(trade_value);
    assert_eq!(total, dec!(540.0));
}

#[test]
fn test_breakeven_spread_bps() {
    let fees = FeeStructure::default();
    let trade_value = dec!(1000.0);
    
    let breakeven = fees.breakeven_spread_bps(trade_value);
    let total_fees = fees.total_fee_bps(trade_value);
    assert_eq!(breakeven, total_fees);
}

#[test]
fn test_net_profit_usd_profitable() {
    let fees = FeeStructure::default();
    let spread_bps = dec!(100.0); // 1% spread
    let trade_value = dec!(1000.0);
    
    // gross = (100 / 10000) * 1000 = 10.0
    // total_fees_bps = 90.0
    // fees = (90 / 10000) * 1000 = 9.0
    // net = 10.0 - 9.0 = 1.0
    let net_profit = fees.net_profit_usd(spread_bps, trade_value);
    assert_eq!(net_profit, dec!(1.0));
}

#[test]
fn test_net_profit_usd_unprofitable() {
    let fees = FeeStructure::default();
    let spread_bps = dec!(50.0); // 0.5% spread
    let trade_value = dec!(1000.0);
    
    // gross = (50 / 10000) * 1000 = 5.0
    // total_fees_bps = 90.0
    // fees = (90 / 10000) * 1000 = 9.0
    // net = 5.0 - 9.0 = -4.0
    let net_profit = fees.net_profit_usd(spread_bps, trade_value);
    assert_eq!(net_profit, dec!(-4.0));
}

#[test]
fn test_net_profit_usd_breakeven() {
    let fees = FeeStructure::default();
    let trade_value = dec!(1000.0);
    
    // Use breakeven spread
    let spread_bps = fees.breakeven_spread_bps(trade_value);
    let net_profit = fees.net_profit_usd(spread_bps, trade_value);
    
    // Should be exactly zero
    assert_eq!(net_profit, Decimal::ZERO);
}

#[test]
fn test_zero_trade_value_safety() {
    let fees = FeeStructure::default();
    let total = fees.total_fee_bps(Decimal::ZERO);
    
    // Should handle zero trade value without panicking
    // Gas BPS should be zero, only cex + dex fees
    assert_eq!(total, dec!(40.0)); // 10 + 30
}
