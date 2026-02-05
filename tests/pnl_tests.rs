//! PnL Engine tests.

use peanut_task::exchange::OrderSide;
use peanut_task::inventory::{ArbRecord, PnLEngine, TradeLeg, Venue};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::io::Read;
use time::OffsetDateTime;

fn trade_leg(
    id: &str,
    timestamp: OffsetDateTime,
    venue: Venue,
    symbol: &str,
    side: OrderSide,
    amount: Decimal,
    price: Decimal,
    fee: Decimal,
    fee_asset: &str,
    fee_usd: Decimal,
) -> TradeLeg {
    TradeLeg {
        id: id.to_string(),
        timestamp,
        venue,
        symbol: symbol.to_string(),
        side,
        amount,
        price,
        fee,
        fee_asset: fee_asset.to_string(),
        fee_usd,
    }
}

fn sample_arb(
    id: &str,
    buy_venue: Venue,
    sell_venue: Venue,
    amount: Decimal,
    buy_price: Decimal,
    sell_price: Decimal,
    buy_fee_usd: Decimal,
    sell_fee_usd: Decimal,
    gas_cost_usd: Decimal,
) -> ArbRecord {
    let ts = OffsetDateTime::now_utc();
    ArbRecord {
        id: id.to_string(),
        timestamp: ts,
        buy_leg: trade_leg(
            &format!("{}-buy", id),
            ts,
            buy_venue,
            "ETH/USDT",
            OrderSide::Buy,
            amount,
            buy_price,
            dec!(0),
            "USDT",
            buy_fee_usd,
        ),
        sell_leg: trade_leg(
            &format!("{}-sell", id),
            ts,
            sell_venue,
            "ETH/USDT",
            OrderSide::Sell,
            amount,
            sell_price,
            dec!(0),
            "USDT",
            sell_fee_usd,
        ),
        gas_cost_usd,
    }
}

#[test]
fn test_gross_pnl_calculation() {
    // Buy 1 ETH @ 2000, sell 1 ETH @ 2005 -> gross = 2005 - 2000 = 5
    let arb = sample_arb(
        "1",
        Venue::Binance,
        Venue::Wallet,
        dec!(1),
        dec!(2000),
        dec!(2005),
        dec!(0),
        dec!(0),
        dec!(0),
    );
    assert_eq!(arb.gross_pnl(), dec!(5));
}

#[test]
fn test_net_pnl_includes_all_fees() {
    // Gross 5, buy_fee 0.5, sell_fee 0.5, gas 1 -> net = 5 - 2 = 3
    let arb = sample_arb(
        "1",
        Venue::Binance,
        Venue::Wallet,
        dec!(1),
        dec!(2000),
        dec!(2005),
        dec!(0.5),
        dec!(0.5),
        dec!(1),
    );
    assert_eq!(arb.gross_pnl(), dec!(5));
    assert_eq!(arb.total_fees(), dec!(2));
    assert_eq!(arb.net_pnl(), dec!(3));
}

#[test]
fn test_pnl_bps_calculation() {
    // Net 3, notional 2000 -> bps = 3/2000 * 10000 = 15
    let arb = sample_arb(
        "1",
        Venue::Binance,
        Venue::Wallet,
        dec!(1),
        dec!(2000),
        dec!(2003),
        dec!(0),
        dec!(0),
        dec!(0),
    );
    assert_eq!(arb.net_pnl(), dec!(3));
    assert_eq!(arb.notional(), dec!(2000));
    assert_eq!(arb.net_pnl_bps(), dec!(15));
}

#[test]
fn test_summary_win_rate() {
    let mut engine = PnLEngine::new();
    // 3 winning, 1 losing
    engine.record(sample_arb(
        "1", Venue::Binance, Venue::Wallet, dec!(1), dec!(2000), dec!(2005),
        dec!(0), dec!(0), dec!(0),
    ));
    engine.record(sample_arb(
        "2", Venue::Wallet, Venue::Binance, dec!(1), dec!(2000), dec!(2003),
        dec!(0), dec!(0), dec!(0),
    ));
    engine.record(sample_arb(
        "3", Venue::Binance, Venue::Wallet, dec!(1), dec!(2000), dec!(2002),
        dec!(0), dec!(0), dec!(0),
    ));
    engine.record(sample_arb(
        "4", Venue::Wallet, Venue::Binance, dec!(1), dec!(2000), dec!(1998),
        dec!(0), dec!(0), dec!(0),
    ));

    let summary = engine.summary();
    assert_eq!(summary.total_trades, 4);
    assert_eq!(summary.win_rate, 0.75);
}

#[test]
fn test_summary_with_no_trades() {
    let engine = PnLEngine::new();
    let summary = engine.summary();
    assert_eq!(summary.total_trades, 0);
    assert_eq!(summary.total_pnl_usd, Decimal::ZERO);
    assert_eq!(summary.total_fees_usd, Decimal::ZERO);
    assert_eq!(summary.avg_pnl_per_trade, Decimal::ZERO);
    assert_eq!(summary.win_rate, 0.0);
    assert_eq!(summary.best_trade_pnl, Decimal::ZERO);
    assert_eq!(summary.worst_trade_pnl, Decimal::ZERO);
    assert_eq!(summary.total_notional, Decimal::ZERO);
    assert_eq!(summary.sharpe_estimate, 0.0);
}

#[test]
fn test_export_csv_format() {
    let mut engine = PnLEngine::new();
    engine.record(sample_arb(
        "arb-1",
        Venue::Binance,
        Venue::Wallet,
        dec!(1),
        dec!(2000),
        dec!(2005),
        dec!(0.5),
        dec!(0.5),
        dec!(1),
    ));

    let path = std::env::temp_dir().join("pnl_test_export.csv");
    let path_str = path.to_str().unwrap();
    engine.export_csv(path_str).unwrap();

    let mut contents = String::new();
    std::fs::File::open(path_str)
        .unwrap()
        .read_to_string(&mut contents)
        .unwrap();

    let lines: Vec<&str> = contents.trim().lines().collect();
    assert_eq!(lines.len(), 2, "header + 1 data row");

    let header = lines[0];
    assert!(header.contains("id"));
    assert!(header.contains("timestamp"));
    assert!(header.contains("symbol"));
    assert!(header.contains("buy_venue"));
    assert!(header.contains("sell_venue"));
    assert!(header.contains("gross_pnl"));
    assert!(header.contains("total_fees"));
    assert!(header.contains("net_pnl"));
    assert!(header.contains("net_pnl_bps"));
    assert!(header.contains("notional"));
    assert!(header.contains("gas_cost_usd"));

    let row = lines[1];
    assert!(row.contains("arb-1"));
    assert!(row.contains("binance"));
    assert!(row.contains("wallet"));
    assert!(row.contains("5")); // gross_pnl
    assert!(row.contains("2")); // total_fees
    assert!(row.contains("3")); // net_pnl

    let _ = std::fs::remove_file(path_str);
}
