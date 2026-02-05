//! CLI for PnL summary and trade display.
//! Usage: pnl_cli --summary [--demo]
//!
//! --demo: use hardcoded sample trades for display testing.

use peanut_task::exchange::OrderSide;
use peanut_task::inventory::{ArbRecord, PnLEngine, TradeLeg, Venue};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
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

fn demo_trades() -> Vec<ArbRecord> {
    let base = OffsetDateTime::now_utc();
    let t = |min: i64| base.saturating_add(time::Duration::minutes(min));

    vec![
        // Win: buy 2000, sell 2005 -> gross 5, fees 0.5+0.5+0.5=1.5 -> net 3.5
        ArbRecord {
            id: "arb-1".to_string(),
            timestamp: t(0),
            buy_leg: trade_leg(
                "leg-1a",
                t(0),
                Venue::Wallet,
                "ETH/USDT",
                OrderSide::Buy,
                dec!(1),
                dec!(2000),
                dec!(0.001),
                "ETH",
                dec!(0.5),
            ),
            sell_leg: trade_leg(
                "leg-1b",
                t(0),
                Venue::Binance,
                "ETH/USDT",
                OrderSide::Sell,
                dec!(1),
                dec!(2005),
                dec!(0.5),
                "USDT",
                dec!(0.5),
            ),
            gas_cost_usd: dec!(0.5),
        },
        // Win: buy 1999, sell 2003 -> gross 2, fees 0.25+0.25+0.3=0.8 -> net 1.2
        ArbRecord {
            id: "arb-2".to_string(),
            timestamp: t(-5),
            buy_leg: trade_leg(
                "leg-2a",
                t(-5),
                Venue::Wallet,
                "ETH/USDT",
                OrderSide::Buy,
                dec!(0.5),
                dec!(1999),
                dec!(0.0005),
                "ETH",
                dec!(0.25),
            ),
            sell_leg: trade_leg(
                "leg-2b",
                t(-5),
                Venue::Binance,
                "ETH/USDT",
                OrderSide::Sell,
                dec!(0.5),
                dec!(2003),
                dec!(0.25),
                "USDT",
                dec!(0.25),
            ),
            gas_cost_usd: dec!(0.3),
        },
        // Loss: buy 2010, sell 2008 -> gross -4, fees 2+1+0.8=3.8 -> net -7.8
        ArbRecord {
            id: "arb-3".to_string(),
            timestamp: t(-10),
            buy_leg: trade_leg(
                "leg-3a",
                t(-10),
                Venue::Binance,
                "ETH/USDT",
                OrderSide::Buy,
                dec!(2),
                dec!(2010),
                dec!(2),
                "USDT",
                dec!(2),
            ),
            sell_leg: trade_leg(
                "leg-3b",
                t(-10),
                Venue::Wallet,
                "ETH/USDT",
                OrderSide::Sell,
                dec!(2),
                dec!(2008),
                dec!(0.002),
                "ETH",
                dec!(1),
            ),
            gas_cost_usd: dec!(0.8),
        },
        // Win: buy 2005, sell 2009 -> gross 6, fees 0.3+0.3+0.6=1.2 -> net 4.8
        ArbRecord {
            id: "arb-4".to_string(),
            timestamp: t(-15),
            buy_leg: trade_leg(
                "leg-4a",
                t(-15),
                Venue::Wallet,
                "ETH/USDT",
                OrderSide::Buy,
                dec!(1.5),
                dec!(2005),
                dec!(0.0015),
                "ETH",
                dec!(0.3),
            ),
            sell_leg: trade_leg(
                "leg-4b",
                t(-15),
                Venue::Binance,
                "ETH/USDT",
                OrderSide::Sell,
                dec!(1.5),
                dec!(2009),
                dec!(0.75),
                "USDT",
                dec!(0.3),
            ),
            gas_cost_usd: dec!(0.6),
        },
        // Loss: buy 1998, sell 1995 -> gross -0.9, fees 0.3+0.15+0.5=0.95 -> net -1.85
        ArbRecord {
            id: "arb-5".to_string(),
            timestamp: t(-20),
            buy_leg: trade_leg(
                "leg-5a",
                t(-20),
                Venue::Binance,
                "ETH/USDT",
                OrderSide::Buy,
                dec!(0.3),
                dec!(1998),
                dec!(0.3),
                "USDT",
                dec!(0.3),
            ),
            sell_leg: trade_leg(
                "leg-5b",
                t(-20),
                Venue::Wallet,
                "ETH/USDT",
                OrderSide::Sell,
                dec!(0.3),
                dec!(1995),
                dec!(0.0003),
                "ETH",
                dec!(0.15),
            ),
            gas_cost_usd: dec!(0.5),
        },
    ]
}

fn format_num(s: &Decimal, decimals: u32) -> String {
    let st = s.round_dp(decimals).to_string();
    let parts: Vec<&str> = st.split('.').collect();
    let int_part: Vec<char> = parts[0].chars().collect();
    let len = int_part.len();
    let mut out = String::new();
    for (i, c) in int_part.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*c);
    }
    if parts.len() > 1 {
        let frac = parts[1].trim_end_matches('0');
        out.push('.');
        out.push_str(if frac.is_empty() { "0" } else { frac });
    }
    out
}

fn run_summary(use_demo: bool) -> Result<(), String> {
    let mut engine = PnLEngine::new();
    if use_demo {
        for t in demo_trades() {
            engine.record(t);
        }
    }

    let summary = engine.summary();

    println!("PnL Summary");
    println!("═══════════════════════════════════════════");
    println!("Total Trades:        {}", summary.total_trades);
    println!(
        "Win Rate:            {:.1}%",
        summary.win_rate * 100.0
    );
    println!("Total PnL:           ${}", format_num(&summary.total_pnl_usd, 2));
    println!("Total Fees:         ${}", format_num(&summary.total_fees_usd, 2));
    println!(
        "Avg PnL/Trade:       ${}",
        format_num(&summary.avg_pnl_per_trade, 2)
    );
    println!(
        "Avg PnL (bps):       {} bps",
        summary.avg_pnl_bps.round_dp(1)
    );
    println!(
        "Best Trade:          ${}",
        format_num(&summary.best_trade_pnl, 2)
    );
    println!(
        "Worst Trade:        ${}",
        format_num(&summary.worst_trade_pnl, 2)
    );
    println!(
        "Total Notional:      ${}",
        format_num(&summary.total_notional, 0)
    );

    println!("\nRecent Trades:");
    let recent = engine.recent(10);
    for r in recent {
        let time_str = format!("{:02}:{:02}", r.timestamp.hour(), r.timestamp.minute());
        let symbol = r.symbol.split('/').next().unwrap_or(&r.symbol);
        let pnl_sign = if r.net_pnl >= Decimal::ZERO { "+" } else { "" };
        let bps_str = r.net_pnl_bps.round_dp(1).to_string();
        let mark = if r.is_win { "✅" } else { "❌" };
        println!(
            "  {}  {}  Buy {} / Sell {}  {}${} ({} bps) {}",
            time_str,
            symbol,
            r.buy_venue,
            r.sell_venue,
            pnl_sign,
            format_num(&r.net_pnl, 2),
            bps_str,
            mark
        );
    }

    Ok(())
}

fn parse_args() -> (bool, bool) {
    let args: Vec<String> = std::env::args().collect();
    let mut summary = false;
    let mut demo = false;
    for i in 1..args.len() {
        match args[i].as_str() {
            "--summary" => summary = true,
            "--demo" => demo = true,
            _ => {}
        }
    }
    (summary, demo)
}

fn main() {
    let (summary, demo) = parse_args();

    if !summary {
        eprintln!("Usage: pnl_cli --summary [--demo]");
        eprintln!("  --summary  Show PnL summary and recent trades");
        eprintln!("  --demo     Use demo trades");

        std::process::exit(1);
    }

    if let Err(e) = run_summary(demo) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
