//! CLI for order book analysis. Usage: orderbook_cli [SYMBOL] [--depth 20] [--url BASE_URL]
//! Default symbol: ETH/USDT.
//! Needs BINANCE_TESTNET_API_KEY and BINANCE_TESTNET_SECRET.

use std::env;

use peanut_task::exchange::{BookSide, ExchangeClient, ExchangeConfig, OrderBookAnalyzer, OrderSide};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

fn format_timestamp_utc(timestamp: u64) -> String {
    use time::format_description::well_known::Rfc3339;
    use time::{OffsetDateTime, UtcOffset};
    let Ok(dt) = OffsetDateTime::from_unix_timestamp(timestamp as i64) else {
        return format!("{} (invalid)", timestamp);
    };
    let dt_utc = dt.to_offset(UtcOffset::UTC);
    dt_utc
        .format(&Rfc3339)
        .map(|s| s.replace('T', " ").replace('Z', ""))
        .unwrap_or_else(|_| format!("{} (invalid)", timestamp))
}

const WIDTH: usize = 52;

fn format_num_str(s: &str) -> String {
    let (neg, rest) = if s.starts_with('-') {
        ("-", &s[1..])
    } else {
        ("", s)
    };
    let int_part: Vec<char> = rest
        .split('.')
        .next()
        .unwrap_or(rest)
        .chars()
        .collect();
    let len = int_part.len();
    let mut out = String::from(neg);
    for (i, c) in int_part.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*c);
    }
    if let Some(dot) = rest.find('.') {
        out.push_str(&rest[dot..]);
    }
    out
}

fn format_price(d: &Decimal) -> String {
    format_num_str(&d.round_dp(2).to_string())
}

fn format_qty(d: &Decimal) -> String {
    let s = d.round_dp(4).to_string();
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    format_num_str(trimmed)
}

fn format_quote(d: &Decimal) -> String {
    format_num_str(&d.round_dp(0).to_string())
}

fn pad_line(s: &str) -> String {
    let len = s.chars().count();
    if len >= WIDTH {
        s.chars().take(WIDTH).collect()
    } else {
        format!("{:<width$}", s, width = WIDTH)
    }
}

fn imbalance_interpretation(v: f64) -> &'static str {
    if v >= 0.3 {
        "strong buy pressure"
    } else if v >= 0.1 {
        "slight buy pressure"
    } else if v <= -0.3 {
        "strong sell pressure"
    } else if v <= -0.1 {
        "slight sell pressure"
    } else {
        "balanced"
    }
}

fn parse_args() -> Result<(String, u32, Option<String>), String> {
    let args: Vec<String> = env::args().collect();
    let mut symbol = None;
    let mut depth = 20u32;
    let mut url = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--depth" => {
                i += 1;
                if let Some(s) = args.get(i) {
                    depth = s.parse().map_err(|_| "invalid --depth")?;
                }
                i += 1;
            }
            "--url" => {
                i += 1;
                url = args.get(i).cloned();
                i += 1;
            }
            s if !s.starts_with('-') && symbol.is_none() => {
                symbol = Some(s.to_string());
                i += 1;
            }
            _ => i += 1,
        }
    }
    let symbol = symbol.unwrap_or_else(|| "ETH/USDT".to_string());
    Ok((symbol, depth, url))
}

fn run() -> Result<(), String> {
    dotenvy::dotenv().ok();
    let (symbol, depth, url_override) = parse_args()?;

    let mut config = ExchangeConfig::from_env().map_err(|e| e.to_string())?;
    if let Some(url) = url_override {
        config.url_override = Some(url);
    }

    let client = ExchangeClient::new(config).map_err(|e| e.to_string())?;
    let ob = client.fetch_order_book(&symbol, depth).map_err(|e| e.to_string())?;

    let analyzer = OrderBookAnalyzer::new(ob.clone());

    let timestamp_secs = (ob.timestamp / 1000).max(0) as u64;
    let ts_str = format_timestamp_utc(timestamp_secs);

    let spread_dollars = ob.best_ask.0 - ob.best_bid.0;

    let depth_bps = 10.0;
    let bid_depth = analyzer.depth_at_bps(BookSide::Bid, depth_bps).map_err(|e| e.to_string())?;
    let ask_depth = analyzer.depth_at_bps(BookSide::Ask, depth_bps).map_err(|e| e.to_string())?;
    let bid_quote = analyzer
        .depth_quote_value_at_bps(BookSide::Bid, depth_bps)
        .map_err(|e| e.to_string())?;
    let ask_quote = analyzer
        .depth_quote_value_at_bps(BookSide::Ask, depth_bps)
        .map_err(|e| e.to_string())?;

    let imb = analyzer.imbalance(10);
    let imb_str = imbalance_interpretation(imb);

    let walk_2 = analyzer.walk_the_book(OrderSide::Buy, dec!(2)).map_err(|e| e.to_string())?;
    let walk_10 = analyzer.walk_the_book(OrderSide::Buy, dec!(10)).map_err(|e| e.to_string())?;

    let eff_spread = analyzer
        .effective_spread(dec!(2))
        .map_err(|e| e.to_string())?;

    let base = symbol.split('/').next().unwrap_or("");
    let border = "═".repeat(WIDTH);
    println!("╔{}╗", border);
    println!("║{}║", pad_line(&format!(" {} Order Book Analysis", symbol)));
    println!("║{}║", pad_line(&format!(" Timestamp: {} UTC", ts_str)));
    println!("╠{}╣", border);
    println!(
        "║{}║",
        pad_line(&format!(
            " Best Bid:    ${} × {} {}",
            format_price(&ob.best_bid.0),
            format_qty(&ob.best_bid.1),
            base
        ))
    );
    println!(
        "║{}║",
        pad_line(&format!(
            " Best Ask:    ${} × {} {}",
            format_price(&ob.best_ask.0),
            format_qty(&ob.best_ask.1),
            base
        ))
    );
    println!(
        "║{}║",
        pad_line(&format!(" Mid Price:   ${}", format_price(&ob.mid_price)))
    );
    println!(
        "║{}║",
        pad_line(&format!(
            " Spread:      ${} ({:.2} bps)",
            format_price(&spread_dollars),
            ob.spread_bps
        ))
    );
    println!("╠{}╣", border);
    println!("║{}║", pad_line(" Depth (within 10 bps):"));
    println!(
        "║{}║",
        pad_line(&format!(
            "   Bids: {} {} (${})",
            format_qty(&bid_depth),
            base,
            format_quote(&bid_quote)
        ))
    );
    println!(
        "║{}║",
        pad_line(&format!(
            "   Asks: {} {} (${})",
            format_qty(&ask_depth),
            base,
            format_quote(&ask_quote)
        ))
    );
    println!(
        "║{}║",
        pad_line(&format!(" Imbalance: {:.2} ({})", imb, imb_str))
    );
    println!("╠{}╣", border);
    println!(
        "║{}║",
        pad_line(&format!(" Walk-the-book (2 {} buy):", base))
    );
    println!(
        "║{}║",
        pad_line(&format!(
            "   Avg price:  ${}",
            format_price(&walk_2.avg_price)
        ))
    );
    println!(
        "║{}║",
        pad_line(&format!("   Slippage:   {:.2} bps", walk_2.slippage_bps))
    );
    println!(
        "║{}║",
        pad_line(&format!("   Levels:     {}", walk_2.levels_consumed))
    );
    println!(
        "║{}║",
        pad_line(&format!(" Walk-the-book (10 {} buy):", base))
    );
    println!(
        "║{}║",
        pad_line(&format!(
            "   Avg price:  ${}",
            format_price(&walk_10.avg_price)
        ))
    );
    println!(
        "║{}║",
        pad_line(&format!("   Slippage:   {:.2} bps", walk_10.slippage_bps))
    );
    println!(
        "║{}║",
        pad_line(&format!("   Levels:     {}", walk_10.levels_consumed))
    );
    println!("╠{}╣", border);
    println!(
        "║{}║",
        pad_line(&format!(
            " Effective spread (2 {} round-trip): {:.2} bps",
            base,
            eff_spread
        ))
    );
    println!("╚{}╝", border);

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
