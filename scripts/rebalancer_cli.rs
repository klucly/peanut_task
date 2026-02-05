//! CLI for inventory rebalance planning.
//! Usage: rebalancer_cli --check | --plan ASSET [--demo] [--test]
//!
//! Fetches live data from:
//! - Binance: BINANCE_TESTNET_API_KEY, BINANCE_TESTNET_SECRET
//! - Wallet: SECRET_KEY (address), INFURA_API_KEY or ALCHEMY_API_KEY or ETH_RPC_URL (RPC)
//!
//! Use --demo to fall back to demo data when env vars are unset.
//! Use --test to use Infura Sepolia testnet instead of mainnet.

use std::collections::HashMap;
use std::env;

use peanut_task::chain::{ChainClient, RpcUrl};
use peanut_task::core::wallet_manager::WalletManager;
use peanut_task::exchange::{AssetBalance, ExchangeClient, ExchangeConfig};
use peanut_task::inventory::{InventoryTracker, RebalancePlanner, Venue};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

fn asset_balance(free: Decimal, locked: Decimal) -> AssetBalance {
    AssetBalance {
        free,
        locked,
        total: free + locked,
    }
}

/// Build tracker with demo data: ETH 2/8, USDT 60/40.
fn demo_tracker() -> InventoryTracker {
    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();

    let mut binance = HashMap::new();
    binance.insert("ETH".to_string(), asset_balance(dec!(2), dec!(0)));
    binance.insert("USDT".to_string(), asset_balance(dec!(18000), dec!(0)));
    tracker.update_from_cex(Venue::Binance, binance).unwrap();

    let mut wallet = HashMap::new();
    wallet.insert("ETH".to_string(), dec!(8));
    wallet.insert("USDT".to_string(), dec!(12000));
    tracker.update_from_wallet(Venue::Wallet, wallet).unwrap();

    tracker
}

fn token_amount_to_decimal(raw: u128, decimals: u8) -> Decimal {
    let div = 10u128.pow(decimals as u32);
    let int_part = raw / div;
    let frac_part = raw % div;
    Decimal::from(int_part as u64)
        + Decimal::from(frac_part as u64) / Decimal::from(div as u64)
}

/// Build tracker from live data (Binance + wallet ETH).
/// When use_testnet is true, uses Infura Sepolia testnet for wallet balance.
fn live_tracker(use_testnet: bool) -> Result<InventoryTracker, String> {
    dotenvy::dotenv().ok();

    let mut tracker = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap();

    let config = ExchangeConfig::from_env().map_err(|e| e.to_string())?;
    let client = ExchangeClient::new(config).map_err(|e| e.to_string())?;
    let binance_balances = client.fetch_balance().map_err(|e| e.to_string())?;
    tracker
        .update_from_cex(Venue::Binance, binance_balances)
        .map_err(|e| e.to_string())?;

    let wallet = WalletManager::from_env("SECRET_KEY").map_err(|e| e.to_string())?;
    let address = wallet.address();

    let mut rpc_urls = Vec::new();
    if use_testnet {
        if let Ok(key) = env::var("INFURA_API_KEY") {
            if let Ok(url) = RpcUrl::new("https://sepolia.infura.io/v3/{}", &key) {
                rpc_urls.push(url);
            }
        }
        if rpc_urls.is_empty() {
            return Err("Testnet mode: set INFURA_API_KEY for Sepolia".to_string());
        }
    } else {
        if let Ok(key) = env::var("INFURA_API_KEY") {
            if let Ok(url) = RpcUrl::new("https://mainnet.infura.io/v3/{}", &key) {
                rpc_urls.push(url);
            }
        }
        if let Ok(key) = env::var("ALCHEMY_API_KEY") {
            if let Ok(url) = RpcUrl::new("https://eth-mainnet.g.alchemy.com/v2/{}", &key) {
                rpc_urls.push(url);
            }
        }
        if let Ok(url_str) = env::var("ETH_RPC_URL") {
            if !url_str.is_empty() {
                if let Ok(rpc_url) = RpcUrl::new("{}", &url_str) {
                    rpc_urls.push(rpc_url);
                }
            }
        }
        if rpc_urls.is_empty() {
            return Err("No RPC URL. Set INFURA_API_KEY, ALCHEMY_API_KEY, or ETH_RPC_URL".to_string());
        }
    }

    let chain_client = ChainClient::new(rpc_urls, 30, 3).map_err(|e| e.to_string())?;
    let eth_balance = chain_client.get_balance(address).map_err(|e| e.to_string())?;
    let eth_decimal = token_amount_to_decimal(eth_balance.raw, eth_balance.decimals());

    let mut wallet_balances = HashMap::new();
    wallet_balances.insert("ETH".to_string(), eth_decimal);
    tracker
        .update_from_wallet(Venue::Wallet, wallet_balances)
        .map_err(|e| e.to_string())?;

    Ok(tracker)
}

fn get_tracker(use_demo: bool, use_testnet: bool) -> Result<InventoryTracker, String> {
    if use_demo {
        Ok(demo_tracker())
    } else {
        live_tracker(use_testnet)
    }
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

fn run_check(use_demo: bool, use_testnet: bool) -> Result<(), String> {
    let tracker = get_tracker(use_demo, use_testnet)?;
    let planner = RebalancePlanner::new(&tracker, 30.0, None);
    let checks = planner.check_all();

    println!("Inventory Skew Report");
    println!("═══════════════════════════════════════════");

    for check in checks {
        let skew = tracker.skew(&check.asset);
        let status = if check.needs_rebalance {
            "⚠️  NEEDS REBALANCE"
        } else {
            "✅  OK"
        };

        let n_venues = skew.venues.len() as u32;
        let equal_pct = if n_venues > 0 {
            Decimal::from(100) / Decimal::from(n_venues)
        } else {
            Decimal::ZERO
        };

        println!("\nAsset: {}", check.asset);
        for (venue_name, v) in &skew.venues {
            let venue_label = venue_name.chars().next().unwrap().to_uppercase().to_string()
                + &venue_name[1..];
            let amount_str = format_num(&v.amount, 4);
            let pct_str = format!("{:.0}", v.pct);
            let signed_dev = v.pct - equal_pct;
            let dev_str = signed_dev.round_dp(1).to_string();
            let sign = if signed_dev >= Decimal::ZERO { "+" } else { "" };
            if check.needs_rebalance {
                println!(
                    "  {}:  {} {}  ({}%)   ← deviation: {}{}%",
                    venue_label, amount_str, check.asset, pct_str, sign, dev_str
                );
            } else {
                println!("  {}:  {} {}  ({}%)", venue_label, amount_str, check.asset, pct_str);
            }
        }
        if !check.needs_rebalance {
            println!(
                "  (deviation: {}%)",
                check.max_deviation_pct.round_dp(1)
            );
        }
        println!("  Status: {}", status);
    }

    println!("\n═══════════════════════════════════════════");
    Ok(())
}

fn run_plan(asset: &str, use_demo: bool, use_testnet: bool) -> Result<(), String> {
    let tracker = get_tracker(use_demo, use_testnet)?;
    let planner = RebalancePlanner::new(&tracker, 30.0, None);
    let plans = planner.plan(asset);

    println!("Rebalance Plan: {}", asset);
    println!("───────────────────────────────────────────");

    if plans.is_empty() {
        println!("No rebalance needed.");
        return Ok(());
    }

    for (i, p) in plans.iter().enumerate() {
        let to_before = tracker.get_available(p.to_venue, &p.asset);
        let from_before = tracker.get_available(p.from_venue, &p.asset);
        let to_after = to_before + p.net_amount();
        let from_after = from_before - p.amount;

        println!("\nTransfer {}:", i + 1);
        println!("  From:     {}", p.from_venue);
        println!("  To:       {}", p.to_venue);
        println!("  Amount:   {} {}", format_num(&p.amount, 4), p.asset);
        let fee_usd = if p.asset == "ETH" {
            p.estimated_fee * Decimal::from(2000)
        } else {
            p.estimated_fee
        };
        println!(
            "  Fee:      {} {} (~${})",
            p.estimated_fee,
            p.asset,
            format_num(&fee_usd, 2)
        );
        println!("  ETA:      ~{} min", p.estimated_time_min);
        println!();
        println!("  Result:");
        let total = to_after + from_after;
        let to_pct = if total.is_zero() {
            Decimal::ZERO
        } else {
            to_after / total * Decimal::from(100)
        };
        let from_pct = if total.is_zero() {
            Decimal::ZERO
        } else {
            from_after / total * Decimal::from(100)
        };
        println!(
            "    {}:  {} {} ({:.0}%)",
            p.to_venue,
            format_num(&to_after, 4),
            p.asset,
            to_pct
        );
        println!(
            "    {}:  {} {} ({:.0}%)",
            p.from_venue,
            format_num(&from_after, 4),
            p.asset,
            from_pct
        );
    }

    let cost = planner.estimate_cost(&plans);
    println!("\nEstimated total cost: ${}", format_num(&cost.total_fees_usd, 2));
    Ok(())
}

fn parse_args() -> Result<(bool, bool, Option<String>, bool, bool), String> {
    let args: Vec<String> = std::env::args().collect();
    let mut check = false;
    let mut plan_asset = None;
    let mut use_demo = false;
    let mut use_testnet = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--check" => {
                check = true;
                i += 1;
            }
            "--plan" => {
                i += 1;
                plan_asset = args.get(i).cloned();
                i += 1;
            }
            "--demo" => {
                use_demo = true;
                i += 1;
            }
            "--test" => {
                use_testnet = true;
                i += 1;
            }
            _ => i += 1,
        }
    }
    Ok((check, plan_asset.is_some(), plan_asset, use_demo, use_testnet))
}

fn main() {
    let (check, _, plan_asset, use_demo, use_testnet) =
        parse_args().unwrap_or((false, false, None, false, false));

    let result = if check {
        run_check(use_demo, use_testnet)
    } else if let Some(asset) = plan_asset {
        run_plan(&asset, use_demo, use_testnet)
    } else {
        eprintln!("Usage: rebalancer_cli --check | --plan ASSET [--demo] [--test]");
        eprintln!("  --check       Show skew report for all assets");
        eprintln!("  --plan ASSET  Show rebalance plan for asset (e.g. ETH)");
        eprintln!("  --demo        Use demo data (when env vars unset or for testing)");
        eprintln!("  --test        Use Infura Sepolia testnet for wallet balance");
        eprintln!();
        eprintln!("Env: BINANCE_TESTNET_API_KEY, BINANCE_TESTNET_SECRET, SECRET_KEY,");
        eprintln!("     INFURA_API_KEY or ALCHEMY_API_KEY or ETH_RPC_URL");
        std::process::exit(1);
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
