use std::env;
use std::time::Duration;

mod core;
mod chain;
mod pricing;

use core::base_types::{Address, Token};
use pricing::{
    Decimal, ImpactRow, MempoolMonitor, ParsedSwap, PriceImpactAnalyzer, RouteFinder,
    UniswapV2Pair,
};
use rust_decimal::prelude::FromPrimitive;

/// USDC/WETH Uniswap V2 pair on Ethereum mainnet
const USDC_WETH_POOL: &str = "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc";
/// USDC/USDT pair (for routing demo)
const USDC_USDT_POOL: &str = "0x3041CbD36888bECc7bbCBc0045E3B1f144466f5f";
/// DAI/WETH pair (for routing demo)
const DAI_WETH_POOL: &str = "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11";

fn human_amount(raw: u128, decimals: u8) -> String {
    let div = 10u128.pow(decimals as u32);
    let i = raw / div;
    let f = raw % div;
    if f == 0 {
        return i.to_string();
    }
    let fs = format!("{:0>width$}", f, width = decimals as usize);
    let fs = fs.trim_end_matches('0');
    format!("{}.{}", i, fs)
}

fn human_max_frac(raw: u128, decimals: u8, max_frac: usize) -> String {
    let div = 10u128.pow(decimals as u32);
    let i = raw / div;
    let f = raw % div;
    if max_frac == 0 || f == 0 {
        return i.to_string();
    }
    let fs = format!("{:0>width$}", f, width = decimals as usize);
    let take = max_frac.min(fs.len());
    let fs = fs[..take].trim_end_matches('0');
    if fs.is_empty() {
        i.to_string()
    } else {
        format!("{}.{}", i, fs)
    }
}

fn draw_impact_table(
    rows: &[ImpactRow],
    token_in: &Token,
    token_out: &Token,
    sym_in: &str,
    sym_out: &str,
) {
    const W: usize = 13;
    const W_IMPACT: usize = 10;
    println!(
        "┌{:─^w$}┬{:─^w$}┬{:─^w$}┬{:─^wi$}┐",
        format!(" {} In ", sym_in),
        format!(" {} Out ", sym_out),
        " Exec Price ",
        " Impact ",
        w = W,
        wi = W_IMPACT
    );
    println!(
        "├{:─^w$}┼{:─^w$}┼{:─^w$}┼{:─^wi$}┤",
        "", "", "", "", w = W, wi = W_IMPACT
    );
    let in_dec = 10u128.pow(token_in.decimals() as u32);
    let out_dec = 10u128.pow(token_out.decimals() as u32);
    for row in rows {
        let exec = if row.amount_out == 0 {
            String::from("N/A")
        } else {
            let hi =
                Decimal::from_u128(row.amount_in).unwrap() / Decimal::from_u128(in_dec).unwrap();
            let ho =
                Decimal::from_u128(row.amount_out).unwrap() / Decimal::from_u128(out_dec).unwrap();
            format!("{:.2}", hi / ho)
        };
        let impact =
            format!("{:.2}%", row.price_impact_pct * Decimal::from_u128(100).unwrap());
        let out_str = human_max_frac(row.amount_out, token_out.decimals(), 4);
        println!(
            "│{:^w$}│{:^w$}│{:^w$}│{:^wi$}│",
            human_amount(row.amount_in, token_in.decimals()),
            out_str,
            exec,
            impact,
            w = W,
            wi = W_IMPACT
        );
    }
    println!(
        "└{:─^w$}┴{:─^w$}┴{:─^w$}┴{:─^wi$}┘",
        "", "", "", "", w = W, wi = W_IMPACT
    );
}

fn main() {
    dotenvy::dotenv().ok();

    // --- RPC setup ---
    let mut rpc_urls = vec![];
    if let Ok(infura_key) = env::var("INFURA_API_KEY") {
        if let Ok(url) = chain::RpcUrl::new("https://mainnet.infura.io/v3/{}", &infura_key) {
            rpc_urls.push(url);
        }
    }
    if let Ok(alchemy_key) = env::var("ALCHEMY_API_KEY") {
        if let Ok(url) = chain::RpcUrl::new("https://eth-mainnet.g.alchemy.com/v2/{}", &alchemy_key) {
            rpc_urls.push(url);
        }
    }

    if rpc_urls.is_empty() {
        eprintln!("Error: No RPC URLs configured. Set INFURA_API_KEY or ALCHEMY_API_KEY.");
        std::process::exit(1);
    }

    let chain_client = match chain::chain_client::ChainClient::new(rpc_urls.clone(), 30, 3) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create ChainClient: {}", e);
            std::process::exit(1);
        }
    };

    let gas_price = match chain_client.get_gas_price() {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Failed to get gas price: {}", e);
            std::process::exit(1);
        }
    };
    let gas_price_gwei = (gas_price.base_fee / 1_000_000_000).max(1) as u64;

    // --- 1. Price impact table for a real pool ---
    println!("═══════════════════════════════════════════════════════════════");
    println!("  PRICE IMPACT TABLE (USDC/WETH pool)");
    println!("═══════════════════════════════════════════════════════════════");

    let pool_addr = Address::from_string(USDC_WETH_POOL).expect("valid pool address");
    match UniswapV2Pair::from_chain(pool_addr, &chain_client) {
        Ok(pair) => {
        let token_in = pair
            .token0
            .token
            .symbol()
            .filter(|s| s.eq_ignore_ascii_case("USDC"))
            .map(|_| pair.token0.token.clone())
            .or_else(|| {
                pair.token1
                    .token
                    .symbol()
                    .filter(|s| s.eq_ignore_ascii_case("USDC"))
                    .map(|_| pair.token1.token.clone())
            })
            .unwrap_or_else(|| pair.token0.token.clone());

        let token_out = if token_in == pair.token0.token {
            pair.token1.token.clone()
        } else {
            pair.token0.token.clone()
        };

        let sym_in = token_in.symbol().unwrap_or("IN").to_string();
        let sym_out = token_out.symbol().unwrap_or("OUT").to_string();

        let dec = 10u128.pow(token_in.decimals() as u32);
        let sizes_raw: Vec<u128> = [1000u128, 10000, 100000]
            .iter()
            .map(|&s| s * dec)
            .collect();

        let analyzer = PriceImpactAnalyzer::new(pair.clone());
        if let Ok(rows) = analyzer.generate_impact_table(&token_in, &sizes_raw) {
            let res_in = analyzer.pair.reserve_for_token(&token_in).unwrap_or(0);
            let res_out = analyzer.pair.reserve_for_token(&token_out).unwrap_or(0);
            println!(
                "{} -> {}  |  Pool {}",
                sym_in, sym_out, analyzer.pair.address.value
            );
            println!(
                "Reserves: {} {} / {} {}",
                human_amount(res_out, token_out.decimals()),
                sym_out,
                human_amount(res_in, token_in.decimals()),
                sym_in
            );
            println!();
            draw_impact_table(&rows, &token_in, &token_out, &sym_in, &sym_out);
            if let Ok(max) =
                analyzer.find_max_size_for_impact(&token_in, Decimal::new(1, 2))
            {
                println!(
                    "\nMax trade for 1% impact: {} {}",
                    human_amount(max, token_in.decimals()),
                    sym_in
                );
            }
        } else {
            eprintln!("Failed to generate impact table");
        }
        }
        Err(e) => {
            eprintln!("Failed to load pool: {}", e);
        }
    }
    println!();

    // --- 2. Find best route between two tokens ---
    println!("═══════════════════════════════════════════════════════════════");
    println!("  BEST ROUTE (USDC -> WETH)");
    println!("═══════════════════════════════════════════════════════════════");

    let pool_addrs = [
        Address::from_string(USDC_WETH_POOL).unwrap(),
        Address::from_string(USDC_USDT_POOL).unwrap(),
        Address::from_string(DAI_WETH_POOL).unwrap(),
    ];

    let mut pools = Vec::new();
    for addr in &pool_addrs {
        if let Ok(p) = UniswapV2Pair::from_chain(addr.clone(), &chain_client) {
            pools.push(p);
        }
    }

    if pools.is_empty() {
        eprintln!("Could not load any pools for routing");
    } else {
        let (usdc, weth) = pools
            .iter()
            .find_map(|p| {
                let t0 = &p.token0.token;
                let t1 = &p.token1.token;
                let has_usdc = t0.symbol().map(|s| s == "USDC").unwrap_or(false)
                    || t1.symbol().map(|s| s == "USDC").unwrap_or(false);
                let has_weth = t0.symbol().map(|s| s == "WETH" || s == "ETH").unwrap_or(false)
                    || t1.symbol().map(|s| s == "WETH" || s == "ETH").unwrap_or(false);
                if has_usdc && has_weth {
                    let usdc = if t0.symbol() == Some("USDC") {
                        t0.clone()
                    } else {
                        t1.clone()
                    };
                    let weth = if t0.symbol().map(|s| s == "WETH" || s == "ETH").unwrap_or(false) {
                        t0.clone()
                    } else {
                        t1.clone()
                    };
                    Some((usdc, weth))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| {
                (
                    Token::new(6, Some("USDC".to_string())),
                    Token::native_eth(),
                )
            });
        let route_finder = RouteFinder::new(pools);
        let amount_in = 10_000 * 10u128.pow(usdc.decimals() as u32); // 10k USDC

        match route_finder.find_best_route(&usdc, &weth, amount_in, gas_price_gwei, 3) {
            Ok(Some((route, net_output))) => {
                let path_str = route
                    .path
                    .iter()
                    .filter_map(|t| t.symbol())
                    .collect::<Vec<_>>()
                    .join(" -> ");
                println!("Best route: {} ({} hops)", path_str, route.num_hops());
                println!(
                    "  Amount in: {} USDC",
                    human_amount(amount_in, usdc.decimals())
                );
                println!(
                    "  Net output: {} (after gas)",
                    human_amount(net_output, weth.decimals())
                );
            }
            Ok(None) => {
                println!("No route found between USDC and WETH with loaded pools");
            }
            Err(e) => {
                eprintln!("Route finding error: {}", e);
            }
        }
    }
    println!();

    // --- 3. Mempool monitoring ---
    println!("═══════════════════════════════════════════════════════════════");
    println!("  MEMPOOL MONITORING");
    println!("═══════════════════════════════════════════════════════════════");

    let ws_url = if let Ok(key) = env::var("INFURA_API_KEY") {
        if !key.is_empty() && key != "apikey" {
            Some(format!("wss://mainnet.infura.io/ws/v3/{}", key))
        } else {
            None
        }
    } else if let Ok(key) = env::var("ALCHEMY_API_KEY") {
        if !key.is_empty() {
            Some(format!("wss://eth-mainnet.g.alchemy.com/v2/{}", key))
        } else {
            None
        }
    } else {
        None
    };

    if let Some(ws_url) = ws_url {
        println!("Mempool monitor started. Listening for swap txs");
        println!("(swapExactTokensForTokens, swapExactETHForTokens, swapExactTokensForETH)");
        println!("Send test swaps to see them here. Running for 60 seconds...");
        println!();

        let monitor = MempoolMonitor::new(ws_url, |swap: ParsedSwap| {
            println!("  [SWAP] {} -> {}", swap.method, swap.tx_hash);
            println!("    amount_in: {}, min_out: {}, sender: {}", swap.amount_in, swap.min_amount_out, swap.sender);
        });

        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        rt.block_on(async {
            match tokio::time::timeout(Duration::from_secs(60), monitor.start()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => eprintln!("Mempool monitor error: {}", e),
                Err(_) => println!("(Monitor timed out after 60 seconds)"),
            }
        });
    } else {
        println!("Skipping mempool: no WebSocket URL (set INFURA_API_KEY or ALCHEMY_API_KEY)");
    }
}