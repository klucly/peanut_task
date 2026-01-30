//! CLI to analyze price impact. Usage: price_impact_cli <PAIR> --token-in USDC --sizes 1000,10000,...
//! Needs INFURA_API_KEY or RPC_URL.

use std::env;

use peanut_task::chain::{ChainClient, RpcUrl};
use peanut_task::core::base_types::{Address, Token, TokenAmount};
use peanut_task::pricing::{
    Decimal, ImpactRow, PriceImpactAnalyzer, UniswapV2Pair, UniswapV2PairError,
};
use rust_decimal::prelude::FromPrimitive;

fn human(raw: u128, decimals: u8) -> String {
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

/// Like human() but at most max_frac decimal digits, so table columns don't overflow.
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

fn parse_args() -> Result<(String, String, Vec<String>), String> {
    let args: Vec<String> = env::args().collect();
    let mut pair = None;
    let mut token_in = None;
    let mut sizes = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--token-in" => {
                i += 1;
                token_in = args.get(i).cloned();
                i += 1;
            }
            "--sizes" => {
                i += 1;
                sizes = args.get(i).cloned();
                i += 1;
            }
            s if s.starts_with("0x") => {
                pair = Some(s.to_string());
                i += 1;
            }
            _ => i += 1,
        }
    }
    let pair = pair.ok_or("missing pair address (0x...)")?;
    let token_in = token_in.ok_or("missing --token-in (e.g. USDC or ETH)")?;
    let sizes = sizes.ok_or("missing --sizes (e.g. 1000,10000)")?;
    let list: Vec<String> = sizes.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if list.is_empty() {
        return Err("--sizes must have at least one value".to_string());
    }
    Ok((pair, token_in, list))
}

/// Draw the impact table (box-drawing) to stdout.
fn draw_impact_table(
    rows: &[ImpactRow],
    token_in: &Token,
    token_out: &Token,
    sym_in: &str,
    sym_out: &str,
) {
    const W: usize = 13;
    const W_IMPACT: usize = 10;
    println!("┌{:─^w$}┬{:─^w$}┬{:─^w$}┬{:─^wi$}┐", format!(" {} In ", sym_in), format!(" {} Out ", sym_out), " Exec Price ", " Impact ", w = W, wi = W_IMPACT);
    println!("├{:─^w$}┼{:─^w$}┼{:─^w$}┼{:─^wi$}┤", "", "", "", "", w = W, wi = W_IMPACT);
    let in_dec = 10u128.pow(token_in.decimals() as u32);
    let out_dec = 10u128.pow(token_out.decimals() as u32);
    for row in rows {
        let exec = if row.amount_out == 0 { String::from("N/A") } else {
            let hi = Decimal::from_u128(row.amount_in).unwrap() / Decimal::from_u128(in_dec).unwrap();
            let ho = Decimal::from_u128(row.amount_out).unwrap() / Decimal::from_u128(out_dec).unwrap();
            format!("{:.2}", hi / ho)
        };
        let impact = format!("{:.2}%", row.price_impact_pct * Decimal::from_u128(100).unwrap());
        let out_str = human_max_frac(row.amount_out, token_out.decimals(), 4);
        println!("│{:^w$}│{:^w$}│{:^w$}│{:^wi$}│",
            human(row.amount_in, token_in.decimals()),
            out_str,
            exec, impact, w = W, wi = W_IMPACT);
    }
    println!("└{:─^w$}┴{:─^w$}┴{:─^w$}┴{:─^wi$}┘", "", "", "", "", w = W, wi = W_IMPACT);
}

fn rpc_url() -> Result<RpcUrl, String> {
    if let Ok(url) = env::var("RPC_URL") {
        RpcUrl::new("{}", &url).map_err(|e| e.to_string())
    } else if let Ok(key) = env::var("INFURA_API_KEY") {
        if key.is_empty() || key == "apikey" {
            return Err("set INFURA_API_KEY or RPC_URL".to_string());
        }
        RpcUrl::new("https://mainnet.infura.io/v3/{}", &key).map_err(|e| e.to_string())
    } else {
        Err("set INFURA_API_KEY or RPC_URL".to_string())
    }
}

fn run() -> Result<(), String> {
    let _ = dotenvy::dotenv();
    let (pair_addr, token_in_sym, sizes_list) = parse_args()?;
    let addr = Address::from_string(&pair_addr).map_err(|e| e.to_string())?;
    let rpc = rpc_url()?;
    let client = ChainClient::new(vec![rpc], 30, 3).map_err(|e| e.to_string())?;
    let pair = UniswapV2Pair::from_chain(addr, &client).map_err(|e| e.to_string())?;

    let token_in = pair
        .token0
        .token
        .symbol()
        .filter(|s| s.eq_ignore_ascii_case(&token_in_sym))
        .map(|_| pair.token0.token.clone())
        .or_else(|| {
            pair.token1.token.symbol().filter(|s| s.eq_ignore_ascii_case(&token_in_sym)).map(|_| pair.token1.token.clone())
        })
        .ok_or_else(|| format!("token {:?} not in pair (use USDC or ETH)", token_in_sym))?;

    let token_out = if token_in == pair.token0.token { pair.token1.token.clone() } else { pair.token0.token.clone() };
    let sym_in = token_in
        .symbol()
        .ok_or("token_in has no symbol (pair token metadata incomplete)")?
        .to_string();
    let sym_out = token_out
        .symbol()
        .ok_or("token_out has no symbol (pair token metadata incomplete)")?
        .to_string();

    let sizes_raw: Vec<u128> = sizes_list
        .iter()
        .map(|s| TokenAmount::from_human(s, token_in.clone()).map(|ta| ta.raw))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e)?;

    let analyzer = PriceImpactAnalyzer::new(pair.clone());
    let rows = analyzer.generate_impact_table(&token_in, &sizes_raw).map_err(|e: UniswapV2PairError| e.to_string())?;

    let res_in = analyzer.pair.reserve_for_token(&token_in).map_err(|e| e.to_string())?;
    let res_out = analyzer.pair.reserve_for_token(&token_out).map_err(|e| e.to_string())?;
    // Spot = price of token_in in token_out: how many token_out per one token_in (out_reserve / in_reserve in human units).
    let spot = if res_out == 0 {
        String::from("N/A")
    } else {
        let di = Decimal::from_u128(10u128.pow(token_in.decimals() as u32))
            .ok_or("decimal conversion failed (token decimals)")?;
        let do_ = Decimal::from_u128(10u128.pow(token_out.decimals() as u32))
            .ok_or("decimal conversion failed (token decimals)")?;
        let hi = Decimal::from_u128(res_in).ok_or("decimal conversion failed (reserve too large)")? / di;
        let ho = Decimal::from_u128(res_out).ok_or("decimal conversion failed (reserve too large)")? / do_;
        let ratio = ho / hi;
        let s = if ratio < Decimal::ONE && ratio > Decimal::ZERO {
            format!("{:.6}", ratio)
        } else {
            format!("{:.2}", ratio)
        };
        s
    };

    println!("{} -> {}  |  Pool {}", sym_in, sym_out, analyzer.pair.address.value);
    println!("Reserves: {} {} / {} {}", human(res_out, token_out.decimals()), sym_out, human(res_in, token_in.decimals()), sym_in);
    println!("Spot: {} {}/{}", spot, sym_out, sym_in);
    println!();
    draw_impact_table(&rows, &token_in, &token_out, &sym_in, &sym_out);
    println!();
    let max = analyzer.find_max_size_for_impact(&token_in, Decimal::new(1, 2)).map_err(|e| e.to_string())?;
    println!("\nMax trade for 1% impact: {} {}", human(max, token_in.decimals()), sym_in);

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        if e.contains("overflow") {
            eprintln!("hint: use smaller --sizes (e.g. 1,10,100 for 18-decimal tokens like WETH)");
        }
        std::process::exit(1);
    }
}
