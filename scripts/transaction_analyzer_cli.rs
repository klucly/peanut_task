//! CLI to analyze a transaction. Usage: chain_analyzer <TX_HASH> [--rpc URL]
//! Needs INFURA_API_KEY, RPC_URL, or --rpc.

use std::env;

use peanut_task::chain::{ChainClient, RpcUrl};
use peanut_task::core::base_types::{Address, TokenAmount, Transaction};

const TRANSFER_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const SELECTOR_DECIMALS: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];
const SELECTOR_SYMBOL: [u8; 4] = [0x95, 0xd8, 0x9b, 0x41];

fn format_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*c);
    }
    out
}

fn format_u128_with_commas(n: u128) -> String {
    let s = n.to_string();
    let mut out = String::new();
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*c);
    }
    out
}

/// Unix timestamp → "YYYY-MM-DD HH:MM:SS" in UTC.
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

fn gwei(n: u64) -> String {
    let whole = n / 1_000_000_000;
    let frac = n % 1_000_000_000;
    if frac == 0 {
        format!("{} gwei", format_num(whole))
    } else {
        format!("{}.{} gwei", format_num(whole), frac / 100_000_000)
    }
}

fn human_raw(raw: u128, decimals: u8) -> String {
    let div = 10u128.pow(decimals as u32);
    let i = raw / div;
    let f = raw % div;
    if f == 0 {
        return format_num(i as u64);
    }
    let fs = format!("{:0>width$}", f, width = decimals as usize);
    let fs = fs.trim_end_matches('0');
    format!("{}.{}", format_num(i as u64), fs)
}

fn parse_args() -> Result<(String, Option<String>), String> {
    let args: Vec<String> = env::args().collect();
    let mut tx_hash = None;
    let mut rpc = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rpc" => {
                i += 1;
                rpc = args.get(i).cloned();
                i += 1;
            }
            s if s.starts_with("0x") && s.len() >= 66 => {
                tx_hash = Some(s.to_string());
                i += 1;
            }
            _ => i += 1,
        }
    }
    let tx_hash = tx_hash.ok_or("missing tx hash (0x...)")?;
    Ok((tx_hash, rpc))
}

fn rpc_url(rpc_override: Option<String>) -> Result<RpcUrl, String> {
    if let Some(url) = rpc_override {
        return RpcUrl::new("{}", &url).map_err(|e| e.to_string());
    }
    if let Ok(url) = env::var("RPC_URL") {
        return RpcUrl::new("{}", &url).map_err(|e| e.to_string());
    }
    if let Ok(key) = env::var("INFURA_API_KEY") {
        if key.is_empty() || key == "apikey" {
            return Err("set INFURA_API_KEY, RPC_URL, or --rpc URL".to_string());
        }
        return RpcUrl::new("https://mainnet.infura.io/v3/{}", &key).map_err(|e| e.to_string());
    }
    Err("set INFURA_API_KEY, RPC_URL, or --rpc URL".to_string())
}

/// Known Uniswap V2 Router selectors for display.
fn selector_name(sel: &[u8]) -> Option<&'static str> {
    if sel.len() < 4 {
        return None;
    }
    match (sel[0], sel[1], sel[2], sel[3]) {
        (0x38, 0xed, 0x17, 0x39) => Some("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"),
        (0x88, 0x03, 0xdb, 0x0e) => Some("swapExactTokensForETH(uint256,uint256,address[],address,uint256)"),
        (0x7f, 0xff, 0xff, 0x02) => Some("swapExactETHForTokens(uint256,address[],address,uint256)"),
        (0x18, 0xcb, 0x30, 0x15) => Some("swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)"),
        _ => None,
    }
}

/// Decode ABI-encoded uint256 (32 bytes, big-endian).
fn decode_u256(data: &[u8], offset: usize) -> Option<u128> {
    if offset + 32 > data.len() {
        return None;
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&data[offset..offset + 32]);
    let mut v: u128 = 0;
    for b in &raw {
        v = v.wrapping_mul(256).wrapping_add(*b as u128);
    }
    Some(v)
}

/// Decode ABI-encoded address (32 bytes, last 20 bytes).
fn decode_address(data: &[u8], offset: usize) -> Option<String> {
    if offset + 32 > data.len() {
        return None;
    }
    let addr = &data[offset + 12..offset + 32];
    Some(format!("0x{}", hex::encode(addr)))
}

/// Decode swapExactTokensForTokens calldata: amountIn, amountOutMin, path offset, to, deadline.
fn decode_swap_exact_tokens_for_tokens(data: &[u8]) -> Vec<(String, String)> {
    let mut args = Vec::new();
    if data.len() < 4 + 32 * 5 {
        return args;
    }
    let d = &data[4..];
    let amount_in = decode_u256(d, 0).map(|v| format_u128_with_commas(v));
    let amount_out_min = decode_u256(d, 32).map(|v| format_u128_with_commas(v));
    let path_offset = decode_u256(d, 64).and_then(|o| Some(o as usize));
    let to = path_offset.and_then(|_| decode_address(d, 96));
    let deadline = decode_u256(d, 128).map(|v| v.to_string());

    if let Some(a) = amount_in {
        args.push(("amountIn".to_string(), a));
    }
    if let Some(a) = amount_out_min {
        args.push(("amountOutMin".to_string(), a));
    }
    if let Some(off) = path_offset {
        let path_len = decode_u256(d, off).map(|l| l as usize);
        if let Some(len) = path_len {
            let mut path_addrs = Vec::new();
            for i in 0..len {
                let addr = decode_address(d, off + 32 + i * 32);
                if let Some(a) = addr {
                    path_addrs.push(a);
                }
            }
            if !path_addrs.is_empty() {
                args.push(("path".to_string(), format!("[{}]", path_addrs.join(", "))));
            }
        }
    }
    if let Some(t) = to {
        args.push(("to".to_string(), t));
    }
    if let Some(t) = deadline {
        args.push(("deadline".to_string(), t));
    }
    args
}

fn run() -> Result<(), String> {
    let _ = dotenvy::dotenv();
    let (tx_hash, rpc_override) = parse_args()?;
    let rpc = rpc_url(rpc_override)?;
    let client = ChainClient::new(vec![rpc], 30, 3).map_err(|e| e.to_string())?;

    let tx = client.get_transaction(&tx_hash).map_err(|e| e.to_string())?;
    let receipt = client
        .get_receipt(&tx_hash)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "transaction not found or not yet mined".to_string())?;

    let chain_id = client.get_chain_id().map_err(|e| e.to_string())?;
    let block_meta = client
        .get_block(&receipt.block_number.to_string())
        .map_err(|e| e.to_string())
        .ok();
    let timestamp_str = block_meta
        .map(|b| format_timestamp_utc(b.timestamp))
        .unwrap_or_else(|| "—".to_string());

    println!("Transaction Analysis");
    println!("====================");
    println!("Hash:           {}", receipt.tx_hash);
    println!("Block:          {}", format_num(receipt.block_number));
    println!("Timestamp:      {} UTC", timestamp_str);
    println!("Status:         {}", if receipt.status { "SUCCESS" } else { "FAILED" });
    println!();
    println!(
        "From:           {}",
        tx.from.as_ref().map(|a| a.value.as_str()).unwrap_or("—")
    );
    println!("To:             {}", tx.to.value);
    println!("Value:          {} ETH", tx.value.human());
    println!();
    println!("Gas Analysis");
    println!("------------");
    let gas_limit = tx.gas_limit.unwrap_or(0);
    println!("Gas Limit:      {}", format_num(gas_limit));
    let pct = if gas_limit > 0 {
        (receipt.gas_used as f64 / gas_limit as f64) * 100.0
    } else {
        0.0
    };
    println!(
        "Gas Used:       {} ({:.2}%)",
        format_num(receipt.gas_used),
        pct
    );
    let base_fee = tx.max_fee_per_gas.map(|m| m.saturating_sub(tx.max_priority_fee.unwrap_or(0)));
    println!(
        "Base Fee:       {}",
        base_fee.map(gwei).unwrap_or_else(|| "—".to_string())
    );
    println!(
        "Priority Fee:   {}",
        tx.max_priority_fee
            .map(gwei)
            .unwrap_or_else(|| "—".to_string())
    );
    println!("Effective Price: {} gwei", receipt.effective_gas_price / 1_000_000_000);
    let fee = receipt.tx_fee();
    println!("Transaction Fee: {} ETH (— USD)", fee.human());
    println!();

    println!("Function Called");
    println!("---------------");
    let selector = if tx.data.len() >= 4 {
        format!("0x{}", hex::encode(&tx.data[0..4]))
    } else {
        "—".to_string()
    };
    println!("Selector:       {}", selector);
    let name = tx
        .data
        .get(0..4)
        .and_then(|s| selector_name(s))
        .unwrap_or("(unknown)");
    println!("Function:       {}", name);
    if tx.data.len() > 4 {
        let args: Vec<(String, String)> = if tx
            .data
            .get(0..4)
            .map_or(false, |s| selector_name(s).is_some())
        {
            decode_swap_exact_tokens_for_tokens(&tx.data)
        } else {
            Vec::new()
        };
        if !args.is_empty() {
            println!("Arguments:");
            for (k, v) in args {
                println!("  - {}: {}", k, v);
            }
        }
    }
    println!();

    println!("Token Transfers");
    println!("---------------");
    let block_str = receipt.block_number.to_string();
    let mut transfer_logs: Vec<(Address, String, String, u128, u8, String)> = Vec::new();
    for log in &receipt.logs {
        if log.topics.first().map(|s| s.as_str()) != Some(TRANSFER_TOPIC) || log.topics.len() < 3 {
            continue;
        }
        let from = decode_log_address(log.topics.get(1).unwrap());
        let to = decode_log_address(log.topics.get(2).unwrap());
        let amount = decode_log_u256(&log.data).unwrap_or(0);
        let (decimals, symbol) = fetch_token_meta(&client, &log.address, &block_str, chain_id)?;
        transfer_logs.push((log.address.clone(), from, to, amount, decimals, symbol));
    }
    for (i, (_addr, from, to, amount, decimals, symbol)) in transfer_logs.iter().enumerate() {
        let human = human_raw(*amount, *decimals);
        println!(
            "{}. {}: {} → {}  {} {}",
            i + 1,
            symbol,
            shorten(from),
            shorten(to),
            human,
            symbol
        );
    }
    if transfer_logs.is_empty() {
        println!("(none)");
    }
    println!();

    println!("Swap Summary");
    println!("------------");
    if transfer_logs.len() >= 2 {
        let (_, _, _, amt0, dec0, sym0) = &transfer_logs[0];
        let (_, _, _, amt1, dec1, sym1) = &transfer_logs[1];
        let sold = human_raw(*amt0, *dec0);
        let received = human_raw(*amt1, *dec1);
        println!("Sold:           {} {}", sold, sym0);
        println!("Received:       {} {}", received, sym1);
        let exec_price = if *amt1 > 0 {
            let n = (*amt0 as f64) / 10f64.powi(*dec0 as i32);
            let d = (*amt1 as f64) / 10f64.powi(*dec1 as i32);
            if d > 0.0 {
                format!("{:.2} {}/{}", n / d, sym0, sym1)
            } else {
                "—".to_string()
            }
        } else {
            "—".to_string()
        };
        println!("Execution Price: {}", exec_price);
    } else {
        println!("—");
    }

    Ok(())
}

fn decode_log_address(topic: &str) -> String {
    let hex_part = topic.strip_prefix("0x").unwrap_or(topic);
    let hex_part = if hex_part.len() >= 64 {
        &hex_part[hex_part.len() - 40..]
    } else {
        hex_part
    };
    format!("0x{}", hex_part)
}

fn decode_log_u256(data: &str) -> Option<u128> {
    let hex_part = data.strip_prefix("0x").unwrap_or(data);
    let bytes = hex::decode(hex_part).ok()?;
    decode_u256(&bytes, 0)
}

fn shorten(addr: &str) -> String {
    if addr.len() <= 10 {
        return addr.to_string();
    }
    format!("{}...{}", &addr[..6], &addr[addr.len() - 4..])
}

fn fetch_token_meta(
    client: &ChainClient,
    token_addr: &Address,
    block: &str,
    chain_id: u64,
) -> Result<(u8, String), String> {
    let decimals = fetch_decimals(client, token_addr, block, chain_id)?;
    let symbol = fetch_symbol(client, token_addr, block, chain_id).unwrap_or_else(|_| {
        format!("Token({})", shorten(&token_addr.value))
    });
    Ok((decimals, symbol))
}

fn fetch_decimals(
    client: &ChainClient,
    token_addr: &Address,
    block: &str,
    chain_id: u64,
) -> Result<u8, String> {
    let tx = Transaction {
        from: None,
        to: token_addr.clone(),
        value: TokenAmount::native_eth(0),
        data: SELECTOR_DECIMALS.to_vec(),
        nonce: None,
        gas_limit: None,
        max_fee_per_gas: None,
        max_priority_fee: None,
        chain_id,
    };
    let out = client.call(&tx, block).map_err(|e| e.to_string())?;
    if out.len() >= 32 {
        let low = out[31];
        Ok(low)
    } else {
        Ok(18)
    }
}

fn fetch_symbol(
    client: &ChainClient,
    token_addr: &Address,
    block: &str,
    chain_id: u64,
) -> Result<String, String> {
    let tx = Transaction {
        from: None,
        to: token_addr.clone(),
        value: TokenAmount::native_eth(0),
        data: SELECTOR_SYMBOL.to_vec(),
        nonce: None,
        gas_limit: None,
        max_fee_per_gas: None,
        max_priority_fee: None,
        chain_id,
    };
    let out = client.call(&tx, block).map_err(|e| e.to_string())?;
    if out.len() >= 32 {
        let offset = decode_u256(&out, 0).unwrap_or(0) as usize;
        if offset + 32 <= out.len() {
            let len = decode_u256(&out, offset).unwrap_or(0) as usize;
            if offset + 32 + len <= out.len() {
                let bytes = &out[offset + 32..offset + 32 + len];
                let s = String::from_utf8_lossy(bytes);
                return Ok(s.trim_matches('\0').to_string());
            }
        }
    }
    Err("invalid symbol response".to_string())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
