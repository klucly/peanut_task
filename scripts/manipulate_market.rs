use peanut_task::chain::{ChainClient, RpcUrl, TransactionBuilder, gas_price::Priority};
use peanut_task::core::{
    base_types::{Address, Token, TokenAmount},
    wallet_manager::WalletManager,
};
use peanut_task::pricing::uniswap_v2_pair::UniswapV2Pair;
use peanut_task::pricing::{ChainConfig, PricingEngine};
use rust_decimal::Decimal;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use tokio::runtime::Runtime;

// Anvil's default Account #0 private key
const ANVIL_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
// USDC/WETH pool address
const USDC_WETH_POOL: &str = "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc";

// WETH Mainnet
const WETH_ADDRESS: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
// USDC Mainnet
const USDC_ADDRESS: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

// Uniswap V2 Router 02
const UNISWAP_ROUTER: &str = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";

fn print_usage() {
    println!("Usage: manipulate_market [buy|sell] [amount_eth]");
    println!("  buy: Buy ETH with USDC (pushes ETH price UP)");
    println!("  sell: Sell ETH for USDC (pushes ETH price DOWN)");
    println!("  amount_eth: Amount of ETH to buy/sell (default: 100)");
}

fn main() {
    // Setup logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    let direction = &args[1];
    let amount_eth_str = if args.len() > 2 { &args[2] } else { "100" };
    let amount_eth = Decimal::from_str(amount_eth_str).unwrap_or(Decimal::from(100));

    // Connect to local fork
    // We append a dummy query param to satisfy the placeholder requirement without breaking the path.
    let rpc_url = RpcUrl::new("http://127.0.0.1:8545/?key={}", "dummy").expect("Invalid RPC URL");
    let chain_client =
        ChainClient::new(vec![rpc_url], 30, 3).expect("Failed to create chain client");

    // Setup wallet
    let wallet = WalletManager::from_hex_string(ANVIL_PRIVATE_KEY).expect("Invalid private key");
    let address = wallet.address();

    println!("Using wallet: {}", address);

    // Set balance to 100,000,000 ETH using anvil_setBalance (via curl)
    println!("Setting balance to 100,000,000 ETH...");
    let status = std::process::Command::new("curl")
        .arg("-s") // silent
        .arg("-H").arg("Content-Type: application/json")
        .arg("-d").arg(format!(r#"{{"jsonrpc":"2.0","method":"anvil_setBalance","params":["{}", "0x52b7d2dcc80cd2e4000000"],"id":1}}"#, address.value))
        .arg("http://127.0.0.1:8545")
        .output()
        .expect("Failed to execute curl");

    println!("Curl output: {:?}", String::from_utf8_lossy(&status.stdout));

    if !status.status.success() {
        eprintln!(
            "Failed to set balance: {:?}",
            String::from_utf8_lossy(&status.stderr)
        );
    }

    // Slight delay to ensure state update propagates?
    std::thread::sleep(std::time::Duration::from_millis(100));

    let balance = chain_client.get_balance(address.clone()).unwrap();
    println!("Start Balance: {} ETH", balance.human());

    let router_address = Address::from_string(UNISWAP_ROUTER).unwrap();
    let pair_addr = Address::from_string(USDC_WETH_POOL).unwrap();

    // Check reserves before
    let pair_before = UniswapV2Pair::from_chain(pair_addr.clone(), &chain_client).unwrap();
    println!(
        "Reserves Before: {} / {}",
        pair_before.reserve0, pair_before.reserve1
    );

    if direction == "sell" {
        println!("Selling {} ETH for USDC...", amount_eth);

        let self_addr_clean = address.value.replace("0x", "");
        // swapExactETHForTokens(amountOutMin, path, to, deadline)
        let calldata = format!(
            "7ff36ab5{:0>64}{:0>64}000000000000000000000000{}{:0>64}{:0>64}000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "0",  // amountOutMin
            "80", // path offset = 4 * 32 = 128 = 0x80
            self_addr_clean,
            "ffffffffffffffffffffffffffffffffffffffff", // deadline
            "2",                                        // path length
        );

        let calldata_bytes = hex::decode(calldata).expect("Failed to decode calldata");

        let amount_wei = amount_eth * Decimal::from(1_000_000_000_000_000_000u128);
        let amount_wei_u128: u128 = amount_wei.try_into().unwrap();

        let tx_builder = TransactionBuilder::new(&chain_client, &wallet)
            .to(router_address)
            .value(TokenAmount::native_eth(amount_wei_u128))
            .data(calldata_bytes)
            .gas_limit(500_000) // Manual gas limit
            .max_fee_per_gas_raw(300_000_000_000) // 300 gwei manual gas price
            .max_priority_fee_raw(20_000_000_000); // 20 gwei priority fee 

        let tx = tx_builder
            .build_and_sign()
            .expect("Failed to sign transaction");
        println!("Sending TX to Swap {} ETH for USDC...", amount_eth);
        let hash = chain_client
            .send_transaction(&tx)
            .expect("Failed to send transaction");
        println!("Swap TX: {}", hash);

        let receipt = chain_client
            .wait_for_receipt(&hash, 5, 1.0)
            .expect("Failed to wait for receipt");
        if receipt.status {
            println!("Swap SUCCESS. Price crashed.");
        } else {
            println!("Swap FAILED.");
        }

        // Check reserves after
        let pair_after = UniswapV2Pair::from_chain(pair_addr, &chain_client).unwrap();
        println!(
            "Reserves After:  {} / {}",
            pair_after.reserve0, pair_after.reserve1
        );
    } else if direction == "buy" {
        println!(
            "Buying ETH with USDC not implemented efficiently (requires approve + swap). Use 'sell' to crash ETH price."
        );
    }
}
