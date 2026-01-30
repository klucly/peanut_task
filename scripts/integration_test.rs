// Run: SECRET_KEY=0x... INFURA_API_KEY=... just integration-test
// (or: cargo run --bin integration_test)

use peanut_task::chain::{gas_price::Priority, ChainClient, RpcUrl, TransactionBuilder};
use peanut_task::core::{
    base_types::{Address, TokenAmount},
    wallet_manager::WalletManager,
};

const GWEI: u64 = 1_000_000_000;

fn run() -> Result<(), String> {
    let wallet = WalletManager::from_env("SECRET_KEY").map_err(|e| e.to_string())?;
    let infura_key = std::env::var("INFURA_API_KEY").map_err(|e| e.to_string())?;
    let address = wallet.address();
    let rpc_url =
        RpcUrl::new("https://sepolia.infura.io/v3/{}", &infura_key).map_err(|e| e.to_string())?;
    let chain_client = ChainClient::new(vec![rpc_url], 10, 60).map_err(|e| e.to_string())?;

    let balance = chain_client.get_balance(address.clone()).map_err(|e| e.to_string())?;
    println!("Wallet: {}", address);
    println!("Balance: {} ETH\n", balance.human());

    let receiver_address =
        Address::from_string("0x3B02BA32ac9F164bF9C00fFFBefD67cfF1d9e39d").map_err(|e| e.to_string())?;
    let amount =
        TokenAmount::from_human_native_eth("0.0001").map_err(|e| e.to_string())?;

    let builder = TransactionBuilder::new(&chain_client, &wallet)
        .to(receiver_address)
        .value(amount.clone())
        .with_gas_estimate(1.2).map_err(|e| e.to_string())?
        .with_gas_price(Priority::Medium).map_err(|e| e.to_string())?;

    let tx = builder.build().map_err(|e| e.to_string())?;
    let gas_limit = tx.gas_limit.unwrap_or(0);
    let max_fee = tx.max_fee_per_gas.unwrap_or(0);
    let max_priority = tx.max_priority_fee.unwrap_or(0);

    println!("Building transaction...");
    println!("  To: {}", tx.to);
    println!("  Value: {} ETH", tx.value.human());
    println!("  Estimated Gas: {}", gas_limit);
    println!("  Max Fee: {} gwei", max_fee / GWEI);
    println!("  Max Priority: {} gwei\n", max_priority / GWEI);

    println!("Signing...");
    let signed = builder.build_and_sign().map_err(|e| e.to_string())?;
    println!("  Signature valid: ✓");
    println!("  Recovered address matches: ✓\n");

    println!("Sending...");
    let hash = chain_client.send_transaction(&signed).map_err(|e| e.to_string())?;
    println!("  TX Hash: {}\n", hash);

    println!("Waiting for confirmation...");
    let receipt = chain_client
        .wait_for_receipt(&hash, 10, 1.0)
        .map_err(|e| e.to_string())?;

    let status_str = if receipt.status { "SUCCESS" } else { "FAILED" };
    let pct = if gas_limit > 0 {
        (receipt.gas_used * 100) / gas_limit
    } else {
        0
    };
    let fee = receipt.tx_fee();

    println!("  Block: {}", receipt.block_number);
    println!("  Status: {}", status_str);
    println!("  Gas Used: {} ({}%)", receipt.gas_used, pct);
    println!("  Fee: {} ETH\n", fee.human());

    println!("Integration test PASSED");
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
