use std::env;
mod core;
mod chain;

fn main() {
    dotenvy::dotenv().ok();
    let rpc_urls = vec![chain::RpcUrl::new("https://mainnet.infura.io/v3/{}", &env::var("INFURA_API_KEY")
        .expect("INFURA_API_KEY environment variable not set")
    ).unwrap()];
    let chain_client = chain::chain_client::ChainClient::new(rpc_urls, 10, 1)
        .expect("Failed to create ChainClient: invalid or unreachable RPC URLs");
    
    let address = core::base_types::Address::from_string("0xB028b84783A0381D51Dcf0e8ef04b5e502958618").unwrap();
    let balance = chain_client.get_balance(address.clone()).unwrap();
    println!("Balance: {}", balance.human());
    
    let nonce_pending = chain_client.get_nonce(address.clone(), "pending").unwrap();
    println!("Nonce (pending): {}", nonce_pending);
    
    let nonce_latest = chain_client.get_nonce(address.clone(), "latest").unwrap();
    println!("Nonce (latest): {}", nonce_latest);
    
    let gas_price = chain_client.get_gas_price().unwrap();
    println!("Gas Price Info:");
    println!("  Base fee: {} wei ({} gwei)", gas_price.base_fee, gas_price.base_fee / 1_000_000_000);
    println!("  Priority fee (low): {} wei ({} gwei)", gas_price.priority_fee_low, gas_price.priority_fee_low / 1_000_000_000);
    println!("  Priority fee (medium): {} wei ({} gwei)", gas_price.priority_fee_medium, gas_price.priority_fee_medium / 1_000_000_000);
    println!("  Priority fee (high): {} wei ({} gwei)", gas_price.priority_fee_high, gas_price.priority_fee_high / 1_000_000_000);
    
    let to_address = core::base_types::Address::from_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0").unwrap();
    let tx = core::base_types::Transaction {
        to: to_address,
        value: core::base_types::TokenAmount::new(1_000_000_000_000_000u128, 18, Some("ETH".to_string())), // 0.001 ETH
        data: vec![],
        nonce: None,
        gas_limit: None,
        max_fee_per_gas: None,
        max_priority_fee: None,
        chain_id: 1,
    };
    let gas_estimate = chain_client.estimate_gas(&tx).unwrap();
    println!("Gas Estimate: {} gas units", gas_estimate);
}