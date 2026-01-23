use std::env;
mod core;
mod chain;

fn main() {
    dotenvy::dotenv().ok();
    // let wallet_manager = core::wallet_manager::WalletManager::from_env("SECRET_KEY").unwrap();
    let rpc_urls = vec![chain::RpcUrl::new("https://mainnet.infura.io/v3/{}", &env::var("INFURA_API_KEY")
        .expect("INFURA_API_KEY environment variable not set")
    ).unwrap()];
    let chain_client = chain::chain_client::ChainClient::new(rpc_urls, 10, 1)
        .expect("Failed to create ChainClient: invalid or unreachable RPC URLs");
    
    // Test get_balance
    let address = core::base_types::Address::from_string("0xB028b84783A0381D51Dcf0e8ef04b5e502958618").unwrap();
    let balance = chain_client.get_balance(address.clone()).unwrap();
    println!("Balance: {}", balance.human());
    
    // Test get_nonce with "pending" block
    let nonce_pending = chain_client.get_nonce(address.clone(), "pending").unwrap();
    println!("Nonce (pending): {}", nonce_pending);
    
    // Test get_nonce with "latest" block
    let nonce_latest = chain_client.get_nonce(address.clone(), "latest").unwrap();
    println!("Nonce (latest): {}", nonce_latest);
}