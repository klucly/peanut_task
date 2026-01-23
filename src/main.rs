use std::env;
mod core;
mod chain;

fn main() {
    dotenvy::dotenv().ok();
    // let wallet_manager = core::wallet_manager::WalletManager::from_env("SECRET_KEY").unwrap();
    let rpc_urls = vec![chain::SafeUrl::new("https://mainnet.infura.io/v3/{}", &env::var("INFURA_API_KEY")
        .expect("INFURA_API_KEY environment variable not set")
    ).unwrap()];
    let chain_client = chain::chain_client::ChainClient::new(rpc_urls, 10, 1);
    let balance = chain_client.get_balance(core::base_types::Address::from_string("0x0000000000000000000000000000000000000000").unwrap()).unwrap();
    println!("Balance: {}", balance.human());
}