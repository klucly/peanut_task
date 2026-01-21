use std::env;
mod core;

fn main() {
    dotenvy::dotenv().ok();
    let wallet_manager = core::wallet_manager::WalletManager::from_env("SECRET_KEY").unwrap();
    println!("{:?}", wallet_manager);
}