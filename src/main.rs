use std::env;
mod core;
mod chain;

fn main() {
    dotenvy::dotenv().ok();
    
    // Demonstrate multiple RPC URLs for failover
    let mut rpc_urls = vec![];
    if let Ok(infura_key) = env::var("INFURA_API_KEY") {
        rpc_urls.push(
            chain::RpcUrl::new("https://mainnet.infura.io/v3/{}", &infura_key)
                .expect("Failed to create Infura RPC URL")
        );
    }
    if let Ok(alchemy_key) = env::var("ALCHEMY_API_KEY") {
        rpc_urls.push(
            chain::RpcUrl::new("https://eth-mainnet.g.alchemy.com/v2/{}", &alchemy_key)
                .expect("Failed to create Alchemy RPC URL")
        );
    }
    
    if rpc_urls.is_empty() {
        eprintln!("Warning: No RPC URLs configured. Using fallback.");
        rpc_urls.push(
            chain::RpcUrl::new("https://mainnet.infura.io/v3/{}", "demo")
                .expect("Failed to create fallback RPC URL")
        );
    }
    
    let chain_client = chain::chain_client::ChainClient::new(rpc_urls, 10, 1)
        .expect("Failed to create ChainClient: invalid or unreachable RPC URLs");
    
    let address = core::base_types::Address::from_string("0xB028b84783A0381D51Dcf0e8ef04b5e502958618").unwrap();
    let balance = chain_client.get_balance(address.clone()).unwrap();
    println!("Balance: {}", balance.human());
    
    let nonce_pending = chain_client.get_nonce(address.clone(), "pending").unwrap();
    let nonce_latest = chain_client.get_nonce(address.clone(), "latest").unwrap();
    let nonce_earliest = chain_client.get_nonce(address.clone(), "earliest").unwrap();
    println!("Nonce - pending: {}, latest: {}, earliest: {}", nonce_pending, nonce_latest, nonce_earliest);
    
    let gas_price = chain_client.get_gas_price().unwrap();
    let max_fee_low = gas_price.get_max_fee(chain::gas_price::Priority::Low, 1.2);
    let max_fee_medium = gas_price.get_max_fee(chain::gas_price::Priority::Medium, 1.2);
    let max_fee_high = gas_price.get_max_fee(chain::gas_price::Priority::High, 1.2);
    println!("Gas - base: {} gwei, max fees - low: {} gwei, medium: {} gwei, high: {} gwei", 
        gas_price.base_fee / 1_000_000_000,
        max_fee_low / 1_000_000_000,
        max_fee_medium / 1_000_000_000,
        max_fee_high / 1_000_000_000);
    
    let to_address = core::base_types::Address::from_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0").unwrap();

    let wallet = core::wallet_manager::WalletManager::from_hex_string(
        "0x0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let built_tx = chain::TransactionBuilder::new(&chain_client, &wallet)
        .to(to_address.clone())
        .value(core::base_types::TokenAmount::from_human("0.001", 18, None).unwrap())
        .with_gas_estimate(1.2)
        .unwrap()
        .with_gas_price(chain::gas_price::Priority::Medium)
        .unwrap()
        .build()
        .unwrap();
    println!(
        "TransactionBuilder: built tx to {}, value {}, gas_limit {:?}",
        built_tx.to,
        built_tx.value.human(),
        built_tx.gas_limit
    );

    let mut tx = core::base_types::Transaction {
        to: to_address.clone(),
        value: core::base_types::TokenAmount::new(1_000_000_000_000_000u128, 18, Some("ETH".to_string())),
        data: vec![],
        nonce: Some(nonce_latest),
        gas_limit: None,
        max_fee_per_gas: Some(max_fee_medium),
        max_priority_fee: Some(gas_price.priority_fee_medium),
        chain_id: 1,
    };
    let gas_estimate = chain_client.estimate_gas(&tx).unwrap();
    tx.gas_limit = Some(gas_estimate);
    println!("Gas estimate: {} units", gas_estimate);
    
    let simple_call_tx = core::base_types::Transaction {
        to: address.clone(),
        value: core::base_types::TokenAmount::new(0, 18, Some("ETH".to_string())),
        data: vec![],
        nonce: None,
        gas_limit: None,
        max_fee_per_gas: None,
        max_priority_fee: None,
        chain_id: 1,
    };
    match chain_client.call(&simple_call_tx, "latest") {
        Ok(result) => println!("Call result: {} bytes", result.len()),
        Err(e) => println!("Call error: {}", e),
    }
    
    // Try to get a transaction (may fail if hash doesn't exist or RPC format differs)
    let known_tx_hash = "0x7dc3fd13b5a3e4ed26fba67ad8faa765fbe7e9e38e503a73c71dbc3555144c56";
    match chain_client.get_transaction(known_tx_hash) {
        Ok(tx) => println!("Transaction: {} -> {}", tx.to, tx.value.human()),
        Err(e) => println!("Transaction lookup failed: {}", e),
    }
    
    // Try to get a receipt
    match chain_client.get_receipt(known_tx_hash) {
        Ok(Some(receipt)) => println!("Receipt: block {}, status: {}", receipt.block_number, if receipt.status { "success" } else { "failed" }),
        Ok(None) => println!("Receipt: not found"),
        Err(e) => println!("Receipt lookup failed: {}", e),
    }
    
    // Demonstrate send_transaction error handling with invalid data
    let invalid_signed_tx = core::base_types::SignedTransaction::from_raw("0x1234".to_string());
    if let Ok(signed_tx) = invalid_signed_tx {
        match chain_client.send_transaction(&signed_tx) {
            Ok(hash) => println!("Send transaction: {}", hash),
            Err(e) => println!("Send transaction (expected error): {}", e),
        }
    } else {
        println!("Send transaction: invalid format (expected)");
    }
}