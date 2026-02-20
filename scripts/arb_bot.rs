use std::env;
use std::sync::Arc;

use peanut_task::{
    ArbBot, BotConfig, ExchangeClient, ExchangeConfig, FeeStructure, GeneratorConfig,
    InventoryTracker, ScorerConfig, Venue,
    chain::{ChainClient, RpcUrl},
    core::utility::Address,
    pricing::{Chain, PricingEngine},
    strategy::{CircuitBreakerConfig, ExecutorConfig},
};
use rust_decimal::Decimal;
use tokio::signal;
fn main() {
    // Initialize environment and logging
    dotenvy::dotenv().ok();

    // Initialize tracing subscriber
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let mut pairs = vec!["ETH/USDC".to_string()];
    let mut simulation_mode = true;
    let mut min_score = Decimal::from(60);
    let mut tick_interval = 1u64;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--pairs" => {
                pairs.clear();
                i += 1;
                while i < args.len() && !args[i].starts_with("--") {
                    pairs.push(args[i].clone());
                    i += 1;
                }
                continue;
            }
            "--simulation" => {
                simulation_mode = true;
            }
            "--live" => {
                simulation_mode = false;
            }
            "--min-score" => {
                if i + 1 < args.len() {
                    min_score = args[i + 1]
                        .parse::<f64>()
                        .map(Decimal::try_from)
                        .ok()
                        .and_then(Result::ok)
                        .unwrap_or(Decimal::from(60));
                    i += 1;
                }
            }
            "--tick-interval" => {
                if i + 1 < args.len() {
                    tick_interval = args[i + 1].parse::<u64>().unwrap_or(1);
                    i += 1;
                }
            }
            "--help" | "-h" => {
                print_usage(&args[0]);
                return;
            }
            _ => {}
        }
        i += 1;
    }

    // Pricing URLs: from env or localhost default (Phase 3.1)
    let pricing_rpc_url = env::var("PRICING_RPC_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let pricing_ws_url = env::var("PRICING_WS_URL")
        .unwrap_or_else(|_| "ws://127.0.0.1:8545".to_string());

    // Load exchange config before building clients (needed for consistency guard)
    let exchange_config = ExchangeConfig::from_env().expect("Failed to load exchange config");

    // Mainnet/testnet consistency guard: fail fast if --live with testnet CEX or localhost pricing (Phase 1.2)
    if !simulation_mode {
        if exchange_config.sandbox {
            panic!(
                "Live mode requires mainnet CEX; set BINANCE_API_KEY and BINANCE_SECRET (not testnet keys)"
            );
        }
        let localhost_rpc = pricing_rpc_url.contains("127.0.0.1") || pricing_rpc_url.contains("localhost");
        let localhost_ws = pricing_ws_url.contains("127.0.0.1") || pricing_ws_url.contains("localhost");
        if localhost_rpc || localhost_ws {
            panic!(
                "Live mode requires non-localhost pricing RPC/WS; set PRICING_RPC_URL and PRICING_WS_URL"
            );
        }
    }

    // Initialize RPC client
    let rpc_urls = if simulation_mode {
        vec![RpcUrl::new("http://127.0.0.1:8545/?key={}", "dummy").expect("Invalid RPC URL")]
    } else {
        let infura_key = env::var("INFURA_API_KEY").expect("INFURA_API_KEY not set");
        vec![RpcUrl::new("https://mainnet.infura.io/v3/{}", &infura_key).unwrap()]
    };
    let chain_client = ChainClient::new(rpc_urls, 30, 3).unwrap();

    // Initialize pricing engine (blocking)
    let mut pricing_engine = PricingEngine::new(
        chain_client.clone(),
        &pricing_rpc_url,
        &pricing_ws_url,
        Chain::EthereumMainnet,
        Some(Address::from_string("0x0000000000000000000000000000000000000000").unwrap()),
    )
    .expect("Failed to create pricing engine");

    // Define token map (Symbol -> Address)
    // In a real bot this would be loaded from config file or token list API
    let mut token_map = std::collections::HashMap::new();
    token_map.insert(
        "ETH".to_string(),
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    ); // WETH
    token_map.insert(
        "WETH".to_string(),
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    );
    token_map.insert(
        "USDC".to_string(),
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    );
    token_map.insert(
        "USDT".to_string(),
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    );
    token_map.insert(
        "DAI".to_string(),
        "0x6B175474E89094C44Da98b954EedeAC495271d0F",
    );
    token_map.insert(
        "WBTC".to_string(),
        "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
    );

    let factory_address =
        Address::from_string("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f").unwrap();

    // Resolve pool addresses dynamically
    let mut pool_addresses = Vec::new();
    let mut valid_pairs = Vec::new();

    for pair_str in &pairs {
        if let Some((base, quote)) = pair_str.split_once('/') {
            let base_addr_str = token_map.get(base).or_else(|| token_map.get("WETH")); // Default to WETH if base is ETH
            let quote_addr_str = token_map.get(quote);

            if let (Some(base_addr), Some(quote_addr)) = (base_addr_str, quote_addr_str) {
                // Call Factory.getPair(tokenA, tokenB)
                // getPair selector: 0xe6a43905
                // input: address (pad to 32), address (pad to 32)

                // Construct call data manually or use a helper if available.
                // Since we don't have a generated ABI wrapper, constructing manually.
                let mut data = Vec::with_capacity(4 + 32 + 32);
                data.extend_from_slice(&hex::decode("e6a43905").unwrap());

                let t0 = Address::from_string(base_addr).unwrap();
                let t1 = Address::from_string(quote_addr).unwrap();

                // ABI Encode: pad addresses to 32 bytes
                let mut t0_pad = [0u8; 32];
                let t0_bytes = hex::decode(&t0.value[2..]).unwrap(); // Skip 0x
                t0_pad[12..32].copy_from_slice(&t0_bytes);

                let mut t1_pad = [0u8; 32];
                let t1_bytes = hex::decode(&t1.value[2..]).unwrap(); // Skip 0x
                t1_pad[12..32].copy_from_slice(&t1_bytes);

                data.extend_from_slice(&t0_pad);
                data.extend_from_slice(&t1_pad);

                let tx = peanut_task::core::base_types::Transaction {
                    from: None,
                    to: factory_address.clone(),
                    value: peanut_task::core::base_types::TokenAmount::native_eth(0),
                    data,
                    nonce: None,
                    gas_limit: None,
                    max_fee_per_gas: None,
                    max_priority_fee: None,
                    chain_id: 1,
                };

                match chain_client.call(&tx, "latest") {
                    Ok(result) => {
                        if result.len() >= 32 {
                            let addr_bytes = &result[12..32];
                            let pair_address =
                                Address::from_string(&format!("0x{}", hex::encode(addr_bytes)))
                                    .unwrap();

                            if pair_address
                                != Address::from_string(
                                    "0x0000000000000000000000000000000000000000",
                                )
                                .unwrap()
                            {
                                log::info!("Found pool for {}: {}", pair_str, pair_address);
                                pool_addresses.push(pair_address);
                                valid_pairs.push(pair_str.clone());
                            } else {
                                log::warn!("Factory returned zero address for {}", pair_str);
                            }
                        }
                    }
                    Err(e) => log::error!("Failed to resolve pool for {}: {}", pair_str, e),
                }
            } else {
                log::warn!("Unknown token in pair {}", pair_str);
            }
        }
    }

    if pool_addresses.is_empty() {
        log::error!("No valid pools found. Exiting.");
        return;
    }

    // Load pools (blocking)
    pricing_engine
        .load_pools(&pool_addresses)
        .expect("Failed to load pools");

    // Initialize exchange client (blocking)
    let exchange = ExchangeClient::new(exchange_config.clone()).expect("Failed to create exchange client");

    // Initialize inventory tracker (blocking)
    let inventory = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet])
        .expect("Failed to create inventory tracker");

    // Initialize fee structure
    let fee_structure = FeeStructure::default();

    // Circuit breaker: optional env vars (all three must be set to override defaults)
    let circuit_breaker = match (
        env::var("CIRCUIT_FAILURE_THRESHOLD").ok().and_then(|s| s.parse::<u32>().ok()),
        env::var("CIRCUIT_WINDOW_SECS").ok().and_then(|s| s.parse::<f64>().ok()),
        env::var("CIRCUIT_COOLDOWN_SECS").ok().and_then(|s| s.parse::<f64>().ok()),
    ) {
        (Some(threshold), Some(window), Some(cooldown)) => {
            Some(CircuitBreakerConfig::new(threshold, window, cooldown))
        }
        _ => None,
    };

    // CEX and DEX slippage from env (optional)
    let cex_slippage_bps = env::var("CEX_SLIPPAGE_BPS")
        .ok()
        .and_then(|s| s.parse::<u16>().ok());
    let dex_slippage_bps = env::var("DEX_SLIPPAGE_BPS")
        .ok()
        .and_then(|s| s.parse::<u16>().ok());

    // Create bot configuration
    let executor_config = ExecutorConfig::new(
        10,                               // leg1_timeout_secs
        10,                               // leg2_timeout_secs
        Decimal::try_from(0.98).unwrap(), // min_fill_ratio
        false,                            // use_flashbots
        simulation_mode,
        circuit_breaker,
        dex_slippage_bps,
        cex_slippage_bps,
    );

    // Generator limits from env (Phase 5.2)
    let generator_min_profit_usd = env::var("GENERATOR_MIN_PROFIT_USD")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .map(Decimal::try_from)
        .and_then(Result::ok)
        .unwrap_or(Decimal::from(5));
    let generator_max_position_usd = env::var("GENERATOR_MAX_POSITION_USD")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .map(Decimal::try_from)
        .and_then(Result::ok)
        .unwrap_or(Decimal::from(10_000));
    let generator_signal_ttl_secs = env::var("GENERATOR_SIGNAL_TTL_SECS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(5);
    let generator_cooldown_secs = env::var("GENERATOR_COOLDOWN_SECS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(2);
    let generator_config = GeneratorConfig::new(
        generator_min_profit_usd,
        generator_max_position_usd,
        generator_signal_ttl_secs,
        generator_cooldown_secs,
    );

    let bot_config = BotConfig::new(
        valid_pairs,
        tick_interval,
        min_score,
        simulation_mode,
        generator_config,
        ScorerConfig::default(),
        executor_config,
    );

    log::info!("═══════════════════════════════════════════");
    log::info!("  Arbitrage Bot Configuration");
    log::info!("═══════════════════════════════════════════");
    log::info!("Pairs: {:?}", pairs);
    log::info!("Simulation mode: {}", simulation_mode);
    log::info!("Min score threshold: {}", min_score);
    log::info!("Tick interval: {}s", tick_interval);
    log::info!("═══════════════════════════════════════════");

    // Initialize wallet: in live mode ETH_PRIVATE_KEY is required (no default).
    let wallet_key = if simulation_mode {
        env::var("ETH_PRIVATE_KEY").unwrap_or_else(|_| {
            // Default Anvil key (Account 0) for simulation only
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string()
        })
    } else {
        env::var("ETH_PRIVATE_KEY").expect("ETH_PRIVATE_KEY must be set in live mode (--live)")
    };
    let wallet_manager =
        peanut_task::core::wallet_manager::WalletManager::from_hex_string(&wallet_key)
            .expect("Invalid private key");
    let wallet_address = wallet_manager.address();
    tracing::info!("Bot Wallet Address: {}", wallet_address);

    // Token map for DEX executor (symbol -> Address)
    let dex_token_map: std::collections::HashMap<String, Address> = token_map
        .iter()
        .map(|(k, v)| (k.clone(), Address::from_string(v).expect("token address")))
        .collect();

    // Create bot (pass wallet and token map for real DEX when in live mode)
    let mut bot = ArbBot::new(
        exchange,
        pricing_engine,
        inventory,
        fee_structure,
        bot_config,
        chain_client.clone(),
        wallet_address,
        Some(Arc::new(wallet_manager)),
        Some(dex_token_map),
    );

    // Setup Ctrl+C handler
    let stop_handle = bot.stop_handle();

    // Create runtime for async execution
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // Spawn Ctrl+C handler in the runtime
    rt.spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        log::info!("Received Ctrl+C, stopping bot...");
        stop_handle.store(false, std::sync::atomic::Ordering::SeqCst);
    });

    // Run the bot
    bot.run();
}
fn print_usage(program: &str) {
    println!("Usage: {} [OPTIONS]", program);
    println!();
    println!("Options:");
    println!("  --pairs <PAIR1> <PAIR2> ...  Trading pairs to monitor (default: ETH/USDT)");
    println!("  --simulation                 Run in simulation mode (default)");
    println!("  --live                       Run in live trading mode (requires ETH_PRIVATE_KEY)");
    println!("  --min-score <SCORE>          Minimum score threshold (default: 60)");
    println!("  --tick-interval <SECS>       Tick interval in seconds (default: 1)");
    println!("  -h, --help                   Print this help message");
    println!();
    println!("Examples:");
    println!("  {} --pairs ETH/USDT --simulation", program);
    println!("  {} --pairs ETH/USDT BTC/USDT --min-score 70", program);
}
