use std::env;

use rust_decimal::Decimal;
use tokio::signal;
use peanut_task::{
    ExchangeClient, ExchangeConfig, InventoryTracker, Venue,
    chain::{ChainClient, RpcUrl},
    core::utility::Address,
    pricing::{Chain, PricingEngine},
    strategy::ExecutorConfig,
    ArbBot, BotConfig, GeneratorConfig, ScorerConfig, FeeStructure,
};
fn main() {
    // Initialize environment and logging
    dotenvy::dotenv().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let mut pairs = vec!["ETH/USDT".to_string()];
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
                    min_score = args[i + 1].parse::<f64>()
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

    // Initialize RPC client (blocking)
    let infura_key = env::var("INFURA_API_KEY").expect("INFURA_API_KEY not set");
    let rpc_urls = vec![
        RpcUrl::new("https://mainnet.infura.io/v3/{}", &infura_key).unwrap()
    ];
    let chain_client = ChainClient::new(rpc_urls, 30, 3).unwrap();

    // Initialize pricing engine (blocking)
    let mut pricing_engine = PricingEngine::new(
        chain_client,
        "http://127.0.0.1:8545",
        "ws://127.0.0.1:8546",
        Chain::EthereumMainnet,
        Some(Address::from_string("0x0000000000000000000000000000000000000000").unwrap()),
    ).expect("Failed to create pricing engine");

    // Load pools (blocking)
    let pair_address = Address::from_string("0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852").unwrap();
    pricing_engine.load_pools(&[pair_address])
        .expect("Failed to load pools");

    // Initialize exchange client (blocking)
    let exchange_config = ExchangeConfig::from_env()
        .expect("Failed to load exchange config");
    let exchange = ExchangeClient::new(exchange_config)
        .expect("Failed to create exchange client");

    // Initialize inventory tracker (blocking)
    let inventory = InventoryTracker::new(vec![Venue::Binance, Venue::Wallet])
        .expect("Failed to create inventory tracker");

    // Initialize fee structure
    let fee_structure = FeeStructure::default();

    // Create bot configuration
    let executor_config = ExecutorConfig::new(
        10,  // leg1_timeout_secs
        10,  // leg2_timeout_secs
        Decimal::try_from(0.98).unwrap(),  // min_fill_ratio
        false,  // use_flashbots
        simulation_mode,
    );
    
    let bot_config = BotConfig::new(
        pairs.clone(),
        tick_interval,
        min_score,
        simulation_mode,
        GeneratorConfig::default(),
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

    // Create bot
    let mut bot = ArbBot::new(
        exchange,
        pricing_engine,
        inventory,
        fee_structure,
        bot_config,
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
    println!("  --live                       Run in live trading mode");
    println!("  --min-score <SCORE>          Minimum score threshold (default: 60)");
    println!("  --tick-interval <SECS>       Tick interval in seconds (default: 1)");
    println!("  -h, --help                   Print this help message");
    println!();
    println!("Examples:");
    println!("  {} --pairs ETH/USDT --simulation", program);
    println!("  {} --pairs ETH/USDT BTC/USDT --min-score 70", program);
}
