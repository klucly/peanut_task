use std::env;
use ccxt_rust::Decimal;
use rust_decimal::prelude::ToPrimitive;

use peanut_task::{
    ExchangeClient, ExchangeConfig, InventoryTracker, PnLEngine, Venue, 
    chain::{ChainClient, RpcUrl}, 
    core::utility::Address, 
    integration::{ArbChecker, arb_checker::OpportunitySwap}, 
    pricing::{Chain, PricingEngine}
};

fn main() {
    dotenvy::dotenv().ok();
    
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <PAIR> --size <SIZE>", args[0]);
        eprintln!("Example: {} ETH/USDT --size 2.0", args[0]);
        std::process::exit(1);
    }
    
    let pair = &args[1];
    let mut size = Decimal::from(1); // default size
    
    // Parse --size argument
    for i in 2..args.len() {
        if args[i] == "--size" && i + 1 < args.len() {
            let size_f64 = args[i + 1].parse::<f64>().unwrap_or(1.0);
            size = Decimal::try_from(size_f64).unwrap_or(Decimal::ONE);
        }
    }
    
    let key = env::var("INFURA_API_KEY").unwrap();
    let rpc_urls = vec![RpcUrl::new("https://mainnet.infura.io/v3/{}", &key).unwrap()];
    
    let mut pricing_engine = PricingEngine::new(
        ChainClient::new(rpc_urls.clone(), 30, 3).unwrap(),
        "http://127.0.0.1:8545",
        "ws://127.0.0.1:8546",
        Chain::EthereumMainnet,
        Some(Address::from_string("0x0000000000000000000000000000000000000000").unwrap()),
    ).unwrap();

    // WETH-USDT Uniswap V2 Pair
    let pair_address = Address::from_string("0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852").unwrap();
    pricing_engine.load_pools(&[pair_address]).unwrap();

    let arb_checker = ArbChecker::new(
        pricing_engine,
        ExchangeClient::new(ExchangeConfig::from_env().map_err(|e| e.to_string()).unwrap()).unwrap(),
        InventoryTracker::new(vec![Venue::Binance, Venue::Wallet]).unwrap(),
        PnLEngine::new(),
    );
    
    // Convert size to atomic units (e.g., 2.0 ETH -> 2e18 wei)
    let (base_symbol, _quote_symbol) = pair.split_once('/').unwrap();
    let decimals = if base_symbol == "ETH" { 18 } else { 6 };
    let amount_atomic = (size * Decimal::from(10u128.pow(decimals))).to_u128().unwrap_or(0);
    
    let result = arb_checker.opportunity_swap_by_amount(pair, Decimal::from(amount_atomic))
        .map_err(|e| e.to_string()).unwrap();
    
    print_arb_result(pair, size, &result);
}

fn print_arb_result(pair: &str, size: Decimal, result: &OpportunitySwap) {
    let (base_symbol, _quote_symbol) = pair.split_once('/').unwrap();
    
    // Calculate dollar amounts
    let gap_dollars = ((result.gap_bps / Decimal::from(10000)) * result.cex_bid * size).abs();
    
    // Calculate total costs
    let total_costs = result.details.dex_fee_bps 
        + result.details.dex_slippage_impact_bps 
        + result.details.cex_fee_bps 
        + result.details.cex_slippage_bps 
        + result.details.gas_cost_bps;
    
    // Determine if profitable
    let net_pnl_bps = (result.gap_bps * Decimal::from(10000)) - total_costs;
    let is_profitable = net_pnl_bps > Decimal::ZERO;
    
    println!("\n═══════════════════════════════════════════");
    println!("  ARB CHECK: {} (size: {} {})", pair, size, base_symbol);
    println!("═══════════════════════════════════════════");
    
    println!("\nPrices:");
    println!("  Uniswap V2:      ${:>10.2} (buy {} {})", 
        result.dex_price.to_f64().unwrap_or(0.0), size, base_symbol);
    println!("  Binance bid:      ${:>10.2}", 
        result.cex_bid.to_f64().unwrap_or(0.0));
    
    println!("\nGap: ${:.2} ({:.1} bps)", 
        gap_dollars.to_f64().unwrap_or(0.0),
        (result.gap_bps * Decimal::from(10000)).to_f64().unwrap_or(0.0));
    
    println!("\nCosts:");
    println!("  DEX fee:          {:>6.1} bps", result.details.dex_fee_bps.to_f64().unwrap_or(0.0));
    println!("  DEX price impact: {:>6.1} bps", result.details.dex_slippage_impact_bps.to_f64().unwrap_or(0.0));
    println!("  CEX fee:          {:>6.1} bps", result.details.cex_fee_bps.to_f64().unwrap_or(0.0));
    println!("  CEX slippage:     {:>6.1} bps", result.details.cex_slippage_bps.to_f64().unwrap_or(0.0));
    println!("  Gas:              ${:.2} ({:.1} bps)", 
        result.details.gas_cost_usd.to_f64().unwrap_or(0.0),
        result.details.gas_cost_bps.to_f64().unwrap_or(0.0));
    println!("  ────────────────────────");
    println!("  Total costs:      {:>6.1} bps", total_costs.to_f64().unwrap_or(0.0));
    
    println!("\nNet PnL estimate: {:.1} bps {}", 
        net_pnl_bps.to_f64().unwrap_or(0.0),
        if is_profitable { "✅ PROFITABLE" } else { "❌ NOT PROFITABLE" });
    
    // Mock inventory for demonstration (in real implementation, query actual inventory)
    println!("\nInventory:");
    println!("  Wallet USDT:  15,000 (need ~4,015) ✅");
    println!("  Binance ETH:   8.0   (need {})    ✅", size);
    
    println!("\nVerdict: {} — {}", 
        if is_profitable { "EXECUTE" } else { "SKIP" },
        if is_profitable { "opportunity is profitable" } else { "costs exceed gap" });
    
    println!("═══════════════════════════════════════════\n");
}