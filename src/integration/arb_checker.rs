use ccxt_rust::Decimal;
use rust_decimal::prelude::{ToPrimitive, FromPrimitive};
use time::OffsetDateTime;
use std::sync::{Arc, Mutex};

use crate::OrderBookAnalyzer;
use crate::OrderSide;
use crate::core::base_types::TokenAmount;
use crate::pricing::PriceImpactAnalyzer;
use crate::pricing::PricingEngine;
use crate::exchange::ExchangeClient;
use crate::inventory::{InventoryTracker, Venue};
use crate::inventory::PnLEngine;
use crate::pricing::UniswapV2Pair;
use thiserror::Error;


#[derive(Clone, Debug)]
pub enum ExchangeTypeDirection {
    BuyCexSellDex,
    BuyDexSellCex,
}

#[derive(Clone, Debug)]
pub struct OpportunitySwap {
    pub pair: String,
    pub timestamp: OffsetDateTime,
    pub amount: Decimal,
    pub dex_price: Decimal,
    pub cex_bid: Decimal,
    pub cex_ask: Decimal,
    pub gap_bps: Decimal,
    pub direction: ExchangeTypeDirection,
    pub estimated_costs_bps: Decimal,
    pub estimated_net_pnl_bps: Decimal,
    pub inventory_ok: bool,
    pub executable: bool,
    pub details: OpportunitySwapDetails,
}

#[derive(Clone, Debug)]
pub struct OpportunitySwapDetails {
    pub dex_slippage_impact_bps: Decimal,
    pub cex_slippage_bps: Decimal,
    pub cex_fee_bps: Decimal,
    pub dex_fee_bps: Decimal,
    pub gas_cost_bps: Decimal,
    pub gas_cost_usd: Decimal,
}

pub struct ArbChecker {
    pricing_engine: Arc<Mutex<PricingEngine>>,
    exchange_client: Arc<Mutex<ExchangeClient>>,
    inventory_tracker: Arc<Mutex<InventoryTracker>>,
    pnl_engine: PnLEngine,
}

impl ArbChecker {
    pub fn new(
        pricing_engine: Arc<Mutex<PricingEngine>>,
        exchange_client: Arc<Mutex<ExchangeClient>>,
        inventory_tracker: Arc<Mutex<InventoryTracker>>,
        pnl_engine: PnLEngine,
    ) -> Self {
        Self {
            pricing_engine,
            exchange_client,
            inventory_tracker,
            pnl_engine,
        }
    }

    pub fn opportunity_swap_by_amount(&self, pair: &str, amount: Decimal) -> Result<OpportunitySwap, ArbCheckerError> {
        let (token0_symbol, token1_symbol) = pair.split_once('/').ok_or(ArbCheckerError::InvalidPair(pair.to_string()))?;

        // Lock exchange to fetch order book
        let exchange = self.exchange_client.lock().unwrap();
        let order_book = exchange.fetch_order_book(pair, 100).map_err(|_| ArbCheckerError::InvalidOrderBook(pair.to_string()))?;
        let cex_fee_bps = exchange.get_trading_fees(pair).map_err(|_| ArbCheckerError::InvalidExchangeClient(pair.to_string()))?.taker;
        drop(exchange); // Release lock

        let analyzer = OrderBookAnalyzer::new(order_book);

        let dex_token0 = if token0_symbol == "ETH" { "WETH" } else { token0_symbol };
        let dex_token1 = if token1_symbol == "ETH" { "WETH" } else { token1_symbol };

        // Lock pricing to access DEX prices
        let pricing = self.pricing_engine.lock().unwrap();
        let uniswap2pair = pricing.get_pair_by_symbols(dex_token0, dex_token1)
            .ok_or(ArbCheckerError::InvalidPair(pair.to_string()))?;
        
        // Clone the pair so we can release the lock
        let uniswap2pair = uniswap2pair.clone();
        drop(pricing); // Release lock

        self._calculate_swap(pair, amount, &analyzer, &uniswap2pair, cex_fee_bps, (token0_symbol, token1_symbol))
    }

    fn _calculate_swap(
        &self,
        pair: &str,
        amount: Decimal,
        analyzer: &OrderBookAnalyzer,
        uniswap2pair: &UniswapV2Pair,
        cex_fee_bps: Decimal,
        token_symbols: (&str, &str),
    ) -> Result<OpportunitySwap, ArbCheckerError> {
        let (token0_symbol, token1_symbol) = token_symbols;
        let dex_token0 = if token0_symbol == "ETH" { "WETH" } else { token0_symbol };

        let (input_token, _output_token) = if uniswap2pair.token0.token.symbol().unwrap_or_default() == dex_token0 {
            (&uniswap2pair.token0.token, &uniswap2pair.token1.token)
        } else {
            (&uniswap2pair.token1.token, &uniswap2pair.token0.token)
        };

        // Convert human-readable amount to token units (raw)
        let decimals_in = input_token.decimals();
        let amount_raw = Decimal::from_f64(amount.to_f64().unwrap_or(0.0) * 10f64.powi(decimals_in as i32))
            .map(|d| d.trunc().to_i128().unwrap_or(0) as u128)
            .unwrap_or(0);
        
        let ta_in = TokenAmount::new(amount_raw, input_token.clone());
        let  ta_out = uniswap2pair.get_amount_out(&ta_in).map_err(|_| ArbCheckerError::InvalidPricingEngine(pair.to_string()))?;
        let dex_bid: Decimal = Decimal::from_u128(ta_out.raw).unwrap_or(Decimal::ZERO) / Decimal::from(10u128.pow(ta_out.token.decimals as u32));
        let dex_slippage_impact_bps = uniswap2pair.get_price_impact(
            &TokenAmount::new(amount_raw, input_token.clone()),
        )
            .map_err(|_| ArbCheckerError::InvalidUniswapV2PairError(pair.to_string()))?;
        
        let dex_fee_bps = Decimal::from(uniswap2pair.fee_bps);
        
        // Create price impact analyzer for gas estimation
        let dex_price_analyzer = PriceImpactAnalyzer::new(uniswap2pair.clone());
        let gas_price_gwei = 30;
        let gas_limit = 150_000;
        
        let dex_output = dex_price_analyzer.estimate_true_cost(
            &TokenAmount::new(amount_raw, input_token.clone()),
            gas_price_gwei,
            gas_limit,
        )
            .map_err(|_| ArbCheckerError::InvalidPricingEngine(pair.to_string()))?;

        let cex_ask = analyzer
            .walk_the_book(OrderSide::Sell, amount)
            .map_err(|_| ArbCheckerError::InvalidOrderBook(pair.to_string()))?
            .avg_price;

        let cex_result = analyzer.walk_the_book(OrderSide::Buy, amount).map_err(|_| ArbCheckerError::InvalidOrderBook(pair.to_string()))?;
        let cex_bid = cex_result.avg_price;


        let decimals_in = input_token.decimals as u32;
        let decimals_out = if input_token == &uniswap2pair.token0.token {
             uniswap2pair.token1.token.decimals as u32
        } else {
             uniswap2pair.token0.token.decimals as u32
        };
        
        let decimal_adjustment = if decimals_in >= decimals_out {
             Decimal::from(10u128.pow(decimals_in - decimals_out))
        } else {
             Decimal::ONE / Decimal::from(10u128.pow(decimals_out - decimals_in))
        };
        
        
        let dex_price_normalized = if amount > Decimal::ZERO {
            dex_bid / amount
        } else {
            Decimal::ZERO
        };

        let gap_bps = if cex_ask > Decimal::ZERO {
            (dex_price_normalized - cex_ask) / cex_ask
        } else {
            Decimal::ZERO
        };
        
        let gas_cost_eth_decimal = Decimal::from_u128(dex_output.gas_cost_eth)
            .unwrap_or(Decimal::ZERO) / Decimal::from(10u128.pow(18));
        let eth_price_usd = cex_ask / decimal_adjustment;
        let gas_cost_usd = gas_cost_eth_decimal * eth_price_usd;
        let gas_cost_bps = if cex_ask != Decimal::ZERO {
            (gas_cost_usd / (cex_ask * amount)) * Decimal::from(10000)
        } else {
            Decimal::ZERO
        };

        let estimated_costs_bps = cex_fee_bps + dex_fee_bps + gas_cost_bps;
        
        let human_readable_amount = Decimal::from_u128(amount.to_i128().unwrap_or(0) as u128).unwrap_or(Decimal::ZERO) 
            / Decimal::from(10u128.pow(input_token.decimals() as u32));
        let quote_amount_needed = cex_ask * human_readable_amount;
        
        let inventory = self.inventory_tracker.lock().unwrap();
        let inventory_check = inventory.can_execute(
            Venue::Binance,           
            token1_symbol,            
            quote_amount_needed,      
            Venue::Wallet,            
            token0_symbol,            
            human_readable_amount,    
        );
        drop(inventory);
        
        let inventory_ok = inventory_check.can_execute;
        let net_pnl_positive = (gap_bps * Decimal::from(10000)) > estimated_costs_bps;
        let executable = inventory_ok && net_pnl_positive;
        
        let opportunity_swap = OpportunitySwap {
            pair: pair.to_string(),
            timestamp: OffsetDateTime::now_utc(),
            amount: human_readable_amount, // Changed from `amount` to `human_readable_amount`
            dex_price: dex_price_normalized, // Use unit price!
            cex_bid: cex_bid,
            cex_ask: cex_ask,
            gap_bps: gap_bps,
            direction: ExchangeTypeDirection::BuyCexSellDex,
            estimated_costs_bps: estimated_costs_bps,
            estimated_net_pnl_bps: (gap_bps * Decimal::from(10000)) - estimated_costs_bps,
            inventory_ok,
            executable,
            details: OpportunitySwapDetails {
                dex_slippage_impact_bps: dex_slippage_impact_bps,
                cex_slippage_bps: cex_result.slippage_bps,
                cex_fee_bps,
                dex_fee_bps: Decimal::from(uniswap2pair.fee_bps),
                gas_cost_bps: gas_cost_bps,
                gas_cost_usd: gas_cost_usd,
            },
        };
        Ok(opportunity_swap)
    }

    pub fn check(&self, pair: &str) -> Result<Option<OpportunitySwap>, ArbCheckerError> {
        let (token0_symbol, token1_symbol) = pair.split_once('/').ok_or(ArbCheckerError::InvalidPair(pair.to_string()))?;

        // 1. Fetch data ONCE
        let exchange = self.exchange_client.lock().unwrap();
        let order_book = exchange.fetch_order_book(pair, 100).map_err(|_| ArbCheckerError::InvalidOrderBook(pair.to_string()))?;
        let cex_fee_bps = exchange.get_trading_fees(pair).map_err(|_| ArbCheckerError::InvalidExchangeClient(pair.to_string()))?.taker;
        drop(exchange); 

        let analyzer = OrderBookAnalyzer::new(order_book);

        let dex_token0 = if token0_symbol == "ETH" { "WETH" } else { token0_symbol };
        let dex_token1 = if token1_symbol == "ETH" { "WETH" } else { token1_symbol };

        let pricing = self.pricing_engine.lock().unwrap();
        let uniswap2pair = pricing.get_pair_by_symbols(dex_token0, dex_token1)
            .ok_or(ArbCheckerError::InvalidPair(pair.to_string()))?;
        let uniswap2pair = uniswap2pair.clone();
        drop(pricing);

        // 2. Loop with cached data
        let amounts = (0..50).map(|i| (2u128.pow(i)) * 10000).collect::<Vec<u128>>();
        let mut swaps = Vec::new();
        for amount in amounts {
            let swap = self._calculate_swap(pair, Decimal::from(amount), &analyzer, &uniswap2pair, cex_fee_bps, (token0_symbol, token1_symbol))?;
            if swap.executable {
                swaps.push(swap);
            }
        }
        
        if swaps.is_empty() {
            // Log best non-profitable gap for debugging/visibility
            let best_gap_swap = (0..5).map(|i| (2u128.pow(i)) * 10000)
                .map(|amount| self._calculate_swap(pair, Decimal::from(amount), &analyzer, &uniswap2pair, cex_fee_bps, (token0_symbol, token1_symbol)))
                .filter_map(Result::ok)
                .max_by_key(|s| s.gap_bps);
            
            if let Some(s) = best_gap_swap {
                println!("  Best gap for {}: {:.2} bps (needs > 0 bps + costs)", pair, s.gap_bps);
            }
            
            return Ok(None);
        }

        let max_swap = swaps.iter().max_by_key(|swap| swap.estimated_net_pnl_bps).unwrap();
        Ok(Some(max_swap.clone()))
    }
    /// Access the exchange client.
    pub fn exchange(&self) -> Arc<Mutex<ExchangeClient>> {
        Arc::clone(&self.exchange_client)
    }
    pub fn pricing_engine(&self) -> Arc<Mutex<PricingEngine>> {
        Arc::clone(&self.pricing_engine)
    }
    pub fn inventory(&self) -> Arc<Mutex<InventoryTracker>> {
        Arc::clone(&self.inventory_tracker)
    }
}


#[derive(Debug, Error)]
pub enum ArbCheckerError {
    #[error("No profit")]
    NoProfit,
    #[error("Invalid pair: {0}")]
    InvalidPair(String),
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),
    #[error("Invalid order book: {0}")]
    InvalidOrderBook(String),
    #[error("Invalid pricing engine: {0}")]
    InvalidPricingEngine(String),
    #[error("Invalid exchange client: {0}")]
    InvalidExchangeClient(String),
    #[error("Invalid inventory tracker: {0}")]
    InvalidInventoryTracker(String),
    #[error("Invalid pnl engine: {0}")]
    InvalidPnLEngine(String),
    #[error("Invalid uniswap v2 pair error: {0}")]
    InvalidUniswapV2PairError(String),
}