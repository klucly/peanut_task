use ccxt_rust::Decimal;
use rust_decimal::prelude::{ToPrimitive, FromPrimitive};
use time::OffsetDateTime;

use crate::OrderBookAnalyzer;
use crate::OrderSide;
use crate::core::base_types::TokenAmount;
use crate::pricing::PriceImpactAnalyzer;
use crate::pricing::PricingEngine;
use crate::exchange::ExchangeClient;
use crate::inventory::{InventoryTracker, Venue};
use crate::inventory::PnLEngine;
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
    pricing_engine: PricingEngine,
    exchange_client: ExchangeClient,
    inventory_tracker: InventoryTracker,
    pnl_engine: PnLEngine,
}

impl ArbChecker {
    pub fn new(
        pricing_engine: PricingEngine,
        exchange_client: ExchangeClient,
        inventory_tracker: InventoryTracker,
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

        let order_book = self.exchange_client.fetch_order_book(pair, 100).map_err(|_| ArbCheckerError::InvalidOrderBook(pair.to_string()))?;
        let analyzer = OrderBookAnalyzer::new(order_book);
        let cex_result = analyzer.walk_the_book(OrderSide::Buy, amount).map_err(|_| ArbCheckerError::InvalidOrderBook(pair.to_string()))?;

        let dex_token0 = if token0_symbol == "ETH" { "WETH" } else { token0_symbol };
        let dex_token1 = if token1_symbol == "ETH" { "WETH" } else { token1_symbol };

        let uniswap2pair = self.pricing_engine.get_pair_by_symbols(dex_token0, dex_token1)
            .ok_or(ArbCheckerError::InvalidPair(pair.to_string()))?;
        
        let (input_token, _output_token) = if uniswap2pair.token0.token.symbol().unwrap_or_default() == dex_token0 {
            (&uniswap2pair.token0.token, &uniswap2pair.token1.token)
        } else {
            (&uniswap2pair.token1.token, &uniswap2pair.token0.token)
        };

        let dex_price_analyzer = PriceImpactAnalyzer::new(uniswap2pair.clone());
        
        let dex_output = dex_price_analyzer.estimate_true_cost(
            &TokenAmount::new(amount.to_i128().unwrap_or(0) as u128, input_token.clone()),
            1,
            1,
        )
            .map_err(|_| ArbCheckerError::InvalidPricingEngine(pair.to_string()))?;
        
        let dex_fee_bps = Decimal::from(uniswap2pair.fee_bps);
        let dex_slippage_impact_bps = uniswap2pair.get_price_impact(
            &TokenAmount::new(amount.to_i128().unwrap_or(0) as u128, input_token.clone()),
        )
            .map_err(|_| ArbCheckerError::InvalidUniswapV2PairError(pair.to_string()))?;
        
        let gas_price_gwei = 30;
        let gas_limit = 150_000;
        let gas_result = dex_price_analyzer.estimate_true_cost(
            &TokenAmount::new(amount.to_i128().unwrap_or(0) as u128, input_token.clone()),
            gas_price_gwei,
            gas_limit,
        )
            .map_err(|_| ArbCheckerError::InvalidPricingEngine(pair.to_string()))?;

        let cex_ask = analyzer
            .walk_the_book(OrderSide::Sell, amount)
            .map_err(|_| ArbCheckerError::InvalidOrderBook(pair.to_string()))?
            .avg_price;

        let cex_bid = cex_result.avg_price;

        let cex_fee_bps = self
            .exchange_client
            .get_trading_fees(pair)
            .map_err(|_| ArbCheckerError::InvalidExchangeClient(pair.to_string()))?
            .taker;

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
        
        let dex_price_normalized = dex_output.effective_price * decimal_adjustment;

        let gas_cost_eth_decimal = Decimal::from_u128(gas_result.gas_cost_eth)
            .unwrap_or(Decimal::ZERO);
        let gas_cost_eth_human = gas_cost_eth_decimal / Decimal::from(1_000_000_000_000_000_000u128);
        let gas_cost_usd = gas_cost_eth_human * cex_bid;
        let amount_human = amount / Decimal::from(10u128.pow(decimals_in));
        let trade_value_usd = amount_human * cex_bid;
        let gas_cost_bps = if trade_value_usd > Decimal::ZERO {
            (gas_cost_usd / trade_value_usd) * Decimal::from(10000)
        } else {
            Decimal::ZERO
        };

        let estimated_costs_bps = cex_fee_bps + dex_fee_bps + gas_cost_bps;
        let gap_bps = (dex_price_normalized - cex_ask) / cex_ask;
        
        let human_readable_amount = Decimal::from_u128(amount.to_i128().unwrap_or(0) as u128).unwrap_or(Decimal::ZERO) 
            / Decimal::from(10u128.pow(input_token.decimals() as u32));
        let quote_amount_needed = cex_ask * human_readable_amount;
        let inventory_check = self.inventory_tracker.can_execute(
            Venue::Binance,           
            token1_symbol,            
            quote_amount_needed,      
            Venue::Wallet,            
            token0_symbol,            
            human_readable_amount,    
        );
        
        let inventory_ok = inventory_check.can_execute;
        let net_pnl_positive = (gap_bps * Decimal::from(10000)) > estimated_costs_bps;
        let executable = inventory_ok && net_pnl_positive;
        
        let opportunity_swap = OpportunitySwap {
            pair: pair.to_string(),
            timestamp: OffsetDateTime::now_utc(),
            amount,
            dex_price: dex_price_normalized,
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
                cex_fee_bps: self.exchange_client.get_trading_fees(pair).map_err(|_| ArbCheckerError::InvalidExchangeClient(pair.to_string()))?.taker,
                dex_fee_bps: Decimal::from(uniswap2pair.fee_bps),
                gas_cost_bps: gas_cost_bps,
                gas_cost_usd: gas_cost_usd,
            },
        };
        Ok(opportunity_swap)
    }

    pub fn check(&self, pair: &str) -> Result<OpportunitySwap, ArbCheckerError> {
        let amounts = (0..50).map(|i| (2u128.pow(i)) * 10000).collect::<Vec<u128>>();
        let mut swaps = Vec::new();
        for amount in amounts {
            let swap = self.opportunity_swap_by_amount(pair, Decimal::from(amount))?;
            if swap.executable {
                swaps.push(swap);
            }
        }
        let max_swap = swaps.iter().max_by_key(|swap| swap.estimated_net_pnl_bps).unwrap();
        Ok(max_swap.clone())
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