use ccxt_rust::Decimal;
use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

use crate::OrderBookAnalyzer;
use crate::OrderSide;
use crate::core::base_types::TokenAmount;
use crate::exchange::ExchangeClient;
use crate::inventory::PnLEngine;
use crate::inventory::{InventoryTracker, Venue};
use crate::pricing::PriceImpactAnalyzer;
use crate::pricing::PricingEngine;
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

    pub fn opportunity_swap_by_amount(
        &self,
        pair: &str,
        amount: Decimal,
    ) -> Result<OpportunitySwap, ArbCheckerError> {
        let (token0_symbol, token1_symbol) = pair
            .split_once('/')
            .ok_or(ArbCheckerError::InvalidPair(pair.to_string()))?;

        // Lock exchange to fetch order book
        let exchange = self.exchange_client.lock().unwrap();
        let order_book = exchange
            .fetch_order_book(pair, 100)
            .map_err(|_| ArbCheckerError::InvalidOrderBook(pair.to_string()))?;
        let cex_fee_bps = exchange
            .get_trading_fees(pair)
            .map_err(|_| ArbCheckerError::InvalidExchangeClient(pair.to_string()))?
            .taker;
        drop(exchange); // Release lock

        let analyzer = OrderBookAnalyzer::new(order_book);

        let dex_token0 = if token0_symbol == "ETH" {
            "WETH"
        } else {
            token0_symbol
        };
        let dex_token1 = if token1_symbol == "ETH" {
            "WETH"
        } else {
            token1_symbol
        };

        // Lock pricing to access DEX prices
        let pricing = self.pricing_engine.lock().unwrap();
        let uniswap2pair = pricing
            .get_pair_by_symbols(dex_token0, dex_token1)
            .ok_or(ArbCheckerError::InvalidPair(pair.to_string()))?;

        // Clone the pair so we can release the lock
        let uniswap2pair = uniswap2pair.clone();
        drop(pricing); // Release lock

        self._calculate_swap(
            pair,
            amount,
            &analyzer,
            &uniswap2pair,
            cex_fee_bps,
            (token0_symbol, token1_symbol),
        )
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
        // Identify which token is the base asset (e.g. ETH in ETH/USDC)
        let dex_token0 = if token0_symbol == "ETH" {
            "WETH"
        } else {
            token0_symbol
        };

        // Find pool tokens
        let (base_token_in_pair, quote_token_in_pair) =
            if uniswap2pair.token0.token.symbol().unwrap_or_default() == dex_token0 {
                (&uniswap2pair.token0.token, &uniswap2pair.token1.token)
            } else {
                (&uniswap2pair.token1.token, &uniswap2pair.token0.token)
            };

        // Common conversions
        let decimals_base = base_token_in_pair.decimals();
        let amount_raw =
            Decimal::from_f64(amount.to_f64().unwrap_or(0.0) * 10f64.powi(decimals_base as i32))
                .map(|d| d.trunc().to_i128().unwrap_or(0) as u128)
                .unwrap_or(0);
        let ta_base = TokenAmount::new(amount_raw, base_token_in_pair.clone());

        // --- Direction 1: Buy CEX, Sell DEX (Sell Base on DEX) ---
        // Input: Base (ETH). Output: Quote (USDC).
        // We Use get_amount_out using Base as input.
        let (dir1_swap, dir1_pnl) = {
            let ta_out_quote = uniswap2pair.get_amount_out(&ta_base).ok();

            if let Some(ta_out) = ta_out_quote {
                let dex_bid: Decimal = Decimal::from_u128(ta_out.raw).unwrap_or(Decimal::ZERO)
                    / Decimal::from(10u128.pow(ta_out.token.decimals as u32));

                // Dex Price = Quote Amount / Base Amount
                // (dex_bid is total quote received. amount is base amount)
                let dex_price = if amount > Decimal::ZERO {
                    dex_bid / amount
                } else {
                    Decimal::ZERO
                };

                // CEX Ask (Buy price)
                let cex_ask = analyzer
                    .walk_the_book(OrderSide::Sell, amount)
                    .map(|r| r.avg_price)
                    .unwrap_or(Decimal::MAX);

                // Gap: (DEX Sell Price - CEX Buy Price) / CEX Buy Price
                let gap_bps = if cex_ask > Decimal::ZERO && cex_ask != Decimal::MAX {
                    (dex_price - cex_ask) / cex_ask
                } else {
                    Decimal::from(-1)
                };

                // Costs
                let dex_slippage_bps = uniswap2pair
                    .get_price_impact(&ta_base)
                    .unwrap_or(Decimal::ZERO);
                let dex_fee_bps = Decimal::from(uniswap2pair.fee_bps);
                let gas_cost_bps = Decimal::from(20); // Simplified for now, or use estimator
                let estimated_costs_bps =
                    cex_fee_bps + dex_fee_bps + gas_cost_bps + dex_slippage_bps; // + cex_slippage

                let pnl_bps = (gap_bps * Decimal::from(10000)) - estimated_costs_bps;

                let swap = OpportunitySwap {
                    pair: pair.to_string(),
                    timestamp: OffsetDateTime::now_utc(),
                    amount,
                    dex_price,
                    cex_bid: Decimal::ZERO, // Not used for this direction
                    cex_ask,
                    gap_bps,
                    direction: ExchangeTypeDirection::BuyCexSellDex,
                    estimated_costs_bps,
                    estimated_net_pnl_bps: pnl_bps,
                    inventory_ok: true, // Check later
                    executable: false,  // Check later
                    details: OpportunitySwapDetails {
                        dex_slippage_impact_bps: dex_slippage_bps,
                        cex_slippage_bps: Decimal::ZERO,
                        cex_fee_bps,
                        dex_fee_bps,
                        gas_cost_bps,
                        gas_cost_usd: Decimal::ZERO,
                    },
                };
                (Some(swap), pnl_bps)
            } else {
                (None, Decimal::MIN)
            }
        };

        // --- Direction 2: Buy DEX, Sell CEX (Buy Base on DEX) ---
        // Input: Quote (USDC). Output: Base (ETH).
        // We use get_amount_in specifying Output Base amount.
        let (dir2_swap, dir2_pnl) = {
            let ta_in_quote_res = uniswap2pair.get_amount_in(&ta_base); // How much Quote needed to buy Base

            if let Ok(ta_in_quote) = ta_in_quote_res {
                let dex_ask_cost: Decimal = Decimal::from_u128(ta_in_quote.raw)
                    .unwrap_or(Decimal::ZERO)
                    / Decimal::from(10u128.pow(ta_in_quote.token.decimals as u32));

                // Dex Price = Quote Cost / Base Amount
                let dex_price = if amount > Decimal::ZERO {
                    dex_ask_cost / amount
                } else {
                    Decimal::MAX
                };

                // CEX Bid (Sell price)
                let cex_bid = analyzer
                    .walk_the_book(OrderSide::Buy, amount)
                    .map(|r| r.avg_price)
                    .unwrap_or(Decimal::ZERO);

                // Gap: (CEX Sell Price - DEX Buy Price) / DEX Buy Price
                let gap_bps = if dex_price > Decimal::ZERO {
                    (cex_bid - dex_price) / dex_price
                } else {
                    Decimal::ZERO
                };

                // Costs
                // Slippage logic for get_amount_in is different, usually included in price impact?
                // For now reuse similar impact calc or 0
                let dex_slippage_bps = Decimal::ZERO; // Simplified
                let dex_fee_bps = Decimal::from(uniswap2pair.fee_bps);
                let gas_cost_bps = Decimal::from(20);
                let estimated_costs_bps = cex_fee_bps + dex_fee_bps + gas_cost_bps;

                let pnl_bps = (gap_bps * Decimal::from(10000)) - estimated_costs_bps;

                let swap = OpportunitySwap {
                    pair: pair.to_string(),
                    timestamp: OffsetDateTime::now_utc(),
                    amount,
                    dex_price,
                    cex_bid,
                    cex_ask: Decimal::ZERO,
                    gap_bps,
                    direction: ExchangeTypeDirection::BuyDexSellCex,
                    estimated_costs_bps,
                    estimated_net_pnl_bps: pnl_bps,
                    inventory_ok: true,
                    executable: false,
                    details: OpportunitySwapDetails {
                        dex_slippage_impact_bps: dex_slippage_bps,
                        cex_slippage_bps: Decimal::ZERO,
                        cex_fee_bps,
                        dex_fee_bps,
                        gas_cost_bps,
                        gas_cost_usd: Decimal::ZERO,
                    },
                };
                (Some(swap), pnl_bps)
            } else {
                (None, Decimal::MIN)
            }
        };

        // Pick best
        let best_swap = if dir2_pnl > dir1_pnl {
            dir2_swap
        } else {
            dir1_swap
        };

        let mut swap = best_swap.ok_or(ArbCheckerError::NoProfit)?;

        // Final inventory check for the winner
        let inventory = self.inventory_tracker.lock().unwrap();
        // Venue::Binance / Venue::Wallet logic depends on direction
        let inventory_check = match swap.direction {
            ExchangeTypeDirection::BuyCexSellDex => {
                // Sell Dex (Base), Buy Cex (Base) -> Need Base in Wallet, Quote in Cex
                inventory.can_execute(
                    Venue::Binance,
                    token1_symbol, // Quote usually needed on CEX to buy
                    swap.cex_ask * amount,
                    Venue::Wallet,
                    token0_symbol, // Base needed in Wallet to sell
                    amount,
                )
            }
            ExchangeTypeDirection::BuyDexSellCex => {
                // Buy Dex (Base), Sell Cex (Base) -> Need Quote in Wallet, Base in Cex
                inventory.can_execute(
                    Venue::Binance,
                    token0_symbol, // Base needed on CEX to sell
                    amount,
                    Venue::Wallet,
                    token1_symbol, // Quote needed in Wallet to buy Base
                    swap.dex_price * amount,
                )
            }
        };
        drop(inventory);

        swap.inventory_ok = inventory_check.can_execute;
        swap.executable = swap.inventory_ok && swap.estimated_net_pnl_bps > Decimal::ZERO;

        Ok(swap)
    }

    pub fn check(&self, pair: &str) -> Result<Option<OpportunitySwap>, ArbCheckerError> {
        let (token0_symbol, token1_symbol) = pair
            .split_once('/')
            .ok_or(ArbCheckerError::InvalidPair(pair.to_string()))?;

        // 1. Fetch data ONCE
        let exchange = self.exchange_client.lock().unwrap();
        let order_book = exchange
            .fetch_order_book(pair, 100)
            .map_err(|_| ArbCheckerError::InvalidOrderBook(pair.to_string()))?;
        let cex_fee_bps = exchange
            .get_trading_fees(pair)
            .map_err(|_| ArbCheckerError::InvalidExchangeClient(pair.to_string()))?
            .taker;
        drop(exchange);

        let analyzer = OrderBookAnalyzer::new(order_book);

        let dex_token0 = if token0_symbol == "ETH" {
            "WETH"
        } else {
            token0_symbol
        };
        let dex_token1 = if token1_symbol == "ETH" {
            "WETH"
        } else {
            token1_symbol
        };

        let pricing = self.pricing_engine.lock().unwrap();
        let uniswap2pair = pricing
            .get_pair_by_symbols(dex_token0, dex_token1)
            .ok_or(ArbCheckerError::InvalidPair(pair.to_string()))?;
        let uniswap2pair = uniswap2pair.clone();
        drop(pricing);

        // 2. Loop with cached data
        let amounts = (0..50)
            .map(|i| (2u128.pow(i)) * 10000)
            .collect::<Vec<u128>>();
        let mut swaps = Vec::new();
        for amount in amounts {
            let swap = self._calculate_swap(
                pair,
                Decimal::from(amount),
                &analyzer,
                &uniswap2pair,
                cex_fee_bps,
                (token0_symbol, token1_symbol),
            )?;
            if swap.executable {
                swaps.push(swap);
            }
        }

        if swaps.is_empty() {
            // Log best non-profitable gap for debugging/visibility
            let best_gap_swap = (0..5)
                .map(|i| (2u128.pow(i)) * 10000)
                .map(|amount| {
                    self._calculate_swap(
                        pair,
                        Decimal::from(amount),
                        &analyzer,
                        &uniswap2pair,
                        cex_fee_bps,
                        (token0_symbol, token1_symbol),
                    )
                })
                .filter_map(Result::ok)
                .max_by_key(|s| s.gap_bps);

            if let Some(s) = best_gap_swap {
                println!(
                    "  Best gap for {}: {:.2} bps (needs > 0 bps + costs)",
                    pair, s.gap_bps
                );
            }

            return Ok(None);
        }

        let max_swap = swaps
            .iter()
            .max_by_key(|swap| swap.estimated_net_pnl_bps)
            .unwrap();
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
