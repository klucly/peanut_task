use crate::core::base_types::{Token, TokenAmount};
use rust_decimal::prelude::FromPrimitive;
use rust_decimal::Decimal;
use thiserror::Error;

use super::uniswap_v2_pair::{UniswapV2Pair, UniswapV2PairError};

#[derive(Debug, Clone)]
pub struct ImpactRow {
    pub amount_in: u128,
    pub amount_out: u128,
    pub spot_price: Decimal,
    pub execution_price: Decimal,
    pub price_impact_pct: Decimal,
}

#[derive(Debug, Clone)]
pub struct TrueCostResult {
    pub gross_output: u128,
    pub gas_cost_eth: u128,
    pub gas_cost_in_output_token: u128,
    pub net_output: u128,
    pub effective_price: Decimal,
}

#[derive(Error, Debug)]
pub enum PriceImpactAnalyzerError {
    #[error("Pair error: {0}")]
    Pair(#[from] UniswapV2PairError),
    #[error("Arithmetic overflow")]
    Overflow,
}

pub struct PriceImpactAnalyzer {
    pub pair: UniswapV2Pair,
}

impl PriceImpactAnalyzer {
    pub fn new(pair: UniswapV2Pair) -> Self {
        Self { pair }
    }

    pub fn generate_impact_table(
        &self,
        token_in: &Token,
        sizes: &[u128],
    ) -> Result<Vec<ImpactRow>, UniswapV2PairError> {
        let mut rows = Vec::with_capacity(sizes.len());
        for &amount_in in sizes {
            let amount_in_ta = TokenAmount::new(amount_in, token_in.clone());
            let spot_price = self.pair.get_spot_price(token_in)?;
            let amount_out = self.pair.get_amount_out(&amount_in_ta)?;
            let execution_price = self.pair.get_execution_price(&amount_in_ta)?;
            let price_impact_pct = self.pair.get_price_impact(&amount_in_ta)?;
            rows.push(ImpactRow {
                amount_in,
                amount_out: amount_out.raw,
                spot_price,
                execution_price,
                price_impact_pct,
            });
        }
        Ok(rows)
    }

    // Use binary search to comply with the specs
    pub fn find_max_size_for_impact(
        &self,
        token_in: &Token,
        max_impact_pct: Decimal,
    ) -> Result<u128, UniswapV2PairError> {
        let reserve_in = self.pair.reserve_for_token(token_in)?;
        if reserve_in == 0 {
            return Ok(0);
        }
        let mut lo: u128 = 0;
        let mut hi = reserve_in;
        while lo < hi {
            let mid = lo + (hi - lo + 1) / 2;
            let amt = TokenAmount::new(mid, token_in.clone());
            let impact = self.pair.get_price_impact(&amt)?;
            if impact <= max_impact_pct {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        Ok(lo)
    }

    pub fn estimate_true_cost(
        &self,
        amount_in: &TokenAmount,
        gas_price_gwei: u64,
        gas_estimate: u64,
    ) -> Result<TrueCostResult, PriceImpactAnalyzerError> {
        let amount_out = self.pair.get_amount_out(amount_in)?;
        let gross_output = amount_out.raw;
        let gas_cost_eth = Self::gas_cost_wei(gas_price_gwei, gas_estimate)?;
        let is_output_eth = amount_out.token == Token::native_eth();
        let gas_cost_in_output_token = if is_output_eth {
            gas_cost_eth
        } else {
            0
        };
        let net_output = gross_output.checked_sub(gas_cost_in_output_token).unwrap_or(0);
        let effective_price = Self::effective_price(amount_in.raw, net_output);
        Ok(TrueCostResult {
            gross_output,
            gas_cost_eth,
            gas_cost_in_output_token,
            net_output,
            effective_price,
        })
    }

    fn gas_cost_wei(gas_price_gwei: u64, gas_estimate: u64) -> Result<u128, PriceImpactAnalyzerError> {
        const GWEI_PER_WEI: u128 = 1_000_000_000;
        (gas_price_gwei as u128)
            .checked_mul(GWEI_PER_WEI)
            .and_then(|g| g.checked_mul(gas_estimate as u128))
            .ok_or(PriceImpactAnalyzerError::Overflow)
    }

    /// Effective price as net_output / amount_in; ZERO when amount_in is 0.
    fn effective_price(amount_in_raw: u128, net_output: u128) -> Decimal {
        if amount_in_raw == 0 {
            return Decimal::ZERO;
        }
        let net_d = Decimal::from_u128(net_output).unwrap_or(Decimal::ZERO);
        let in_d = Decimal::from_u128(amount_in_raw).unwrap_or(Decimal::ONE);
        net_d / in_d
    }
}
