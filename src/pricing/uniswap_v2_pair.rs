use crate::core::base_types::{Address, TokenAmount, TokenInfo, Transaction};
use crate::chain::ChainClient;
use hex;
use rust_decimal::prelude::FromPrimitive;
use rust_decimal::Decimal;
use sha3::{Digest, Keccak256};
use thiserror::Error;

fn u128_to_decimal(n: u128) -> Result<Decimal, UniswapV2PairError> {
    Decimal::from_u128(n).ok_or(UniswapV2PairError::Overflow)
}

#[derive(Debug, Clone)]
pub struct UniswapV2Pair {
    pub address: Address,
    pub token0: TokenInfo,
    pub token1: TokenInfo,
    pub reserve0: u128,
    pub reserve1: u128,
    pub fee_bps: u16,
}

#[derive(Error, Debug)]
pub enum UniswapV2PairError {
    #[error("Token not found in pair: {0}")]
    TokenNotInPair(String),
    #[error("Chain / RPC error: {0}")]
    Chain(#[from] crate::chain::ChainClientError),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Arithmetic overflow")]
    Overflow,
}

const FEE_DENOM: u128 = 10000;

impl UniswapV2Pair {
    pub fn new(
        address: Address,
        token0: TokenInfo,
        token1: TokenInfo,
        reserve0: u128,
        reserve1: u128,
        fee_bps: u16,
    ) -> Self {
        Self {
            address,
            token0,
            token1,
            reserve0,
            reserve1,
            fee_bps,
        }
    }

    pub fn get_amount_out(&self, amount_in: u128, token_in: &TokenInfo) -> Result<u128, UniswapV2PairError> {
        let (reserve_in, reserve_out) = self.reserves_for(token_in)?;
        let amount_in_with_fee = amount_in
            .checked_mul(FEE_DENOM - self.fee_bps as u128)
            .ok_or(UniswapV2PairError::Overflow)?;
        let numerator = amount_in_with_fee
            .checked_mul(reserve_out)
            .ok_or(UniswapV2PairError::Overflow)?;
        let denominator = reserve_in
            .checked_mul(FEE_DENOM)
            .and_then(|d| d.checked_add(amount_in_with_fee))
            .ok_or(UniswapV2PairError::Overflow)?;
        Ok(numerator / denominator)
    }

    pub fn get_amount_in(&self, amount_out: u128, token_out: &TokenInfo) -> Result<u128, UniswapV2PairError> {
        let (reserve_in, reserve_out) = self.reserves_for_token_out(token_out)?;
        let numerator = amount_out
            .checked_mul(reserve_in)
            .and_then(|n| n.checked_mul(FEE_DENOM))
            .ok_or(UniswapV2PairError::Overflow)?;
        let denominator = reserve_out
            .checked_sub(amount_out)
            .ok_or(UniswapV2PairError::Overflow)?
            .checked_mul(FEE_DENOM - self.fee_bps as u128)
            .ok_or(UniswapV2PairError::Overflow)?;
        if denominator == 0 {
            return Err(UniswapV2PairError::Overflow);
        }
        let amount_in = (numerator + denominator - 1) / denominator;
        Ok(amount_in)
    }

    pub fn get_spot_price(&self, token_in: &TokenInfo) -> Result<Decimal, UniswapV2PairError> {
        let (reserve_in, reserve_out) = self.reserves_for(token_in)?;
        if reserve_in == 0 {
            return Ok(Decimal::ZERO);
        }
        let out = u128_to_decimal(reserve_out)?;
        let inn = u128_to_decimal(reserve_in)?;
        Ok(out / inn)
    }

    pub fn get_execution_price(&self, amount_in: u128, token_in: &TokenInfo) -> Result<Decimal, UniswapV2PairError> {
        let amount_out = self.get_amount_out(amount_in, token_in)?;
        if amount_in == 0 {
            return Ok(Decimal::ZERO);
        }
        let out = u128_to_decimal(amount_out)?;
        let inn = u128_to_decimal(amount_in)?;
        Ok(out / inn)
    }

    pub fn get_price_impact(&self, amount_in: u128, token_in: &TokenInfo) -> Result<Decimal, UniswapV2PairError> {
        let (reserve_in, reserve_out) = self.reserves_for(token_in)?;
        let amount_out = self.get_amount_out(amount_in, token_in)?;
        if reserve_in == 0 || amount_in == 0 {
            return Ok(Decimal::ZERO);
        }
        let spot_val = u128_to_decimal(reserve_out * amount_in)?;
        let exec_val = u128_to_decimal(amount_out * reserve_in)?;
        if spot_val <= exec_val {
            return Ok(Decimal::ZERO);
        }
        Ok((spot_val - exec_val) / spot_val)
    }

    pub fn simulate_swap(&self, amount_in: u128, token_in: &TokenInfo) -> Result<Self, UniswapV2PairError> {
        let amount_out = self.get_amount_out(amount_in, token_in)?;
        let (reserve_in, reserve_out) = self.reserves_for(token_in)?;
        let new_reserve_in = reserve_in + amount_in;
        let new_reserve_out = reserve_out - amount_out;
        let (new_reserve0, new_reserve1) = if token_in.address == self.token0.address {
            (new_reserve_in, new_reserve_out)
        } else {
            (new_reserve_out, new_reserve_in)
        };
        Ok(Self {
            address: self.address.clone(),
            token0: self.token0.clone(),
            token1: self.token1.clone(),
            reserve0: new_reserve0,
            reserve1: new_reserve1,
            fee_bps: self.fee_bps,
        })
    }

    pub fn from_chain(address: Address, client: &ChainClient) -> Result<Self, UniswapV2PairError> {
        let chain_id = client.get_chain_id()?;

        let reserves = call_pair(client, &address, &selector("getReserves()"), chain_id)?;
        if reserves.len() < 96 {
            return Err(UniswapV2PairError::InvalidResponse(
                "getReserves returned fewer than 96 bytes".to_string(),
            ));
        }
        let reserve0 = u128::from_be_bytes(array_from(&reserves[16..32]));
        let reserve1 = u128::from_be_bytes(array_from(&reserves[48..64]));

        let token0_bytes = call_pair(client, &address, &selector("token0()"), chain_id)?;
        let token1_bytes = call_pair(client, &address, &selector("token1()"), chain_id)?;
        if token0_bytes.len() < 32 || token1_bytes.len() < 32 {
            return Err(UniswapV2PairError::InvalidResponse(
                "token0/token1 returned fewer than 32 bytes".to_string(),
            ));
        }
        let token0_addr = address_from_slice(&token0_bytes[12..32]);
        let token1_addr = address_from_slice(&token1_bytes[12..32]);

        let token0_addr = Address::from_string(&token0_addr).map_err(|e| {
            UniswapV2PairError::InvalidResponse(format!("Invalid token0 address: {}", e))
        })?;
        let token1_addr = Address::from_string(&token1_addr).map_err(|e| {
            UniswapV2PairError::InvalidResponse(format!("Invalid token1 address: {}", e))
        })?;

        Ok(Self::new(
            address,
            TokenInfo::new(token0_addr, 18, None),
            TokenInfo::new(token1_addr, 18, None),
            reserve0,
            reserve1,
            30,
        ))
    }

    fn reserves_for(&self, token_in: &TokenInfo) -> Result<(u128, u128), UniswapV2PairError> {
        if token_in.address == self.token0.address {
            Ok((self.reserve0, self.reserve1))
        } else if token_in.address == self.token1.address {
            Ok((self.reserve1, self.reserve0))
        } else {
            Err(UniswapV2PairError::TokenNotInPair(token_in.address.to_string()))
        }
    }

    fn reserves_for_token_out(&self, token_out: &TokenInfo) -> Result<(u128, u128), UniswapV2PairError> {
        if token_out.address == self.token0.address {
            Ok((self.reserve1, self.reserve0))
        } else if token_out.address == self.token1.address {
            Ok((self.reserve0, self.reserve1))
        } else {
            Err(UniswapV2PairError::TokenNotInPair(token_out.address.to_string()))
        }
    }
}

fn selector(sig: &str) -> [u8; 4] {
    let h = Keccak256::digest(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

fn array_from(slice: &[u8]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(slice);
    a
}

fn address_from_slice(slice: &[u8]) -> String {
    format!("0x{}", hex::encode(slice))
}

fn call_pair(
    client: &ChainClient,
    to: &Address,
    data: &[u8; 4],
    chain_id: u64,
) -> Result<Vec<u8>, UniswapV2PairError> {
    let tx = Transaction {
        to: to.clone(),
        value: TokenAmount::new(0, 18, None),
        data: data.to_vec(),
        nonce: None,
        gas_limit: None,
        max_fee_per_gas: None,
        max_priority_fee: None,
        chain_id,
    };
    Ok(client.call(&tx, "latest")?)
}
