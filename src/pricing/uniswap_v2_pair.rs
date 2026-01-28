use crate::core::base_types::{Address, TokenAmount, Token, Transaction};
use crate::chain::ChainClient;
use hex;
use rust_decimal::prelude::FromPrimitive;
use rust_decimal::Decimal;
use sha3::{Digest, Keccak256};
use thiserror::Error;

fn u128_to_decimal(n: u128) -> Result<Decimal, UniswapV2PairError> {
    Decimal::from_u128(n).ok_or(UniswapV2PairError::Overflow)
}

/// Token in a pair: currency + contract address for reserve lookup. Swap/pricing only; not in core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInPair {
    pub token: Token,
    pub address: Address,
}

impl TokenInPair {
    pub fn new(token: Token, address: Address) -> Self {
        Self { token, address }
    }
}

#[derive(Debug, Clone)]
pub struct UniswapV2Pair {
    pub address: Address,
    pub token0: TokenInPair,
    pub token1: TokenInPair,
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
        token0: TokenInPair,
        token1: TokenInPair,
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

    pub fn get_amount_out(&self, amount_in: &TokenAmount) -> Result<TokenAmount, UniswapV2PairError> {
        let (reserve_in, reserve_out) = self.reserves_for_token(&amount_in.token)?;
        let amount_in_raw = amount_in.raw;
        let amount_in_with_fee = amount_in_raw
            .checked_mul(FEE_DENOM - self.fee_bps as u128)
            .ok_or(UniswapV2PairError::Overflow)?;
        let numerator = amount_in_with_fee
            .checked_mul(reserve_out)
            .ok_or(UniswapV2PairError::Overflow)?;
        let denominator = reserve_in
            .checked_mul(FEE_DENOM)
            .and_then(|d| d.checked_add(amount_in_with_fee))
            .ok_or(UniswapV2PairError::Overflow)?;
        let raw_out = numerator / denominator;
        let token_out = self.other_token_for(&amount_in.token)?;
        Ok(TokenAmount::new(raw_out, token_out))
    }

    pub fn get_amount_in(&self, amount_out: &TokenAmount) -> Result<TokenAmount, UniswapV2PairError> {
        let (reserve_in, reserve_out) = self.reserves_for_token_out(&amount_out.token)?;
        let numerator = amount_out.raw
            .checked_mul(reserve_in)
            .and_then(|n| n.checked_mul(FEE_DENOM))
            .ok_or(UniswapV2PairError::Overflow)?;
        let denominator = reserve_out
            .checked_sub(amount_out.raw)
            .ok_or(UniswapV2PairError::Overflow)?
            .checked_mul(FEE_DENOM - self.fee_bps as u128)
            .ok_or(UniswapV2PairError::Overflow)?;
        if denominator == 0 {
            return Err(UniswapV2PairError::Overflow);
        }
        let raw_in = (numerator + denominator - 1) / denominator;
        let token_in = self.other_token_for(&amount_out.token)?;
        Ok(TokenAmount::new(raw_in, token_in))
    }

    pub fn get_spot_price(&self, token_in: &Token) -> Result<Decimal, UniswapV2PairError> {
        let (reserve_in, reserve_out) = self.reserves_for_token(token_in)?;
        if reserve_in == 0 {
            return Ok(Decimal::ZERO);
        }
        let out = u128_to_decimal(reserve_out)?;
        let inn = u128_to_decimal(reserve_in)?;
        Ok(out / inn)
    }

    pub fn get_execution_price(
        &self,
        amount_in: &TokenAmount,
    ) -> Result<Decimal, UniswapV2PairError> {
        let amount_out = self.get_amount_out(amount_in)?;
        if amount_in.raw == 0 {
            return Ok(Decimal::ZERO);
        }
        let out = u128_to_decimal(amount_out.raw)?;
        let inn = u128_to_decimal(amount_in.raw)?;
        Ok(out / inn)
    }

    pub fn get_price_impact(&self, amount_in: &TokenAmount) -> Result<Decimal, UniswapV2PairError> {
        let (reserve_in, reserve_out) = self.reserves_for_token(&amount_in.token)?;
        let amount_out = self.get_amount_out(amount_in)?;
        if reserve_in == 0 || amount_in.raw == 0 {
            return Ok(Decimal::ZERO);
        }
        let spot_val = u128_to_decimal(reserve_out * amount_in.raw)?;
        let exec_val = u128_to_decimal(amount_out.raw * reserve_in)?;
        if spot_val <= exec_val {
            return Ok(Decimal::ZERO);
        }
        Ok((spot_val - exec_val) / spot_val)
    }

    pub fn simulate_swap(&self, amount_in: &TokenAmount) -> Result<Self, UniswapV2PairError> {
        let amount_out = self.get_amount_out(amount_in)?;
        let (reserve_in, reserve_out) = self.reserves_for_token(&amount_in.token)?;
        let new_reserve_in = reserve_in + amount_in.raw;
        let new_reserve_out = reserve_out - amount_out.raw;
        let (new_reserve0, new_reserve1) = if amount_in.token == self.token0.token {
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
            TokenInPair::new(Token::new(18, None), token0_addr),
            TokenInPair::new(Token::new(18, None), token1_addr),
            reserve0,
            reserve1,
            30,
        ))
    }

    fn reserves_for_token(&self, token: &Token) -> Result<(u128, u128), UniswapV2PairError> {
        if token == &self.token0.token {
            Ok((self.reserve0, self.reserve1))
        } else if token == &self.token1.token {
            Ok((self.reserve1, self.reserve0))
        } else {
            Err(UniswapV2PairError::TokenNotInPair(format!("{:?}", token)))
        }
    }

    fn reserves_for_token_out(&self, token: &Token) -> Result<(u128, u128), UniswapV2PairError> {
        if token == &self.token0.token {
            Ok((self.reserve1, self.reserve0))
        } else if token == &self.token1.token {
            Ok((self.reserve0, self.reserve1))
        } else {
            Err(UniswapV2PairError::TokenNotInPair(format!("{:?}", token)))
        }
    }

    fn other_token_for(&self, token: &Token) -> Result<Token, UniswapV2PairError> {
        if token == &self.token0.token {
            Ok(self.token1.token.clone())
        } else if token == &self.token1.token {
            Ok(self.token0.token.clone())
        } else {
            Err(UniswapV2PairError::TokenNotInPair(format!("{:?}", token)))
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
        value: TokenAmount::native_eth(0),
        data: data.to_vec(),
        nonce: None,
        gas_limit: None,
        max_fee_per_gas: None,
        max_priority_fee: None,
        chain_id,
    };
    Ok(client.call(&tx, "latest")?)
}
