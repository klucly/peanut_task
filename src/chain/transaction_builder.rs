use crate::core::base_types::{
    Address, SignedTransaction, TokenAmount, Transaction, TransactionReceipt,
};
use crate::core::wallet_manager::WalletManager;
use crate::chain::errors::ChainClientError;
use super::chain_client::ChainClient;
use thiserror::Error;

pub struct TransactionBuilder<'a> {
    client: &'a ChainClient,
    wallet: &'a WalletManager,
    to: Option<Address>,
    value: Option<TokenAmount>,
    data: Vec<u8>,
    nonce: Option<u64>,
    gas_limit: Option<u64>,
    max_fee_per_gas: Option<u64>,
    max_priority_fee: Option<u64>,
}

#[derive(Error, Debug)]
pub enum TransactionBuilderError {
    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Chain client error: {0}")]
    Chain(#[from] ChainClientError),

    #[error("Wallet/signing error: {0}")]
    Wallet(String),
}

impl<'a> TransactionBuilder<'a> {
    pub fn new(client: &'a ChainClient, wallet: &'a WalletManager) -> Self {
        Self {
            client,
            wallet,
            to: None,
            value: None,
            data: vec![],
            nonce: None,
            gas_limit: None,
            max_fee_per_gas: None,
            max_priority_fee: None,
        }
    }

    pub fn to(mut self, address: Address) -> Self {
        self.to = Some(address);
        self
    }

    pub fn value(mut self, amount: TokenAmount) -> Self {
        self.value = Some(amount);
        self
    }

    pub fn data(mut self, calldata: impl Into<Vec<u8>>) -> Self {
        self.data = calldata.into();
        self
    }

    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn gas_limit(mut self, limit: u64) -> Self {
        self.gas_limit = Some(limit);
        self
    }

    pub fn with_gas_estimate(
        mut self,
        buffer: f64,
    ) -> Result<Self, TransactionBuilderError> {
        let tx = self.partial_tx_for_estimate()?;
        let estimated = self.client.estimate_gas(&tx)?;
        let limit = ((estimated as f64) * buffer).ceil() as u64;
        self.gas_limit = Some(limit);
        Ok(self)
    }

    pub fn with_gas_price(
        mut self,
        priority: crate::chain::gas_price::Priority,
    ) -> Result<Self, TransactionBuilderError> {
        use crate::chain::gas_price::Priority;
        let gas_price = self.client.get_gas_price()?;
        let max_fee = gas_price.get_max_fee(priority, 1.0);
        let priority_fee = match priority {
            Priority::Low => gas_price.priority_fee_low,
            Priority::Medium => gas_price.priority_fee_medium,
            Priority::High => gas_price.priority_fee_high,
        };
        self.max_fee_per_gas = Some(max_fee);
        self.max_priority_fee = Some(priority_fee);
        Ok(self)
    }

    pub fn build(&self) -> Result<Transaction, TransactionBuilderError> {
        let to = self
            .to
            .clone()
            .ok_or_else(|| TransactionBuilderError::MissingField("to".into()))?;
        let chain_id = self.client.get_chain_id()?;
        let value = self
            .value
            .clone()
            .unwrap_or_else(|| TokenAmount::new(0, 18, Some("ETH".to_string())));
        Ok(Transaction {
            to,
            value,
            data: self.data.clone(),
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee: self.max_priority_fee,
            chain_id,
        })
    }

    pub fn build_and_sign(&self) -> Result<SignedTransaction, TransactionBuilderError> {
        let mut tx = self.build()?;
        if tx.nonce.is_none() {
            let from = self.wallet.address();
            tx.nonce = Some(self.client.get_nonce(from, "pending")?);
        }
        if tx.gas_limit.is_none() {
            return Err(TransactionBuilderError::MissingField(
                "gas_limit (use with_gas_estimate or gas_limit)".into(),
            ));
        }
        if tx.max_fee_per_gas.is_none() || tx.max_priority_fee.is_none() {
            return Err(TransactionBuilderError::MissingField(
                "max_fee_per_gas / max_priority_fee (use with_gas_price)".into(),
            ));
        }
        self.wallet
            .sign_transaction(tx)
            .map_err(|e| TransactionBuilderError::Wallet(e.to_string()))
    }

    pub fn send(&self) -> Result<String, TransactionBuilderError> {
        let signed = self.build_and_sign()?;
        self.client
            .send_transaction(&signed)
            .map_err(TransactionBuilderError::from)
    }

    pub fn send_and_wait(
        &self,
        timeout: u64,
    ) -> Result<TransactionReceipt, TransactionBuilderError> {
        let hash = self.send()?;
        self.client
            .wait_for_receipt(&hash, timeout, 1.0)
            .map_err(TransactionBuilderError::from)
    }

    fn partial_tx_for_estimate(&self) -> Result<Transaction, TransactionBuilderError> {
        let to = self
            .to
            .clone()
            .ok_or_else(|| TransactionBuilderError::MissingField("to (required for gas estimate)".into()))?;
        let chain_id = self.client.get_chain_id()?;
        let value = self.value.clone().unwrap_or_else(|| {
            TokenAmount::new(0, 18, Some("ETH".to_string()))
        });
        Ok(Transaction {
            to,
            value,
            data: self.data.clone(),
            nonce: self.nonce,
            gas_limit: None,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee: self.max_priority_fee,
            chain_id,
        })
    }
}
