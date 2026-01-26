use crate::chain::errors::ChainClientError;

#[derive(Debug, Clone)]
pub struct GasPrice {
    pub base_fee: u64,
    pub priority_fee_low: u64,
    pub priority_fee_medium: u64,
    pub priority_fee_high: u64,
}

impl GasPrice {
    pub fn new(
        base_fee: u64,
        priority_fee_low: u64,
        priority_fee_medium: u64,
        priority_fee_high: u64,
    ) -> Self {
        Self {
            base_fee,
            priority_fee_low,
            priority_fee_medium,
            priority_fee_high,
        }
    }

    pub fn get_max_fee(&self, priority: &str, buffer: f64) -> Result<u64, ChainClientError> {
        todo!()
    }
}
