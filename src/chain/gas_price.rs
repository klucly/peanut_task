/// Priority level for gas fees. Parse from `"low"` | `"medium"` | `"high"` via `FromStr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Low,
    Medium,
    High,
}

impl std::str::FromStr for Priority {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Priority::Low),
            "medium" => Ok(Priority::Medium),
            "high" => Ok(Priority::High),
            _ => Err(format!("Invalid gas priority '{}', use low|medium|high", s)),
        }
    }
}

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

    pub fn get_max_fee(&self, priority: Priority, buffer: f64) -> u64 {
        let priority_fee = match priority {
            Priority::Low => self.priority_fee_low,
            Priority::Medium => self.priority_fee_medium,
            Priority::High => self.priority_fee_high,
        };

        let buffered_base_fee = (self.base_fee as f64 * buffer) as u64;
        buffered_base_fee + priority_fee
    }
}
