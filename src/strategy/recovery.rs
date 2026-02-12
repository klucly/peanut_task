//! Circuit breaker and replay protection for executor recovery.

use std::collections::HashMap;
use time::OffsetDateTime;

use super::signal::Signal;

/// Configuration for the circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures within window before tripping
    pub failure_threshold: u32,
    /// Time window in seconds for counting failures
    pub window_seconds: f64,
    /// Cooldown period in seconds after tripping
    pub cooldown_seconds: f64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            window_seconds: 300.0,
            cooldown_seconds: 600.0,
        }
    }
}

impl CircuitBreakerConfig {
    pub fn new(failure_threshold: u32, window_seconds: f64, cooldown_seconds: f64) -> Self {
        Self {
            failure_threshold,
            window_seconds,
            cooldown_seconds,
        }
    }
}

/// Circuit breaker to prevent cascading failures.
/// 
/// Tracks failures within a time window and trips when threshold is exceeded.
/// Automatically resets after cooldown period.
#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    /// Timestamps of recent failures
    failures: Vec<f64>,
    /// Timestamp when breaker was tripped
    tripped_at: Option<f64>,
}

impl CircuitBreaker {
    pub fn new(config: Option<CircuitBreakerConfig>) -> Self {
        Self {
            config: config.unwrap_or_default(),
            failures: Vec::new(),
            tripped_at: None,
        }
    }

    /// Record a failure and check if breaker should trip.
    pub fn record_failure(&mut self) {
        let now = current_timestamp();
        self.failures.push(now);

        // Remove failures outside the window
        let cutoff = now - self.config.window_seconds;
        self.failures.retain(|&t| t > cutoff);

        // Trip if threshold exceeded
        if self.failures.len() >= self.config.failure_threshold as usize {
            self.trip();
        }
    }

    /// Record a success (placeholder for future reset logic).
    pub fn record_success(&mut self) {
        // Could implement gradual reset here
    }

    /// Trip the circuit breaker.
    fn trip(&mut self) {
        self.tripped_at = Some(current_timestamp());
        tracing::error!("CIRCUIT BREAKER TRIPPED");
    }

    /// Check if the circuit breaker is open (tripped).
    /// 
    /// Returns true if tripped and still in cooldown period.
    /// Auto-resets if cooldown has elapsed.
    pub fn is_open(&mut self) -> bool {
        if let Some(tripped_time) = self.tripped_at {
            let now = current_timestamp();
            let elapsed = now - tripped_time;

            if elapsed > self.config.cooldown_seconds {
                // Auto-reset after cooldown
                self.tripped_at = None;
                self.failures.clear();
                return false;
            }

            return true;
        }

        false
    }

    /// Get time in seconds until the breaker resets.
    pub fn time_until_reset(&self) -> f64 {
        if let Some(tripped_time) = self.tripped_at {
            let now = current_timestamp();
            let remaining = self.config.cooldown_seconds - (now - tripped_time);
            return remaining.max(0.0);
        }

        0.0
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Replay protection to prevent duplicate signal execution.
/// 
/// Tracks executed signals with TTL-based cleanup.
#[derive(Debug)]
pub struct ReplayProtection {
    /// Map of signal_id to execution timestamp
    executed: HashMap<String, f64>,
    /// Time-to-live in seconds for executed signals
    ttl_seconds: f64,
}

impl ReplayProtection {
    pub fn new(ttl_seconds: Option<f64>) -> Self {
        Self {
            executed: HashMap::new(),
            ttl_seconds: ttl_seconds.unwrap_or(60.0),
        }
    }

    /// Check if a signal is a duplicate (already executed).
    pub fn is_duplicate(&mut self, signal: &Signal) -> bool {
        self.cleanup();
        self.executed.contains_key(&signal.signal_id)
    }

    /// Mark a signal as executed.
    pub fn mark_executed(&mut self, signal: &Signal) {
        let now = current_timestamp();
        self.executed.insert(signal.signal_id.clone(), now);
    }

    /// Clean up expired entries.
    fn cleanup(&mut self) {
        let now = current_timestamp();
        let cutoff = now - self.ttl_seconds;
        self.executed.retain(|_, &mut timestamp| timestamp > cutoff);
    }
}

impl Default for ReplayProtection {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Get current timestamp as seconds since epoch.
fn current_timestamp() -> f64 {
    let now = OffsetDateTime::now_utc();
    now.unix_timestamp() as f64 + now.nanosecond() as f64 / 1_000_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_signal(id: &str) -> Signal {
        use rust_decimal_macros::dec;
        use super::super::signal::Direction;

        Signal::create(
            "ETH/USDT".to_string(),
            Direction::BuyCexSellDex,
            dec!(2000),
            dec!(2010),
            dec!(50),
            dec!(1.0),
            dec!(10),
            dec!(0.5),
            dec!(9.5),
            dec!(100),
            OffsetDateTime::now_utc() + time::Duration::seconds(60),
            true,
            true,
        )
    }

    #[test]
    fn test_circuit_breaker_default_config() {
        let cb = CircuitBreaker::default();
        assert_eq!(cb.config.failure_threshold, 3);
        assert_eq!(cb.config.window_seconds, 300.0);
        assert_eq!(cb.config.cooldown_seconds, 600.0);
    }

    #[test]
    fn test_replay_protection_default_ttl() {
        let rp = ReplayProtection::default();
        assert_eq!(rp.ttl_seconds, 60.0);
    }
}
