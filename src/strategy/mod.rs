//! Strategy module for trading signals and execution logic.

pub mod signal;
pub mod fees;
pub mod generator;
pub mod scorer;
pub mod executor;
pub mod recovery;

pub use signal::{Direction, Signal};
pub use fees::FeeStructure;
pub use generator::{GeneratorConfig, SignalGenerator};
pub use scorer::{ScorerConfig, SignalScorer};
pub use executor::{ExecutorConfig, Executor, ExecutionContext, ExecutorState};
pub use recovery::{CircuitBreakerConfig, CircuitBreaker, ReplayProtection};
