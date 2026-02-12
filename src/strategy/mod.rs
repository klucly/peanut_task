//! Strategy module for trading signals and execution logic.

pub mod signal;
pub mod fees;
pub mod generator;

pub use signal::{Direction, Signal};
pub use fees::FeeStructure;
pub use generator::{GeneratorConfig, SignalGenerator};
