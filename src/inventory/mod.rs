//! Inventory tracker for multi-venue position management.
//!
//! Tracks positions across CEX (e.g. Binance) and DEX (on-chain wallet) venues.

pub mod types;
pub mod errors;
mod tracker;

pub use errors::InventoryTrackerError;
pub use tracker::InventoryTracker;
pub use types::{CanExecuteResult, PortfolioSnapshot, SkewResult, Venue, VenueSkew};
