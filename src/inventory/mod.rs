//! Inventory tracker for multi-venue position management.
//!
//! Tracks positions across CEX (e.g. Binance) and DEX (on-chain wallet) venues.

pub mod errors;
pub mod rebalancer;
pub mod types;
mod tracker;

pub use errors::InventoryTrackerError;
pub use rebalancer::{AssetSkewCheck, CostEstimate, RebalancePlanner, TransferPlan};
pub use tracker::InventoryTracker;
pub use types::{CanExecuteResult, PortfolioSnapshot, SkewResult, Venue, VenueSkew};
