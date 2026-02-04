//! Types for the inventory tracker module.

use crate::exchange::AssetBalance;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::fmt;
use time::OffsetDateTime;

/// Venue where assets can be held (CEX or on-chain wallet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Venue {
    Binance,
    Wallet,
}

impl fmt::Display for Venue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Venue::Binance => write!(f, "binance"),
            Venue::Wallet => write!(f, "wallet"),
        }
    }
}

/// Per-venue breakdown for skew analysis.
#[derive(Debug, Clone)]
pub struct VenueSkew {
    pub amount: Decimal,
    pub pct: Decimal,
    pub deviation_pct: Decimal,
}

/// Full portfolio snapshot at a point in time.
#[derive(Debug, Clone)]
pub struct PortfolioSnapshot {
    pub timestamp: OffsetDateTime,
    /// Per-venue balances: venue_name -> asset -> balance
    pub venues: HashMap<String, HashMap<String, AssetBalance>>,
    /// Aggregated totals across all venues: asset -> total amount
    pub totals: HashMap<String, Decimal>,
    /// Total portfolio value in USD (None if no price feed provided)
    pub total_usd: Option<Decimal>,
}

/// Result of a pre-flight can_execute check.
#[derive(Debug, Clone)]
pub struct CanExecuteResult {
    pub can_execute: bool,
    pub buy_venue_available: Decimal,
    pub buy_venue_needed: Decimal,
    pub sell_venue_available: Decimal,
    pub sell_venue_needed: Decimal,
    pub reason: Option<String>,
}

/// Skew analysis for an asset across venues.
#[derive(Debug, Clone)]
pub struct SkewResult {
    pub asset: String,
    pub total: Decimal,
    /// Per-venue: venue_name -> VenueSkew
    pub venues: HashMap<String, VenueSkew>,
    pub max_deviation_pct: Decimal,
    pub needs_rebalance: bool,
}
