use super::types::Venue;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InventoryTrackerError {
    #[error("Cannot initialize tracker with empty venues list")]
    EmptyVenues,

    #[error("Invalid venue for this operation: {0}")]
    InvalidVenue(String),

    #[error("Venue {0:?} is not being tracked")]
    VenueNotTracked(Venue),

    #[error("Arithmetic overflow or underflow during balance update")]
    ArithmeticOverflow,
}
