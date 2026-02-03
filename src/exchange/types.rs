use rust_decimal::Decimal;

/// Normalized L2 order book snapshot.
#[derive(Debug, Clone)]
pub struct OrderBook {
    pub symbol: String,
    pub timestamp: i64,
    pub bids: Vec<(Decimal, Decimal)>,
    pub asks: Vec<(Decimal, Decimal)>,
    pub best_bid: (Decimal, Decimal),
    pub best_ask: (Decimal, Decimal),
    pub mid_price: Decimal,
    pub spread_bps: Decimal,
}

/// Balance for a single asset.
#[derive(Debug, Clone)]
pub struct AssetBalance {
    pub free: Decimal,
    pub locked: Decimal,
    pub total: Decimal,
}

/// Normalized order result.
#[derive(Debug, Clone)]
pub struct OrderResult {
    pub id: String,
    pub symbol: String,
    pub side: String,
    pub order_type: String,
    pub time_in_force: String,
    pub amount_requested: Decimal,
    pub amount_filled: Decimal,
    pub avg_fill_price: Decimal,
    pub fee: Decimal,
    pub fee_asset: String,
    pub status: String,
    pub timestamp: i64,
}

/// Trading fee structure.
#[derive(Debug, Clone)]
pub struct TradingFees {
    pub maker: Decimal,
    pub taker: Decimal,
}
