//! Order book analyzer tests.

use peanut_task::exchange::{BookSide, OrderBook, OrderBookAnalyzer, OrderSide};
use rust_decimal_macros::dec;

fn make_orderbook(
    bids: Vec<(rust_decimal::Decimal, rust_decimal::Decimal)>,
    asks: Vec<(rust_decimal::Decimal, rust_decimal::Decimal)>,
) -> OrderBook {
    let best_bid = bids.first().copied().unwrap_or((dec!(0), dec!(0)));
    let best_ask = asks.first().copied().unwrap_or((dec!(0), dec!(0)));
    let mid_price = (best_bid.0 + best_ask.0) / dec!(2);
    let spread_bps = if best_ask.0.is_zero() {
        dec!(0)
    } else {
        (best_ask.0 - best_bid.0) / best_ask.0 * dec!(10000)
    };
    OrderBook {
        symbol: "ETH/USDT".to_string(),
        timestamp: 0,
        bids,
        asks,
        best_bid,
        best_ask,
        mid_price,
        spread_bps,
    }
}

#[test]
fn test_walk_the_book_exact_fill() {
    let asks = vec![(dec!(100), dec!(5))];
    let bids = vec![(dec!(99), dec!(10))];
    let ob = make_orderbook(bids, asks);
    let analyzer = OrderBookAnalyzer::new(ob);

    let result = analyzer.walk_the_book(OrderSide::Buy, dec!(2)).unwrap();
    assert!(result.fully_filled);
    assert_eq!(result.avg_price, dec!(100));
    assert_eq!(result.total_cost, dec!(200));
    assert_eq!(result.levels_consumed, 1);
    assert_eq!(result.fills.len(), 1);
    assert_eq!(result.fills[0].price, dec!(100));
    assert_eq!(result.fills[0].qty, dec!(2));
    assert_eq!(result.fills[0].cost, dec!(200));
}

#[test]
fn test_walk_the_book_multiple_levels() {
    let asks = vec![(dec!(100), dec!(2)), (dec!(101), dec!(3))];
    let bids = vec![(dec!(99), dec!(10))];
    let ob = make_orderbook(bids, asks);
    let analyzer = OrderBookAnalyzer::new(ob);

    let result = analyzer.walk_the_book(OrderSide::Buy, dec!(4)).unwrap();
    assert!(result.fully_filled);
    assert_eq!(result.avg_price, dec!(100.5));
    assert_eq!(result.total_cost, dec!(402));
    assert_eq!(result.levels_consumed, 2);
    assert_eq!(result.fills.len(), 2);
    assert_eq!(
        result.fills[0],
        peanut_task::exchange::Fill {
            price: dec!(100),
            qty: dec!(2),
            cost: dec!(200)
        }
    );
}

#[test]
fn test_walk_the_book_insufficient_liquidity() {
    let asks = vec![(dec!(100), dec!(1))];
    let bids = vec![(dec!(99), dec!(10))];
    let ob = make_orderbook(bids, asks);
    let analyzer = OrderBookAnalyzer::new(ob);

    let result = analyzer.walk_the_book(OrderSide::Buy, dec!(5)).unwrap();
    assert!(!result.fully_filled);
    assert_eq!(result.fills.len(), 1);
    assert_eq!(result.fills[0].qty, dec!(1));
    assert_eq!(result.fills[0].price, dec!(100));
    assert_eq!(result.total_cost, dec!(100));
}

#[test]
fn test_depth_at_bps_correct() {
    let asks = vec![
        (dec!(100), dec!(10)),
        (dec!(100.05), dec!(5)),
        (dec!(100.2), dec!(3)),
    ];
    let bids = vec![(dec!(99), dec!(20))];
    let ob = make_orderbook(bids, asks.clone());
    let analyzer = OrderBookAnalyzer::new(ob);

    let depth = analyzer.depth_at_bps(BookSide::Ask, 10.0).unwrap();
    let threshold = dec!(100.1);
    let expected: rust_decimal::Decimal = asks
        .iter()
        .filter(|(p, _)| *p <= threshold)
        .map(|(_, q)| q)
        .sum();
    assert_eq!(depth, expected);
    assert_eq!(depth, dec!(15));
}

#[test]
fn test_imbalance_range() {
    let ob_all_bids = make_orderbook(
        vec![(dec!(100), dec!(10)), (dec!(99), dec!(5))],
        vec![(dec!(101), dec!(0))],
    );
    let analyzer = OrderBookAnalyzer::new(ob_all_bids);
    let imb = analyzer.imbalance(10);
    assert!(imb >= -1.0 && imb <= 1.0);
    assert!(imb > 0.9);

    let ob_all_asks = make_orderbook(
        vec![(dec!(99), dec!(0.001))],
        vec![(dec!(100), dec!(10)), (dec!(101), dec!(5))],
    );
    let analyzer = OrderBookAnalyzer::new(ob_all_asks);
    let imb = analyzer.imbalance(10);
    assert!(imb >= -1.0 && imb <= 1.0);
    assert!(imb < -0.9);

    let ob_balanced = make_orderbook(
        vec![(dec!(99), dec!(5))],
        vec![(dec!(100), dec!(5))],
    );
    let analyzer = OrderBookAnalyzer::new(ob_balanced);
    let imb = analyzer.imbalance(10);
    assert!(imb >= -1.0 && imb <= 1.0);
    assert_eq!(imb, 0.0);
}

#[test]
fn test_effective_spread_greater_than_quoted() {
    let bids = vec![(dec!(100), dec!(0.5)), (dec!(99.5), dec!(5))];
    let asks = vec![(dec!(100.5), dec!(0.5)), (dec!(101), dec!(5))];
    let ob = make_orderbook(bids, asks);
    let analyzer = OrderBookAnalyzer::new(ob.clone());

    let qty = dec!(1);
    let eff = analyzer.effective_spread(qty).unwrap();
    assert!(eff >= ob.spread_bps);
}
