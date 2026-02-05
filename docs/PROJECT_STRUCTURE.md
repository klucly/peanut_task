# Project Structure

## Overview

Rust library and binaries for Ethereum: wallet operations (EIP-191/EIP-712 signing, transaction handling), RPC client with multi-URL failover, and a pricing module integrating AMM math, routing, fork simulation, and mempool monitoring.

## Binaries

### peanut_task (`src/main.rs`)
- Default binary. Demonstrates: RPC failover (Infura + Alchemy), balance/nonce/gas fetch, TransactionBuilder (to, value, with_gas_estimate, with_gas_price, build), eth_call, get_receipt, send_transaction (expected to fail on unsupported tx type).
- Requires `INFURA_API_KEY` or `ALCHEMY_API_KEY` in `.env`.
- Run: `just run`.

### price_impact_cli (`scripts/price_impact_cli.rs`)
- CLI for price impact analysis. Usage: `price_impact_cli <PAIR> --token-in USDC --sizes 1000,10000,...` (or `just price-impact ...`).
- Requires `INFURA_API_KEY` or `ETH_RPC_URL`. Loads pair from chain; token decimals and symbols are fetched from each token contract (ERC-20 `decimals()` / `symbol()`).
- Output: one-line header (X → Y, pool), reserves, spot price, then one line per size (in → out, exec price, impact %), then max trade for 1% impact.

### chain_analyzer (`scripts/transaction_analyzer_cli.rs`)
- CLI to analyze a transaction. Usage: `chain_analyzer <TX_HASH> [--rpc URL]` (or `just analyzer <TX_HASH> [--rpc URL]`).
- Requires `INFURA_API_KEY`, `ETH_RPC_URL`, or `--rpc`. Fetches tx and receipt via `ChainClient::get_transaction` / `get_receipt`; block timestamp via `ChainClient::get_block`; for token transfers parses `Transfer(address,address,uint256)` logs and fetches token `decimals()` / `symbol()` via `eth_call`.
- Output: Transaction Analysis (hash, block, timestamp UTC, status, from/to/value), Gas Analysis (limit, used, base/priority/effective fee, tx fee), Function Called (selector and known name, ABI-decoded args for swapExactTokensForTokens-style calldata), Token Transfers (from/to/amount with symbol), Swap Summary when exactly two transfers (sold/received, execution price).

### integration_test (`scripts/integration_test.rs`)
- Integration test: loads wallet from env, fetches balance, builds a simple transfer (to fixed Sepolia address, 0.0001 ETH), prints build details (to, value, gas, max fee, max priority), signs, sends, waits for receipt, then prints block, status, gas used, fee.
- Run: `just integration-test`. Requires `SECRET_KEY` and `INFURA_API_KEY` in env. Uses Sepolia Infura URL.

### rebalancer_cli (`scripts/rebalancer_cli.rs`)
- CLI for inventory rebalance planning. Usage: `rebalancer_cli --check | --plan ASSET [--demo] [--test]`.
- `--check`: show skew report for all assets across Binance and wallet.
- `--plan ASSET`: show rebalance plan for a specific asset (e.g. ETH).
- `--demo`: use hardcoded demo data (no env vars).
- `--test`: use Infura Sepolia testnet for wallet balance.
- Requires `BINANCE_TESTNET_API_KEY`, `BINANCE_TESTNET_SECRET`, `SECRET_KEY`, and `INFURA_API_KEY` (or `ALCHEMY_API_KEY` or `ETH_RPC_URL`) for live data.
- Run: `just rebalancer --check` or `just rebalancer --plan ETH`.

### pnl_cli (`scripts/pnl_cli.rs`)
- CLI for PnL summary and trade display. Usage: `pnl_cli --summary [--demo]`.
- `--summary`: show aggregate PnL stats and recent trades.
- `--demo`: use hardcoded sample trades (no env vars).
- Run: `just pnl --summary [--demo]`.

## Core

Core is organized into modules: `address`, `utility`, `signatures`, `token`, `token_amount`, `transaction_receipt`, `base_types`, `wallet_manager`, `serializer`, `signature_algorithms`. The `address` module defines `Address` and `AddressError`; `utility` re-exports them so existing imports (e.g. from `base_types`) remain valid. `token` is declared before `token_amount` (dependency order).

### address (`core/address.rs`)
- Defines `Address` and `AddressError`.
- `Address::zero()` — zero address (native ETH / placeholder)
- `Address::from_string`, `checksum`, `lower`, `validate`, `alloy_address`, `to_string`
- `AddressError`

### utility (`core/utility.rs`)
- Re-exports `Address`, `AddressError` from the address module.
- `Message`
- `TypedData::new`
- `Transaction` — `from: Option<Address>` (parsed from RPC when present), `to`, `value`, `data`, gas fields, `chain_id`
- `Transaction::to_eip1559` (internal), `eip1559_signature_hash` — EIP-1559 signing hash uses Alloy's encoding (0x02 || RLP) so node recovers correct sender
- `Transaction::to_transaction_request`, `to_dict`, `from_web3`
- `SignedTransaction::new` (RLP-encodes EIP-1559), `from_raw`, `hex`, `raw`

### signatures (`core/signatures.rs`)
- `Signature::new`, `to_bytes`, `to_hex`
- `SignedMessage::new` (verifies before creating), `verify`, `recover_signer`, `algorithm`

### token (`core/token.rs`)
- **Token** — currency identity: `decimals`, `symbol`. No address in core. `Token::new(decimals, symbol)`, `Token::native_eth()` = 18 decimals, "ETH". `decimals()`, `symbol()` → `Option<&str>`.

### token_amount (`core/token_amount.rs`)
- `TokenAmount { raw, token }` — amount of a currency; identity from `Token` only (no address in core)
- `TokenAmount::new(raw, token: Token)`, `from_human(amount, token: Token)`, `human()` (no floats)
- `TokenAmount::native_eth(raw)`, `from_human_native_eth(amount)` — native ETH (tx value, balance, fee) = `new(raw, Token::native_eth())`
- `decimals()`, `symbol()` → `Option<&str>` (from `token`)
- `try_add`, `try_mul` — require same token; `TokenAmountError::TokenMismatch`, `Overflow`
- `Mul<u8|u16|u32|u64|u128>` (no negative check); `Mul<i8|…|i128>` panics on negative factor.

### transaction_receipt (`core/transaction_receipt.rs`)
- Uses `address::Address` for `Log.address`.
- `TransactionReceipt::from_web3` (parses hex or numeric), `tx_fee`
- `Log`

### serializer (`core/serializer.rs`)
- `DeterministicSerializer::serialize` (canonical JSON), `hash`, `verify_determinism`

### signature_algorithms (`core/signature_algorithms.rs`)
- `Eip191Hasher`, `Eip712Hasher`, `TransactionHasher` (EIP-1559; uses `Transaction::eip1559_signature_hash` so signature matches node recovery)
- `sign_with_algorithm`, `verify_and_recover_with_algorithm`, `recover_signer_with_algorithm`, `compute_hash_with_algorithm`
- `derive_public_key_from_private_key`, `derive_address_from_public_key`

### wallet_manager (`core/wallet_manager.rs`)
- `WalletManager::from_hex_string`, `from_env`, `generate`, `address`, `public_key`
- `sign_message` (EIP-191), `sign_typed_data` (EIP-712), `sign_transaction`
- `sign_transaction` validates `tx.to` via `Address::validate()` before signing; invalid format returns `TransactionError::InvalidAddress`.
- `Display` / `ToString`: show only `WalletManager(0x<address>)`; private key never printed (security).
- `Debug`: shows only `address` (derived); key material never in logs or panic output.

### base_types (`core/base_types.rs`)
- Re-exports only: from utility (so `Address`, `AddressError` come via utility from address), signatures, token_amount, token (`Token` only; no address in core), transaction_receipt.

## Chain

### url_wrapper (`chain/url_wrapper.rs`)
- `RpcUrl::new` (template with exactly one `{}`), `as_url`, `redacted` (Display/Debug show `****`)
- `validate` (connectivity check via `get_chain_id`)

### errors (`chain/errors.rs`)
- `ChainClientCreationError`, `ChainClientError`
- `all_endpoints_failed` (helper for fallback error aggregation)

### gas_price (`chain/gas_price.rs`)
- `GasPrice::new`, `get_max_fee`
- `Priority` enum (Low/Medium/High); `FromStr` for `"low"` | `"medium"` | `"high"`

### parsers (`chain/parsers.rs`)
- `parse_tx_hash` (validates 0x-prefixed 64-char hex)
- `parse_block_id` (accepts `"latest"`, `"pending"`, `"earliest"`, or block number)

### receipt_polling (`chain/receipt_polling.rs`)
- `poll_for_receipt` (polls all URLs until found or timeout)
- `try_get_receipt_from_url_async`

### chain_client (`chain/chain_client.rs`)
- `ChainClient::new(rpc_urls, timeout, max_retries)` — requires non-empty `rpc_urls`, creates Tokio runtime. For each RPC call: tries each URL in order; per URL, retries up to `max_retries` times (1 initial attempt + retries) before moving to the next URL. `timeout` is stored for future use (e.g. request timeouts).
- `get_chain_id`, `get_balance`, `get_nonce` (accepts `"latest"`, `"pending"`, `"earliest"`, or block number), `get_gas_price`, `estimate_gas`
- `get_block(block)` — fetches block metadata by block id; returns `Block { number, timestamp }` (Unix timestamp)
- `send_transaction` (`eth_sendRawTransaction`), `wait_for_receipt` (polls until found or timeout)
- `get_transaction` (returns `TransactionNotFound` if not found), `get_receipt`, `call` (`eth_call`)
- **Block** — `number: u64`, `timestamp: u64` (Unix seconds)
- Tests in `tests/chain_client_tests.rs`: multi-URL fallback (first URL unreachable, second stub succeeds), `AllEndpointsFailed` for send_transaction/get_chain_id/get_balance, error classification. Uses `httpmock` (dev-dependency) for local JSON-RPC stubs; no second RPC/API key required.

### transaction_builder (`chain/transaction_builder.rs`)
- `TransactionBuilder::new(client, wallet)` — fluent builder for transactions
- Fluent setters: `to`, `value`, `data`, `nonce`, `gas_limit`
- `with_gas_estimate(buffer)` — estimate gas and set limit with buffer (e.g. 1.2 = 20% headroom); requires `to` (MissingField if omitted); delegates to `ChainClient::estimate_gas`
- `with_gas_price(priority)` — set gas from network; `priority`: `Priority` enum (or `s.parse::<Priority>()` for strings)
- Terminal: `build()` → `Transaction`; `build_and_sign()` → `SignedTransaction`; `send()` → tx hash; `send_and_wait(timeout)` → `TransactionReceipt`
- `TransactionBuilderError`: `MissingField`, `Chain`, `Wallet`
- Tests in `tests/transaction_builder_tests.rs`: build fails without `to`; `with_gas_estimate` requires `to` (MissingField); `with_gas_estimate` with `to` fails with Chain when RPC unreachable; build_and_sign without gas_limit or gas_price fails; fluent chaining; priority FromStr; with_gas_price accepts priority enum

## Inventory

Inventory module tracks positions across CEX (e.g. Binance) and on-chain wallet. Supports skew analysis, rebalance planning (planning only; no execution), and PnL tracking for arb trades.

### types (`inventory/types.rs`)
- **Venue** — `Binance`, `Wallet`; display as "binance", "wallet".
- **VenueSkew** — per-venue amount, pct, deviation_pct for skew analysis.
- **SkewResult** — asset, total, venues, max_deviation_pct, needs_rebalance.
- **PortfolioSnapshot** — timestamp, venues, totals, total_usd.
- **CanExecuteResult** — pre-flight check for arb execution.

### errors (`inventory/errors.rs`)
- **InventoryTrackerError** — `EmptyVenues`, `InvalidVenue`, `VenueNotTracked`, `ArithmeticOverflow`.

### tracker (`inventory/tracker.rs`)
- **InventoryTracker** — `new(venues)`, `update_from_cex`, `update_from_wallet`, `snapshot`, `get_available`, `can_execute`, `record_trade`, `skew`.
- `skew(asset)` — computes distribution skew; `needs_rebalance` when max_deviation_pct >= 30.
- Tests in `tests/inventory_tracker_tests.rs`.

### rebalancer (`inventory/rebalancer.rs`)
- **TransferPlan** — from_venue, to_venue, asset, amount, estimated_fee, estimated_time_min; `net_amount()`.
- **RebalancePlanner** — `new(tracker, threshold_pct, target_ratio)`, `check_all`, `plan`, `plan_all`, `estimate_cost`.
- Uses hardcoded transfer fees and min operating balances for ETH, USDT, USDC (testnet estimation).
- Plans only — does NOT execute transfers.
- Tests in `tests/rebalancer_tests.rs`.

### pnl (`inventory/pnl.rs`)
- **TradeLeg** — single execution leg: venue, symbol, side (OrderSide), amount, price, fee, fee_usd.
- **ArbRecord** — complete arb: buy_leg, sell_leg, gas_cost_usd; `gross_pnl()`, `total_fees()`, `net_pnl()`, `notional()`, `net_pnl_bps()`.
- **PnLEngine** — `record(trade)`, `summary()` (aggregate stats), `recent(n)`, `export_csv(path)`.
- **PnLSummary** — total_trades, total_pnl_usd, win_rate, sharpe_estimate, pnl_by_hour, etc.
- **ArbRecordSummary** — display-friendly trade summary for CLI.
- Tests in `tests/pnl_tests.rs`.

## Pricing

The pricing module integrates AMM math, routing, fork simulation, and mempool monitoring. Main entry point: `PricingEngine`.

### pricing_engine (`pricing/pricing_engine.rs`)
- **PricingEngine** — unified interface. `new(chain_client, fork_url, ws_url, chain, simulation_sender)` — requires fork URL; run `just fork` first.
- `load_pools(&[Address])` — loads Uniswap V2 pairs from chain, builds RouteFinder
- `refresh_pool(address)` — updates reserves for a single pool
- `get_quote(token_in, token_out, amount_in, gas_price_gwei, max_hops)` → `Quote` — finds best route, simulates on fork, returns expected_output, simulated_output, gas_estimate; `Quote::is_valid()` when simulation matches calculation
- **Quote** — route, amount_in, expected_output, simulated_output, gas_estimate, timestamp
- **QuoteError**, **PricingEngineError**
- Integration tests in `tests/pricing_engine_tests.rs` require running fork and valid RPC (`FORK_URL` or `http://127.0.0.1:8545`).

### route (`pricing/route.rs`)
- **Route** — `pools: Vec<UniswapV2Pair>`, `path: Vec<Token>`. `new`, `num_hops`, `simulate`, `get_output`, `get_intermediate_amounts`, `estimate_gas`, `path_addresses` (for fork simulation)
- **RouteFinder** — `new(pools)`, `find_all_routes(token_in, token_out, max_hops)` (bidirectional meet-in-the-middle), `find_best_route` (best net output after gas)
- **RouteComparison**, **RouteError**
- Tests in `tests/route_tests.rs`

### mempool_monitor (`pricing/mempool_monitor.rs`)
- **MempoolMonitor** — connects to WebSocket RPC, parses pending swap transactions (swapExactTokensForTokens, swapExactETHForTokens, swapExactTokensForETH)
- **ParsedSwap** — tx_hash, router, dex, method, token_in, token_out, amount_in, min_amount_out, deadline, sender, gas_price; `slippage_tolerance_with_expected`
- `parse_transaction` — parses raw tx into `ParsedSwap` when applicable
- **MempoolMonitorError**
- Tests in `tests/mempool_monitor_tests.rs` (require `INFURA_API_KEY` for WebSocket tests)

### uniswap_v2_pair (`pricing/uniswap_v2_pair.rs`)
- `Decimal` (rust_decimal) — re-exported for prices and impact; use `*`, `/`, `round_dp()`, `to_string()` etc. for calculations and display
- **TokenInPair** (swap/pricing only): `token: Token`, `address: Address` — used only for pair tokens and reserve lookup; not in core
- **Token** re-exported from core for building amounts and `TokenInPair`
- `UniswapV2Pair::new(address, token0: TokenInPair, token1: TokenInPair, reserve0, reserve1, fee_bps)` — pair tokens carry currency + contract address
- Input/output: `TokenAmount` (amount + `Token`). Which side of the pair is determined by **matching `Token`** to `pair.token0.token` or `pair.token1.token`; no address argument.
- `get_amount_out(amount_in: &TokenAmount)` → `TokenAmount` — side from `amount_in.token`; output in the other token's Token; matches Solidity formula
- `get_amount_in(amount_out: &TokenAmount)` → `TokenAmount` — side from `amount_out.token`; required input in the other token (inverse, rounds up)
- `get_spot_price(token_in: &Token)` → `Decimal` — spot price; prefer for display
- `get_execution_price(amount_in: &TokenAmount)` → `Decimal` — execution price; use for precise calculations
- `get_price_impact(amount_in: &TokenAmount)` → `Decimal` — impact as (spot - execution) / spot
- `simulate_swap(amount_in: &TokenAmount)` → `Self` — side from `amount_in.token`; new pair with updated reserves (for multi-hop)
- `reserve_for_token(token: &Token)` → `u128` — reserve of the given token (for sizing / upper bounds)
- `from_chain(address, client)` — fetch reserves and token0/token1 via `eth_call`; fetches ERC-20 `decimals()` and `symbol()` from each token contract; both must succeed (errors if symbol missing or call fails; no fallbacks)
- `UniswapV2PairError`: `TokenNotInPair`, `Chain`, `InvalidResponse`, `Overflow`, `TokenMetadataUnavailable` (decimals/symbol fetch required; no fallbacks)
- Tests for `from_chain` in `tests/uniswap_v2_pair_tests.rs` run only when `INFURA_API_KEY` is set and not the placeholder `apikey`; otherwise they skip (pass without network call).

### fork_simulator (`pricing/fork_simulator.rs`)
- **ForkSimulator** — simulates Uniswap V2 swaps on a local Anvil fork. `ForkSimulator::new(fork_url, chain)` accepts `Chain` enum or `ChainConfig` directly.
- **ChainConfig** / **Chain** — chain-specific router (Uniswap V2–compatible), WETH address, and chain_id. Predefined: `EthereumMainnet`, `Polygon`, `ArbitrumOne`, `Base`. Use `ChainConfig::custom` for others.
- **simulate_swap**, **simulate_route** — full swap via `eth_call`; `simulate_route` uses `Route::path_addresses`.
- **compare_simulation_vs_calculation** — uses Router `getAmountsOut` (view) to validate AMM math vs router; no token balance/approval needed.
- Run `just fork` to start Anvil (requires `ETH_RPC_URL` or `INFURA_API_KEY` in `.env`).
- Tests in `tests/fork_simulator_tests.rs` require running fork.

### price_impact_analyzer (`pricing/price_impact_analyzer.rs`)
- **PriceImpactAnalyzer** — analyzes price impact across different trade sizes; holds a `UniswapV2Pair`
- `new(pair: UniswapV2Pair)` — construct from a pair
- `generate_impact_table(token_in: &Token, sizes: &[u128])` → `Vec<ImpactRow>` — one row per size: `amount_in`, `amount_out`, `spot_price`, `execution_price`, `price_impact_pct`
- `find_max_size_for_impact(token_in: &Token, max_impact_pct: Decimal)` → `u128` — binary search for largest trade with impact ≤ max_impact_pct
- `estimate_true_cost(amount_in: &TokenAmount, gas_price_gwei: u64, gas_estimate: u64)` → `TrueCostResult`: gross_output, gas_cost_eth, gas_cost_in_output_token, net_output, effective_price; errors on overflow (net_output subtraction or decimal conversion); no fallbacks
- **ImpactRow** — single row: amount_in, amount_out, spot_price, execution_price, price_impact_pct
- **TrueCostResult** — gross_output, gas_cost_eth, gas_cost_in_output_token, net_output, effective_price
- **PriceImpactAnalyzerError**: `Pair(UniswapV2PairError)`, `Overflow`
- Tests in `tests/price_impact_analyzer_tests.rs`

## Tests

Integration tests in `tests/` (one file per module). Many require a **running Anvil fork** and **valid RPC** (`ETH_RPC_URL` or `INFURA_API_KEY`). Run `just fork` in a separate terminal before `just test`.

| Test file | Notes |
|-----------|-------|
| `address_derivation_tests.rs` | Address derivation from keys |
| `chain_client_tests.rs` | Multi-URL fallback, error classification; uses httpmock |
| `inventory_tracker_tests.rs` | Tracker CRUD, skew, can_execute |
| `pnl_tests.rs` | PnL engine: gross/net PnL, summary, CSV export |
| `rebalancer_tests.rs` | Rebalance planner checks and plans |
| `fork_simulator_tests.rs` | Requires fork |
| `key_security_tests.rs` | Wallet key handling |
| `key_validity_tests.rs` | Key validation |
| `mempool_monitor_tests.rs` | Requires `INFURA_API_KEY` for WebSocket |
| `price_impact_analyzer_tests.rs` | Price impact logic |
| `pricing_engine_tests.rs` | Requires fork |
| `route_tests.rs` | Route finding |
| `serializer_tests.rs` | Deterministic serialization |
| `signature_algorithm_tests.rs` | EIP-191/712 hashing |
| `signature_verification_tests.rs` | Signature verification |
| `spec_tests.rs` | Spec compliance |
| `token_amount_tests.rs` | TokenAmount math |
| `transaction_address_validation_tests.rs` | Address validation in txs |
| `transaction_builder_tests.rs` | Builder fluent API |
| `transaction_receipt_tests.rs` | Receipt parsing |
| `uniswap_v2_pair_tests.rs` | Pair math; `from_chain` requires `INFURA_API_KEY` |
| `url_wrapper_tests.rs` | RpcUrl redaction, display |

## Scripts

- `scripts/start_fork.sh` — starts Anvil fork. Requires `anvil` (Foundry). Uses `ETH_RPC_URL` or builds from `INFURA_API_KEY`. Port 8545.

## Build

- `just install` — install deps (rustup components + cargo build); cross-platform (Unix/Windows)
- `just` — default: lint → build → test
- `just lint`, `just build`, `just test`, `just run`, `just doc`, `just clean`, `just fmt`
- `just price-impact <PAIR> --token-in USDC --sizes 1000,10000,...`
- `just analyzer <TX_HASH> [--rpc URL]`
- `just rebalancer --check | just rebalancer --plan ETH [--demo] [--test]`
- `just pnl --summary [--demo]`
- `just integration-test` (requires `SECRET_KEY`, `INFURA_API_KEY`)
- `just fork` (requires `ETH_RPC_URL` or `INFURA_API_KEY` in `.env`)
