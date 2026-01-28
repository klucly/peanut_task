# Project Structure

## Overview

Rust library for Ethereum wallet operations: EIP-191/EIP-712 signing, transaction handling, and RPC.

## Core

Core is organized into modules: `address`, `utility`, `signatures`, `token`, `token_amount`, `transaction_receipt`, `base_types`, `wallet_manager`, `serializer`, `signature_algorithms`. The `address` module defines `Address` and `AddressError`; `utility` re-exports them so existing imports (e.g. from `base_types`) remain valid. `token` is declared before `token_amount` (dependency order).

### address (`core/address.rs`)
- Defines `Address` and `AddressError` (moved out of utility to break dependency cycles and support token abstraction).
- `Address::zero()` — zero address (native ETH / placeholder)
- `Address::from_string`, `checksum`, `lower`, `validate`, `alloy_address`, `to_string`
- `AddressError`

### utility
- Re-exports `Address`, `AddressError` from the address module (does not define them).
- `Message`
- `TypedData::new`
- `Transaction::to_transaction_request`, `to_dict`, `from_web3`
- `SignedTransaction::new` (RLP-encodes EIP-1559), `from_raw`, `hex`, `raw`

### signatures
- `Signature::new`, `to_bytes`, `to_hex`
- `SignedMessage::new` (verifies before creating), `verify`, `recover_signer`, `algorithm`

### token (`core/token.rs`)
- **Token** — currency identity: `decimals`, `symbol`. No address in core. `Token::new(decimals, symbol)`, `Token::native_eth()` = 18 decimals, "ETH". `decimals()`, `symbol()` → `Option<&str>`.

### token_amount
- `TokenAmount { raw, token }` — amount of a currency; identity from `Token` only (no address in core)
- `TokenAmount::new(raw, token: Token)`, `from_human(amount, token: Token)`, `human()` (no floats)
- `TokenAmount::native_eth(raw)`, `from_human_native_eth(amount)` — native ETH (tx value, balance, fee) = `new(raw, Token::native_eth())`
- `decimals()`, `symbol()` → `Option<&str>` (from `token`)
- `try_add`, `try_mul` — require same token; `TokenAmountError::TokenMismatch`, `Overflow`
- `Mul<u8|u16|u32|u64|u128>` (no negative check); `Mul<i8|…|i128>` panics on negative factor.

### transaction_receipt
- Uses `address::Address` for `Log.address`.
- `TransactionReceipt::from_web3` (parses hex or numeric), `tx_fee`
- `Log`

### serializer
- `DeterministicSerializer::serialize` (canonical JSON), `hash`, `verify_determinism`

### signature_algorithms
- `Eip191Hasher`, `Eip712Hasher`, `TransactionHasher` (EIP-155)
- `sign_with_algorithm`, `verify_and_recover_with_algorithm`, `recover_signer_with_algorithm`, `compute_hash_with_algorithm`
- `derive_public_key_from_private_key`, `derive_address_from_public_key`

### wallet_manager
- `WalletManager::from_hex_string`, `from_env`, `generate`, `address`, `public_key`
- `sign_message` (EIP-191), `sign_typed_data` (EIP-712), `sign_transaction`

### base_types
Re-exports only: from utility (so `Address`, `AddressError` come via utility from address), signatures, token_amount, token (`Token` only; no address in core), transaction_receipt.

## Pricing

### uniswap_v2_pair
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
- `from_chain(address, client)` — fetch reserves and token0/token1 via `eth_call`; builds `TokenInPair::new(Token::new(18, None), addr)`
- `UniswapV2PairError`: `TokenNotInPair`, `Chain`, `InvalidResponse`, `Overflow`
- Tests for `from_chain` in `tests/uniswap_v2_pair_tests.rs` run only when `INFURA_API_KEY` is set and not the placeholder `apikey`; otherwise they skip (pass without network call).

## Chain

### url_wrapper
- `RpcUrl::new` (template with exactly one `{}`), `as_url`, `redacted` (Display/Debug show `****`)
- `validate` (connectivity check via `get_chain_id`)

### errors
- `ChainClientCreationError`, `ChainClientError`
- `all_endpoints_failed` (helper for fallback error aggregation)

### gas_price
- `GasPrice::new`, `get_max_fee`
- `Priority` enum (Low/Medium/High); `FromStr` for `"low"` | `"medium"` | `"high"`

### parsers
- `parse_tx_hash` (validates 0x-prefixed 64-char hex)
- `parse_block_id` (accepts `"latest"`, `"pending"`, `"earliest"`, or block number)

### receipt_polling
- `poll_for_receipt` (polls all URLs until found or timeout)
- `try_get_receipt_from_url_async`

### chain_client
- `ChainClient::new` (requires non-empty `rpc_urls`, creates Tokio runtime; tries URLs in order on failure)
- `get_chain_id`, `get_balance`, `get_nonce` (accepts `"latest"`, `"pending"`, `"earliest"`, or block number), `get_gas_price`, `estimate_gas`
- `send_transaction` (`eth_sendRawTransaction`), `wait_for_receipt` (polls until found or timeout)
- `get_transaction` (returns `TransactionNotFound` if not found), `get_receipt`, `call` (`eth_call`)

### transaction_builder
- `TransactionBuilder::new(client, wallet)` — fluent builder for transactions
- Fluent setters: `to`, `value`, `data`, `nonce`, `gas_limit`
- `with_gas_estimate(buffer)` — estimate gas and set limit with buffer (e.g. 1.2 = 20% headroom)
- `with_gas_price(priority)` — set gas from network; `priority`: `Priority` enum (or `s.parse::<Priority>()` for strings)
- Terminal: `build()` → `Transaction`; `build_and_sign()` → `SignedTransaction`; `send()` → tx hash; `send_and_wait(timeout)` → `TransactionReceipt`
- `TransactionBuilderError`: `MissingField`, `Chain`, `Wallet`

## Build

`just test`, `just lint`, `just build`, `just run`, `just doc`.
