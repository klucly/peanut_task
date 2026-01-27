# Project Structure

## Overview

Rust library for Ethereum wallet operations: EIP-191/EIP-712 signing, transaction handling, and RPC.

## Core

### utility
- `Address::from_string`, `checksum`, `lower`, `validate`, `alloy_address`
- `Message`
- `TypedData::new`
- `Transaction::to_transaction_request`, `to_dict`, `from_web3`
- `SignedTransaction::new` (RLP-encodes EIP-1559), `from_raw`, `hex`, `raw`

### signatures
- `Signature::new`, `to_bytes`, `to_hex`
- `SignedMessage::new` (verifies before creating), `verify`, `recover_signer`, `algorithm`

### token_amount
- `TokenAmount::new`, `from_human`, `human` (no floats), `try_add`, `try_mul`

### transaction_receipt
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
Re-exports from utility, signatures, token_amount, transaction_receipt.

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

## Dependencies

`core`: utility, token_amount, serializer (base) → signatures, signature_algorithms, transaction_receipt, wallet_manager. `base_types` re-exports only. `chain`: url_wrapper; chain_client uses `core::base_types` and `RpcUrl`; transaction_builder uses chain_client, gas_price, and `core::wallet_manager`.

## Build

`just test`, `just lint`, `just build`, `just run`, `just doc`.
