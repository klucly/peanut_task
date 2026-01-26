# Project Structure

## Overview

Rust library for Ethereum wallet operations: EIP-191/EIP-712 signing, transaction handling, and RPC. Uses `k256` (secp256k1), Keccak-256, canonical JSON for EIP-712.

## Core

- **utility**: `Address` (EIP-55 checksum on creation), `Message` (EIP-191), `TypedData` (EIP-712), `Transaction`, `SignedTransaction`. `SignedTransaction::new(tx, sig)` RLP-encodes EIP-1559 signed tx; `SignedTransaction::from_raw(hex)` validates hex decodes to bytes. `hex()` returns 0x-prefixed hex, `raw()` returns bytes. `Transaction::to_dict` → web3-style JSON with hex-encoded values. `Transaction::to_transaction_request` → alloy `TransactionRequest` for `eth_call` / `eth_estimateGas` / `eth_sendTransaction`.
- **signatures**: `Signature` (r,s,v), `SignedMessage` — only constructible via `SignedMessage::new(..., expected_signer)`, which verifies before creating.
- **token_amount**: `raw` (smallest unit) + `decimals`; `from_human` / `human` for decimal string; no floats.
- **transaction_receipt**: `from_web3` parses hex or numeric for numeric fields. `tx_fee()` = `gas_used * effective_gas_price` as `TokenAmount` (18 decimals, ETH).
- **base_types**: Re-exports from utility, signatures, token_amount, transaction_receipt.
- **serializer**: Canonical JSON (keys sorted, no whitespace) + Keccak-256. Used for EIP-712; determinism required.
- **signature_algorithms**: `SignatureHasher` (compute_hash, sign, verify_and_recover). `Eip191Hasher` (personal sign), `Eip712Hasher` (typed data), `TransactionHasher` (EIP-155: `v = chain_id*2+35+recovery_id`). Address = last 20 bytes of Keccak( uncompressed pubkey without 0x04 ).
- **wallet_manager**: Holds `SigningKey`; no direct key access. `from_hex_string`, `from_env`, `generate`; `sign_message` (EIP-191), `sign_typed_data` (EIP-712), `sign_transaction`.

## Chain

- **url_wrapper**: `RpcUrl` — template with `{}` + separate API key; Display/Debug show redacted (`****`). `as_url()` for full URL; `validate()` does `get_chain_id` as connectivity check.
- **chain_client**: `ChainClient::new(rpc_urls, timeout_sec, max_retries)`. Tries `rpc_urls` in order on failure. `get_nonce(addr, block)`: `block` = `"latest"`|`"pending"`|`"earliest"` or block number. `send_transaction(signed_tx)`: `eth_sendRawTransaction` — `SignedTransaction` (0x-hex of RLP), returns tx hash (0x-hex). `call(tx, block)`: `eth_call` — simulates tx at `block`, returns return data or errors if the call would revert. `GasPrice`: `priority_fee_*` from `eth_feeHistory` 25/50/75 percentiles.

## Dependencies

`core`: utility, token_amount, serializer (base) → signatures, signature_algorithms, transaction_receipt, wallet_manager. `base_types` re-exports only. `chain`: url_wrapper; chain_client uses `core::base_types` and `RpcUrl`.

## Build

`just test`, `just lint`, `just build`, `just run`, `just doc`.
