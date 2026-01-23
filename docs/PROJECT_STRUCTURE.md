# Project Structure Documentation

## Overview

This project is a Rust library for Ethereum wallet operations, providing secure cryptographic signing capabilities for messages, typed data (EIP-712), and transactions. The library implements Ethereum signature standards (EIP-191 and EIP-712) with a focus on security, type safety, and preventing accidental key exposure.

## Project Architecture

The project follows a modular architecture with clear separation of concerns:

```
peanut_task/
├── src/
│   ├── lib.rs              # Public API exports
│   ├── main.rs             # Binary entry point (demo)
│   ├── core/               # Core implementation modules
│   │   ├── mod.rs          # Module declarations
│   │   ├── utility.rs      # Utility types (Address, Message, etc.)
│   │   ├── signatures.rs   # Signature types (Signature, SignedMessage)
│   │   ├── token_amount.rs # Token amount handling with precision
│   │   ├── transaction_receipt.rs # Transaction receipt parsing
│   │   ├── base_types.rs  # Re-exports from utility, signatures, token_amount, transaction_receipt
│   │   ├── serializer.rs   # Canonical JSON serialization
│   │   ├── signature_algorithms.rs # Signature algorithm implementations
│   │   └── wallet_manager.rs # Wallet operations wrapper
│   └── chain/              # Ethereum RPC client module
│       ├── mod.rs          # Module declarations
│       ├── chain_client.rs  # RPC client with reliability features
│       └── url_wrapper.rs  # Safe URL wrapper for API key protection
├── tests/                  # Integration tests
├── examples/               # Usage examples
└── docs/                   # Documentation
```

## Core Modules

### 1. `utility.rs` - Utility Types

**Purpose**: Defines utility types used throughout the library with security-focused design.

**Key Components**:

- **`Address`**: Ethereum address wrapper with validation and checksumming
  - `value`: The address string (stored in EIP-55 checksummed format)
  - `from_string(s)`: Creates an Address from a string, validates and converts to checksum format (equivalent to Python `from_string` class method and `__post_init__`)
  - `checksum()`: Returns the checksummed address (EIP-55 format, equivalent to Python `checksum` property)
  - `lower()`: Returns the lowercase address (equivalent to Python `lower` property)
  - `validate()`: Validates address format (0x prefix, 42 chars, 20 bytes)
  - Implements case-insensitive equality comparison (equivalent to Python `__eq__`)
  - Automatically converts addresses to EIP-55 checksummed format on creation
  - Error type: `AddressError`

- **`Message`**: Simple string message for EIP-191 signing

- **`TypedData`**: Structured data for EIP-712 signing
  - Contains domain, types, and value (all as JSON)

- **`Transaction`**: Ethereum transaction structure (ready to be signed)
  - `to`: Recipient address (required, `Address`)
  - `value`: Value to transfer (`TokenAmount`)
  - `data`: Transaction data (bytes, `Vec<u8>`)
  - `nonce`: Transaction nonce (optional, `Option<u64>`)
  - `gas_limit`: Gas limit (optional, `Option<u64>`)
  - `max_fee_per_gas`: Maximum fee per gas, EIP-1559 (optional, `Option<u64>`)
  - `max_priority_fee`: Maximum priority fee per gas, EIP-1559 (optional, `Option<u64>`)
  - `chain_id`: Chain ID for replay protection (defaults to 1, `u64`)
  - `to_dict()`: Converts to web3-compatible dict (serde_json::Value)
  - Implements `Default` trait with chain_id = 1

- **`SignedTransaction`**: Wrapper for signed transaction data

**Security Features**:
- Address validation ensures only valid addresses are used
- Private keys use `k256::ecdsa::SigningKey` which has secure Debug implementation

### 2. `signatures.rs` - Signature Types

**Purpose**: Defines signature-related types and structures.

**Key Components**:

- **`Signature`**: ECDSA signature representation
  - Contains r, s (32 bytes each) and v (recovery id)
  - Supports conversion to hex and raw bytes
  - `new()`: Creates from r, s, v components
  - `to_bytes()`: Returns 65-byte array
  - `to_hex()`: Returns hex string with 0x prefix

- **`SignedMessage`**: Type-safe wrapper for verified signatures
  - Can only be created through verification
  - Guarantees signature is cryptographically valid
  - Supports signer recovery
  - `verify()`: Verifies signature validity
  - `recover_signer()`: Recovers signer address
  - `algorithm()`: Returns the signature algorithm used

- **`SignatureError`**: Error type for signature operations
  - Wraps `SignatureAlgorithmError`
  - Provides signer mismatch error

**Security Features**:
- Type system prevents invalid signature creation
- Verification required for `SignedMessage` construction

### 3. `token_amount.rs` - Token Amount Handling

**Purpose**: Provides secure handling of token amounts with decimal precision.

**Key Components**:

- **`TokenAmount`**: Token amount representation with precision
  - Stores raw amount in smallest unit (u128)
  - Decimal precision (u8, e.g., 18 for ETH, 6 for USDC)
  - Optional symbol (e.g., "ETH", "USDC")
  - `new()`: Creates from raw amount
  - `from_human()`: Creates from human-readable string (e.g., "1.5")
  - `human()`: Returns human-readable decimal as string (preserves precision, no floating-point)
  - `try_add()`: Adds two TokenAmounts, returns Result (validates same decimals)
  - `try_mul()`: Multiplies by integer factor, returns Result
  - `Add` trait: `+` operator for adding TokenAmounts (panics on error)
  - `Mul` trait: `*` operator for multiplying by integers (panics on error)
  - `Display` trait: Formats as "{human_readable} {symbol}" (e.g., "1.5 ETH")
  - All operations use integer arithmetic and string formatting to avoid precision loss

- **`TokenAmountError`**: Error type for token amount operations
  - `DecimalMismatch`: When adding amounts with different decimals
  - `Overflow`: When arithmetic operations overflow

**Design Principles**:
- No floating-point arithmetic (prevents precision loss)
- Integer-based calculations with string formatting
- Type-safe operations with clear error handling

### 4. `transaction_receipt.rs` - Transaction Receipt Parsing

**Purpose**: Provides parsing of Ethereum transaction receipts from web3 format, including transaction fees calculation and log parsing.

**Key Components**:

- **`TransactionReceipt`**: Parsed transaction receipt
  - Contains transaction hash, block number, status, gas information, and logs
  - `tx_fee()`: Returns transaction fee as `TokenAmount` (gas_used * effective_gas_price)
  - `from_web3()`: Parses from web3 receipt dict (serde_json::Value)
  - Supports both hex string and numeric formats for numeric fields
  - Handles status as hex string ("0x1"/"0x0") or number (1/0)

- **`Log`**: Ethereum transaction log entry
  - Contains address, topics, and data fields
  - Used within `TransactionReceipt` to represent event logs
  - Supports parsing from web3 log format

- **`TransactionReceiptError`**: Error type for transaction receipt parsing
  - `MissingField`: When a required field is missing
  - `InvalidFormat`: When a field has invalid format or type

**Design Principles**:
- Flexible parsing supporting both hex strings and numbers
- Comprehensive error handling with clear error messages
- Type-safe receipt representation

### 5. `base_types.rs` - Base Types Re-exports

**Purpose**: Convenience module that re-exports all base types from utility, signatures, token_amount, and transaction_receipt modules.

**Usage**: Provides a single import point for all core types:
```rust
use peanut_task::core::base_types::*;
```

This allows importing all types from one location while maintaining the modular structure.

### 6. `serializer.rs` - Canonical JSON Serialization

**Purpose**: Provides deterministic JSON serialization for cryptographic operations.

**Key Features**:

- **Deterministic Serialization**: Same JSON data always produces same bytes
  - Keys sorted alphabetically (recursively for nested objects)
  - Compact format (no whitespace)
  - Consistent encoding

- **Keccak-256 Hashing**: Computes 32-byte hashes of JSON data
  - Used for EIP-712 typed data hashing
  - Ensures consistent hashing regardless of key order

- **Determinism Verification**: Tests that different key orders produce identical output

**Algorithm**:
1. Recursively sort all object keys alphabetically
2. Serialize to compact JSON (no whitespace)
3. Convert to bytes for hashing

**Usage**: Critical for EIP-712 where domain, types, and value must be hashed deterministically.

### 7. `signature_algorithms.rs` - Signature Algorithm Implementations

**Purpose**: Implements Ethereum signature standards with compile-time type safety.

**Key Components**:

#### Signature Algorithm Types

- **`Eip191Hasher`**: Personal message signing (EIP-191)
  - Prefix: `"\x19Ethereum Signed Message:\n" + message_length`
  - Hashes with Keccak-256
  - Used for simple message signing

- **`Eip712Hasher`**: Typed structured data signing (EIP-712)
  - Uses canonical JSON serialization
  - Creates domain separator hash
  - Combines domain and message hashes: `keccak256("\x19\x01" + domainHash + messageHash)`
  - Used for complex structured data signing

- **`TransactionHasher`**: Transaction signing
  - Serializes transaction fields to bytes
  - Uses EIP-155 encoding: `v = chain_id * 2 + 35 + recovery_id`
  - Hashes with Keccak-256

#### SignatureHasher Trait

Provides a unified interface for all signature algorithms:
- `compute_hash()`: Computes the hash to be signed
- `sign()`: Signs data with a private key
- `verify_and_recover()`: Verifies signature and recovers signer address

**Algorithms Used**:

1. **ECDSA (secp256k1)**: Elliptic curve digital signature algorithm
   - Uses `k256` crate (Rust implementation)
   - Private keys are 32 bytes
   - Public keys are 65 bytes (uncompressed)

2. **Keccak-256**: Cryptographic hash function
   - Used for message hashing
   - Used for address derivation (last 20 bytes of public key hash)
   - Used for EIP-712 domain/message hashing

3. **Address Derivation**:
   - Public key → Keccak-256 hash → last 20 bytes → hex with 0x prefix

**Runtime Dispatch Functions**:
- `sign_with_algorithm()`: Signs based on `SignatureData` type
- `verify_and_recover_with_algorithm()`: Verifies and recovers signer
- `recover_signer_with_algorithm()`: Recovers signer without verification
- `compute_hash_with_algorithm()`: Computes hash based on data type

### 8. `wallet_manager.rs` - Wallet Operations Wrapper

**Purpose**: High-level interface for wallet operations that prevents direct key access.

**Key Features**:

- **Key Management**:
  - `from_hex_string()`: Load private key from hex string
  - `from_env()`: Load private key from environment variable
  - `generate()`: Generate new random private key
  - Validates keys are cryptographically valid for secp256k1

- **Address Operations**:
  - `address()`: Derives Ethereum address from private key
  - `public_key()`: Gets public key (VerifyingKey)

- **Signing Operations**:
  - `sign_message()`: Signs a message using EIP-191
  - `sign_typed_data()`: Signs typed data using EIP-712
  - `sign_transaction()`: Signs a transaction

**Security Design**:
- Private key is never directly accessible
- All operations go through `WalletManager`
- Debug output shows key hash, not actual key
- Signatures are automatically verified upon creation

### 9. `chain/url_wrapper.rs` - RPC URL Wrapper

**Purpose**: Provides a secure wrapper that stores a URL template and API key separately, preventing accidental exposure of sensitive information (like API keys) in logs or error messages. Also provides RPC endpoint validation.

**Key Components**:

- **`RpcUrl`**: Safe wrapper that stores URL template and API key separately
  - Stores a URL template with `{}` placeholder for the API key
  - Stores the API key separately (never exposed in Display/Debug)
  - Stores the parsed `Url` (validated at construction time)
  - `new()`: Creates a RpcUrl from a URL template and API key
    - Template must contain exactly one `{}` placeholder (e.g., "https://api.example.com/v1?key={}")
    - Validates that the formatted URL is valid and parses it
    - Returns `Result<RpcUrl, RpcUrlError>` if validation fails
  - `as_url()`: Returns a reference to the full `Url` with the actual API key (always succeeds, validated at construction)
  - `redacted()`: Returns a redacted version of the URL with `****` instead of the API key
  - `validate()`: Validates the RPC endpoint by attempting to connect and make a test RPC call
    - Returns `Result<(), RpcUrlValidationError>` indicating if the endpoint is reachable
    - Uses `get_chain_id()` as a lightweight validation call
  - Implements `Display` and `Debug` to show redacted URLs with `****`

- **`RpcUrlError`**: Errors that can occur during RpcUrl construction
  - `InvalidPlaceholderCount`: Template doesn't have exactly one `{}` placeholder
  - `InvalidUrl`: URL cannot be parsed after formatting

- **`RpcUrlValidationError`**: Errors that can occur during RPC endpoint validation
  - `UrlUnreachable`: Network/connection issues (connection, network, timeout, unreachable)
  - `UrlRpcError`: RPC endpoint returned an error during validation

**Security Features**:
- API keys are stored separately and never exposed in Display/Debug
- When displayed, the API key is replaced with `****` in the formatted URL
- Full URL with actual API key only accessible via explicit method (`as_url()`)
- Prevents accidental API key exposure in error messages or logs
- URL format is validated at construction time, ensuring `as_url()` always succeeds

### 10. `chain/chain_client.rs` - Ethereum RPC Client

**Purpose**: Provides a reliable Ethereum RPC client with automatic retry, fallback endpoints, and proper error handling.

**Key Components**:

- **`ChainClient`**: Ethereum RPC client with reliability features
  - `rpc_urls`: List of RPC endpoint URLs as `RpcUrl` (with fallback support)
  - `timeout`: Request timeout in seconds
  - `max_retries`: Maximum number of retries per request
  - `runtime`: Tokio runtime for async operations (internal)
  - `new()`: Creates a new ChainClient with configuration (returns `Result<ChainClient, ChainClientCreationError>`)
  - `get_balance()`: Gets the balance of an address
  - `get_nonce()`: Gets the nonce of an address (takes `block` parameter: "latest", "pending", "earliest", or block number)
  - `get_gas_price()`: Returns current gas price information
  - `estimate_gas()`: Estimates gas required for a transaction
  - `send_transaction()`: Sends a signed transaction (returns tx hash) - **Not yet implemented**
  - `wait_for_receipt()`: Waits for transaction confirmation - **Not yet implemented**
  - `get_transaction()`: Gets transaction information by hash - **Not yet implemented**
  - `get_receipt()`: Gets transaction receipt by hash - **Not yet implemented**
  - `call()`: Simulates a transaction without sending (eth_call) - **Not yet implemented**

- **`GasPrice`**: Current gas price information
  - `base_fee`: Base fee per gas (in wei)
  - `priority_fee_low`: Low priority fee estimate (in wei)
  - `priority_fee_medium`: Medium priority fee estimate (in wei)
  - `priority_fee_high`: High priority fee estimate (in wei)
  - `new()`: Creates a new GasPrice instance
  - `get_max_fee()`: Calculates maxFeePerGas with buffer for base fee increase - **Not yet implemented**

- **`ChainClientCreationError`**: Error type for ChainClient creation
  - `NoRpcUrlsProvided`: No RPC URLs were provided during construction
  - `TokioRuntimeError`: Failed to create Tokio runtime

- **`ChainClientError`**: Error type for ChainClient operations
  - `RpcError`: RPC request failed
  - `NetworkError`: Network error occurred
  - `TimeoutError`: Request timed out
  - `InvalidResponse`: Invalid response from RPC
  - `AllEndpointsFailed`: All RPC endpoints failed
  - `TransactionNotFound`: Transaction not found
  - `InvalidPriority`: Invalid priority level

**Features**:
- Multiple RPC endpoint fallback (tries URLs in sequence until one succeeds)
- Automatic retry with exponential backoff - **Not yet implemented** (max_retries field stored but unused)
- Request timing/logging - **Not yet implemented**
- Proper error classification

**Design Principles**:
- Reliability through retry and fallback mechanisms
- Clear error handling with descriptive error types
- Type-safe operations using existing core types

## Module Interconnections

**Public API (lib.rs)**:
- Modules: `core`, `chain`
- Re-exports: `SignatureAlgorithm`, `SignatureData`, `SignatureAlgorithmError`, `TypedData`

**Dependency Flow**:

1. **Base modules** (no dependencies on other core modules):
   - `utility`: Base types (Address, Message, TypedData, Transaction, SignedTransaction)
   - `serializer`: Canonical JSON serialization
   - `token_amount`: Token amount handling

2. **Dependent modules**:
   - `signatures`: Uses `utility` (Address) and `signature_algorithms`
   - `signature_algorithms`: Uses `utility`, `signatures` (Signature), `serializer`
     (Note: Circular dependency between `signatures` ↔ `signature_algorithms` is resolved at compile time)
   - `transaction_receipt`: Uses `utility` (Address) and `token_amount` (TokenAmount)
   - `wallet_manager`: Uses `utility`, `signatures`, `signature_algorithms`

3. **Re-export module**:
   - `base_types`: Re-exports from `utility`, `signatures`, `token_amount`, `transaction_receipt`
     (No runtime dependencies, just convenience re-exports)

4. **Chain module**:
   - `url_wrapper`: Standalone (RPC URL wrapper)
   - `chain_client`: Uses `core::base_types` (re-exports all core types) and `chain::RpcUrl`

## Data Flow Examples

### Message Signing (EIP-191)

```
1. User creates Message("Hello")
2. WalletManager.sign_message()
   └─> Uses SigningKey (from k256)
   └─> Eip191Hasher.sign()
       └─> Eip191Hasher.compute_hash()
           └─> Prefix: "\x19Ethereum Signed Message:\n" + len
           └─> Keccak-256 hash
       └─> ECDSA sign with recovery
       └─> Returns Signature {r, s, v}
   └─> Creates SignedMessage
       └─> Verifies signature matches wallet address
3. Returns SignedMessage (guaranteed valid)
```

### Typed Data Signing (EIP-712)

```
1. User provides domain, types, value (JSON)
2. WalletManager.sign_typed_data()
   └─> Creates TypedData struct
   └─> Eip712Hasher.sign()
       └─> Eip712Hasher.compute_hash()
           └─> Serializer::hash(domain)
           └─> Serializer::hash(types)
           └─> Serializer::hash(value)
           └─> Combine: keccak256("\x19\x01" + domainHash + messageHash)
       └─> ECDSA sign with recovery
       └─> Returns Signature {r, s, v}
   └─> Creates SignedMessage
       └─> Verifies signature matches wallet address
3. Returns SignedMessage (guaranteed valid)
```

### Address Derivation

```
1. SigningKey (from k256, wraps 32-byte private key)
2. Derive public key (secp256k1)
   └─> SigningKey → VerifyingKey
3. Get uncompressed public key (65 bytes: 0x04 + X + Y)
4. Hash with Keccak-256
   └─> Skip 0x04 prefix, hash 64 bytes
5. Take last 20 bytes
6. Format as hex with 0x prefix
7. Validate address format
8. Return Address
```

## Algorithms and Cryptographic Primitives

### 1. ECDSA (secp256k1)
- **Purpose**: Digital signatures
- **Library**: `k256` crate
- **Key Sizes**: 
  - Private key: 32 bytes
  - Public key: 65 bytes (uncompressed)
- **Signature Format**: r (32 bytes) + s (32 bytes) + v (1 byte)

### 2. Keccak-256
- **Purpose**: Cryptographic hashing
- **Library**: `sha3` crate
- **Output**: 32 bytes
- **Usage**:
  - Message hashing (EIP-191)
  - Address derivation
  - EIP-712 domain/message hashing


### 4. Canonical JSON Serialization
- **Purpose**: Deterministic JSON representation
- **Algorithm**:
  1. Recursively sort object keys alphabetically
  2. Serialize to compact JSON (no whitespace)
  3. Convert to UTF-8 bytes
- **Critical for**: EIP-712 typed data hashing

## Security Features

1. **Private Key Protection**:
   - Keys use `k256::ecdsa::SigningKey` which has secure Debug implementation
   - Debug output doesn't expose actual key bytes
   - No direct key access outside `WalletManager`

2. **Signature Verification**:
   - `SignedMessage` can only be created through verification
   - Ensures signatures are cryptographically valid
   - Prevents invalid signatures from being used

3. **Address Validation**:
   - All addresses validated before use
   - Ensures proper format (0x prefix, 42 chars, 20 bytes)

4. **Key Validation**:
   - Private keys validated for secp256k1 curve
   - Ensures keys are in valid range
   - Prevents weak/invalid keys

5. **Type Safety**:
   - Compile-time guarantees for signature algorithms
   - Prevents mixing incompatible data types
   - Runtime dispatch for `SignatureData` enum

## Testing Strategy

The project includes comprehensive tests:

- **`address_derivation_tests.rs`**: Tests address derivation from keys
- **`key_security_tests.rs`**: Tests key security (no accidental exposure)
- **`key_validity_tests.rs`**: Tests key validation and loading
- **`serializer_tests.rs`**: Tests canonical JSON serialization
- **`signature_algorithm_tests.rs`**: Tests signature algorithm correctness
- **`signature_verification_tests.rs`**: Tests signature verification
- **`spec_tests.rs`**: Specification compliance tests (verifies code follows specific requirements)
- **`token_amount_tests.rs`**: Tests TokenAmount creation, parsing, formatting, and edge cases
- **`transaction_address_validation_tests.rs`**: Tests transaction address validation
- **`transaction_receipt_tests.rs`**: Tests transaction receipt parsing and fee calculation
- **`url_wrapper_tests.rs`**: Tests RpcUrl redaction, validation, and API key protection

## Usage Patterns

### Basic Message Signing

```rust
let wallet = WalletManager::from_hex_string("0x...")?;
let message = Message("Hello, Ethereum!".to_string());
let signed = wallet.sign_message(message);
```

### Typed Data Signing

```rust
let wallet = WalletManager::from_hex_string("0x...")?;
let domain = json!({"name": "MyApp", "version": "1"});
let types = json!({"Person": [...]});
let value = json!({"name": "Alice"});
let signed = wallet.sign_typed_data(domain, types, value)?;
```

### Transaction Signing

```rust
let wallet = WalletManager::from_hex_string("0x...")?;
let tx = Transaction {
    nonce: 0,
    gas_price: 20000000000,
    gas_limit: 21000,
    to: Some(Address("0x...".to_string())),
    value: 1000000000000000000,
    data: vec![],
    chain_id: 1,
};
let signed_tx = wallet.sign_transaction(tx)?;
```

## Dependencies

- **`alloy`**: Ethereum RPC client library (used in chain module for provider operations)
- **`k256`**: ECDSA/secp256k1 cryptography (provides SigningKey with secure Debug)
- **`sha3`**: Keccak-256 hashing (Ethereum standard)
- **`serde`/`serde_json`**: JSON serialization
- **`hex`**: Hex encoding/decoding
- **`thiserror`**: Error handling
- **`getrandom`**: Cryptographically secure random number generation
- **`dotenvy`**: Environment variable loading
- **`url`**: URL parsing and validation (used in url_wrapper)
- **`tokio`**: Async runtime (used in chain_client for async RPC operations)
- **`reqwest`**: HTTP client (transitive dependency via alloy)
- **`sha2`**: SHA-2 hashing (available but not currently used)

## Build System

The project uses `just` for build commands (per project conventions):

- `just test`: Run all tests
- `just lint`: Run clippy and fmt checks
- `just build`: Build the project
- `just run`: Run the binary
- `just doc`: Generate and open documentation

## Design Principles

1. **Security First**: Private keys never directly accessible
2. **Type Safety**: Compile-time guarantees where possible
3. **Determinism**: All cryptographic operations are deterministic
4. **Validation**: Inputs validated at boundaries
5. **Zero-Copy**: Efficient memory usage where possible
6. **Clear Errors**: Descriptive error messages with `thiserror`

## Future Extensibility

The architecture supports easy extension:

- New signature algorithms: Implement `SignatureHasher` trait
- New data types: Add to `SignatureData` enum
- New operations: Extend `WalletManager`
- New validations: Extend validation in `basic_structs`
