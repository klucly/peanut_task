
# peanut_task

A test task for getting into Penut Trade.

## Requirements
- Rust 1.80+ (2024 edition or newer recommended)
- [just](https://github.com/casey/just) command runner (install via `cargo install just` or your package manager)
- [rustup](https://rustup.rs/) recommended for managing toolchains & components (rust-analyzer, clippy, etc.)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/klucly/peanut_task.git
   cd peanut_task
   ```

2. Install `just` (if not already installed):
   - Arch Linux:
     ```bash
     sudo pacman -S just
     ```
   - Most systems (via Cargo):
     ```bash
     cargo install just
     ```
   - Homebrew (macOS):
     ```bash
     brew install just
     ```
   - Other options: see https://github.com/casey/just#installation

3. Install common Rust components (optional but recommended for development):
   ```bash
   rustup component add rust-src clippy rustfmt
   ```

4. Sync dependencies & build (creates `target/`):
   ```bash
   just install
   ```
   (This usually just runs `cargo build` + `cargo fmt`/`clippy` checks — see Development Commands below)

## Setup .env

Copy `.env.example/` to `.env`

## Run the Project

```bash
just run
```

(Or with arguments: `just run -- --verbose`)

## Example Output

Sample output from `just run`:

```
Balance: 800.86843519544927043
Nonce - pending: 35887, latest: 35887, earliest: 0
Gas - base: 0 gwei, max fees - low: 0 gwei, medium: 0 gwei, high: 1 gwei
TransactionBuilder: built tx to 0x742D35CC6634c0532925A3b844BC9E7595F0BEb0, value 0.001, gas_limit Some(25200)
Gas estimate: 21000 units
Call result: 0 bytes
Transaction: 0x388C818CA8B9251b393131C08a736A67ccB19297 -> 0.008653912357036746
Receipt: block 24320264, status: success
Send transaction (expected error): All RPC endpoints failed: RPC request failed: eth_sendRawTransaction failed: server returned an error response: error code -32602: Invalid parameters: transaction could not be decoded: unsupported transaction type
```

## Limitations & Assumptions
- **Rust version**: Tested with stable 1.84+. May work on older editions but not guaranteed.
- **Error handling**: RPC failures trigger fallback across configured endpoints; some flows (e.g. send) deliberately exercise expected-error paths (e.g. unsupported transaction type). Not all error paths are fully surfaced to the user.
- **Platform**: Developed on Linux (Arch). Should work on macOS/Windows but shell commands in `justfile` or file paths / env vars may need minor tweaks.
- **dotenv**: Loads `.env` at runtime if present.

## Development Commands (just cheatsheet)

Run `just --list` to see all available commands with descriptions.

Common ones:

```bash
just              # Runs the default pipeline: lint → build → test
just all          # lint + build + test + doc
just ci           # Same as CI would run (lint + build + test)
just run          # cargo run (with optional args: just run -- --help)
just test         # cargo test
just test-watch   # Watch mode for TDD (requires cargo-watch)
just lint         # cargo fmt --check + clippy
just fmt          # cargo fmt --all
just doc          # cargo doc --open
just clean        # cargo clean
just nextest      # cargo nextest run (if you add nextest)
```

