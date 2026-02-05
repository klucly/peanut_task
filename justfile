# justfile  (run `just` or `just --list` to see available commands)

set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]
set dotenv-load    := true
set ignore-comments := true

default: lint build test

all: lint build test doc

# Install all dependencies required to build the project (rustup components + Cargo crates).
[unix]
install:
    rustup component add rust-src clippy rustfmt 2>/dev/null || true
    cargo build --all-targets --all-features

[windows]
install:
    rustup component add rust-src clippy rustfmt 2>$null; if (-not $?) { exit 0 }
    cargo build --all-targets --all-features

# ────────────────────────────────────────────────
# Development loop commands
# ────────────────────────────────────────────────

lint:
    cargo fmt --all -- --check || true
    cargo clippy --all-targets --all-features -- -D warnings

build:
    cargo build --all-targets --all-features

test *ARGS:
    cargo test --all-targets --all-features {{ARGS}}

test-security *ARGS:
    cargo test --test key_security_tests {{ARGS}}

test-validity *ARGS:
    cargo test --test key_validity_tests {{ARGS}}

test-watch *ARGS:
    cargo watch -x "test -- --nocapture {{ARGS}}"

# Run main.rs by default, or another binary: just run price_impact_cli
run bin="peanut_task" *ARGS:
    cargo run --bin {{bin}} -- {{ARGS}}

# Price impact CLI: pair address, --token-in USDC|ETH, --sizes 1000,10000,...
# Requires INFURA_API_KEY or RPC_URL.
price-impact *ARGS:
    cargo run --bin price_impact_cli -- {{ARGS}}

# Transaction analyzer CLI: tx hash, optional --rpc URL.
# Usage: just analyzer <TX_HASH> [--rpc URL]
analyzer *ARGS:
    cargo run --bin chain_analyzer -- {{ARGS}}
    
integration-test *ARGS:
    cargo run --bin integration_test -- {{ARGS}}

# Order book analysis CLI. Usage: just orderbook [ETH/USDT] [--depth 20] [--url BASE_URL]
# Requires BINANCE_TESTNET_API_KEY and BINANCE_TESTNET_SECRET.
orderbook *ARGS:
    cargo run --bin orderbook_cli -- {{ARGS}}

# Rebalance planner CLI. Usage: just rebalancer --check | just rebalancer --plan ETH [--demo] [--test]
# Live data: BINANCE_TESTNET_*, SECRET_KEY, INFURA_API_KEY or ALCHEMY_API_KEY or ETH_RPC_URL
# --test: use Infura Sepolia testnet for wallet
rebalancer *ARGS:
    cargo run --bin rebalancer_cli -- {{ARGS}}

# Start local Anvil fork. Requires ETH_RPC_URL.
fork:
    bash scripts/start_fork.sh

# ────────────────────────────────────────────────
# Longer / heavier commands
# ────────────────────────────────────────────────

ci: lint build test

doc:
    cargo doc --no-deps --open

clean:
    cargo clean

fmt:
    cargo fmt --all

# Optional: if you use nextest
nextest:
    cargo nextest run --all-features

bench:
    cargo bench

# Example: run one integration test file
test-int:
    cargo test --test '*'

# ────────────────────────────────────────────────
# Release helpers (optional)
# ────────────────────────────────────────────────

release version:
    cargo set-version {{version}}
    git commit -am "chore: release v{{version}}"
    git tag v{{version}}
    git push && git push --tags
    cargo publish