# justfile  (run `just` or `just --list` to see available commands)

set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]
set dotenv-load    := true
set ignore-comments := true

default: lint build test

all: lint build test doc

# ────────────────────────────────────────────────
# Development loop commands
# ────────────────────────────────────────────────

lint:
    cargo fmt --all -- --check || true
    cargo clippy --all-targets --all-features -- -D warnings

build:
    cargo build --all-targets --all-features

test:
    cargo test --all-targets --all-features

test-watch:
    cargo watch -x "test -- --nocapture"

run *ARGS:
    cargo run -- {{ARGS}}

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