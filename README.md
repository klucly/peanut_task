
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

Current implementation (as of initial version):

```
Secret info: `123`
Works
```

## Limitations & Assumptions
- **Rust version**: Tested with stable 1.84+. May work on older editions but not guaranteed.
- **Error handling**: Minimal – assumes happy path for baseline.
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

