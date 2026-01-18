## Requirements

- Python +3.11
- [uv](https://github.com/astral-sh/uv) (global install recommended)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/klucly/peanut_task.git
   cd peanut_task
   ```

2. Install uv (if not already installed):

    Windows:
   ```powershell
   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
   ```

    Linux:
    ```bash
    curl -LsSf https://astral.sh/uv/install.sh | sh
    ```

    MacOS:
    ```bash
    brew install uv
    ```

3. Sync dependencies (creates `.venv` and installs everything):

   ```bash
   make install
   ```

## Run the Project

```bash
make run
```

## Example Output

Current implementation (as of initial version):

```
IM WORKING LOL
```

## Limitations & Assumptions

- **Python version**: Tested on 3.14.2. May work on 3.11 - 3.13 but not guaranteed.
- **Error handling**: Minimal – assumes happy path.
- **Platform**: Developed on Linux (Arch). Should work on macOS/Windows but file paths / env vars may need tweaks.

## Development Commands (Makefile cheatsheet)

```bash
make install     # sync dependencies
make lint        # run ruff + basedpyright checks
make test        # run pytest
make run         # run the main script
make clean       # remove caches, venv, dist/
```
