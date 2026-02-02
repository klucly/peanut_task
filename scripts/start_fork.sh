#!/bin/bash
# Requires: anvil (from foundry)
# Install: curl -L https://foundry.paradigm.xyz | bash && foundryup
# Requires: ETH_RPC_URL or INFURA_API_KEY
set -o pipefail

if [ -z "${ETH_RPC_URL:-}" ] && [ -n "${INFURA_API_KEY:-}" ]; then
    ETH_RPC_URL="https://mainnet.infura.io/v3/${INFURA_API_KEY}"
fi

anvil \
    --fork-url ${ETH_RPC_URL:?Set ETH_RPC_URL or INFURA_API_KEY} \
    --port 8545 \
    --accounts 10 \
    --balance 10000 \
    2>&1 | sed -E 's/(v[23]\/)[^/[:space:]]+/\1***/g'
