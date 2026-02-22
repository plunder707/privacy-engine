#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# This script exists because long CLI invocations are fragile to copy/paste and terminal wrapping.
# It downloads EasyList once (if missing) and then runs the engine using the versioned JSON config.

EASYLIST_URL="https://easylist.to/easylist/easylist.txt"
EASYLIST_PATH="/tmp/easylist.txt"

if [[ ! -s "${EASYLIST_PATH}" ]]; then
  echo "Downloading EasyList to ${EASYLIST_PATH} ..." >&2
  curl -fsSL "${EASYLIST_URL}" -o "${EASYLIST_PATH}"
fi

exec ./scripts/run_engine_config.sh "${1:-configs/easylist.local.json}"

