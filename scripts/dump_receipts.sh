#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

RECEIPTS_FILE="${RECEIPTS_FILE:-/tmp/pe_receipts.json}"
TOP="${1:-30}"

BIN="./target/release/privacy-engine-rust"
if [[ -x "${BIN}" ]]; then
  exec "${BIN}" --dump-receipts --receipts-file "${RECEIPTS_FILE}" --top-hosts "${TOP}"
fi

exec cargo run -- --dump-receipts --receipts-file "${RECEIPTS_FILE}" --top-hosts "${TOP}"
