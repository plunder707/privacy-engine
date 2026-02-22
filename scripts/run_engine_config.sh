#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

CONFIG="${1:-configs/basic.local.json}"

BIN="./target/release/privacy-engine-rust"

# Build if missing or stale. This prevents confusing "unknown flag" behavior when the code changes
# but the old release binary is still present.
if [[ ! -x "${BIN}" ]] \
  || [[ "${BIN}" -ot Cargo.toml ]] \
  || [[ "${BIN}" -ot Cargo.lock ]] \
  || find src -type f -newer "${BIN}" -print -quit | grep -q .; then
  cargo build --release
fi

exec env RUST_LOG="${RUST_LOG:-info}" "${BIN}" --engine-config "${CONFIG}"
