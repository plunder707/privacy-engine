#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PORT="${1:-18081}"

POLICY_CONFIG_FILE="${POLICY_CONFIG_FILE:-./docs/policy.example.json}"
PINNED_HOSTS_FILE="${PINNED_HOSTS_FILE:-/tmp/pe_pinned_hosts.json}"

MITM_CA_CERT_FILE="${MITM_CA_CERT_FILE:-/tmp/pe_ca_cert.pem}"
MITM_CA_KEY_FILE="${MITM_CA_KEY_FILE:-/tmp/pe_ca_key.pem}"
MITM_CA_EXPORT_FILE="${MITM_CA_EXPORT_FILE:-/tmp/pe_ca_cert_export.pem}"

RECEIPTS_FILE="${RECEIPTS_FILE:-/tmp/pe_receipts.json}"

exec cargo run -- \
  --listen-host 127.0.0.1 \
  --listen-port "${PORT}" \
  --enable-mitm \
  --pinned-hosts-file "${PINNED_HOSTS_FILE}" \
  --mitm-ca-cert-file "${MITM_CA_CERT_FILE}" \
  --mitm-ca-key-file "${MITM_CA_KEY_FILE}" \
  --mitm-ca-export-cert-file "${MITM_CA_EXPORT_FILE}" \
  --policy-config-file "${POLICY_CONFIG_FILE}" \
  --policy-reload-interval-secs 5 \
  --receipts-file "${RECEIPTS_FILE}" \
  --receipts-flush-interval-secs 10 \
  --metrics-log-interval-secs 10
