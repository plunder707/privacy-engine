#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA_FILE="${PE_CA_FILE:-${ROOT}/certs/ca_cert_export.pem}"
MODE=install
INSTALL_SYSTEM=0

usage() {
  cat <<'EOF'
Usage: scripts/pe-trust.sh [--check] [--system] [--ca PATH]

Installs a managed user CA bundle and environment contract for Python,
Node.js, Cargo, curl, and Git. The operation is idempotent. --system also
installs the CA into the Linux system trust store (sudo may prompt).
EOF
}

while (($#)); do
  case "$1" in
    --check) MODE=check ;;
    --system) INSTALL_SYSTEM=1 ;;
    --ca)
      shift
      [[ $# -gt 0 ]] || { echo "--ca requires a path" >&2; exit 2; }
      CA_FILE="$1"
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
[[ -r "${CA_FILE}" ]] || { echo "CA certificate not found: ${CA_FILE}" >&2; exit 1; }
openssl x509 -in "${CA_FILE}" -noout >/dev/null 2>&1 \
  || { echo "not a readable PEM certificate: ${CA_FILE}" >&2; exit 1; }
if grep -q -- "PRIVATE KEY" "${CA_FILE}"; then
  echo "refusing certificate file containing a private key: ${CA_FILE}" >&2
  exit 1
fi

SYSTEM_BUNDLE="${PE_TRUST_SYSTEM_BUNDLE:-}"
if [[ -z "${SYSTEM_BUNDLE}" ]]; then
  for candidate in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt; do
    if [[ -r "${candidate}" ]]; then
      SYSTEM_BUNDLE="${candidate}"
      break
    fi
  done
fi
[[ -n "${SYSTEM_BUNDLE}" && -r "${SYSTEM_BUNDLE}" ]] \
  || { echo "system CA bundle not found; set PE_TRUST_SYSTEM_BUNDLE" >&2; exit 1; }

DATA_DIR="${PE_TRUST_DATA_DIR:-${HOME}/.local/share/privacy-engine}"
CONFIG_DIR="${PE_TRUST_CONFIG_DIR:-${HOME}/.config/privacy-engine}"
STATE_DIR="${PE_TRUST_STATE_DIR:-${HOME}/.local/state/privacy-engine}"
ENVIRONMENT_DIR="${PE_TRUST_ENVIRONMENT_DIR:-${HOME}/.config/environment.d}"
BUNDLE="${DATA_DIR}/ca-bundle.pem"
FINGERPRINT_FILE="${DATA_DIR}/ca.sha256"
ENV_FILE="${CONFIG_DIR}/trust.env"
ENVIRONMENT_FILE="${ENVIRONMENT_DIR}/90-privacy-engine-trust.conf"
RECEIPT_FILE="${STATE_DIR}/trust-receipt.json"
FINGERPRINT="$(openssl x509 -in "${CA_FILE}" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')"

check_user_install() {
  [[ -r "${BUNDLE}" ]] || return 1
  [[ "$(cat "${FINGERPRINT_FILE}" 2>/dev/null || true)" == "${FINGERPRINT}" ]] || return 1
  [[ -r "${ENV_FILE}" ]] || return 1
  grep -Fq "REQUESTS_CA_BUNDLE=" "${ENV_FILE}" || return 1
  grep -Fq "NODE_EXTRA_CA_CERTS=" "${ENV_FILE}" || return 1
  [[ "$(git config --global --get http.sslCAInfo 2>/dev/null || true)" == "${BUNDLE}" ]] || return 1
}

check_system_install() {
  local target=/usr/local/share/ca-certificates/privacy-engine.crt
  [[ -r "${target}" ]] || return 1
  cmp -s "${CA_FILE}" "${target}"
}

if [[ "${MODE}" == check ]]; then
  check_user_install || {
    echo "privacy-engine user trust is missing or stale" >&2
    exit 1
  }
  if ((INSTALL_SYSTEM)); then
    check_system_install || {
      echo "privacy-engine system trust is missing or stale" >&2
      exit 1
    }
  fi
  echo "privacy-engine trust verified (${FINGERPRINT})"
  exit 0
fi

mkdir -p "${DATA_DIR}" "${CONFIG_DIR}" "${STATE_DIR}" "${ENVIRONMENT_DIR}"
tmp_bundle="${BUNDLE}.tmp.$$"
trap 'rm -f "${tmp_bundle}"' EXIT
cp "${SYSTEM_BUNDLE}" "${tmp_bundle}"
printf '\n' >> "${tmp_bundle}"
cat "${CA_FILE}" >> "${tmp_bundle}"
chmod 0644 "${tmp_bundle}"
mv "${tmp_bundle}" "${BUNDLE}"
printf '%s\n' "${FINGERPRINT}" > "${FINGERPRINT_FILE}"

{
  printf 'export SSL_CERT_FILE=%q\n' "${BUNDLE}"
  printf 'export REQUESTS_CA_BUNDLE=%q\n' "${BUNDLE}"
  printf 'export CURL_CA_BUNDLE=%q\n' "${BUNDLE}"
  printf 'export NODE_EXTRA_CA_CERTS=%q\n' "${BUNDLE}"
  printf 'export CARGO_HTTP_CAINFO=%q\n' "${BUNDLE}"
  printf 'export GIT_SSL_CAINFO=%q\n' "${BUNDLE}"
} > "${ENV_FILE}"
chmod 0644 "${ENV_FILE}"

cat > "${ENVIRONMENT_FILE}" <<EOF
SSL_CERT_FILE=${BUNDLE}
REQUESTS_CA_BUNDLE=${BUNDLE}
CURL_CA_BUNDLE=${BUNDLE}
NODE_EXTRA_CA_CERTS=${BUNDLE}
CARGO_HTTP_CAINFO=${BUNDLE}
GIT_SSL_CAINFO=${BUNDLE}
EOF
chmod 0644 "${ENVIRONMENT_FILE}"

git config --global http.sslCAInfo "${BUNDLE}"

system_installed=false
if ((INSTALL_SYSTEM)); then
  target=/usr/local/share/ca-certificates/privacy-engine.crt
  if [[ ${EUID} -eq 0 ]]; then
    install -m 0644 "${CA_FILE}" "${target}"
    update-ca-certificates
  else
    sudo install -m 0644 "${CA_FILE}" "${target}"
    sudo update-ca-certificates
  fi
  system_installed=true
fi

python3 - "${RECEIPT_FILE}" "${CA_FILE}" "${BUNDLE}" "${FINGERPRINT}" "${system_installed}" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

receipt, ca_file, bundle, fingerprint, system_installed = sys.argv[1:]
payload = {
    "format": "privacy_engine_trust_receipt/v1",
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "ca_file": os.path.realpath(ca_file),
    "bundle": os.path.realpath(bundle),
    "ca_sha256_fingerprint": fingerprint,
    "system_installed": system_installed == "true",
    "strategy": "managed_bundle_and_environment",
}
with open(receipt, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

check_user_install
echo "privacy-engine trust installed (${FINGERPRINT})"
echo "source ${ROOT}/scripts/privacy_engine_env.sh"
