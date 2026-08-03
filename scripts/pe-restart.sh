#!/usr/bin/env bash
# Restart the privacy engine cleanly and verify it actually came up.
#
# Replaces the pkill/nohup copy-paste. Safe to run when the engine is already
# stopped. Exits non-zero if the engine fails to start, so a broken config is
# reported immediately rather than discovered later as "the internet is down".
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

CONFIG="${1:-configs/easylist.local.json}"
LOG="engine.log"
BIN="./target/release/privacy-engine-rust"
PATTERN='(^|/)privacy-engine-rust --engine-config'

port_of() { python3 -c "import json,sys; print(json.load(open('$CONFIG')).get('$1') or '')" 2>/dev/null; }
PROXY_PORT="$(port_of listen_port)"; PROXY_PORT="${PROXY_PORT:-18081}"
DASHBOARD_PORT="$(port_of dashboard_port)"
DNS_ENABLED="$(port_of enable_dns_filter)"
DNS_HOST="$(port_of dns_listen_host)"; DNS_HOST="${DNS_HOST:-127.0.0.1}"
DNS_PORT="$(port_of dns_listen_port)"; DNS_PORT="${DNS_PORT:-5353}"
engine_pids() { pgrep -f "$PATTERN" 2>/dev/null || true; }

echo "==> config: $CONFIG"
python3 -m json.tool "$CONFIG" >/dev/null || { echo "config is not valid JSON; refusing to restart" >&2; exit 1; }

# Build before stopping the current process. Rebuilding replaces the executable
# and therefore drops any Linux file capabilities previously applied to it.
cargo build --release || { echo "release build failed; existing engine left running" >&2; exit 1; }

if [[ "$DNS_ENABLED" == "True" || "$DNS_ENABLED" == "true" ]] && (( DNS_PORT < 1024 )) && (( EUID != 0 )); then
  if ! getcap "$BIN" 2>/dev/null | grep -q 'cap_net_bind_service'; then
    cat >&2 <<EOF
DNS is configured on privileged port $DNS_PORT, but $BIN cannot bind it.
Existing engine left running. Apply the capability, then rerun:
  sudo setcap cap_net_bind_service=+ep $BIN
EOF
    exit 1
  fi
fi

if [[ -n "$(engine_pids)" ]]; then
  echo "==> stopping existing engine (pids: $(engine_pids | tr '\n' ' '))"
  pkill -f "$PATTERN" || true
  for _ in $(seq 1 20); do
    [[ -n "$(engine_pids)" ]] || break
    sleep 0.25
  done
  if [[ -n "$(engine_pids)" ]]; then
    echo "==> still running, sending SIGKILL"
    pkill -9 -f "$PATTERN" || true
    sleep 1
  fi
else
  echo "==> no running engine"
fi

echo "==> starting (log: $LOG)"
nohup setsid bash scripts/run_easylist_local.sh "$CONFIG" >"$LOG" 2>&1 </dev/null &

for _ in $(seq 1 40); do
  sleep 0.25
  if ss -ltn 2>/dev/null | grep -q "127.0.0.1:${PROXY_PORT}" && [[ -n "$(engine_pids)" ]]; then
    sleep 1
    break
  fi
done

if ! ss -ltn 2>/dev/null | grep -q "127.0.0.1:${PROXY_PORT}" || [[ -z "$(engine_pids)" ]]; then
  echo "==> FAILED to keep 127.0.0.1:${PROXY_PORT} active. Last log lines:" >&2
  tail -20 "$LOG" >&2
  exit 1
fi

if [[ -n "$DASHBOARD_PORT" ]] && ! curl -fsS "http://127.0.0.1:${DASHBOARD_PORT}/api/status" >/dev/null; then
  echo "==> FAILED dashboard check on 127.0.0.1:${DASHBOARD_PORT}" >&2
  exit 1
fi

if [[ "$DNS_ENABLED" == "True" || "$DNS_ENABLED" == "true" ]] \
  && ! ss -lun 2>/dev/null | grep -q "${DNS_HOST}:${DNS_PORT}"; then
  echo "==> FAILED DNS listener check on ${DNS_HOST}:${DNS_PORT}" >&2
  exit 1
fi

echo "==> up: proxy=127.0.0.1:${PROXY_PORT} pid=$(engine_pids | head -1)"
[[ -n "$DASHBOARD_PORT" ]] && echo "==> dashboard=http://127.0.0.1:${DASHBOARD_PORT}"
[[ "$DNS_ENABLED" == "True" || "$DNS_ENABLED" == "true" ]] && echo "==> dns=${DNS_HOST}:${DNS_PORT}"
