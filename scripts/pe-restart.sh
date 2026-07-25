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
PATTERN="privacy-engine-rust --engine-config"

port_of() { python3 -c "import json,sys; print(json.load(open('$CONFIG')).get('$1') or '')" 2>/dev/null; }
PROXY_PORT="$(port_of listen_port)"; PROXY_PORT="${PROXY_PORT:-18081}"

echo "==> config: $CONFIG"
python3 -m json.tool "$CONFIG" >/dev/null || { echo "config is not valid JSON; refusing to restart" >&2; exit 1; }

if pgrep -f "$PATTERN" >/dev/null; then
  echo "==> stopping existing engine (pids: $(pgrep -f "$PATTERN" | tr '\n' ' '))"
  pkill -f "$PATTERN"
  for _ in $(seq 1 20); do
    pgrep -f "$PATTERN" >/dev/null || break
    sleep 0.25
  done
  pgrep -f "$PATTERN" >/dev/null && { echo "==> still running, sending SIGKILL"; pkill -9 -f "$PATTERN"; sleep 1; }
else
  echo "==> no running engine"
fi

echo "==> starting (log: $LOG)"
nohup bash scripts/run_easylist_local.sh "$CONFIG" >"$LOG" 2>&1 </dev/null &

for _ in $(seq 1 40); do
  sleep 0.25
  if ss -ltn 2>/dev/null | grep -q "127.0.0.1:${PROXY_PORT}"; then
    echo "==> up: listening on 127.0.0.1:${PROXY_PORT} (pid $(pgrep -f "$PATTERN" | head -1))"
    exit 0
  fi
done

echo "==> FAILED to bind 127.0.0.1:${PROXY_PORT} within 10s. Last log lines:" >&2
tail -20 "$LOG" >&2
exit 1
