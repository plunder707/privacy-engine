# Compatibility Matrix

This matrix tracks transport and interception compatibility for the Rust engine by client and mode. It also tracks the major HTTP response shapes relevant to body rewriting.

Legend:

- `PASS`: validated end-to-end (live) or covered by targeted tests plus basic smoke runs.
- `PENDING`: not run yet (or needs artifact capture).

## Transport Compatibility (Client x Mode)

| Client | Mode | Result | Notes / How to Validate |
|---|---|---|---|
| `curl` | Explicit proxy (`CONNECT`) | PASS | `curl -vk -x http://127.0.0.1:18081 https://google.com/` |
| `curl` | “Transparent TLS” style (`--connect-to`) | PASS | `curl -vk --connect-to google.com:443:127.0.0.1:18081 https://google.com/` |
| Desktop browser (Chrome/Firefox) | Explicit proxy | PENDING | See `docs/BROWSER_TESTING.md` (CA trust + proxy + feature checks). |
| Android (Wi-Fi proxy mode) | Explicit proxy | PENDING | Requires device CA + Wi-Fi proxy; expect many pinned apps to passthrough. |
| Android (VPN capture) | Transparent capture | PENDING | Not implemented in this repo. |

## HTTP Response Shapes (Body Rewriting)

Body rewriting runs in the HTTP/1.1 MITM relay path for HTML responses. Current support:

- `Content-Encoding`: `identity`, `gzip`, `deflate`, `br` supported (decompress→rewrite→recompress)
- `Transfer-Encoding: chunked`: supported (buffer then decode→rewrite→send with `Content-Length`)
- `Content-Encoding: zstd`: not supported (skipped)
- Oversize bodies: skipped (`max_body_bytes`, default 2 MiB)

## Runbook

### 1) Start engine

Recommended (config-first; avoids copy/paste fragility):

```bash
cd ~/workspace/privacy-engine-rust
./scripts/run_engine_config.sh configs/basic.local.json
```

Equivalent explicit flags (for debugging):

```bash
cd ~/workspace/privacy-engine-rust
cargo run --release -- \
  --listen-host 127.0.0.1 \
  --listen-port 18081 \
  --pinned-hosts-file /tmp/pe_pinned_hosts.json \
  --enable-mitm \
  --tls-profile chrome \
  --mitm-ca-cert-file /tmp/pe_ca_cert.pem \
  --mitm-ca-key-file /tmp/pe_ca_key.pem \
  --mitm-ca-export-cert-file /tmp/pe_ca_cert_export.pem \
  --policy-config-file ./docs/policy.example.json \
  --policy-reload-interval-secs 5 \
  --receipts-file /tmp/pe_receipts.json \
  --receipts-flush-interval-secs 10 \
  --dashboard-port 9090
```

Shortcut script (older baseline flags; add additional flags as needed):

```bash
cd ~/workspace/privacy-engine-rust
./scripts/run_engine_matrix.sh 18081
```

### 2) Explicit proxy verification

```bash
curl -vk -x http://127.0.0.1:18081 https://google.com/
```

Expected:

- `HTTP/1.1 200 Connection established`
- forged issuer (your local MITM CA)
- upstream response returned

### 3) Transparent TLS-style verification (curl)

```bash
curl -vk --connect-to google.com:443:127.0.0.1:18081 https://google.com/
```

### 4) DNS pre-filter verification (optional)

Start engine with DNS filter enabled:

```bash
cargo run --release -- \
  --enable-dns-filter \
  --dns-listen-host 127.0.0.1 \
  --dns-listen-port 5353
```

Validate:

```bash
dig @127.0.0.1 -p 5353 doubleclick.net A +short
dig @127.0.0.1 -p 5353 google.com A +short
```

### 5) Receipts + compliance sanity

```bash
./target/release/privacy-engine-rust --dump-receipts --receipts-file /tmp/pe_receipts.json --top-hosts 20
./target/release/privacy-engine-rust --dump-compliance --compliance-format text --receipts-file /tmp/pe_receipts.json
```

### 6) Dashboard sanity

- Open `http://127.0.0.1:9090/`
- Confirm `/api/metrics` and `/api/receipts` return JSON and counters move during browsing/curl.
- Confirm setup endpoints:
  - `GET /download/ca.crt` returns exported CA PEM when configured
  - `POST /api/pins/reset` requires `x-admin-token` from `/api/status`
