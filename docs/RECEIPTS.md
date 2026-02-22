# Privacy Receipts + Compliance Reports

> Updated: 2026-02-15 09:28 UTC (Codex)

“Receipts” are **local, aggregated summaries** of what the engine decided and what it changed. They are designed to be:

- explainable (“what happened and why”)
- privacy-preserving (no URL/body capture)
- usable for audits (“prove policy enforcement over time”)

Receipts power:

- CLI reports (`--dump-receipts`, `--dump-compliance`)
- Dashboard per-host table (`--dashboard-port`)

## What Receipts Store (High Level)

Per host (normalized domain key):

- Routing decisions: MITM vs passthrough (pinned/fallback)
- MITM outcomes: success/failure + auto-pin events
- DNS enforcement: blocked / would-block + CNAME uncloaking events
- Cookie enforcement: Set-Cookie stripped / would-strip + consent enforcement counts
- Body rewriting: rewrites applied / report-only / skipped, plus removed element counts and bytes saved
- Last seen timestamp + last decision reason (for debugging)

What receipts intentionally do *not* store:

- URLs/paths/query strings
- request/response bodies
- full header contents

## Enable Receipts

Recommended (config-first):

```bash
cd ~/workspace/privacy-engine-rust
./scripts/run_engine_config.sh configs/basic.local.json
```

Equivalent explicit flags:

```bash
cd ~/workspace/privacy-engine-rust
cargo run --release -- \
  --listen-host 127.0.0.1 \
  --listen-port 18081 \
  --enable-mitm \
  --policy-config-file ./docs/policy.example.json \
  --receipts-file /tmp/pe_receipts.json \
  --receipts-flush-interval-secs 10
```

Notes:

- If `--receipts-file` is not set, receipts are disabled.
- Flushing is best-effort and uses an atomic temp-file+rename write.

## View Receipts (CLI)

Top hosts:

```bash
cd ~/workspace/privacy-engine-rust
cargo run --release -- \
  --dump-receipts \
  --receipts-file /tmp/pe_receipts.json \
  --top-hosts 30
```

One host (exact host key match or subdomain match):

```bash
cargo run --release -- \
  --dump-receipts \
  --receipts-file /tmp/pe_receipts.json \
  --receipt-host doubleclick.net
```

## Compliance Report (CLI)

Text:

```bash
cargo run --release -- \
  --dump-compliance \
  --compliance-format text \
  --receipts-file /tmp/pe_receipts.json \
  --top-hosts 50
```

HTML:

```bash
cargo run --release -- \
  --dump-compliance \
  --compliance-format html \
  --receipts-file /tmp/pe_receipts.json > /tmp/compliance.html
```

## Dashboard (Read-Only UI)

Run the dashboard on localhost:

```bash
cargo run --release -- \
  --dashboard-port 9090 \
  --receipts-file /tmp/pe_receipts.json \
  --policy-config-file ./docs/policy.example.json
```

Endpoints:

- `GET /` HTML dashboard
- `GET /api/metrics` metrics snapshot JSON
- `GET /api/receipts` receipts JSON (per-host counters)
- `GET /api/status` uptime + policy mode/status JSON

## Key Counters (Per Host)

The receipts schema is versioned (`version: 1`). The full field list is the JSON produced by `src/receipts.rs` (`HostReceipt::as_json()`), but the important groups are:

- Routing:
  - `seen_total`, `routing_mitm_total`, `routing_passthrough_total`
  - `last_seen_unix`, `last_flow`, `last_action`, `last_reason`
- MITM:
  - `mitm_attempt_total`, `mitm_success_total`, `mitm_failure_total`
  - `mitm_client_tls_reject_total`, `host_auto_pinned_total`
- DNS:
  - `dns_blocked_total`, `dns_report_only_total`, `dns_cname_uncloaked_total`
- Cookies:
  - `policy_set_cookie_stripped_total`, `policy_set_cookie_would_strip_total`, `policy_set_cookie_headers_total`
  - `consent_enforcement_blocked_total`, `consent_enforcement_report_only_total`
- Body rewrite:
  - `body_rewrite_total`, `body_rewrite_report_only_total`, `body_rewrite_skipped_total`
  - element counters + bytes saved:
    - `body_rewrite_removed_script_total`, `body_rewrite_removed_pixel_total`, `body_rewrite_removed_cosmetic_total`
    - `body_rewrite_bytes_saved_total`
  - and the report-only equivalents (`*_report_only_total`)
