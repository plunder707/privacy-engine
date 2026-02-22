# Policy Config (JSON) + Hot Reload

> Updated: 2026-02-15 07:07 UTC (Codex)

This engine supports a **strict JSON policy config** that can be hot-reloaded at runtime. Policy is shared across:

- MITM relay decisions (cookie/header/body rules)
- DNS pre-filter (NXDOMAIN blocking + CNAME uncloaking)
- Filter list integration (ABP/EasyList subset)
- Receipts + compliance reporting + dashboard visibility

Goals:

- Policy changes without recompiling
- Config typos fail fast (strict validation)
- Reload failures do not take down the proxy (last good config stays active)

## Enable

Minimal run (explicit proxy + MITM + policy):

```bash
cd ~/workspace/privacy-engine-rust
cargo run --release -- \
  --listen-host 127.0.0.1 \
  --listen-port 18081 \
  --enable-mitm \
  --tls-profile chrome \
  --policy-config-file ./docs/policy.example.json \
  --policy-reload-interval-secs 5
```

Optional mode override:

```bash
# Overrides the mode in the JSON file.
cargo run --release -- \
  --policy-config-file ./docs/policy.example.json \
  --policy-mode enforce
```

Disable reload (static config):

```bash
cargo run --release -- \
  --policy-config-file ./docs/policy.example.json \
  --policy-reload-interval-secs 0
```

## Reload Semantics

- Reload runs on a timer (`--policy-reload-interval-secs`).
- The engine checks file modification time; if it changed, it attempts parse + validate.
- If parsing/validation succeeds: apply and log `event=policy_reload_applied`.
- If it fails: log `event=policy_reload_failed` and keep the previous config.

## Schema (Version 1)

Top-level keys:

- `version` (required): integer, must be `1`
- `mode` (required): `disabled` | `report_only` | `enforce` (also accepts `report-only`)
- `rules` (required): object with known rule names
- `meta` (optional): free-form object for human notes; ignored by the engine
- `filter_lists` (optional): array of strings (URL or local path) for ABP/EasyList sources

Strictness:

- Unknown top-level keys are rejected (except `meta`).
- Unknown rule names are rejected.
- Unknown keys inside a known rule are rejected.

### Rule: `tracker_set_cookie`

```json
"tracker_set_cookie": { "enabled": true, "domains": ["doubleclick.net", "scorecardresearch.com"] }
```

- `enabled` (required): boolean
- `domains` (required): array of base domains

Effect:

- In MITM relay, on the **first HTTP/1.1 response header block**, `Set-Cookie` headers are stripped when policy says “block”.
- In `report_only`, the headers are not modified but receipts/metrics record the hit.
- Consent enforcement (if enabled) can override the decision of whether cookies are stripped.

### Rule: `dns_block`

```json
"dns_block": { "enabled": true, "domains": ["doubleclick.net", "googletagmanager.com"] }
```

- `enabled` (required): boolean
- `domains` (required): array of base domains

Effect:

- Used by the DNS pre-filter (`--enable-dns-filter`).
- In `enforce`, returns NXDOMAIN for matched names.
- In `report_only`, forwards but logs/records “would block”.
- CNAME uncloaking also uses the same `plan_for_dns_query()` decision for CNAME targets.

### Rule: `body_rewrite`

```json
"body_rewrite": {
  "enabled": true,
  "tracker_script_patterns": ["googletagmanager.com/gtm.js", "google-analytics.com/analytics.js"],
  "remove_selectors": ["ins.adsbygoogle", "div[id^=\"google_ads\"]"],
  "strip_tracking_pixels": true,
  "max_body_bytes": 2097152
}
```

- `enabled` (required): boolean
- `tracker_script_patterns` (optional): strings used to match `<script src="...">` URLs (substring match)
- `remove_selectors` (optional): CSS selectors (validated at config parse time)
- `strip_tracking_pixels` (optional): boolean (default false)
- `max_body_bytes` (optional): integer (default 2 MiB)

Effect:

- Runs only on MITM’d HTTP/1.1 relay responses where `Content-Type` is HTML.
- Supports `Content-Encoding: gzip|deflate|br` with decompress→rewrite→recompress.
- Supports `Transfer-Encoding: chunked` by buffering and rewriting after completion (not streaming).
- Safety gates:
  - size limit (`max_body_bytes`)
  - unknown encodings (e.g. `zstd`) are skipped
  - any rewrite error falls back to passthrough for that response

### Rule: `consent_enforcement`

```json
"consent_enforcement": {
  "enabled": true,
  "default_consent": "essential_only",
  "analytics_domains": ["google-analytics.com", "mixpanel.com"],
  "site_overrides": { "nytimes.com": "analytics_ok", "trusted-site.com": "all" }
}
```

- `enabled` (required): boolean
- `default_consent` (required): `essential_only` | `analytics_ok` | `all`
- `analytics_domains` (optional): array of base domains categorized as Analytics
- `site_overrides` (optional): object mapping domain to consent level (exact + parent-domain walk)

Effect:

- Domain category assignment:
  - Analytics if in `analytics_domains` (wins)
  - Otherwise Advertising if it matches tracker domains or filter list block domains
  - Otherwise uncategorized
- Consent decision (cookie stripping):
  - `essential_only`: block advertising + analytics cookies
  - `analytics_ok`: block advertising, allow analytics
  - `all`: allow all

## Filter Lists (`filter_lists` + CLI)

Filter list sources can come from:

- Policy JSON: `filter_lists: ["https://...easylist.txt", "/path/to/local.txt"]`
- CLI: `--filter-list-url ...` and `--filter-list-file ...` (repeatable)

Rules supported (ABP/EasyList subset):

- `||domain^` domain blocks (feeds DNS blocking + tracker matching)
- `||domain/path` URL patterns (feeds body rewrite script pattern matching)
- `##selector` and `domain##selector` cosmetic selectors (feeds body rewrite selectors)
- `@@||domain^` exceptions (override filter-list-derived blocks only; manual config still wins)

See `docs/NEXT_PHASE.md` for the design notes and scope boundaries.

## Example Files In This Repo

- `docs/policy.example.json`: minimal starter config
- `docs/policy_full.json`: small “demo” config covering the original Phase 1 features (may not include newer Phase 2/3 fields)

