# Privacy Engine Rust Roadmap

> Updated: 2026-02-15 10:01 UTC (Codex)
>
> This file is the high-level roadmap. The detailed milestone checklist and narrative lives in `docs/NEXT_PHASE.md` (do not treat older notes elsewhere as canonical).

## Shipped (Current State)

As of 2026-02-15, the project is no longer “MITM scaffolding”; it is a functioning privacy gateway with observability:

- Selective explicit proxy (`CONNECT`) with **MITM + passthrough pinning** (`src/mitm.rs`, `src/host_store.rs`)
- Strict policy engine with hot reload and modes: `disabled|report_only|enforce` (`src/policy.rs`)
- Cookie privacy:
  - Tracker `Set-Cookie` stripping (HTTP/1.1 first response headers in relay path)
  - **Consent enforcement**: `essential_only|analytics_ok|all` with advertising/analytics categorization (`src/policy.rs`)
- DNS privacy:
  - UDP DNS pre-filter (`--enable-dns-filter`) returning NXDOMAIN
  - **CNAME uncloaking** (blocks if CNAME target is a tracker) (`src/dns_filter.rs`)
- HTML privacy:
  - `lol_html` rewriting (scripts, pixels, cosmetic selectors) in MITM relay
  - Decompress→rewrite→recompress for `gzip|deflate|br` and buffer-then-rewrite for chunked TE (`src/mitm.rs`)
- Filter list support:
  - ABP/EasyList subset parser + URL/file sources + caching + refresh (`src/filter_list*.rs`)
- Receipts + compliance reporting:
  - JSON receipts persistence (`--receipts-file`)
  - CLI rendering (`--dump-receipts`, `--dump-compliance --compliance-format text|html`)
  - Local dashboard (`--dashboard-port`) serving `/api/metrics`, `/api/receipts`, `/api/status` (`src/dashboard.rs`)
- TLS upstream fingerprint normalization (`--tls-profile chrome`) within rustls’ controllable surface (`src/mitm.rs`)
- MITM certificate transparency log (`--cert-log-file`) (`src/mitm.rs`)
- Dashboard setup controls (`/download/ca.crt`, token-guarded pinned-host reset) (`src/dashboard.rs`, `src/host_store.rs`)
- Startup auto-pin grace period (60s) to prevent initial cert-setup race poisoning pinned hosts (`src/main.rs`, `src/host_store.rs`)

## Near-Term Roadmap (Next 1-3 Sprints)

These are the next “real product” steps, prioritized by impact and risk.

1. Multi-user consent profiles (P5 in `docs/NEXT_PHASE.md`)
   - Per-source-IP (or later per-auth principal) consent defaults.
2. WebSocket strategy (P6)
   - v1 likely “block Upgrade for known tracker domains” rather than frame inspection.
3. Auth/access control for proxy usage (Phase 3)
   - Token/basic auth for explicit proxy; future: mTLS.
4. Performance hardening for EasyList-scale rewriting
   - Reduce per-request allocations and parsing; precompile selectors/patterns; add focused benchmarks.
5. Remaining coverage gaps
   - `Content-Encoding: zstd` (rare) and other edge HTTP semantics (trailers/ETag correctness).

## Longer-Term (Packaging + Enterprise)

- Desktop packaging: background service + tray UI that controls policy + shows receipts (dashboard already provides the UI surface).
- Android: VPN capture mode (not implemented in this repo yet); accept that full-device decrypt is not universal on modern Android.
- Signed rule packs / policy supply chain (TUF-style) for safe updates without shipping a new binary.
- HA deployments (state replication) for gateway use.

## Documentation Workflow (So We Don’t Lose State)

When a milestone or feature is completed:

1. Update the relevant doc in `docs/` (policy/receipts/testing/etc).
2. Update `docs/NEXT_PHASE.md` as the canonical milestone ledger.
3. Add any follow-up hazards/tech debt to `suggestfix.md` with file references and a “safe next step” plan.
