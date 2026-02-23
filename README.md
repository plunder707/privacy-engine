# Privacy Engine (Rust)

Privacy Engine is a Rust based HTTPS interception proxy designed to strip trackers, block ads, and protect your privacy at the network level. Rather than running as a browser extension that only covers one tab, it sits between your entire device (or network) and the internet, its decrypting, inspecting, rewriting, and re-encrypting traffic before it ever reaches your browser. It works across every app, every tab, and every device you route through it.

**Disclaimer:** This tool is intended for personal use on networks and devices you own or have explicit permission to monitor. Intercepting traffic without authorization is illegal in most jurisdictions. The MITM capability is designed for privacy protection on your own traffic.. NOT for inspecting others. Use responsibly.

## Features

**Selective MITM Interception:** Intercepts HTTPS traffic using a locally generated CA certificate. For hosts that reject the forged cert (payment processors, pinned apps), it automatically falls back to a transparent passthrough tunnel. No browser errors, no broken sites.

**Tracker & Ad Blocking:** Loads EasyList and AdGuard compatible filter lists (71,000+ rules). Strips tracker `<script>` tags and tracking pixels from HTML responses using a streaming rewriter. Injects cosmetic CSS to hide ad containers.

**DNS Pre-Filter:** Listens on a local UDP port and returns NXDOMAIN for blocked domains before a connection is even opened. Supports CNAME uncloaking and follows CNAME chains and blocks if the resolved target is a known tracker, even if the alias looks first party.

**Encrypted DNS:** Forwards DNS queries upstream over HTTPS (DoH) to Cloudflare or Quad9 instead of plaintext UDP. Also exposes its own DoH server endpoint so any device on your network can use it.

**Query Parameter Stripping:** Removes tracking parameters from outbound request URLs before they reach the server `fbclid`, `gclid`, `utm_source`, `utm_medium`, `utm_campaign`, `_ga`, `msclkid`, and more.

**Cookie & Header Privacy:** Strips `Set-Cookie` headers from tracker domain responses. Removes cache-fingerprinting headers (`Last-Modified`, `X-Cache`, `If-None-Match`, etc.). Normalizes the `Referer` header on outbound requests to tracker domains.

**Consent Enforcement:** Three consent levels `essential_only`, `analytics_ok`, and `all` with per user profiles keyed by source IP. Lets different devices on the same network have different privacy levels.

**Compression-Aware Rewriting:** Decompresses and rewrites HTML through the full stack using gzip, deflate, brotli, and chunked transfer encoding and then re-compresses with a corrected `Content-Length`. Doesn't skip rewriting just because the response is encoded.

**Privacy Receipts:** Maintains a per host audit trail of everything the engine touched and blocks, strips, rewrites, DNS queries, timestamps, counters. Persists to JSON and survives restarts.

**Compliance Reports:** Generates text or HTML reports showing what each site attempted and what was blocked. Useful for auditing or understanding what a particular site is doing.

**Live Dashboard:** A local web UI showing real-time metrics, a per-host activity table, DoH client stats, and a setup wizard for CA cert download and passthrough host management.

**Hot-Reload Policy:** Watches the policy JSON file and reloads every 5 seconds. Change enforcement rules, consent levels, or tracker domain lists without restarting the engine.

**TOFU Cert Pinning:** Records upstream TLS certificate fingerprints on first contact and alerts on changes.

**TLS Fingerprint Normalization:** Mimics a Chrome TLS ClientHello (cipher suite order, key exchange groups, extensions) to avoid standing out as a proxy to TLS-fingerprinting servers.

## Installation & Execution

Install Rust (stable) if you don't have it:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone the repository:

```bash
git clone https://github.com/plunder707/privacy-engine.git
cd privacy-engine-rust
```

Build and run with EasyList (recommended) downloads EasyList and starts with DNS + filter list support):

```bash
./scripts/run_easylist_local.sh
```

Or run with the basic config (MITM + dashboard, no DNS or filter lists):

```bash
./scripts/run_engine_config.sh configs/basic.local.json
```

Trust the CA certificate the engine generates on first run. It's exported to `/tmp/pe_ca_cert_export.pem` and also available as a `.crt` download from the dashboard Setup Wizard.

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/pe_ca_cert_export.pem
```

**Windows:** Download `ca.crt` from the dashboard Setup Wizard. Double click it, choose to install to **Local Machine**, and manually select **Trusted Root Certification Authorities** as the store (do not use auto-select).

**Linux:**
```bash
sudo cp /tmp/pe_ca_cert_export.pem /usr/local/share/ca-certificates/pe-ca.crt
sudo update-ca-certificates
```

Set your browser or OS proxy to `127.0.0.1:18081` and open the dashboard at `http://127.0.0.1:9090/`.

## Engine Configuration

The engine accepts a single JSON config file to avoid long CLI invocations. All keys are optional and fall back to sane defaults. Unknown keys are rejected to catch typos.

```json
{
  "meta": "local dev config",
  "listen_host": "127.0.0.1",
  "listen_port": 18081,
  "enable_mitm": true,
  "mitm_ca_export_cert_file": "/tmp/pe_ca_cert_export.pem",
  "tls_profile": "chrome",
  "policy_config_file": "docs/policy_full.json",
  "policy_mode": "enforce",
  "receipts_file": "/tmp/pe_receipts.json",
  "enable_dns_filter": true,
  "dns_listen_port": 5353,
  "dns_upstream": "1.1.1.1:53",
  "filter_list_url": ["https://easylist.to/easylist/easylist.txt"],
  "filter_list_cache_dir": "/tmp",
  "dashboard_port": 9090
}
```

See [`docs/ENGINE_CONFIG.md`](docs/ENGINE_CONFIG.md) for the full schema.

## Policy Configuration

Policy is a separate JSON file hot-reloaded every 5 seconds. A basic rule looks like this:

```json
{
  "mode": "enforce",
  "body_rewrite": [
    {
      "tracker_domains": ["doubleclick.net", "googletagmanager.com"],
      "strip_scripts": true,
      "strip_pixels": true,
      "cosmetic_selectors": ["#ad-container", ".sponsored-content"],
      "query_param_strip_enabled": true,
      "referer_spoof_enabled": true,
      "websocket_block_enabled": true
    }
  ],
  "consent": {
    "default": "essential_only",
    "users": [
      { "source_ip": "192.168.1.10", "profile": "analytics_ok" }
    ]
  }
}
```

See [`docs/POLICY_CONFIG.md`](docs/POLICY_CONFIG.md) and [`docs/policy_full.json`](docs/policy_full.json) for a full working example covering 41 tracker domains, consent profiles, and paywall CSS selectors.

## Folder Structure

```
privacy-engine-rust/
│
├── src/
│   ├── main.rs                  — CLI, server setup, policy reload, plain HTTP proxy
│   ├── mitm.rs                  — TLS interception, HTTP/1 relay, body pipeline
│   ├── policy.rs                — Policy engine: config parsing, per-host plans
│   ├── dns_filter.rs            — UDP DNS listener, NXDOMAIN, CNAME uncloaking, DoH
│   ├── filter_list.rs           — EasyList download, caching, periodic refresh
│   ├── filter_list_parser.rs    — ABP filter syntax parser
│   ├── receipts.rs              — Per-host audit trail, JSON persistence, reports
│   ├── dashboard.rs             — Hyper web server, live metrics, setup wizard
│   ├── engine_config.rs         — JSON config loader with strict key validation
│   ├── cert_pin.rs              — TOFU cert pinning database
│   ├── host_store.rs            — Passthrough host set, file persistence, grace period
│   ├── metrics.rs               — 22 atomic counters, snapshot + structured logging
│   └── tls_parser.rs            — SNI extraction from TLS ClientHello
│
├── configs/
│   ├── basic.local.json         — MITM + receipts + dashboard (no DNS/filter lists)
│   └── easylist.local.json      — Full config: DNS + EasyList + dashboard
│
├── docs/
│   ├── policy_full.json         — Complete policy config (41 tracker domains)
│   ├── ENGINE_CONFIG.md         — Engine config schema reference
│   ├── POLICY_CONFIG.md         — Policy config schema reference
│   ├── BROWSER_TESTING.md       — Browser proxy + cert setup guide
│   ├── VISION.md                — Long-term roadmap and browser integration concept
│   └── ...                      — Additional research and notes
│
├── scripts/
│   ├── run_easylist_local.sh    — Downloads EasyList and starts the engine
│   ├── run_engine_config.sh     — Starts the engine with a given config file
│   └── check.sh                 — fmt + clippy + full test suite
│
└── Cargo.toml
```

## Smoke Tests

After starting, verify it's working:

```bash
# DNS filter: doubleclick.net should return NXDOMAIN
dig @127.0.0.1 -p 5353 doubleclick.net A +noall +answer +comments

# Known-good domain should resolve normally
dig @127.0.0.1 -p 5353 google.com A +short

# Proxy: fetch a page through the proxy and check for tracker scripts
curl -sk -x http://127.0.0.1:18081 https://www.nytimes.com/ -o /tmp/nyt.html
grep -c 'googletagmanager' /tmp/nyt.html  # should be 0
```

## Development

```bash
# Full check: format + clippy + all tests
./scripts/check.sh

# Tests only
cargo test

# Build release binary
cargo build --release
```

203 tests, 0 failures. Tests cover: DNS parsing, NXDOMAIN building, CNAME chain inspection, filter list parsing (domain blocks, URL patterns, exceptions, cosmetic selectors), chunked TE decode/re-encode, gzip/deflate/brotli roundtrips, HTML rewriting, query param stripping, cache header stripping, referer injection, policy evaluation, consent enforcement, multi-user profiles, TOFU cert pinning, dashboard API endpoints, DoH stats, receipt persistence and pruning, host store grace period, TLS profile ordering.

## Customization

**Change enforcement mode:** Set `"policy_mode"` to `"disabled"`, `"report_only"`, or `"enforce"` in the engine config. `report_only` logs what would have been blocked without actually blocking it. Very useful for evaluating impact before enabling enforcement.

**Add tracker domains:** Edit the `tracker_domains` list in your policy config file. Changes are picked up automatically within 5 seconds.

**Adjust consent levels:** Set `"default"` under `consent` to `essential_only`, `analytics_ok`, or `all`. Add per-IP overrides in the `users` array.

**Use a different DNS upstream:** Change `dns_upstream` to any IP:port, or set `dns_upstream_doh` to a DoH URL (e.g., `"https://9.9.9.9/dns-query"` for Quad9).

**Add your own filter lists:** Add local file paths to `filter_list_file` or URLs to `filter_list_url` in the engine config. Both EasyList and AdGuard formats are supported.

## Safety

- Do not expose the proxy listener on a public interface without adding authentication first. By default it is an open proxy.
- The generated CA is a local root certificate authority. Treat the private key (`mitm_ca_key.pem`) like any root CA key, DO NOT share it or commit it to version control.
- Remove the CA from your system trust store when you're done testing.
- Pre add payment processors and cert-pinned apps to the passthrough list. Stripe, Google Pay, PayPal, and similar services use certificate pinning and will not function correctly under MITM interception.

## What's Next

**Phase 5 — Browser Fingerprint Protection:**
- Core JS shim injected into pages (`navigator`, `screen`, `plugins` normalization)
- Canvas fingerprint noise injection
- WebGL renderer string normalization
- AudioContext fingerprint protection

**Open TODOs:**
- OS-specific cert install instructions directly in the dashboard setup wizard
- Dashboard viewer for the certificate transparency log (currently written to a file only)
- Body rewriting for plain HTTP requests — non-CONNECT `GET`/`POST` traffic currently bypasses the rewrite pipeline
- Server log persistence via `--log-file` flag or `tee` wrapper in the run scripts
- Scheduled receipt file pruning (drop hosts not seen in 24h to keep the JSON file small over time)
- Permanent passthrough list in engine config (currently only set via auto-detection or dashboard reset)
- Proxy authentication (token or basic auth) to prevent open-proxy misuse on shared networks
- `Content-Encoding: zstd` support (rare but increasingly used on modern CDNs)

**Longer-term vision:**

The proxy approach has real limits. It requires a CA cert, a proxy setting on every device, and can't intercept cert pinned apps. The end goal is to embed this engine natively inside a [Servo](https://servo.org)-based browser. Same language (Rust), no MITM certificate required, hooks at the DOM and API level rather than the byte stream. The hard part of the policy engine, filter parser, consent system, streaming rewriter, DNS pipeline is already built. See [`docs/VISION.md`](docs/VISION.md) for the full plan.

## Dependencies

- Rust stable (edition 2021)
- `tokio` — async runtime
- `hyper` — HTTP client/server
- `rustls` + `tokio-rustls` — TLS
- `rcgen` — on-the-fly certificate generation
- `lol_html` — streaming HTML rewriter
- `hickory-proto` — DNS message parsing
- `flate2` — gzip/deflate
- `brotli` — brotli decompression
- `ring` — SHA-256 fingerprinting
- `base64` — DoH query encoding
- `clap` — CLI argument parsing
- `tracing` — structured logging

## Notes

- Ensure the proxy port (`18081` by default) is not already in use before starting.
- If the receipts file (`/tmp/pe_receipts.json`) grows very large after extended use, clearing it to `{}` will restore normal performance. Scheduled pruning is on the TODO list.
- The dashboard token for pin resets is printed to stdout on startup. It changes each run.
- Discord CDN domains (`cdn.discordapp.com`, `gateway.discord.gg`) and payment processors should be pre-added to the passthrough list if you rely on them.

*Built collaboratively across multiple sessions using a mix of cloud AI agents and local models.*
