# Browser Testing (Chrome + Firefox)

This guide validates **explicit proxy MITM** with real desktop browsers, plus the “privacy product” features (cookies, DNS, rewriting, receipts).

Safety notes:

- Only do this on a machine/profile you control.
- Import only the exported CA cert (public). Never share the CA private key.
- Remove the CA and reset proxy settings after testing.

## 1) Start The Engine (Recommended Test Flags)

Recommended (config-first; avoids long flag lists):

```bash
cd ~/workspace/privacy-engine-rust
cargo build --release
RUST_LOG=info ./target/release/privacy-engine-rust --engine-config configs/basic.local.json
```

Equivalent explicit flags (useful for debugging):

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

## 2) Trust The CA

Confirm the CA export exists (path depends on the config/flags you used; defaults below match `configs/basic.local.json`):

- `/tmp/pe_ca_cert_export.pem`

Import it into your OS/browser trust store.

## 3) Configure Browser Proxy

Set the browser (or OS) proxy to:

- Host: `127.0.0.1`
- Port: `18081`

## 4) Validate MITM Is Actually Happening

Open a simple HTTPS site (e.g. `https://example.com/`).

Pass criteria:

- No TLS warning.
- The certificate issuer shows your generated MITM CA (“privacy-engine-*”).
- The engine logs show a routing decision with `action=mitm`.

## 5) Validate Cookie + Rewrite Behavior

Pick one “clean” site and one “tracker-heavy” site and compare:

- On clean sites, cookies should generally be preserved.
- On advertising/tracker sites (depending on policy), cookies may be stripped and HTML may be rewritten.

Practical checks:

- View page source and search for known tracker script URLs (e.g. `googletagmanager.com/gtm.js`).
- Use DevTools Network tab:
  - Check if `Set-Cookie` headers appear for a known advertising/tracker domain under enforcement.
  - (Consent enforcement changes what is blocked; see `docs/POLICY_CONFIG.md`.)

## 6) Validate DNS Pre-Filter (If Enabled)

The DNS filter is a separate UDP listener (`--enable-dns-filter`, default port `5353`). Browser testing depends on your OS DNS settings, so the simplest validation is via `dig`:

```bash
dig @127.0.0.1 -p 5353 doubleclick.net A +short
dig @127.0.0.1 -p 5353 google.com A +short
```

Pass criteria:

- Blocked tracker domains return empty / NXDOMAIN behavior.
- Normal domains resolve normally.

## 7) Validate Receipts + Compliance + Dashboard

Receipts:

```bash
./scripts/dump_receipts.sh 30
```

Compliance report:

```bash
./target/release/privacy-engine-rust --dump-compliance --compliance-format text --receipts-file /tmp/pe_receipts.json
```

Dashboard:

- Open `http://127.0.0.1:9090/`
- Verify counters increment and the per-host table updates
- Use Setup Wizard controls:
  - `Download CA Cert` button (serves `/download/ca.crt`)
  - `Reset Pinned Hosts` button (token-guarded local action)
  - `Auto-Pin Grace` status (startup grace window that suppresses auto-pinning)

## 8) Auto-Pin Grace Period (Startup Safety)

The engine suppresses auto-pinning for the first 60 seconds after startup to avoid poisoning pinned hosts while CA trust is being configured.

Expected behavior:

- During first 60s, client TLS rejections log `event=host_auto_pin_suppressed` with `reason=startup_grace_period`
- After 60s, client TLS rejections can auto-pin as normal (`event=host_auto_pinned`)

## Cleanup Checklist (Important)

1. Disable the proxy settings.
2. Remove the imported CA from Trusted Roots / Keychain / Firefox Authorities.
3. Delete any generated CA files if you were using disposable test material.
