# Platforms: How Users Run This


This project is a **selective privacy gateway**. Users route traffic through it and it enforces privacy rules when safe.

## What Exists In This Repo Today

- Primary integration: **explicit proxy** (HTTP `CONNECT`) on `127.0.0.1:<port>`
- Optional: DNS pre-filter on `127.0.0.1:<port>` (`--enable-dns-filter`)
- Optional: localhost dashboard (`--dashboard-port`)
- Transparent/VPN capture mode: **not implemented** in this repo (planned direction only)

## Desktop (Windows / macOS / Linux)

Recommended development setup:

1. Run the engine locally.
2. Configure OS or browser proxy to `127.0.0.1:<listen_port>`.
3. Export and trust the MITM CA (for the hosts that are MITM’d).
4. Use receipts + dashboard for feedback loops.

Suggested flags:

```bash
cd ~/workspace/privacy-engine-rust
./scripts/run_engine_config.sh configs/basic.local.json
```

## Android (Reality Check)

Two practical approaches:

1. Wi-Fi proxy to another device (best for testing):
   - Run engine on a PC.
   - Set Android Wi-Fi proxy to the PC IP/port.
   - Install the CA certificate on the device for MITM where supported.
2. VPN app (best consumer UX, not implemented here):
   - Use `VpnService` and route traffic into the app for policy.

Important limitation (modern Android):

- Many apps do **not** trust user-installed CAs (apps can opt out). Expect selective MITM to be strongest for browsers and some apps; pinned apps will passthrough.

## Packaging Direction (Not Yet Implemented)

- Desktop: background service + tray UI to toggle mode and display receipts.
- Mobile: Kotlin app + Rust core (JNI/NDK), with clear “no-decrypt vs decrypt” modes.
- Rule pack updates decoupled from binary updates (signed bundles recommended).

For research constraints and why this is necessary, see `docs/RESEARCH.md`.
