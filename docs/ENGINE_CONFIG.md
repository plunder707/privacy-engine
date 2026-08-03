# Engine Config (JSON)


The engine supports a single runtime config file to avoid long `cargo run ... --flag --flag ...` invocations and to provide a foundation for a future UI/launcher.

## Usage

Run the engine using a config file:

```bash
./scripts/run_engine_config.sh configs/easylist.local.json
```

Notes:

- When `--engine-config` is provided, values from the config file **override** the default CLI values (and will also override other runtime flags you pass).
- Unknown keys are rejected (typo protection). Top-level `meta` is allowed for comments.

## Schema (Top-Level Keys)

All keys are optional; unspecified keys use the same defaults as the CLI.

- `listen_host` (string)
- `listen_port` (number)
- `pinned_hosts_file` (string path)
- `never_intercept_hosts` (array of hostnames; extends the built-in `localhost` bypass)
- `never_intercept_cidrs` (array of IP CIDRs; extends the built-in `127.0.0.0/8` and `::1/128` bypass)
- `auto_pin_reject_threshold` (number, default `2`)
- `auto_pin_reject_window_secs` (number, default `300`)

- `enable_mitm` (bool)
- `mitm_ca_cert_file` (string path)
- `mitm_ca_key_file` (string path)
- `mitm_ca_generate_if_missing` (bool)
- `mitm_ca_export_cert_file` (string path or `null`)
- `tls_profile` (`"default"` or `"chrome"`)
- `force_http1_for_filter_rewrite` (bool, default `true`; required for the HTTP/1.1 body rewriter, disable to prefer HTTP/2 passthrough)

- `metrics_log_interval_secs` (number)

- `policy_config_file` (string path or `null`)
- `policy_mode` (`"disabled"`, `"report_only"`, `"enforce"`)
- `policy_reload_interval_secs` (number)

- `receipts_file` (string path or `null`)
- `receipts_flush_interval_secs` (number)

- `enable_dns_filter` (bool)
- `dns_listen_host` (string)
- `dns_listen_port` (number)
- `dns_upstream` (string, e.g. `"1.1.1.1:53"`)
- `dns_upstream_doh` (DoH URL string or `null`)
- `dns_doh_failure_mode` (`"fail_closed"`, default, or `"fallback_udp"`)
- `dns_max_inflight` (positive number, default `128`)

- `filter_list_file` (array of string paths)
- `filter_list_url` (array of strings)
- `filter_list_cache_dir` (string path)
- `filter_list_refresh_secs` (number)
- `filter_list_download_timeout_secs` (number)

- `dashboard_port` (number or `null`)
- `cert_log_file` (string path or `null`)
- `cert_pin_file` (string path or `null`)

## Example

See:

- `configs/basic.local.json` (MITM + receipts + dashboard)
- `configs/easylist.local.json` (portable `127.0.0.1:5353`, strict DoH)
- `configs/easylist.wsl-mirrored.json` (operator-specific `127.0.0.2:53`, measured UDP fallback)
- `scripts/run_easylist_local.sh` (downloads EasyList to `/tmp/easylist.txt` and starts the engine)

Operational note:

- Loopback is a non-disableable MITM bypass. Clients should also carry
  `NO_PROXY/no_proxy=localhost,127.0.0.1,::1`; `scripts/privacy_engine_env.sh`
  adds those entries without replacing existing exclusions.
- Run `scripts/pe-trust.sh --system` once per machine, then
  `scripts/pe-trust.sh --check --system` to verify it. The script uses a
  managed CA bundle and environment variables, so Python virtual environments
  inherit trust without modifying each environment's `certifi` package.
- The dashboard now includes setup actions (`/download/ca.crt`, pinned-host reset button).
- Rewritten responses are not considered complete until their full framed body
  crosses an explicit client flush boundary. The dashboard exposes completed
  flushes, flush failures, incomplete responses, and injected bytes separately
  from rewrite-attempt counters.
- DoH responses are completed by HTTP framing, not connection closure. Status,
  media type, bounded body size, DNS parsing, transaction ID, and question are
  validated before delivery.
- `fallback_udp` never fails silently: DoH failures, UDP fallbacks, upstream
  failures, saturation drops, and completed DNS responses are separate metrics.
- DNS block decisions happen before upstream admission. One stalled upstream
  query cannot delay a local NXDOMAIN response.
- Auto-pin is suppressed during a fixed 60-second startup grace period. After
  that, a host must reach `auto_pin_reject_threshold` TLS failures inside
  `auto_pin_reject_window_secs`; the first observation is logged/receipted as
  pending rather than silently persisted.
