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

- `filter_list_file` (array of string paths)
- `filter_list_url` (array of strings)
- `filter_list_cache_dir` (string path)
- `filter_list_refresh_secs` (number)
- `filter_list_download_timeout_secs` (number)

- `dashboard_port` (number or `null`)
- `cert_log_file` (string path or `null`)

## Example

See:

- `configs/basic.local.json` (MITM + receipts + dashboard)
- `configs/easylist.local.json` (adds DNS + EasyList)
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
- Auto-pin is suppressed during a fixed 60-second startup grace period. After
  that, a host must reach `auto_pin_reject_threshold` TLS failures inside
  `auto_pin_reject_window_secs`; the first observation is logged/receipted as
  pending rather than silently persisted.
