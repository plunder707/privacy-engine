# Engine Config (JSON)

> Updated: 2026-02-15 10:01 UTC (Codex)

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

- The dashboard now includes setup actions (`/download/ca.crt`, pinned-host reset button).
- Auto-pin after client TLS rejection is suppressed during a fixed 60-second startup grace period.
