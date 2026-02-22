use crate::mitm;
use crate::policy;
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Engine runtime configuration loaded from a JSON file.
///
/// This exists to avoid "20 flags" startup commands and to make it easy to
/// build higher-level launchers/UIs later.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub listen_host: String,
    pub listen_port: u16,
    pub pinned_hosts_file: PathBuf,

    pub enable_mitm: bool,
    pub mitm_ca_cert_file: PathBuf,
    pub mitm_ca_key_file: PathBuf,
    pub mitm_ca_generate_if_missing: bool,
    pub mitm_ca_export_cert_file: Option<PathBuf>,
    pub tls_profile: mitm::TlsProfile,

    pub metrics_log_interval_secs: u64,

    pub policy_config_file: Option<PathBuf>,
    pub policy_mode: Option<policy::PolicyMode>,
    pub policy_reload_interval_secs: u64,

    pub receipts_file: Option<PathBuf>,
    pub receipts_flush_interval_secs: u64,

    pub enable_dns_filter: bool,
    pub dns_listen_host: String,
    pub dns_listen_port: u16,
    pub dns_upstream: String,
    pub dns_upstream_doh: Option<String>,

    pub filter_list_file: Vec<PathBuf>,
    pub filter_list_url: Vec<String>,
    pub filter_list_cache_dir: PathBuf,
    pub filter_list_refresh_secs: u64,
    pub filter_list_download_timeout_secs: u64,

    pub dashboard_port: Option<u16>,
    pub cert_log_file: Option<PathBuf>,
    pub cert_pin_file: Option<PathBuf>,

    pub doh_server_port: Option<u16>,
    pub doh_server_cert_file: Option<PathBuf>,
    pub doh_server_key_file: Option<PathBuf>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            listen_host: "127.0.0.1".to_string(),
            listen_port: 8080,
            pinned_hosts_file: PathBuf::from("sni_pinned_hosts.json"),

            enable_mitm: false,
            mitm_ca_cert_file: PathBuf::from("mitm_ca_cert.pem"),
            mitm_ca_key_file: PathBuf::from("mitm_ca_key.pem"),
            mitm_ca_generate_if_missing: true,
            mitm_ca_export_cert_file: None,
            tls_profile: mitm::TlsProfile::Default,

            metrics_log_interval_secs: 30,

            policy_config_file: None,
            policy_mode: None,
            policy_reload_interval_secs: 5,

            receipts_file: None,
            receipts_flush_interval_secs: 30,

            enable_dns_filter: false,
            dns_listen_host: "127.0.0.1".to_string(),
            dns_listen_port: 5353,
            dns_upstream: "8.8.8.8:53".to_string(),
            dns_upstream_doh: None,

            filter_list_file: Vec::new(),
            filter_list_url: Vec::new(),
            filter_list_cache_dir: PathBuf::from("filter_list_cache"),
            filter_list_refresh_secs: 86400,
            filter_list_download_timeout_secs: 30,

            dashboard_port: None,
            cert_log_file: None,
            cert_pin_file: None,

            doh_server_port: None,
            doh_server_cert_file: None,
            doh_server_key_file: None,
        }
    }
}

fn parse_policy_mode_str(s: &str) -> Option<policy::PolicyMode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "disabled" => Some(policy::PolicyMode::Disabled),
        "report_only" | "report-only" | "reportonly" => Some(policy::PolicyMode::ReportOnly),
        "enforce" | "enforced" => Some(policy::PolicyMode::Enforce),
        _ => None,
    }
}

fn parse_tls_profile_str(s: &str) -> Option<mitm::TlsProfile> {
    match s.trim().to_ascii_lowercase().as_str() {
        "default" => Some(mitm::TlsProfile::Default),
        "chrome" => Some(mitm::TlsProfile::Chrome),
        _ => None,
    }
}

fn get_string_field(obj: &serde_json::Map<String, Value>, key: &str) -> io::Result<Option<String>> {
    let Some(v) = obj.get(key) else {
        return Ok(None);
    };
    let s = v.as_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("engine config key '{key}' must be a string"),
        )
    })?;
    Ok(Some(s.to_string()))
}

fn get_bool_field(obj: &serde_json::Map<String, Value>, key: &str) -> io::Result<Option<bool>> {
    let Some(v) = obj.get(key) else {
        return Ok(None);
    };
    let b = v.as_bool().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("engine config key '{key}' must be a boolean"),
        )
    })?;
    Ok(Some(b))
}

fn get_u16_field(obj: &serde_json::Map<String, Value>, key: &str) -> io::Result<Option<u16>> {
    let Some(v) = obj.get(key) else {
        return Ok(None);
    };
    let n = v.as_u64().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("engine config key '{key}' must be a number"),
        )
    })?;
    let n: u16 = n.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("engine config key '{key}' out of range for u16"),
        )
    })?;
    Ok(Some(n))
}

fn get_u64_field(obj: &serde_json::Map<String, Value>, key: &str) -> io::Result<Option<u64>> {
    let Some(v) = obj.get(key) else {
        return Ok(None);
    };
    let n = v.as_u64().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("engine config key '{key}' must be a number"),
        )
    })?;
    Ok(Some(n))
}

fn get_path_field(obj: &serde_json::Map<String, Value>, key: &str) -> io::Result<Option<PathBuf>> {
    Ok(get_string_field(obj, key)?.map(PathBuf::from))
}

fn get_string_array_field(
    obj: &serde_json::Map<String, Value>,
    key: &str,
) -> io::Result<Option<Vec<String>>> {
    let Some(v) = obj.get(key) else {
        return Ok(None);
    };
    let arr = v.as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("engine config key '{key}' must be a JSON array"),
        )
    })?;
    let mut out = Vec::new();
    for entry in arr {
        let s = entry.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("engine config key '{key}' array entries must be strings"),
            )
        })?;
        out.push(s.to_string());
    }
    Ok(Some(out))
}

fn get_path_array_field(
    obj: &serde_json::Map<String, Value>,
    key: &str,
) -> io::Result<Option<Vec<PathBuf>>> {
    Ok(get_string_array_field(obj, key)?.map(|v| v.into_iter().map(PathBuf::from).collect()))
}

impl EngineConfig {
    pub fn load_from_file(path: &Path) -> io::Result<Self> {
        let raw = fs::read_to_string(path)?;
        let parsed: Value = serde_json::from_str(&raw).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid engine config JSON: {e}"),
            )
        })?;
        let obj = parsed.as_object().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "engine config must be a JSON object",
            )
        })?;

        // Strict-but-forward-compatible: allow `meta` for comments, reject unknowns.
        let allowed_keys = [
            "meta",
            "listen_host",
            "listen_port",
            "pinned_hosts_file",
            "enable_mitm",
            "mitm_ca_cert_file",
            "mitm_ca_key_file",
            "mitm_ca_generate_if_missing",
            "mitm_ca_export_cert_file",
            "tls_profile",
            "metrics_log_interval_secs",
            "policy_config_file",
            "policy_mode",
            "policy_reload_interval_secs",
            "receipts_file",
            "receipts_flush_interval_secs",
            "enable_dns_filter",
            "dns_listen_host",
            "dns_listen_port",
            "dns_upstream",
            "dns_upstream_doh",
            "filter_list_file",
            "filter_list_url",
            "filter_list_cache_dir",
            "filter_list_refresh_secs",
            "filter_list_download_timeout_secs",
            "dashboard_port",
            "cert_log_file",
            "cert_pin_file",
            "doh_server_port",
            "doh_server_cert_file",
            "doh_server_key_file",
        ];
        for k in obj.keys() {
            if !allowed_keys.contains(&k.as_str()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown engine config key: '{k}'"),
                ));
            }
        }

        let mut cfg = EngineConfig::default();

        if let Some(v) = get_string_field(obj, "listen_host")? {
            cfg.listen_host = v;
        }
        if let Some(v) = get_u16_field(obj, "listen_port")? {
            cfg.listen_port = v;
        }
        if let Some(v) = get_path_field(obj, "pinned_hosts_file")? {
            cfg.pinned_hosts_file = v;
        }

        if let Some(v) = get_bool_field(obj, "enable_mitm")? {
            cfg.enable_mitm = v;
        }
        if let Some(v) = get_path_field(obj, "mitm_ca_cert_file")? {
            cfg.mitm_ca_cert_file = v;
        }
        if let Some(v) = get_path_field(obj, "mitm_ca_key_file")? {
            cfg.mitm_ca_key_file = v;
        }
        if let Some(v) = get_bool_field(obj, "mitm_ca_generate_if_missing")? {
            cfg.mitm_ca_generate_if_missing = v;
        }
        if obj.contains_key("mitm_ca_export_cert_file") {
            // Explicit null means "disable export".
            cfg.mitm_ca_export_cert_file = if obj
                .get("mitm_ca_export_cert_file")
                .is_some_and(|v| v.is_null())
            {
                None
            } else {
                get_path_field(obj, "mitm_ca_export_cert_file")?
            };
        }
        if let Some(v) = get_string_field(obj, "tls_profile")? {
            cfg.tls_profile = parse_tls_profile_str(&v).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid tls_profile '{v}' (expected: default|chrome)"),
                )
            })?;
        }

        if let Some(v) = get_u64_field(obj, "metrics_log_interval_secs")? {
            cfg.metrics_log_interval_secs = v;
        }

        if obj.contains_key("policy_config_file") {
            cfg.policy_config_file = if obj.get("policy_config_file").is_some_and(|v| v.is_null()) {
                None
            } else {
                get_path_field(obj, "policy_config_file")?
            };
        }
        if let Some(v) = get_string_field(obj, "policy_mode")? {
            cfg.policy_mode = Some(parse_policy_mode_str(&v).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid policy_mode '{v}' (expected: disabled|report_only|enforce)"),
                )
            })?);
        }
        if let Some(v) = get_u64_field(obj, "policy_reload_interval_secs")? {
            cfg.policy_reload_interval_secs = v;
        }

        if obj.contains_key("receipts_file") {
            cfg.receipts_file = if obj.get("receipts_file").is_some_and(|v| v.is_null()) {
                None
            } else {
                get_path_field(obj, "receipts_file")?
            };
        }
        if let Some(v) = get_u64_field(obj, "receipts_flush_interval_secs")? {
            cfg.receipts_flush_interval_secs = v;
        }

        if let Some(v) = get_bool_field(obj, "enable_dns_filter")? {
            cfg.enable_dns_filter = v;
        }
        if let Some(v) = get_string_field(obj, "dns_listen_host")? {
            cfg.dns_listen_host = v;
        }
        if let Some(v) = get_u16_field(obj, "dns_listen_port")? {
            cfg.dns_listen_port = v;
        }
        if let Some(v) = get_string_field(obj, "dns_upstream")? {
            cfg.dns_upstream = v;
        }
        if let Some(v) = get_string_field(obj, "dns_upstream_doh")? {
            cfg.dns_upstream_doh = Some(v);
        }

        if let Some(v) = get_path_array_field(obj, "filter_list_file")? {
            cfg.filter_list_file = v;
        }
        if let Some(v) = get_string_array_field(obj, "filter_list_url")? {
            cfg.filter_list_url = v;
        }
        if let Some(v) = get_path_field(obj, "filter_list_cache_dir")? {
            cfg.filter_list_cache_dir = v;
        }
        if let Some(v) = get_u64_field(obj, "filter_list_refresh_secs")? {
            cfg.filter_list_refresh_secs = v;
        }
        if let Some(v) = get_u64_field(obj, "filter_list_download_timeout_secs")? {
            cfg.filter_list_download_timeout_secs = v;
        }

        if obj.contains_key("dashboard_port") {
            cfg.dashboard_port = if obj.get("dashboard_port").is_some_and(|v| v.is_null()) {
                None
            } else {
                get_u16_field(obj, "dashboard_port")?
            };
        }
        if obj.contains_key("cert_log_file") {
            cfg.cert_log_file = if obj.get("cert_log_file").is_some_and(|v| v.is_null()) {
                None
            } else {
                get_path_field(obj, "cert_log_file")?
            };
        }
        if obj.contains_key("cert_pin_file") {
            cfg.cert_pin_file = if obj.get("cert_pin_file").is_some_and(|v| v.is_null()) {
                None
            } else {
                get_path_field(obj, "cert_pin_file")?
            };
        }

        if obj.contains_key("doh_server_port") {
            cfg.doh_server_port = if obj.get("doh_server_port").is_some_and(|v| v.is_null()) {
                None
            } else {
                get_u16_field(obj, "doh_server_port")?
            };
        }
        if obj.contains_key("doh_server_cert_file") {
            cfg.doh_server_cert_file =
                if obj.get("doh_server_cert_file").is_some_and(|v| v.is_null()) {
                    None
                } else {
                    get_path_field(obj, "doh_server_cert_file")?
                };
        }
        if obj.contains_key("doh_server_key_file") {
            cfg.doh_server_key_file = if obj.get("doh_server_key_file").is_some_and(|v| v.is_null())
            {
                None
            } else {
                get_path_field(obj, "doh_server_key_file")?
            };
        }

        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file(name: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}_{ts}.json"))
    }

    #[test]
    fn load_engine_config_overrides_defaults() {
        let path = temp_file("engine_cfg");
        fs::write(
            &path,
            r#"{
              "listen_port": 18081,
              "enable_mitm": true,
              "tls_profile": "chrome",
              "enable_dns_filter": true,
              "dns_upstream": "1.1.1.1:53",
              "filter_list_file": ["/tmp/easylist.txt"],
              "dashboard_port": 9090
            }"#,
        )
        .expect("write");

        let cfg = EngineConfig::load_from_file(&path).expect("load");
        assert_eq!(cfg.listen_host, "127.0.0.1");
        assert_eq!(cfg.listen_port, 18081);
        assert!(cfg.enable_mitm);
        assert_eq!(cfg.tls_profile, mitm::TlsProfile::Chrome);
        assert!(cfg.enable_dns_filter);
        assert_eq!(cfg.dns_upstream, "1.1.1.1:53");
        assert_eq!(
            cfg.filter_list_file,
            vec![PathBuf::from("/tmp/easylist.txt")]
        );
        assert_eq!(cfg.dashboard_port, Some(9090));
    }

    #[test]
    fn load_engine_config_with_doh() {
        let path = temp_file("engine_cfg_doh");
        fs::write(
            &path,
            r#"{
              "dns_upstream_doh": "https://1.1.1.1/dns-query"
            }"#,
        )
        .expect("write");

        let cfg = EngineConfig::load_from_file(&path).expect("load");
        assert_eq!(
            cfg.dns_upstream_doh,
            Some("https://1.1.1.1/dns-query".to_string())
        );
    }

    #[test]
    fn unknown_engine_config_key_is_rejected() {
        let path = temp_file("engine_cfg_unknown");
        fs::write(&path, r#"{ "nope": true }"#).expect("write");
        let err = EngineConfig::load_from_file(&path).unwrap_err();
        assert!(
            err.to_string().contains("unknown engine config key"),
            "unexpected error: {err}"
        );
    }
}
