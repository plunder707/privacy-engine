use clap::ValueEnum;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};
use tracing::info;

use crate::filter_list::FilterListRules;

const DEFAULT_TRACKER_COOKIE_DOMAINS: [&str; 5] = [
    "google-analytics.com",
    "doubleclick.net",
    "facebook.com",
    "scorecardresearch.com",
    "adnxs.com",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PolicyMode {
    Disabled,
    ReportOnly,
    Enforce,
}

impl PolicyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ReportOnly => "report_only",
            Self::Enforce => "enforce",
        }
    }

    fn parse_config_value(s: &str) -> Option<Self> {
        let normalized = s.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "disabled" => Some(Self::Disabled),
            "report_only" | "report-only" | "reportonly" => Some(Self::ReportOnly),
            "enforce" | "enforced" => Some(Self::Enforce),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentLevel {
    EssentialOnly,
    AnalyticsOk,
    All,
}

impl ConsentLevel {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "essential_only" => Some(Self::EssentialOnly),
            "analytics_ok" => Some(Self::AnalyticsOk),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EssentialOnly => "essential_only",
            Self::AnalyticsOk => "analytics_ok",
            Self::All => "all",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainCategory {
    Advertising,
    Analytics,
}

impl DomainCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advertising => "advertising",
            Self::Analytics => "analytics",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyHookAction {
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPlan {
    pub mode: PolicyMode,
    pub tracker_match: bool,
    pub enable_http1_set_cookie_filter: bool,
    pub consent_enforcement_active: bool,
    pub consent_level: Option<ConsentLevel>,
    pub domain_category: Option<DomainCategory>,
    pub user_profile_name: Option<String>,
    pub websocket_blocking_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderPolicyOutcome {
    pub output_headers: Vec<u8>,
    pub tracker_match: bool,
    pub set_cookie_count: usize,
    pub enforcement_applied: bool,
    pub report_only_hit: bool,
    pub consent_enforcement_active: bool,
    pub consent_level: Option<ConsentLevel>,
    pub domain_category: Option<DomainCategory>,
    pub user_profile_name: Option<String>,
}

#[derive(Debug, Clone)]
struct TrackerSetCookieRule {
    enabled: bool,
    domains: HashSet<String>,
}

impl TrackerSetCookieRule {
    fn default_enabled(mode: PolicyMode) -> Self {
        let mut domains = HashSet::new();
        for d in DEFAULT_TRACKER_COOKIE_DOMAINS {
            let normalized = normalize_host(d);
            if !normalized.is_empty() {
                domains.insert(normalized);
            }
        }
        Self {
            enabled: mode != PolicyMode::Disabled,
            domains,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct DnsBlockRule {
    enabled: bool,
    domains: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct BodyRewriteRule {
    pub enabled: bool,
    pub tracker_script_patterns: Vec<String>,
    pub remove_selectors: Vec<String>,
    /// Selectors injected as CSS `display:none!important` to hide elements created
    /// dynamically by JavaScript after page load (registration walls, overlays, etc.).
    /// These persist in the page and catch elements that lol_html DOM removal misses.
    /// Use specific selectors only (IDs, specific classes) — never broad attribute
    /// substring matches like `div[class*='gateway']` which can hide article content.
    pub css_inject_selectors: Vec<String>,
    pub strip_tracking_pixels: bool,
    pub max_body_bytes: usize,
    pub referer_spoof_domains: HashSet<String>,
    pub query_param_strip_enabled: bool,
}

impl Default for BodyRewriteRule {
    fn default() -> Self {
        Self {
            enabled: false,
            tracker_script_patterns: Vec::new(),
            remove_selectors: Vec::new(),
            css_inject_selectors: Vec::new(),
            strip_tracking_pixels: false,
            max_body_bytes: 2 * 1024 * 1024, // 2MB
            referer_spoof_domains: HashSet::new(),
            query_param_strip_enabled: false,
        }
    }
}

#[derive(Debug, Clone)]
struct UserProfile {
    name: String,
    consent: ConsentLevel,
}

#[derive(Debug, Clone)]
struct ConsentEnforcementRule {
    enabled: bool,
    default_consent: ConsentLevel,
    analytics_domains: HashSet<String>,
    site_overrides: HashMap<String, ConsentLevel>,
    user_profiles: HashMap<String, UserProfile>,
}

impl Default for ConsentEnforcementRule {
    fn default() -> Self {
        Self {
            enabled: false,
            default_consent: ConsentLevel::EssentialOnly,
            analytics_domains: HashSet::new(),
            site_overrides: HashMap::new(),
            user_profiles: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BodyRewritePlan {
    pub mode: PolicyMode,
    pub should_rewrite: bool,
    pub manual_script_patterns: Arc<Vec<String>>,
    pub filter_script_patterns: Arc<Vec<String>>,
    pub manual_remove_selectors: Arc<Vec<String>>,
    pub filter_remove_selectors: Arc<Vec<String>>,
    pub domain_remove_selectors: Vec<Arc<Vec<String>>>,
    /// Selectors to inject as CSS display:none for JS-created elements.
    pub css_inject_selectors: Arc<Vec<String>>,
    pub strip_tracking_pixels: bool,
    pub max_body_bytes: usize,
    pub referer_spoof: bool,
    pub query_param_strip: bool,
}

impl BodyRewritePlan {
    #[cfg(test)]
    pub fn script_patterns_iter(&self) -> impl Iterator<Item = &str> {
        self.manual_script_patterns
            .iter()
            .map(String::as_str)
            .chain(self.filter_script_patterns.iter().map(String::as_str))
    }

    #[cfg(test)]
    pub fn remove_selectors_iter(&self) -> impl Iterator<Item = &str> {
        self.manual_remove_selectors
            .iter()
            .map(String::as_str)
            .chain(self.filter_remove_selectors.iter().map(String::as_str))
            .chain(
                self.domain_remove_selectors
                    .iter()
                    .flat_map(|v| v.iter().map(String::as_str)),
            )
    }
}

fn empty_string_vec_arc() -> Arc<Vec<String>> {
    static EMPTY: OnceLock<Arc<Vec<String>>> = OnceLock::new();
    Arc::clone(EMPTY.get_or_init(|| Arc::new(Vec::new())))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsQueryPlan {
    pub mode: PolicyMode,
    pub should_block: bool,
}

#[derive(Debug, Clone)]
struct PolicyConfig {
    version: u64,
    mode: PolicyMode,
    tracker_set_cookie: TrackerSetCookieRule,
    dns_block: DnsBlockRule,
    body_rewrite: BodyRewriteRule,
    consent_enforcement: ConsentEnforcementRule,
    websocket_blocking_enabled: bool,
}

impl PolicyConfig {
    fn default_for_mode(mode: PolicyMode) -> Self {
        Self {
            version: 1,
            mode,
            tracker_set_cookie: TrackerSetCookieRule::default_enabled(mode),
            dns_block: DnsBlockRule::default(),
            body_rewrite: BodyRewriteRule::default(),
            consent_enforcement: ConsentEnforcementRule::default(),
            websocket_blocking_enabled: true,
        }
    }

    fn validate(&self) -> io::Result<()> {
        if self.version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported policy config version: {}", self.version),
            ));
        }
        if self.tracker_set_cookie.enabled && self.tracker_set_cookie.domains.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tracker_set_cookie.enabled=true but domains list is empty",
            ));
        }
        if self.dns_block.enabled && self.dns_block.domains.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dns_block.enabled=true but domains list is empty",
            ));
        }
        if self.body_rewrite.enabled {
            if self.body_rewrite.tracker_script_patterns.is_empty()
                && self.body_rewrite.remove_selectors.is_empty()
                && !self.body_rewrite.strip_tracking_pixels
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "body_rewrite.enabled=true but no patterns, selectors, or pixel stripping configured",
                ));
            }
            // Validate CSS selectors at config parse time
            for sel in &self.body_rewrite.remove_selectors {
                if sel.parse::<lol_html::Selector>().is_err() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid CSS selector in body_rewrite.remove_selectors: '{sel}'"),
                    ));
                }
            }
        }
        Ok(())
    }

    fn from_json_value(v: &Value) -> io::Result<Self> {
        let obj = v.as_object().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "policy config must be a JSON object",
            )
        })?;

        // Strict-but-forward-compatible key handling: allow `meta` for comments, reject unknowns.
        let allowed_top_keys = ["version", "mode", "rules", "meta", "filter_lists"];
        for k in obj.keys() {
            if !allowed_top_keys.contains(&k.as_str()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown policy config key: '{k}'"),
                ));
            }
        }

        let version = obj.get("version").and_then(|v| v.as_u64()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "policy config missing required integer field: version",
            )
        })?;

        let mode_str = obj.get("mode").and_then(|v| v.as_str()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "policy config missing required string field: mode",
            )
        })?;

        let mode = PolicyMode::parse_config_value(mode_str).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid policy mode '{mode_str}' (expected disabled|report_only|enforce)"),
            )
        })?;

        let rules_val = obj.get("rules").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "policy config missing required object field: rules",
            )
        })?;
        let rules_obj = rules_val.as_object().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "policy rules must be a JSON object",
            )
        })?;

        let allowed_rules = [
            "tracker_set_cookie",
            "dns_block",
            "body_rewrite",
            "consent_enforcement",
            "websocket_blocking",
        ];
        for k in rules_obj.keys() {
            if !allowed_rules.contains(&k.as_str()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown policy rule: '{k}'"),
                ));
            }
        }

        let tracker_rule_val = rules_obj.get("tracker_set_cookie").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "policy rules missing required key: tracker_set_cookie",
            )
        })?;
        let tracker_rule_obj = tracker_rule_val.as_object().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "tracker_set_cookie must be a JSON object",
            )
        })?;

        let allowed_tracker_keys = ["enabled", "domains"];
        for k in tracker_rule_obj.keys() {
            if !allowed_tracker_keys.contains(&k.as_str()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown tracker_set_cookie key: '{k}'"),
                ));
            }
        }

        let enabled = tracker_rule_obj
            .get("enabled")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tracker_set_cookie missing required boolean field: enabled",
                )
            })?;

        let domains_val = tracker_rule_obj.get("domains").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "tracker_set_cookie missing required array field: domains",
            )
        })?;
        let domains_arr = domains_val.as_array().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "tracker_set_cookie.domains must be a JSON array of strings",
            )
        })?;

        let mut domains = HashSet::new();
        for entry in domains_arr {
            let raw = entry.as_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tracker_set_cookie.domains must contain only strings",
                )
            })?;
            let normalized = normalize_host(raw);
            if normalized.is_empty() {
                continue;
            }
            if normalized.contains('/') || normalized.contains(' ') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid tracker domain value: '{raw}'"),
                ));
            }
            domains.insert(normalized);
        }

        // Parse optional dns_block rule (backward-compatible: absent = disabled)
        let dns_block = if let Some(dns_val) = rules_obj.get("dns_block") {
            let dns_obj = dns_val.as_object().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "dns_block must be a JSON object",
                )
            })?;
            let allowed_dns_keys = ["enabled", "domains"];
            for k in dns_obj.keys() {
                if !allowed_dns_keys.contains(&k.as_str()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unknown dns_block key: '{k}'"),
                    ));
                }
            }
            let dns_enabled = dns_obj
                .get("enabled")
                .and_then(|v| v.as_bool())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "dns_block missing required boolean field: enabled",
                    )
                })?;
            let dns_domains_arr = dns_obj
                .get("domains")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "dns_block missing required array field: domains",
                    )
                })?;
            let mut dns_domains = HashSet::new();
            for entry in dns_domains_arr {
                let raw = entry.as_str().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "dns_block.domains must contain only strings",
                    )
                })?;
                let normalized = normalize_host(raw);
                if normalized.is_empty() {
                    continue;
                }
                if normalized.contains('/') || normalized.contains(' ') {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid dns_block domain value: '{raw}'"),
                    ));
                }
                dns_domains.insert(normalized);
            }
            DnsBlockRule {
                enabled: dns_enabled,
                domains: dns_domains,
            }
        } else {
            DnsBlockRule::default()
        };

        // Parse optional body_rewrite rule (backward-compatible: absent = disabled)
        let body_rewrite = if let Some(bw_val) = rules_obj.get("body_rewrite") {
            let bw_obj = bw_val.as_object().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "body_rewrite must be a JSON object",
                )
            })?;
            let allowed_bw_keys = [
                "enabled",
                "tracker_script_patterns",
                "remove_selectors",
                "css_inject_selectors",
                "strip_tracking_pixels",
                "max_body_bytes",
                "referer_spoof_domains",
                "query_param_strip_enabled",
            ];
            for k in bw_obj.keys() {
                if !allowed_bw_keys.contains(&k.as_str()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unknown body_rewrite key: '{k}'"),
                    ));
                }
            }
            let bw_enabled = bw_obj
                .get("enabled")
                .and_then(|v| v.as_bool())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "body_rewrite missing required boolean field: enabled",
                    )
                })?;
            let tracker_script_patterns = bw_obj
                .get("tracker_script_patterns")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let remove_selectors = bw_obj
                .get("remove_selectors")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let css_inject_selectors = bw_obj
                .get("css_inject_selectors")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let strip_tracking_pixels = bw_obj
                .get("strip_tracking_pixels")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let max_body_bytes = bw_obj
                .get("max_body_bytes")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .unwrap_or(2 * 1024 * 1024);
            let mut referer_spoof_domains = HashSet::new();
            if let Some(rsd_arr) = bw_obj
                .get("referer_spoof_domains")
                .and_then(|v| v.as_array())
            {
                for entry in rsd_arr {
                    let raw = entry.as_str().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "body_rewrite.referer_spoof_domains must contain only strings",
                        )
                    })?;
                    let normalized = normalize_host(raw);
                    if !normalized.is_empty() {
                        referer_spoof_domains.insert(normalized);
                    }
                }
            }
            let query_param_strip_enabled = bw_obj
                .get("query_param_strip_enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            BodyRewriteRule {
                enabled: bw_enabled,
                tracker_script_patterns,
                remove_selectors,
                css_inject_selectors,
                strip_tracking_pixels,
                max_body_bytes,
                referer_spoof_domains,
                query_param_strip_enabled,
            }
        } else {
            BodyRewriteRule::default()
        };

        let consent_enforcement = if let Some(ce_val) = rules_obj.get("consent_enforcement") {
            let ce_obj = ce_val.as_object().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "consent_enforcement must be a JSON object",
                )
            })?;
            let allowed_ce_keys = [
                "enabled",
                "default_consent",
                "analytics_domains",
                "site_overrides",
                "user_profiles",
            ];
            for k in ce_obj.keys() {
                if !allowed_ce_keys.contains(&k.as_str()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unknown consent_enforcement key: '{k}'"),
                    ));
                }
            }
            let ce_enabled = ce_obj
                .get("enabled")
                .and_then(|v| v.as_bool())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "consent_enforcement missing required boolean field: enabled",
                    )
                })?;
            let default_consent_str = ce_obj
                .get("default_consent")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "consent_enforcement missing required string field: default_consent",
                    )
                })?;
            let default_consent = ConsentLevel::parse(default_consent_str).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "invalid consent level '{default_consent_str}' \
                             (expected essential_only|analytics_ok|all)"
                    ),
                )
            })?;
            let empty_arr = Vec::new();
            let analytics_domains_arr = ce_obj
                .get("analytics_domains")
                .and_then(|v| v.as_array())
                .unwrap_or(&empty_arr);
            let mut analytics_domains = HashSet::new();
            for entry in analytics_domains_arr {
                let raw = entry.as_str().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "consent_enforcement.analytics_domains must contain only strings",
                    )
                })?;
                let normalized = normalize_host(raw);
                if !normalized.is_empty() {
                    analytics_domains.insert(normalized);
                }
            }
            let mut site_overrides = HashMap::new();
            if let Some(overrides_val) = ce_obj.get("site_overrides") {
                let overrides_obj = overrides_val.as_object().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "consent_enforcement.site_overrides must be a JSON object",
                    )
                })?;
                for (site, level_val) in overrides_obj {
                    let level_str = level_val.as_str().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "consent_enforcement.site_overrides['{site}'] must be a string"
                            ),
                        )
                    })?;
                    let level = ConsentLevel::parse(level_str).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "invalid consent level '{level_str}' for site override '{site}'"
                            ),
                        )
                    })?;
                    site_overrides.insert(normalize_host(site), level);
                }
            }
            let mut user_profiles = HashMap::new();
            if let Some(profiles_val) = ce_obj.get("user_profiles") {
                let profiles_obj = profiles_val.as_object().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "consent_enforcement.user_profiles must be a JSON object",
                    )
                })?;
                for (ip_key, profile_val) in profiles_obj {
                    let profile_obj = profile_val.as_object().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "consent_enforcement.user_profiles['{ip_key}'] must be a JSON object"
                            ),
                        )
                    })?;
                    let allowed_profile_keys = ["name", "consent"];
                    for k in profile_obj.keys() {
                        if !allowed_profile_keys.contains(&k.as_str()) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("unknown key '{k}' in user_profiles['{ip_key}']"),
                            ));
                        }
                    }
                    let name = profile_obj
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "user_profiles['{ip_key}'] missing required string field: name"
                                ),
                            )
                        })?;
                    let consent_str = profile_obj
                        .get("consent")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "user_profiles['{ip_key}'] missing required string field: consent"
                                ),
                            )
                        })?;
                    let consent = ConsentLevel::parse(consent_str).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "invalid consent level '{consent_str}' for user_profiles['{ip_key}']"
                            ),
                        )
                    })?;
                    user_profiles.insert(
                        ip_key.clone(),
                        UserProfile {
                            name: name.to_string(),
                            consent,
                        },
                    );
                }
            }
            ConsentEnforcementRule {
                enabled: ce_enabled,
                default_consent,
                analytics_domains,
                site_overrides,
                user_profiles,
            }
        } else {
            ConsentEnforcementRule::default()
        };

        let websocket_blocking_enabled = if let Some(ws_val) = rules_obj.get("websocket_blocking") {
            let ws_obj = ws_val.as_object().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "websocket_blocking must be a JSON object",
                )
            })?;
            let allowed_ws_keys = ["enabled"];
            for k in ws_obj.keys() {
                if !allowed_ws_keys.contains(&k.as_str()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unknown websocket_blocking key: '{k}'"),
                    ));
                }
            }
            ws_obj
                .get("enabled")
                .and_then(|v| v.as_bool())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "websocket_blocking missing required boolean field: enabled",
                    )
                })?
        } else {
            true // default: enabled
        };

        let cfg = Self {
            version,
            mode,
            tracker_set_cookie: TrackerSetCookieRule { enabled, domains },
            dns_block,
            body_rewrite,
            consent_enforcement,
            websocket_blocking_enabled,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    fn describe_for_logs(&self) -> PolicyConfigSummary {
        PolicyConfigSummary {
            version: self.version,
            mode: self.mode,
            tracker_rule_enabled: self.tracker_set_cookie.enabled
                && self.mode != PolicyMode::Disabled,
            tracker_domain_count: self.tracker_set_cookie.domains.len(),
            dns_block_enabled: self.dns_block.enabled && self.mode != PolicyMode::Disabled,
            dns_block_domain_count: self.dns_block.domains.len(),
            consent_enforcement_enabled: self.consent_enforcement.enabled
                && self.mode != PolicyMode::Disabled,
            consent_default_consent: if self.consent_enforcement.enabled {
                self.consent_enforcement.default_consent.as_str()
            } else {
                "disabled"
            },
            consent_analytics_domain_count: self.consent_enforcement.analytics_domains.len(),
            consent_user_profile_count: self.consent_enforcement.user_profiles.len(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PolicyConfigSummary {
    pub version: u64,
    pub mode: PolicyMode,
    pub tracker_rule_enabled: bool,
    pub tracker_domain_count: usize,
    pub dns_block_enabled: bool,
    pub dns_block_domain_count: usize,
    pub consent_enforcement_enabled: bool,
    pub consent_default_consent: &'static str,
    pub consent_analytics_domain_count: usize,
    pub consent_user_profile_count: usize,
}

#[derive(Debug)]
pub struct PolicyEngine {
    cfg: RwLock<PolicyConfig>,
    filter_list_rules: RwLock<FilterListRules>,
}

impl PolicyEngine {
    pub fn new(mode: PolicyMode) -> Self {
        Self {
            cfg: RwLock::new(PolicyConfig::default_for_mode(mode)),
            filter_list_rules: RwLock::new(FilterListRules::default()),
        }
    }

    pub fn load_from_file(path: &Path, mode_override: Option<PolicyMode>) -> io::Result<Self> {
        let cfg = load_policy_config_from_file(path, mode_override)?;
        Ok(Self {
            cfg: RwLock::new(cfg),
            filter_list_rules: RwLock::new(FilterListRules::default()),
        })
    }

    /// Replace the filter list rules atomically. Called by the refresh task.
    pub fn replace_filter_list_rules(&self, new_rules: FilterListRules) {
        match self.filter_list_rules.write() {
            Ok(mut guard) => *guard = new_rules,
            Err(e) => {
                tracing::error!(error = %e, "filter_list_rules lock poisoned on write");
            }
        }
    }

    /// Get filter list aggregate stats for logging.
    pub fn filter_list_stats(&self) -> crate::filter_list::FilterListAggregateStats {
        self.filter_list_rules
            .read()
            .ok()
            .map(|r| r.stats.clone())
            .unwrap_or_default()
    }

    pub fn summary(&self) -> PolicyConfigSummary {
        self.cfg
            .read()
            .ok()
            .map(|c| c.describe_for_logs())
            .unwrap_or(PolicyConfigSummary {
                version: 1,
                mode: PolicyMode::Disabled,
                tracker_rule_enabled: false,
                tracker_domain_count: 0,
                dns_block_enabled: false,
                dns_block_domain_count: 0,
                consent_enforcement_enabled: false,
                consent_default_consent: "disabled",
                consent_analytics_domain_count: 0,
                consent_user_profile_count: 0,
            })
    }

    pub fn replace_from_file(
        &self,
        path: &Path,
        mode_override: Option<PolicyMode>,
    ) -> io::Result<PolicyConfigSummary> {
        let cfg = load_policy_config_from_file(path, mode_override)?;
        let summary = cfg.describe_for_logs();
        let mut guard = self
            .cfg
            .write()
            .map_err(|e| io::Error::other(format!("policy config lock poisoned: {e}")))?;
        *guard = cfg;
        Ok(summary)
    }

    pub fn plan_for_host(&self, host: &str) -> SessionPlan {
        self.plan_for_host_with_source_ip(host, None)
    }

    pub fn plan_for_host_with_source_ip(&self, host: &str, source_ip: Option<&str>) -> SessionPlan {
        let normalized = normalize_host(host);
        let cfg_guard = match self.cfg.read() {
            Ok(g) => g,
            Err(_) => {
                return SessionPlan {
                    mode: PolicyMode::Disabled,
                    tracker_match: false,
                    enable_http1_set_cookie_filter: false,
                    consent_enforcement_active: false,
                    consent_level: None,
                    domain_category: None,
                    user_profile_name: None,
                    websocket_blocking_enabled: false,
                };
            }
        };

        let mode = cfg_guard.mode;
        let consent_active = cfg_guard.consent_enforcement.enabled && mode != PolicyMode::Disabled;

        // Determine if domain is in advertising lists (tracker_set_cookie + filter list)
        let mut is_advertising =
            if cfg_guard.tracker_set_cookie.enabled && mode != PolicyMode::Disabled {
                domain_in_set_or_parent(&normalized, &cfg_guard.tracker_set_cookie.domains)
            } else {
                false
            };
        if !is_advertising && mode != PolicyMode::Disabled {
            if let Ok(fl) = self.filter_list_rules.read() {
                if domain_in_set_or_parent(&normalized, &fl.block_domains)
                    && !domain_in_set_or_parent(&normalized, &fl.exception_domains)
                {
                    is_advertising = true;
                }
            }
        }

        // Determine if domain is in analytics list
        let is_analytics = consent_active
            && domain_in_set_or_parent(
                &normalized,
                &cfg_guard.consent_enforcement.analytics_domains,
            );

        // Only attach category metadata when consent enforcement is active.
        let domain_category = if consent_active {
            // Analytics category takes priority over advertising
            if is_analytics {
                Some(DomainCategory::Analytics)
            } else if is_advertising {
                Some(DomainCategory::Advertising)
            } else {
                None
            }
        } else {
            None
        };

        let tracker_match = is_advertising || is_analytics;

        // Look up user profile by source IP (if consent enforcement active)
        let user_profile = if consent_active {
            source_ip.and_then(|ip| cfg_guard.consent_enforcement.user_profiles.get(ip))
        } else {
            None
        };
        let user_profile_name = user_profile.map(|p| p.name.clone());

        let consent_level = if consent_active {
            // User profile consent takes priority over site overrides and default
            if let Some(profile) = user_profile {
                Some(profile.consent)
            } else {
                // Look up consent level: exact match, then parent domain walk, then default
                let level = cfg_guard
                    .consent_enforcement
                    .site_overrides
                    .get(&normalized)
                    .copied()
                    .or_else(|| {
                        let mut remainder = normalized.as_str();
                        while let Some((_, after_dot)) = remainder.split_once('.') {
                            remainder = after_dot;
                            if let Some(&level) =
                                cfg_guard.consent_enforcement.site_overrides.get(remainder)
                            {
                                return Some(level);
                            }
                        }
                        None
                    })
                    .unwrap_or(cfg_guard.consent_enforcement.default_consent);
                Some(level)
            }
        } else {
            None
        };

        let enable_filter = if consent_active {
            match (domain_category, consent_level) {
                (Some(DomainCategory::Advertising), Some(ConsentLevel::All)) => false,
                (Some(DomainCategory::Advertising), _) => true,
                (Some(DomainCategory::Analytics), Some(ConsentLevel::EssentialOnly)) => true,
                (Some(DomainCategory::Analytics), _) => false,
                (None, _) => false,
            }
        } else {
            // Legacy path: binary tracker match
            tracker_match && mode != PolicyMode::Disabled
        };

        SessionPlan {
            mode,
            tracker_match,
            enable_http1_set_cookie_filter: enable_filter,
            consent_enforcement_active: consent_active,
            consent_level,
            domain_category,
            user_profile_name,
            websocket_blocking_enabled: cfg_guard.websocket_blocking_enabled,
        }
    }

    pub fn plan_for_dns_query(&self, host: &str) -> DnsQueryPlan {
        let normalized = normalize_host(host);
        let cfg_guard = match self.cfg.read() {
            Ok(g) => g,
            Err(_) => {
                return DnsQueryPlan {
                    mode: PolicyMode::Disabled,
                    should_block: false,
                };
            }
        };

        let mode = cfg_guard.mode;
        if mode == PolicyMode::Disabled {
            return DnsQueryPlan {
                mode,
                should_block: false,
            };
        }

        // Check manual config dns_block domains
        let mut matched = if cfg_guard.dns_block.enabled {
            domain_in_set_or_parent(&normalized, &cfg_guard.dns_block.domains)
        } else {
            false
        };

        // Union with filter list block_domains (minus exceptions, but NOT minus manual config)
        if !matched {
            if let Ok(fl) = self.filter_list_rules.read() {
                if domain_in_set_or_parent(&normalized, &fl.block_domains)
                    && !domain_in_set_or_parent(&normalized, &fl.exception_domains)
                {
                    matched = true;
                }
            }
        }

        DnsQueryPlan {
            mode,
            should_block: matched,
        }
    }

    pub fn plan_for_body_rewrite(&self, host: &str) -> BodyRewritePlan {
        let normalized = normalize_host(host);
        let cfg_guard = match self.cfg.read() {
            Ok(g) => g,
            Err(_) => {
                return BodyRewritePlan {
                    mode: PolicyMode::Disabled,
                    should_rewrite: false,
                    manual_script_patterns: empty_string_vec_arc(),
                    filter_script_patterns: empty_string_vec_arc(),
                    manual_remove_selectors: empty_string_vec_arc(),
                    filter_remove_selectors: empty_string_vec_arc(),
                    domain_remove_selectors: Vec::new(),
                    css_inject_selectors: empty_string_vec_arc(),
                    strip_tracking_pixels: false,
                    max_body_bytes: 2 * 1024 * 1024,
                    referer_spoof: false,
                    query_param_strip: false,
                };
            }
        };

        let mode = cfg_guard.mode;

        // Manual config patterns/selectors (small, cloned per plan)
        let manual_script_patterns = if cfg_guard.body_rewrite.enabled {
            Arc::new(cfg_guard.body_rewrite.tracker_script_patterns.clone())
        } else {
            empty_string_vec_arc()
        };
        let manual_remove_selectors = if cfg_guard.body_rewrite.enabled {
            Arc::new(cfg_guard.body_rewrite.remove_selectors.clone())
        } else {
            empty_string_vec_arc()
        };
        let strip_tracking_pixels =
            cfg_guard.body_rewrite.enabled && cfg_guard.body_rewrite.strip_tracking_pixels;
        let max_body_bytes = cfg_guard.body_rewrite.max_body_bytes;

        // Filter list patterns/selectors (can be large; shared via Arc)
        let mut filter_script_patterns = empty_string_vec_arc();
        let mut filter_remove_selectors = empty_string_vec_arc();
        let mut domain_remove_selectors: Vec<Arc<Vec<String>>> = Vec::new();

        if mode != PolicyMode::Disabled {
            if let Ok(fl) = self.filter_list_rules.read() {
                filter_script_patterns = Arc::clone(&fl.tracker_script_patterns);
                filter_remove_selectors = Arc::clone(&fl.cosmetic_selectors);

                // Domain-scoped cosmetic selectors: walk parent domains
                let mut remainder = normalized.as_str();
                loop {
                    if let Some(sels) = fl.domain_cosmetic_map.get(remainder) {
                        domain_remove_selectors.push(Arc::clone(sels));
                    }
                    match remainder.split_once('.') {
                        Some((_, after_dot)) => remainder = after_dot,
                        None => break,
                    }
                }
            }
        }

        let css_inject_selectors = if cfg_guard.body_rewrite.enabled {
            Arc::new(cfg_guard.body_rewrite.css_inject_selectors.clone())
        } else {
            empty_string_vec_arc()
        };

        let should_rewrite = mode != PolicyMode::Disabled
            && (strip_tracking_pixels
                || !manual_script_patterns.is_empty()
                || !filter_script_patterns.is_empty()
                || !manual_remove_selectors.is_empty()
                || !filter_remove_selectors.is_empty()
                || !domain_remove_selectors.is_empty()
                || !css_inject_selectors.is_empty());

        let referer_spoof = mode != PolicyMode::Disabled
            && cfg_guard.body_rewrite.enabled
            && !cfg_guard.body_rewrite.referer_spoof_domains.is_empty()
            && domain_in_set_or_parent(&normalized, &cfg_guard.body_rewrite.referer_spoof_domains);

        let query_param_strip = mode != PolicyMode::Disabled
            && cfg_guard.body_rewrite.enabled
            && cfg_guard.body_rewrite.query_param_strip_enabled;

        BodyRewritePlan {
            mode,
            should_rewrite,
            manual_script_patterns,
            filter_script_patterns,
            manual_remove_selectors,
            filter_remove_selectors,
            domain_remove_selectors,
            css_inject_selectors,
            strip_tracking_pixels,
            max_body_bytes,
            referer_spoof,
            query_param_strip,
        }
    }

    pub fn on_mitm_session_start(
        &self,
        flow: &'static str,
        host: &str,
        target_addr: &str,
    ) -> PolicyHookAction {
        let plan = self.plan_for_host(host);
        info!(
            event = "policy_hook",
            hook = "mitm_session_start",
            policy_mode = plan.mode.as_str(),
            flow,
            host = host,
            target_addr = target_addr,
            action = "allow",
            tracker_match = plan.tracker_match,
            enable_http1_set_cookie_filter = plan.enable_http1_set_cookie_filter,
            "policy hook evaluated (no-op scaffold)"
        );
        PolicyHookAction::Allow
    }

    pub fn apply_http1_response_header_policy(
        &self,
        host: &str,
        header_block: &[u8],
        source_ip: Option<&str>,
    ) -> HeaderPolicyOutcome {
        let plan = self.plan_for_host_with_source_ip(host, source_ip);
        let consent_enforcement_active = plan.consent_enforcement_active;
        let consent_level = plan.consent_level;
        let domain_category = plan.domain_category;
        let user_profile_name = plan.user_profile_name;

        if !plan.enable_http1_set_cookie_filter {
            return HeaderPolicyOutcome {
                output_headers: header_block.to_vec(),
                tracker_match: plan.tracker_match,
                set_cookie_count: 0,
                enforcement_applied: false,
                report_only_hit: false,
                consent_enforcement_active,
                consent_level,
                domain_category,
                user_profile_name,
            };
        }

        let Some(header_end) = find_headers_end(header_block) else {
            return HeaderPolicyOutcome {
                output_headers: header_block.to_vec(),
                tracker_match: plan.tracker_match,
                set_cookie_count: 0,
                enforcement_applied: false,
                report_only_hit: false,
                consent_enforcement_active,
                consent_level,
                domain_category,
                user_profile_name,
            };
        };

        let header_lines = &header_block[..header_end - 2];
        let mut lines = header_lines.split(|&b| b == b'\n').map(strip_trailing_cr);

        let Some(status_line) = lines.next() else {
            return HeaderPolicyOutcome {
                output_headers: header_block.to_vec(),
                tracker_match: plan.tracker_match,
                set_cookie_count: 0,
                enforcement_applied: false,
                report_only_hit: false,
                consent_enforcement_active,
                consent_level,
                domain_category,
                user_profile_name,
            };
        };

        let mut rebuilt = Vec::with_capacity(header_block.len());
        rebuilt.extend_from_slice(status_line);
        rebuilt.extend_from_slice(b"\r\n");

        let mut set_cookie_count = 0usize;
        for line in lines {
            if starts_with_ascii_case_insensitive(line, b"set-cookie:") {
                set_cookie_count += 1;
                if plan.mode == PolicyMode::Enforce {
                    continue;
                }
            }
            rebuilt.extend_from_slice(line);
            rebuilt.extend_from_slice(b"\r\n");
        }
        rebuilt.extend_from_slice(b"\r\n");
        rebuilt.extend_from_slice(&header_block[header_end..]);

        HeaderPolicyOutcome {
            output_headers: if plan.mode == PolicyMode::Enforce {
                rebuilt
            } else {
                header_block.to_vec()
            },
            tracker_match: plan.tracker_match,
            set_cookie_count,
            enforcement_applied: plan.mode == PolicyMode::Enforce && set_cookie_count > 0,
            report_only_hit: plan.mode == PolicyMode::ReportOnly && set_cookie_count > 0,
            consent_enforcement_active,
            consent_level,
            domain_category,
            user_profile_name,
        }
    }
}

/// Parse optional `"filter_lists"` array from policy JSON.
/// Returns a list of filter list source URLs/paths.
pub fn parse_filter_list_sources_from_config(
    path: &Path,
) -> io::Result<Vec<crate::filter_list::FilterListSource>> {
    let raw = fs::read_to_string(path)?;
    let parsed: Value = serde_json::from_str(&raw).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid policy config JSON: {e}"),
        )
    })?;
    let obj = parsed.as_object().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "policy config must be a JSON object",
        )
    })?;

    let Some(fl_val) = obj.get("filter_lists") else {
        return Ok(Vec::new());
    };
    let fl_arr = fl_val.as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "filter_lists must be a JSON array",
        )
    })?;

    let mut sources = Vec::new();
    for entry in fl_arr {
        let s = entry.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "filter_lists entries must be strings",
            )
        })?;
        if s.starts_with("http://") || s.starts_with("https://") {
            sources.push(crate::filter_list::FilterListSource::url(s));
        } else {
            sources.push(crate::filter_list::FilterListSource::local_file(s));
        }
    }
    Ok(sources)
}

fn load_policy_config_from_file(
    path: &Path,
    mode_override: Option<PolicyMode>,
) -> io::Result<PolicyConfig> {
    let raw = fs::read_to_string(path)?;
    let parsed: Value = serde_json::from_str(&raw).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid policy config JSON: {e}"),
        )
    })?;

    let mut cfg = PolicyConfig::from_json_value(&parsed)?;
    if let Some(override_mode) = mode_override {
        cfg.mode = override_mode;
    }
    cfg.validate()?;
    Ok(cfg)
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn domain_in_set_or_parent(host: &str, domains: &HashSet<String>) -> bool {
    if host.is_empty() {
        return false;
    }
    if domains.contains(host) {
        return true;
    }

    let mut remainder = host;
    while let Some((_, after_dot)) = remainder.split_once('.') {
        remainder = after_dot;
        if domains.contains(remainder) {
            return true;
        }
    }
    false
}

fn starts_with_ascii_case_insensitive(haystack: &[u8], prefix: &[u8]) -> bool {
    haystack.len() >= prefix.len() && haystack[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn strip_trailing_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file(name: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}_{ts}.json"))
    }

    fn write(path: &Path, content: &str) {
        fs::write(path, content).expect("write");
    }

    #[test]
    fn policy_engine_noop_allows_mitm_session() {
        let engine = PolicyEngine::new(PolicyMode::ReportOnly);
        assert_eq!(
            engine.on_mitm_session_start("connect", "example.com", "example.com:443"),
            PolicyHookAction::Allow
        );
    }

    #[test]
    fn report_only_does_not_modify_headers_but_counts_set_cookie() {
        let engine = PolicyEngine::new(PolicyMode::ReportOnly);
        let headers = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=b\r\nServer: test\r\n\r\nbody";
        let out = engine.apply_http1_response_header_policy("doubleclick.net", headers, None);
        assert_eq!(out.output_headers, headers);
        assert_eq!(out.set_cookie_count, 1);
        assert!(out.report_only_hit);
        assert!(!out.enforcement_applied);
    }

    #[test]
    fn enforce_strips_set_cookie_for_tracker_hosts() {
        let engine = PolicyEngine::new(PolicyMode::Enforce);
        let headers = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=b\r\nServer: test\r\n\r\nbody";
        let out = engine.apply_http1_response_header_policy("doubleclick.net", headers, None);
        let out_str = String::from_utf8(out.output_headers).expect("utf8");
        assert!(!out_str.contains("Set-Cookie:"));
        assert!(out_str.contains("Server: test"));
        assert_eq!(out.set_cookie_count, 1);
        assert!(out.enforcement_applied);
    }

    #[test]
    fn disabled_mode_keeps_headers_unchanged() {
        let engine = PolicyEngine::new(PolicyMode::Disabled);
        let headers = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=b\r\n\r\nbody";
        let out = engine.apply_http1_response_header_policy("doubleclick.net", headers, None);
        assert_eq!(out.output_headers, headers);
        assert_eq!(out.set_cookie_count, 0);
    }

    #[test]
    fn enforce_strips_multiple_set_cookie_headers_case_insensitive() {
        let engine = PolicyEngine::new(PolicyMode::Enforce);
        let headers =
            b"HTTP/1.1 200 OK\r\nSeT-CoOkIe: a=b\r\nSet-Cookie: c=d\r\nServer: test\r\n\r\nbody";
        let out = engine.apply_http1_response_header_policy("adnxs.com", headers, None);
        let out_str = String::from_utf8(out.output_headers).expect("utf8");
        assert!(!out_str.to_ascii_lowercase().contains("set-cookie:"));
        assert!(out_str.contains("Server: test"));
        assert_eq!(out.set_cookie_count, 2);
        assert!(out.enforcement_applied);
    }

    #[test]
    fn domain_in_set_matches_suffixes() {
        let set: HashSet<String> = ["google-analytics.com".to_string()].into_iter().collect();
        assert!(domain_in_set_or_parent("google-analytics.com", &set));
        assert!(domain_in_set_or_parent("stats.google-analytics.com", &set));
        assert!(!domain_in_set_or_parent("example.com", &set));
    }

    #[test]
    fn config_loader_rejects_unknown_keys() {
        let path = temp_file("policy_bad_key");
        write(
            &path,
            r#"{
              "version": 1,
              "mode": "report_only",
              "rules": {"tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]}},
              "typoo": true
            }"#,
        );
        let err = PolicyEngine::load_from_file(&path, None).unwrap_err();
        assert!(err.to_string().contains("unknown policy config key"));
    }

    #[test]
    fn config_loader_accepts_valid_config_and_mode_override() {
        let path = temp_file("policy_ok");
        write(
            &path,
            r#"{
              "version": 1,
              "mode": "report_only",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net", "google-analytics.com"]}
              }
            }"#,
        );

        let engine = PolicyEngine::load_from_file(&path, Some(PolicyMode::Enforce)).expect("load");
        assert_eq!(engine.summary().mode, PolicyMode::Enforce);
        let plan = engine.plan_for_host("stats.google-analytics.com");
        assert!(plan.enable_http1_set_cookie_filter);
    }

    #[test]
    fn config_with_dns_block_rule() {
        let path = temp_file("policy_dns");
        write(
            &path,
            r#"{
              "version": 1,
              "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]},
                "dns_block": {"enabled": true, "domains": ["doubleclick.net", "adnxs.com"]}
              }
            }"#,
        );

        let engine = PolicyEngine::load_from_file(&path, None).expect("load");
        let s = engine.summary();
        assert!(s.dns_block_enabled);
        assert_eq!(s.dns_block_domain_count, 2);

        let plan = engine.plan_for_dns_query("ad.doubleclick.net");
        assert!(plan.should_block);
        assert_eq!(plan.mode, PolicyMode::Enforce);

        let plan2 = engine.plan_for_dns_query("example.com");
        assert!(!plan2.should_block);
    }

    #[test]
    fn config_without_dns_block_rule_defaults_disabled() {
        let path = temp_file("policy_no_dns");
        write(
            &path,
            r#"{
              "version": 1,
              "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]}
              }
            }"#,
        );

        let engine = PolicyEngine::load_from_file(&path, None).expect("load");
        assert!(!engine.summary().dns_block_enabled);
        let plan = engine.plan_for_dns_query("doubleclick.net");
        assert!(!plan.should_block);
    }

    // --- Filter list integration tests ---

    fn make_filter_list_rules(
        block: &[&str],
        exceptions: &[&str],
        patterns: &[&str],
        cosmetic: &[&str],
    ) -> crate::filter_list::FilterListRules {
        crate::filter_list::FilterListRules {
            block_domains: block.iter().map(|s| s.to_string()).collect(),
            tracker_script_patterns: Arc::new(patterns.iter().map(|s| s.to_string()).collect()),
            cosmetic_selectors: Arc::new(cosmetic.iter().map(|s| s.to_string()).collect()),
            domain_cosmetic_map: std::collections::HashMap::new(),
            exception_domains: exceptions.iter().map(|s| s.to_string()).collect(),
            stats: Default::default(),
        }
    }

    #[test]
    fn filter_list_dns_block_works() {
        let engine = PolicyEngine::new(PolicyMode::Enforce);
        engine.replace_filter_list_rules(make_filter_list_rules(
            &["ads.tracker.com", "pagead2.googlesyndication.com"],
            &[],
            &[],
            &[],
        ));

        let plan = engine.plan_for_dns_query("pagead2.googlesyndication.com");
        assert!(plan.should_block);

        let plan2 = engine.plan_for_dns_query("sub.ads.tracker.com");
        assert!(plan2.should_block);

        let plan3 = engine.plan_for_dns_query("safe.example.com");
        assert!(!plan3.should_block);
    }

    #[test]
    fn filter_list_exception_overrides_filter_block() {
        let engine = PolicyEngine::new(PolicyMode::Enforce);
        engine.replace_filter_list_rules(make_filter_list_rules(
            &["example.com"],
            &["example.com"],
            &[],
            &[],
        ));

        let plan = engine.plan_for_dns_query("example.com");
        assert!(!plan.should_block, "exception should override filter block");
    }

    #[test]
    fn filter_list_exception_does_not_override_manual_config() {
        let path = temp_file("policy_manual_wins");
        write(
            &path,
            r#"{
              "version": 1,
              "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]},
                "dns_block": {"enabled": true, "domains": ["doubleclick.net"]}
              }
            }"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).expect("load");

        // Add exception for doubleclick.net in filter list
        engine.replace_filter_list_rules(make_filter_list_rules(
            &[],
            &["doubleclick.net"],
            &[],
            &[],
        ));

        // Manual config should still block it
        let plan = engine.plan_for_dns_query("doubleclick.net");
        assert!(
            plan.should_block,
            "manual config should override filter exception"
        );
    }

    #[test]
    fn filter_list_host_tracker_match() {
        let engine = PolicyEngine::new(PolicyMode::Enforce);
        engine.replace_filter_list_rules(make_filter_list_rules(
            &["tracker.example.com"],
            &[],
            &[],
            &[],
        ));

        let plan = engine.plan_for_host("tracker.example.com");
        assert!(plan.tracker_match);
        assert!(plan.enable_http1_set_cookie_filter);
    }

    #[test]
    fn filter_list_body_rewrite_appends_patterns() {
        let path = temp_file("policy_bw_fl");
        write(
            &path,
            r#"{
              "version": 1,
              "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]},
                "body_rewrite": {
                  "enabled": true,
                  "tracker_script_patterns": ["googletagmanager.com"],
                  "remove_selectors": [".manual-ad"],
                  "strip_tracking_pixels": false
                }
              }
            }"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).expect("load");
        engine.replace_filter_list_rules(make_filter_list_rules(
            &[],
            &[],
            &["/tracking.js"],
            &[".ad-banner"],
        ));

        let plan = engine.plan_for_body_rewrite("example.com");
        assert!(plan.should_rewrite);
        assert!(plan
            .script_patterns_iter()
            .any(|p| p == "googletagmanager.com"));
        assert!(plan.script_patterns_iter().any(|p| p == "/tracking.js"));
        assert!(plan.remove_selectors_iter().any(|s| s == ".manual-ad"));
        assert!(plan.remove_selectors_iter().any(|s| s == ".ad-banner"));
    }

    #[test]
    fn filter_list_body_rewrite_without_manual_config() {
        let engine = PolicyEngine::new(PolicyMode::Enforce);
        engine.replace_filter_list_rules(make_filter_list_rules(
            &[],
            &[],
            &["/tracking.js"],
            &[".ad-banner"],
        ));

        let plan = engine.plan_for_body_rewrite("example.com");
        assert!(plan.should_rewrite);
        let patterns: Vec<&str> = plan.script_patterns_iter().collect();
        assert_eq!(patterns, vec!["/tracking.js"]);
        let selectors: Vec<&str> = plan.remove_selectors_iter().collect();
        assert_eq!(selectors, vec![".ad-banner"]);
    }

    #[test]
    fn filter_list_disabled_mode_ignores_filter_rules() {
        let engine = PolicyEngine::new(PolicyMode::Disabled);
        engine.replace_filter_list_rules(make_filter_list_rules(
            &["blocked.com"],
            &[],
            &["/tracking.js"],
            &[".ad"],
        ));

        assert!(!engine.plan_for_dns_query("blocked.com").should_block);
        assert!(!engine.plan_for_host("blocked.com").tracker_match);
        assert!(!engine.plan_for_body_rewrite("example.com").should_rewrite);
    }

    #[test]
    fn filter_list_domain_cosmetic_selectors() {
        let engine = PolicyEngine::new(PolicyMode::Enforce);
        let mut rules = make_filter_list_rules(&[], &[], &[], &[]);
        rules.domain_cosmetic_map.insert(
            "example.com".to_string(),
            Arc::new(vec![".sidebar-ad".to_string()]),
        );
        engine.replace_filter_list_rules(rules);

        let plan = engine.plan_for_body_rewrite("www.example.com");
        assert!(plan.should_rewrite);
        assert!(plan.remove_selectors_iter().any(|s| s == ".sidebar-ad"));

        // Unrelated domain should not get the selector
        let plan2 = engine.plan_for_body_rewrite("other.com");
        assert!(!plan2.remove_selectors_iter().any(|s| s == ".sidebar-ad"));
    }

    #[test]
    fn filter_list_stats_accessible() {
        let engine = PolicyEngine::new(PolicyMode::Enforce);
        let stats = engine.filter_list_stats();
        assert_eq!(stats.source_count, 0);

        engine.replace_filter_list_rules(make_filter_list_rules(&["a.com"], &[], &[], &[]));
        // stats aren't populated by make_filter_list_rules helper, but the method works
        let _ = engine.filter_list_stats();
    }

    #[test]
    fn config_with_filter_lists_key_accepted() {
        let path = temp_file("policy_with_fl");
        write(
            &path,
            r#"{
              "version": 1,
              "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]}
              },
              "filter_lists": [
                "https://easylist.to/easylist/easylist.txt",
                "/path/to/local.txt"
              ]
            }"#,
        );
        // Should not reject the config
        let engine = PolicyEngine::load_from_file(&path, None).expect("load");
        assert_eq!(engine.summary().mode, PolicyMode::Enforce);

        // Parse filter list sources
        let sources = parse_filter_list_sources_from_config(&path).expect("parse sources");
        assert_eq!(sources.len(), 2);
        assert_eq!(
            sources[0].kind,
            crate::filter_list::FilterListSourceKind::Url
        );
        assert_eq!(
            sources[1].kind,
            crate::filter_list::FilterListSourceKind::LocalFile
        );
    }

    // --- Consent enforcement tests ---

    #[test]
    fn consent_disabled_uses_legacy_behavior() {
        let path = temp_file("consent_disabled");
        write(
            &path,
            r#"{
              "version": 1, "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]}
              }
            }"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();

        let plan = engine.plan_for_host("doubleclick.net");
        assert!(plan.tracker_match);
        assert!(plan.enable_http1_set_cookie_filter);
        assert!(!plan.consent_enforcement_active);
        assert!(plan.consent_level.is_none());
        assert!(plan.domain_category.is_none());
    }

    #[test]
    fn consent_essential_only_blocks_advertising() {
        let path = temp_file("consent_ess_ad");
        write(
            &path,
            r#"{
              "version": 1, "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]},
                "consent_enforcement": {
                  "enabled": true,
                  "default_consent": "essential_only",
                  "analytics_domains": ["google-analytics.com"]
                }
              }
            }"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();

        let plan = engine.plan_for_host("doubleclick.net");
        assert!(plan.enable_http1_set_cookie_filter);
        assert_eq!(plan.domain_category, Some(DomainCategory::Advertising));
        assert_eq!(plan.consent_level, Some(ConsentLevel::EssentialOnly));
    }

    #[test]
    fn consent_essential_only_blocks_analytics() {
        let path = temp_file("consent_ess_an");
        write(
            &path,
            r#"{
              "version": 1, "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]},
                "consent_enforcement": {
                  "enabled": true,
                  "default_consent": "essential_only",
                  "analytics_domains": ["google-analytics.com"]
                }
              }
            }"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();

        let plan = engine.plan_for_host("google-analytics.com");
        assert!(plan.enable_http1_set_cookie_filter);
        assert_eq!(plan.domain_category, Some(DomainCategory::Analytics));
    }

    #[test]
    fn consent_analytics_ok_allows_analytics_blocks_advertising() {
        let path = temp_file("consent_aok");
        write(
            &path,
            r#"{
              "version": 1, "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]},
                "consent_enforcement": {
                  "enabled": true,
                  "default_consent": "analytics_ok",
                  "analytics_domains": ["google-analytics.com"]
                }
              }
            }"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();

        // Analytics domain — allowed
        let plan_analytics = engine.plan_for_host("google-analytics.com");
        assert!(!plan_analytics.enable_http1_set_cookie_filter);
        assert_eq!(
            plan_analytics.domain_category,
            Some(DomainCategory::Analytics)
        );

        // Advertising domain — blocked
        let plan_ad = engine.plan_for_host("doubleclick.net");
        assert!(plan_ad.enable_http1_set_cookie_filter);
        assert_eq!(plan_ad.domain_category, Some(DomainCategory::Advertising));
    }

    #[test]
    fn consent_all_allows_everything() {
        let path = temp_file("consent_all");
        write(
            &path,
            r#"{
              "version": 1, "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]},
                "consent_enforcement": {
                  "enabled": true,
                  "default_consent": "all",
                  "analytics_domains": ["google-analytics.com"]
                }
              }
            }"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();

        let plan = engine.plan_for_host("doubleclick.net");
        assert!(!plan.enable_http1_set_cookie_filter);
        assert_eq!(plan.consent_level, Some(ConsentLevel::All));
    }

    #[test]
    fn consent_site_override_takes_precedence() {
        let path = temp_file("consent_override");
        write(
            &path,
            r#"{
              "version": 1, "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]},
                "consent_enforcement": {
                  "enabled": true,
                  "default_consent": "essential_only",
                  "analytics_domains": ["google-analytics.com"],
                  "site_overrides": {"google-analytics.com": "all"}
                }
              }
            }"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();

        let plan = engine.plan_for_host("google-analytics.com");
        assert!(!plan.enable_http1_set_cookie_filter);
        assert_eq!(plan.consent_level, Some(ConsentLevel::All));
    }

    #[test]
    fn consent_analytics_overrides_advertising_category() {
        let path = temp_file("consent_cat_ovr");
        write(
            &path,
            r#"{
              "version": 1, "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["google-analytics.com"]},
                "consent_enforcement": {
                  "enabled": true,
                  "default_consent": "analytics_ok",
                  "analytics_domains": ["google-analytics.com"]
                }
              }
            }"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();

        // In both lists — analytics wins
        let plan = engine.plan_for_host("google-analytics.com");
        assert_eq!(plan.domain_category, Some(DomainCategory::Analytics));
        // analytics_ok + Analytics → allowed
        assert!(!plan.enable_http1_set_cookie_filter);
    }

    #[test]
    fn consent_filter_list_domains_are_advertising() {
        let path = temp_file("consent_fl");
        write(
            &path,
            r#"{
              "version": 1, "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]},
                "consent_enforcement": {
                  "enabled": true,
                  "default_consent": "analytics_ok",
                  "analytics_domains": []
                }
              }
            }"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();
        engine.replace_filter_list_rules(make_filter_list_rules(
            &["tracker.example.com"],
            &[],
            &[],
            &[],
        ));

        let plan = engine.plan_for_host("tracker.example.com");
        assert_eq!(plan.domain_category, Some(DomainCategory::Advertising));
        // analytics_ok blocks advertising
        assert!(plan.enable_http1_set_cookie_filter);
    }

    #[test]
    fn consent_uncategorized_domains_allowed() {
        let path = temp_file("consent_uncat");
        write(
            &path,
            r#"{
              "version": 1, "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]},
                "consent_enforcement": {
                  "enabled": true,
                  "default_consent": "essential_only",
                  "analytics_domains": ["google-analytics.com"]
                }
              }
            }"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();

        let plan = engine.plan_for_host("example.com");
        assert!(!plan.enable_http1_set_cookie_filter);
        assert!(plan.domain_category.is_none());
    }

    #[test]
    fn consent_config_rejects_unknown_keys() {
        let path = temp_file("consent_badkey");
        write(
            &path,
            r#"{
              "version": 1, "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]},
                "consent_enforcement": {
                  "enabled": true,
                  "default_consent": "essential_only",
                  "unknown_key": true
                }
              }
            }"#,
        );
        let err = PolicyEngine::load_from_file(&path, None).unwrap_err();
        assert!(err.to_string().contains("unknown consent_enforcement key"));
    }

    #[test]
    fn consent_enforce_strips_set_cookie() {
        let path = temp_file("consent_strip");
        write(
            &path,
            r#"{
              "version": 1, "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]},
                "consent_enforcement": {
                  "enabled": true,
                  "default_consent": "essential_only",
                  "analytics_domains": []
                }
              }
            }"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();

        let headers = b"HTTP/1.1 200 OK\r\nSet-Cookie: id=abc\r\nServer: test\r\n\r\nbody";
        let out = engine.apply_http1_response_header_policy("doubleclick.net", headers, None);
        let out_str = String::from_utf8(out.output_headers).unwrap();
        assert!(!out_str.contains("Set-Cookie:"));
        assert!(out.enforcement_applied);
        assert!(out.consent_enforcement_active);
        assert_eq!(out.consent_level, Some(ConsentLevel::EssentialOnly));
        assert_eq!(out.domain_category, Some(DomainCategory::Advertising));
    }

    #[test]
    fn consent_site_override_matches_parent_domain() {
        let path = temp_file("consent_parent");
        write(
            &path,
            r#"{
              "version": 1, "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["tracker.example.com"]},
                "consent_enforcement": {
                  "enabled": true,
                  "default_consent": "essential_only",
                  "analytics_domains": [],
                  "site_overrides": {"example.com": "all"}
                }
              }
            }"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();

        let plan = engine.plan_for_host("tracker.example.com");
        assert_eq!(plan.consent_level, Some(ConsentLevel::All));
        assert!(!plan.enable_http1_set_cookie_filter);
    }

    // ---- User Profile Tests ----

    fn user_profile_config(default_consent: &str, profiles: &str) -> String {
        format!(
            r#"{{
              "version": 1, "mode": "enforce",
              "rules": {{
                "tracker_set_cookie": {{"enabled": true, "domains": ["doubleclick.net"]}},
                "consent_enforcement": {{
                  "enabled": true,
                  "default_consent": "{default_consent}",
                  "analytics_domains": ["google-analytics.com"],
                  "user_profiles": {profiles}
                }}
              }}
            }}"#
        )
    }

    #[test]
    fn user_profile_overrides_default_consent() {
        let path = temp_file("up_override");
        let profiles = r#"{"192.168.1.50": {"name": "kid", "consent": "essential_only"}, "192.168.1.51": {"name": "parent", "consent": "all"}}"#;
        write(&path, &user_profile_config("analytics_ok", profiles));
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();

        // Kid (essential_only) should block advertising
        let plan = engine.plan_for_host_with_source_ip("doubleclick.net", Some("192.168.1.50"));
        assert!(plan.enable_http1_set_cookie_filter);
        assert_eq!(plan.consent_level, Some(ConsentLevel::EssentialOnly));
        assert_eq!(plan.user_profile_name.as_deref(), Some("kid"));

        // Parent (all) should allow advertising
        let plan = engine.plan_for_host_with_source_ip("doubleclick.net", Some("192.168.1.51"));
        assert!(!plan.enable_http1_set_cookie_filter);
        assert_eq!(plan.consent_level, Some(ConsentLevel::All));
        assert_eq!(plan.user_profile_name.as_deref(), Some("parent"));

        // Unknown IP falls back to default (analytics_ok) — advertising still blocked
        let plan = engine.plan_for_host_with_source_ip("doubleclick.net", Some("10.0.0.1"));
        assert!(plan.enable_http1_set_cookie_filter);
        assert_eq!(plan.consent_level, Some(ConsentLevel::AnalyticsOk));
        assert!(plan.user_profile_name.is_none());
    }

    #[test]
    fn user_profile_affects_analytics_domains() {
        let path = temp_file("up_analytics");
        let profiles = r#"{"192.168.1.10": {"name": "strict", "consent": "essential_only"}, "192.168.1.20": {"name": "relaxed", "consent": "analytics_ok"}}"#;
        write(&path, &user_profile_config("all", profiles));
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();

        // strict user: analytics blocked
        let plan =
            engine.plan_for_host_with_source_ip("google-analytics.com", Some("192.168.1.10"));
        assert!(plan.enable_http1_set_cookie_filter);
        assert_eq!(plan.domain_category, Some(DomainCategory::Analytics));
        assert_eq!(plan.consent_level, Some(ConsentLevel::EssentialOnly));

        // relaxed user: analytics allowed
        let plan =
            engine.plan_for_host_with_source_ip("google-analytics.com", Some("192.168.1.20"));
        assert!(!plan.enable_http1_set_cookie_filter);
        assert_eq!(plan.consent_level, Some(ConsentLevel::AnalyticsOk));
    }

    #[test]
    fn user_profile_no_source_ip_uses_default() {
        let path = temp_file("up_no_ip");
        let profiles = r#"{"192.168.1.50": {"name": "kid", "consent": "essential_only"}}"#;
        write(&path, &user_profile_config("all", profiles));
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();

        // No source IP → default consent (all) → advertising allowed
        let plan = engine.plan_for_host("doubleclick.net");
        assert!(!plan.enable_http1_set_cookie_filter);
        assert_eq!(plan.consent_level, Some(ConsentLevel::All));
        assert!(plan.user_profile_name.is_none());
    }

    #[test]
    fn user_profile_config_rejects_unknown_keys() {
        let path = temp_file("up_bad_key");
        write(
            &path,
            r#"{
              "version": 1, "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["x.com"]},
                "consent_enforcement": {
                  "enabled": true,
                  "default_consent": "essential_only",
                  "user_profiles": {"1.2.3.4": {"name": "test", "consent": "all", "extra": true}}
                }
              }
            }"#,
        );
        let err = PolicyEngine::load_from_file(&path, None).unwrap_err();
        assert!(err.to_string().contains("unknown key"), "unexpected: {err}");
    }

    #[test]
    fn user_profile_with_header_policy() {
        let path = temp_file("up_header");
        let profiles = r#"{"10.0.0.1": {"name": "kid", "consent": "essential_only"}, "10.0.0.2": {"name": "parent", "consent": "all"}}"#;
        write(&path, &user_profile_config("analytics_ok", profiles));
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();

        let headers = b"HTTP/1.1 200 OK\r\nSet-Cookie: tracker=1\r\n\r\n";

        // Kid: essential_only → advertising blocked → cookies stripped
        let out =
            engine.apply_http1_response_header_policy("doubleclick.net", headers, Some("10.0.0.1"));
        assert!(out.enforcement_applied);
        assert_eq!(out.user_profile_name.as_deref(), Some("kid"));
        let out_str = String::from_utf8(out.output_headers).unwrap();
        assert!(!out_str.contains("Set-Cookie:"));

        // Parent: all → advertising allowed → cookies preserved
        let out =
            engine.apply_http1_response_header_policy("doubleclick.net", headers, Some("10.0.0.2"));
        assert!(!out.enforcement_applied);
        assert_eq!(out.user_profile_name.as_deref(), Some("parent"));
        let out_str = String::from_utf8(out.output_headers).unwrap();
        assert!(out_str.contains("Set-Cookie:"));
    }

    // ---- Referer Spoof Tests ----

    #[test]
    fn referer_spoof_matches_configured_domain() {
        let path = temp_file("referer_spoof");
        write(
            &path,
            r#"{
              "version": 1, "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]},
                "body_rewrite": {
                  "enabled": true,
                  "tracker_script_patterns": ["googletagmanager.com"],
                  "remove_selectors": [],
                  "strip_tracking_pixels": false,
                  "referer_spoof_domains": ["nytimes.com", "washingtonpost.com"]
                }
              }
            }"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();

        let plan = engine.plan_for_body_rewrite("www.nytimes.com");
        assert!(plan.referer_spoof);

        let plan2 = engine.plan_for_body_rewrite("washingtonpost.com");
        assert!(plan2.referer_spoof);

        let plan3 = engine.plan_for_body_rewrite("example.com");
        assert!(!plan3.referer_spoof);
    }

    #[test]
    fn referer_spoof_disabled_when_body_rewrite_disabled() {
        let path = temp_file("referer_spoof_off");
        write(
            &path,
            r#"{
              "version": 1, "mode": "enforce",
              "rules": {
                "tracker_set_cookie": {"enabled": true, "domains": ["doubleclick.net"]}
              }
            }"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();
        let plan = engine.plan_for_body_rewrite("nytimes.com");
        assert!(!plan.referer_spoof);
    }

    #[test]
    fn user_profile_summary_reports_count() {
        let path = temp_file("up_summary");
        let profiles = r#"{"1.1.1.1": {"name": "a", "consent": "all"}, "2.2.2.2": {"name": "b", "consent": "essential_only"}}"#;
        write(&path, &user_profile_config("all", profiles));
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();
        let s = engine.summary();
        assert_eq!(s.consent_user_profile_count, 2);
    }

    // --- WebSocket blocking config tests ---

    #[test]
    fn websocket_blocking_defaults_to_enabled() {
        let path = temp_file("ws_default");
        write(
            &path,
            r#"{"version":1,"mode":"enforce","rules":{"tracker_set_cookie":{"enabled":true,"domains":["tracker.com"]}}}"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();
        let plan = engine.plan_for_host("tracker.com");
        assert!(plan.websocket_blocking_enabled);
    }

    #[test]
    fn websocket_blocking_disabled_via_config() {
        let path = temp_file("ws_disabled");
        write(
            &path,
            r#"{"version":1,"mode":"enforce","rules":{"tracker_set_cookie":{"enabled":true,"domains":["tracker.com"]},"websocket_blocking":{"enabled":false}}}"#,
        );
        let engine = PolicyEngine::load_from_file(&path, None).unwrap();
        let plan = engine.plan_for_host("tracker.com");
        assert!(!plan.websocket_blocking_enabled);
    }

    #[test]
    fn websocket_blocking_rejects_unknown_keys() {
        let path = temp_file("ws_badkey");
        write(
            &path,
            r#"{"version":1,"mode":"enforce","rules":{"tracker_set_cookie":{"enabled":true,"domains":[]},"websocket_blocking":{"enabled":true,"foo":true}}}"#,
        );
        let err = PolicyEngine::load_from_file(&path, None).unwrap_err();
        assert!(err.to_string().contains("unknown websocket_blocking key"));
    }
}
