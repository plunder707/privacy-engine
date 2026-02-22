use serde_json::{json, Value};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn lock_error<T>(err: PoisonError<T>) -> io::Error {
    io::Error::other(format!("receipts lock poisoned: {err}"))
}

fn prune_stale_hosts(hosts: &mut HashMap<String, HostReceipt>, max_age_secs: u64) {
    let cutoff = now_unix_seconds().saturating_sub(max_age_secs);
    hosts.retain(|_, r| r.last_seen_unix >= cutoff);
}

#[derive(Debug, Clone, Default)]
struct HostReceipt {
    seen_total: u64,
    routing_mitm_total: u64,
    routing_passthrough_total: u64,

    mitm_attempt_total: u64,
    mitm_success_total: u64,
    mitm_failure_total: u64,
    mitm_client_tls_reject_total: u64,
    host_auto_pinned_total: u64,

    policy_set_cookie_would_strip_total: u64,
    policy_set_cookie_stripped_total: u64,
    policy_set_cookie_headers_total: u64,

    dns_blocked_total: u64,
    dns_report_only_total: u64,
    dns_cname_uncloaked_total: u64,

    consent_enforcement_blocked_total: u64,
    consent_enforcement_report_only_total: u64,

    body_rewrite_total: u64,
    body_rewrite_report_only_total: u64,
    body_rewrite_skipped_total: u64,

    body_rewrite_removed_script_total: u64,
    body_rewrite_removed_pixel_total: u64,
    body_rewrite_removed_cosmetic_total: u64,
    body_rewrite_bytes_saved_total: u64,

    body_rewrite_removed_script_report_only_total: u64,
    body_rewrite_removed_pixel_report_only_total: u64,
    body_rewrite_removed_cosmetic_report_only_total: u64,
    body_rewrite_bytes_saved_report_only_total: u64,

    websocket_blocked_total: u64,
    referer_spoofed_total: u64,
    cert_pin_violation_total: u64,
    query_params_stripped_total: u64,
    cache_headers_stripped_total: u64,

    last_seen_unix: u64,
    last_flow: Option<String>,
    last_action: Option<String>,
    last_reason: Option<String>,
}

impl HostReceipt {
    fn touch(&mut self, flow: &'static str, action: &'static str, reason: &'static str) {
        self.seen_total = self.seen_total.saturating_add(1);
        self.last_seen_unix = now_unix_seconds();
        self.last_flow = Some(flow.to_string());
        self.last_action = Some(action.to_string());
        self.last_reason = Some(reason.to_string());
        match action {
            "mitm" => {
                self.routing_mitm_total = self.routing_mitm_total.saturating_add(1);
            }
            "passthrough" => {
                self.routing_passthrough_total = self.routing_passthrough_total.saturating_add(1);
            }
            _ => {}
        }
    }

    fn as_json(&self) -> Value {
        json!({
            "seen_total": self.seen_total,
            "routing_mitm_total": self.routing_mitm_total,
            "routing_passthrough_total": self.routing_passthrough_total,

            "mitm_attempt_total": self.mitm_attempt_total,
            "mitm_success_total": self.mitm_success_total,
            "mitm_failure_total": self.mitm_failure_total,
            "mitm_client_tls_reject_total": self.mitm_client_tls_reject_total,
            "host_auto_pinned_total": self.host_auto_pinned_total,

            "policy_set_cookie_would_strip_total": self.policy_set_cookie_would_strip_total,
            "policy_set_cookie_stripped_total": self.policy_set_cookie_stripped_total,
            "policy_set_cookie_headers_total": self.policy_set_cookie_headers_total,

            "dns_blocked_total": self.dns_blocked_total,
            "dns_report_only_total": self.dns_report_only_total,
            "dns_cname_uncloaked_total": self.dns_cname_uncloaked_total,

            "consent_enforcement_blocked_total": self.consent_enforcement_blocked_total,
            "consent_enforcement_report_only_total": self.consent_enforcement_report_only_total,

            "body_rewrite_total": self.body_rewrite_total,
            "body_rewrite_report_only_total": self.body_rewrite_report_only_total,
            "body_rewrite_skipped_total": self.body_rewrite_skipped_total,
            "body_rewrite_removed_script_total": self.body_rewrite_removed_script_total,
            "body_rewrite_removed_pixel_total": self.body_rewrite_removed_pixel_total,
            "body_rewrite_removed_cosmetic_total": self.body_rewrite_removed_cosmetic_total,
            "body_rewrite_bytes_saved_total": self.body_rewrite_bytes_saved_total,
            "body_rewrite_removed_script_report_only_total": self.body_rewrite_removed_script_report_only_total,
            "body_rewrite_removed_pixel_report_only_total": self.body_rewrite_removed_pixel_report_only_total,
            "body_rewrite_removed_cosmetic_report_only_total": self.body_rewrite_removed_cosmetic_report_only_total,
            "body_rewrite_bytes_saved_report_only_total": self.body_rewrite_bytes_saved_report_only_total,

            "websocket_blocked_total": self.websocket_blocked_total,
            "referer_spoofed_total": self.referer_spoofed_total,
            "cert_pin_violation_total": self.cert_pin_violation_total,
            "query_params_stripped_total": self.query_params_stripped_total,
            "cache_headers_stripped_total": self.cache_headers_stripped_total,

            "last_seen_unix": self.last_seen_unix,
            "last_flow": self.last_flow,
            "last_action": self.last_action,
            "last_reason": self.last_reason,
        })
    }

    fn from_json(v: &Value) -> Self {
        let o = v.as_object();
        let get_u64 = |k: &str| -> u64 {
            o.and_then(|m| m.get(k))
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        };
        let get_string = |k: &str| -> Option<String> {
            o.and_then(|m| m.get(k))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        };
        HostReceipt {
            seen_total: get_u64("seen_total"),
            routing_mitm_total: get_u64("routing_mitm_total"),
            routing_passthrough_total: get_u64("routing_passthrough_total"),
            mitm_attempt_total: get_u64("mitm_attempt_total"),
            mitm_success_total: get_u64("mitm_success_total"),
            mitm_failure_total: get_u64("mitm_failure_total"),
            mitm_client_tls_reject_total: get_u64("mitm_client_tls_reject_total"),
            host_auto_pinned_total: get_u64("host_auto_pinned_total"),
            policy_set_cookie_would_strip_total: get_u64("policy_set_cookie_would_strip_total"),
            policy_set_cookie_stripped_total: get_u64("policy_set_cookie_stripped_total"),
            policy_set_cookie_headers_total: get_u64("policy_set_cookie_headers_total"),
            dns_blocked_total: get_u64("dns_blocked_total"),
            dns_report_only_total: get_u64("dns_report_only_total"),
            dns_cname_uncloaked_total: get_u64("dns_cname_uncloaked_total"),
            consent_enforcement_blocked_total: get_u64("consent_enforcement_blocked_total"),
            consent_enforcement_report_only_total: get_u64("consent_enforcement_report_only_total"),
            body_rewrite_total: get_u64("body_rewrite_total"),
            body_rewrite_report_only_total: get_u64("body_rewrite_report_only_total"),
            body_rewrite_skipped_total: get_u64("body_rewrite_skipped_total"),
            body_rewrite_removed_script_total: get_u64("body_rewrite_removed_script_total"),
            body_rewrite_removed_pixel_total: get_u64("body_rewrite_removed_pixel_total"),
            body_rewrite_removed_cosmetic_total: get_u64("body_rewrite_removed_cosmetic_total"),
            body_rewrite_bytes_saved_total: get_u64("body_rewrite_bytes_saved_total"),
            body_rewrite_removed_script_report_only_total: get_u64(
                "body_rewrite_removed_script_report_only_total",
            ),
            body_rewrite_removed_pixel_report_only_total: get_u64(
                "body_rewrite_removed_pixel_report_only_total",
            ),
            body_rewrite_removed_cosmetic_report_only_total: get_u64(
                "body_rewrite_removed_cosmetic_report_only_total",
            ),
            body_rewrite_bytes_saved_report_only_total: get_u64(
                "body_rewrite_bytes_saved_report_only_total",
            ),
            websocket_blocked_total: get_u64("websocket_blocked_total"),
            referer_spoofed_total: get_u64("referer_spoofed_total"),
            cert_pin_violation_total: get_u64("cert_pin_violation_total"),
            query_params_stripped_total: get_u64("query_params_stripped_total"),
            cache_headers_stripped_total: get_u64("cache_headers_stripped_total"),
            last_seen_unix: get_u64("last_seen_unix"),
            last_flow: get_string("last_flow"),
            last_action: get_string("last_action"),
            last_reason: get_string("last_reason"),
        }
    }
}

fn persist_receipts(path: &Path, json: &Value) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Best-effort atomic persistence via temp file + rename.
    let tmp_path = path.with_extension("tmp");
    let file = fs::File::create(&tmp_path)?;
    let writer = BufWriter::new(file);

    serde_json::to_writer_pretty(writer, json).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to serialize receipts: {e}"),
        )
    })?;

    match fs::rename(&tmp_path, path) {
        Ok(()) => {}
        Err(e) => {
            // On Windows, rename does not overwrite an existing destination.
            if matches!(
                e.kind(),
                io::ErrorKind::AlreadyExists | io::ErrorKind::PermissionDenied
            ) {
                let _ = fs::remove_file(path);
                fs::rename(&tmp_path, path)?;
            } else {
                return Err(e);
            }
        }
    }
    Ok(())
}

fn load_receipts(path: &Path) -> io::Result<HashMap<String, HostReceipt>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let raw = fs::read_to_string(path)?;
    let parsed: Value = serde_json::from_str(&raw).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid receipts JSON: {e}"),
        )
    })?;

    let hosts_obj = if let Some(hosts) = parsed.get("hosts") {
        hosts.as_object()
    } else {
        parsed.as_object()
    }
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid receipts root object"))?;

    let mut out = HashMap::new();
    for (host, v) in hosts_obj {
        let normalized = normalize_host(host);
        if normalized.is_empty() {
            continue;
        }
        out.insert(normalized, HostReceipt::from_json(v));
    }
    Ok(out)
}

#[derive(Debug)]
struct ReceiptsReportData {
    version: Option<u64>,
    generated_unix: Option<u64>,
    hosts: Vec<(String, HostReceipt)>,
}

fn load_receipts_for_reporting(path: &Path) -> io::Result<ReceiptsReportData> {
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("receipts file not found: '{}'", path.display()),
        ));
    }

    let raw = fs::read_to_string(path)?;
    let parsed: Value = serde_json::from_str(&raw).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid receipts JSON: {e}"),
        )
    })?;

    let version = parsed.get("version").and_then(|v| v.as_u64());
    let generated_unix = parsed.get("generated_unix").and_then(|v| v.as_u64());

    // Parse hosts out of either:
    // - {"hosts": {...}} (current)
    // - {...}           (legacy)
    let hosts_obj = if let Some(hosts) = parsed.get("hosts") {
        hosts.as_object()
    } else {
        parsed.as_object()
    }
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid receipts root object"))?;

    let mut hosts: Vec<(String, HostReceipt)> = Vec::with_capacity(hosts_obj.len());
    for (host, v) in hosts_obj {
        let normalized = normalize_host(host);
        if normalized.is_empty() {
            continue;
        }
        hosts.push((normalized, HostReceipt::from_json(v)));
    }

    Ok(ReceiptsReportData {
        version,
        generated_unix,
        hosts,
    })
}

pub fn render_receipts_report(
    path: &Path,
    top_hosts: usize,
    host_filter: Option<&str>,
) -> io::Result<String> {
    let data = load_receipts_for_reporting(path)?;
    let version = data.version;
    let generated_unix = data.generated_unix;
    let mut hosts = data.hosts;

    let mut out = String::new();
    writeln!(&mut out, "Privacy receipts: {}", path.display()).ok();
    if let Some(v) = version {
        writeln!(&mut out, "version: {v}").ok();
    }
    if let Some(ts) = generated_unix {
        writeln!(&mut out, "generated_unix: {ts}").ok();
    }
    writeln!(&mut out).ok();

    if hosts.is_empty() {
        writeln!(&mut out, "(no hosts recorded yet)").ok();
        return Ok(out);
    }

    if let Some(filter) = host_filter {
        let filter = normalize_host(filter);
        let mut matched: Vec<(String, HostReceipt)> = hosts
            .into_iter()
            .filter(|(h, _)| h == &filter || h.ends_with(&format!(".{filter}")))
            .collect();
        matched.sort_by_key(|(_, r)| std::cmp::Reverse(r.last_seen_unix));

        writeln!(&mut out, "host_filter: {filter}").ok();
        writeln!(&mut out, "matches: {}", matched.len()).ok();
        writeln!(&mut out).ok();

        for (host, r) in matched {
            writeln!(&mut out, "Host: {host}").ok();
            writeln!(
                &mut out,
                "  seen_total: {} (mitm={}, passthrough={})",
                r.seen_total, r.routing_mitm_total, r.routing_passthrough_total
            )
            .ok();
            writeln!(
                &mut out,
                "  mitm: attempts={} success={} failure={} tls_reject={} auto_pinned={}",
                r.mitm_attempt_total,
                r.mitm_success_total,
                r.mitm_failure_total,
                r.mitm_client_tls_reject_total,
                r.host_auto_pinned_total
            )
            .ok();
            writeln!(
                &mut out,
                "  policy_set_cookie: would_strip={} stripped={} headers_total={}",
                r.policy_set_cookie_would_strip_total,
                r.policy_set_cookie_stripped_total,
                r.policy_set_cookie_headers_total
            )
            .ok();
            if r.dns_blocked_total > 0
                || r.dns_report_only_total > 0
                || r.dns_cname_uncloaked_total > 0
            {
                writeln!(
                    &mut out,
                    "  dns: blocked={} report_only={} cname_uncloaked={}",
                    r.dns_blocked_total, r.dns_report_only_total, r.dns_cname_uncloaked_total
                )
                .ok();
            }
            if r.consent_enforcement_blocked_total > 0
                || r.consent_enforcement_report_only_total > 0
            {
                writeln!(
                    &mut out,
                    "  consent: blocked={} report_only={}",
                    r.consent_enforcement_blocked_total, r.consent_enforcement_report_only_total,
                )
                .ok();
            }
            writeln!(
                &mut out,
                "  last: unix={} flow={:?} action={:?} reason={:?}",
                r.last_seen_unix, r.last_flow, r.last_action, r.last_reason
            )
            .ok();
            writeln!(&mut out).ok();
        }

        return Ok(out);
    }

    // Aggregate totals.
    let mut total_seen = 0u64;
    let mut total_mitm_attempt = 0u64;
    let mut total_mitm_success = 0u64;
    let mut total_mitm_failure = 0u64;
    let mut total_tls_reject = 0u64;
    let mut total_auto_pinned = 0u64;
    let mut total_cookie_would = 0u64;
    let mut total_cookie_stripped = 0u64;
    let mut total_cookie_headers = 0u64;
    let mut total_dns_blocked = 0u64;
    let mut total_dns_report_only = 0u64;
    let mut total_dns_cname_uncloaked = 0u64;
    let mut total_consent_blocked = 0u64;
    let mut total_consent_report_only = 0u64;

    for (_, r) in &hosts {
        total_seen = total_seen.saturating_add(r.seen_total);
        total_mitm_attempt = total_mitm_attempt.saturating_add(r.mitm_attempt_total);
        total_mitm_success = total_mitm_success.saturating_add(r.mitm_success_total);
        total_mitm_failure = total_mitm_failure.saturating_add(r.mitm_failure_total);
        total_tls_reject = total_tls_reject.saturating_add(r.mitm_client_tls_reject_total);
        total_auto_pinned = total_auto_pinned.saturating_add(r.host_auto_pinned_total);
        total_cookie_would =
            total_cookie_would.saturating_add(r.policy_set_cookie_would_strip_total);
        total_cookie_stripped =
            total_cookie_stripped.saturating_add(r.policy_set_cookie_stripped_total);
        total_cookie_headers =
            total_cookie_headers.saturating_add(r.policy_set_cookie_headers_total);
        total_dns_blocked = total_dns_blocked.saturating_add(r.dns_blocked_total);
        total_dns_report_only = total_dns_report_only.saturating_add(r.dns_report_only_total);
        total_dns_cname_uncloaked =
            total_dns_cname_uncloaked.saturating_add(r.dns_cname_uncloaked_total);
        total_consent_blocked =
            total_consent_blocked.saturating_add(r.consent_enforcement_blocked_total);
        total_consent_report_only =
            total_consent_report_only.saturating_add(r.consent_enforcement_report_only_total);
    }

    writeln!(&mut out, "hosts: {}", hosts.len()).ok();
    writeln!(&mut out, "seen_total: {total_seen}").ok();
    writeln!(
        &mut out,
        "mitm: attempts={total_mitm_attempt} success={total_mitm_success} failure={total_mitm_failure} tls_reject={total_tls_reject} auto_pinned={total_auto_pinned}"
    )
    .ok();
    writeln!(
        &mut out,
        "policy_set_cookie: would_strip={total_cookie_would} stripped={total_cookie_stripped} headers_total={total_cookie_headers}"
    )
    .ok();
    if total_dns_blocked > 0 || total_dns_report_only > 0 || total_dns_cname_uncloaked > 0 {
        writeln!(
            &mut out,
            "dns: blocked={total_dns_blocked} report_only={total_dns_report_only} cname_uncloaked={total_dns_cname_uncloaked}"
        )
        .ok();
    }
    if total_consent_blocked > 0 || total_consent_report_only > 0 {
        writeln!(
            &mut out,
            "consent: blocked={total_consent_blocked} report_only={total_consent_report_only}"
        )
        .ok();
    }
    writeln!(&mut out).ok();

    hosts.sort_by_key(|(_, r)| std::cmp::Reverse(r.seen_total));
    let top_hosts = top_hosts.clamp(1, 200);
    writeln!(
        &mut out,
        "Top hosts (by seen_total), showing {}:",
        top_hosts.min(hosts.len())
    )
    .ok();
    writeln!(
        &mut out,
        "{:<35} {:>7} {:>9} {:>9} {:>10} {:>10} {:>12} last_reason",
        "host", "seen", "mitm", "pass", "tls_reject", "auto_pin", "cookie_strp"
    )
    .ok();

    for (host, r) in hosts.into_iter().take(top_hosts) {
        writeln!(
            &mut out,
            "{:<35} {:>7} {:>9} {:>9} {:>10} {:>10} {:>12} {}",
            host,
            r.seen_total,
            r.routing_mitm_total,
            r.routing_passthrough_total,
            r.mitm_client_tls_reject_total,
            r.host_auto_pinned_total,
            r.policy_set_cookie_stripped_total,
            r.last_reason.unwrap_or_else(|| "-".to_string())
        )
        .ok();
    }

    Ok(out)
}

fn percent_u64(numer: u64, denom: u64) -> Option<u64> {
    if denom == 0 {
        None
    } else {
        Some((numer.saturating_mul(100) / denom).min(100))
    }
}

fn fmt_percent(numer: u64, denom: u64) -> String {
    match percent_u64(numer, denom) {
        Some(p) => format!("{p}%"),
        None => "-".to_string(),
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct ComplianceTotals {
    hosts: u64,
    seen_total: u64,
    routing_mitm_total: u64,
    routing_passthrough_total: u64,

    mitm_attempt_total: u64,
    mitm_success_total: u64,
    mitm_failure_total: u64,
    mitm_client_tls_reject_total: u64,
    host_auto_pinned_total: u64,

    cookie_stripped_events_total: u64,
    cookie_report_only_events_total: u64,
    set_cookie_headers_total: u64,

    dns_blocked_total: u64,
    dns_report_only_total: u64,
    dns_cname_uncloaked_total: u64,

    consent_blocked_total: u64,
    consent_report_only_total: u64,

    body_rewrite_enforce_total: u64,
    body_rewrite_report_only_total: u64,
    body_rewrite_skipped_total: u64,

    body_rewrite_removed_script_total: u64,
    body_rewrite_removed_pixel_total: u64,
    body_rewrite_removed_cosmetic_total: u64,
    body_rewrite_bytes_saved_total: u64,

    body_rewrite_removed_script_report_only_total: u64,
    body_rewrite_removed_pixel_report_only_total: u64,
    body_rewrite_removed_cosmetic_report_only_total: u64,
    body_rewrite_bytes_saved_report_only_total: u64,
}

impl ComplianceTotals {
    fn add(&mut self, r: &HostReceipt) {
        self.hosts = self.hosts.saturating_add(1);
        self.seen_total = self.seen_total.saturating_add(r.seen_total);
        self.routing_mitm_total = self.routing_mitm_total.saturating_add(r.routing_mitm_total);
        self.routing_passthrough_total = self
            .routing_passthrough_total
            .saturating_add(r.routing_passthrough_total);

        self.mitm_attempt_total = self.mitm_attempt_total.saturating_add(r.mitm_attempt_total);
        self.mitm_success_total = self.mitm_success_total.saturating_add(r.mitm_success_total);
        self.mitm_failure_total = self.mitm_failure_total.saturating_add(r.mitm_failure_total);
        self.mitm_client_tls_reject_total = self
            .mitm_client_tls_reject_total
            .saturating_add(r.mitm_client_tls_reject_total);
        self.host_auto_pinned_total = self
            .host_auto_pinned_total
            .saturating_add(r.host_auto_pinned_total);

        self.cookie_stripped_events_total = self
            .cookie_stripped_events_total
            .saturating_add(r.policy_set_cookie_stripped_total);
        self.cookie_report_only_events_total = self
            .cookie_report_only_events_total
            .saturating_add(r.policy_set_cookie_would_strip_total);
        self.set_cookie_headers_total = self
            .set_cookie_headers_total
            .saturating_add(r.policy_set_cookie_headers_total);

        self.dns_blocked_total = self.dns_blocked_total.saturating_add(r.dns_blocked_total);
        self.dns_report_only_total = self
            .dns_report_only_total
            .saturating_add(r.dns_report_only_total);
        self.dns_cname_uncloaked_total = self
            .dns_cname_uncloaked_total
            .saturating_add(r.dns_cname_uncloaked_total);

        self.consent_blocked_total = self
            .consent_blocked_total
            .saturating_add(r.consent_enforcement_blocked_total);
        self.consent_report_only_total = self
            .consent_report_only_total
            .saturating_add(r.consent_enforcement_report_only_total);

        self.body_rewrite_enforce_total = self
            .body_rewrite_enforce_total
            .saturating_add(r.body_rewrite_total);
        self.body_rewrite_report_only_total = self
            .body_rewrite_report_only_total
            .saturating_add(r.body_rewrite_report_only_total);
        self.body_rewrite_skipped_total = self
            .body_rewrite_skipped_total
            .saturating_add(r.body_rewrite_skipped_total);

        self.body_rewrite_removed_script_total = self
            .body_rewrite_removed_script_total
            .saturating_add(r.body_rewrite_removed_script_total);
        self.body_rewrite_removed_pixel_total = self
            .body_rewrite_removed_pixel_total
            .saturating_add(r.body_rewrite_removed_pixel_total);
        self.body_rewrite_removed_cosmetic_total = self
            .body_rewrite_removed_cosmetic_total
            .saturating_add(r.body_rewrite_removed_cosmetic_total);
        self.body_rewrite_bytes_saved_total = self
            .body_rewrite_bytes_saved_total
            .saturating_add(r.body_rewrite_bytes_saved_total);

        self.body_rewrite_removed_script_report_only_total = self
            .body_rewrite_removed_script_report_only_total
            .saturating_add(r.body_rewrite_removed_script_report_only_total);
        self.body_rewrite_removed_pixel_report_only_total = self
            .body_rewrite_removed_pixel_report_only_total
            .saturating_add(r.body_rewrite_removed_pixel_report_only_total);
        self.body_rewrite_removed_cosmetic_report_only_total = self
            .body_rewrite_removed_cosmetic_report_only_total
            .saturating_add(r.body_rewrite_removed_cosmetic_report_only_total);
        self.body_rewrite_bytes_saved_report_only_total = self
            .body_rewrite_bytes_saved_report_only_total
            .saturating_add(r.body_rewrite_bytes_saved_report_only_total);
    }
}

pub fn render_compliance_report_text(
    path: &Path,
    top_hosts: usize,
    host_filter: Option<&str>,
) -> io::Result<String> {
    let data = load_receipts_for_reporting(path)?;
    let version = data.version;
    let generated_unix = data.generated_unix;
    let hosts = data.hosts;

    let mut out = String::new();
    writeln!(&mut out, "Privacy compliance report: {}", path.display()).ok();
    if let Some(v) = version {
        writeln!(&mut out, "version: {v}").ok();
    }
    if let Some(ts) = generated_unix {
        writeln!(&mut out, "generated_unix: {ts}").ok();
    }
    writeln!(&mut out).ok();

    if hosts.is_empty() {
        writeln!(&mut out, "(no hosts recorded yet)").ok();
        return Ok(out);
    }

    if let Some(filter) = host_filter {
        let filter = normalize_host(filter);
        let mut matched: Vec<(String, HostReceipt)> = hosts
            .into_iter()
            .filter(|(h, _)| h == &filter || h.ends_with(&format!(".{filter}")))
            .collect();
        matched.sort_by_key(|(_, r)| std::cmp::Reverse(r.last_seen_unix));

        writeln!(&mut out, "host_filter: {filter}").ok();
        writeln!(&mut out, "matches: {}", matched.len()).ok();
        writeln!(&mut out).ok();

        for (host, r) in matched {
            let cookie_events = r
                .policy_set_cookie_stripped_total
                .saturating_add(r.policy_set_cookie_would_strip_total);
            let dns_events = r.dns_blocked_total.saturating_add(r.dns_report_only_total);
            let consent_events = r
                .consent_enforcement_blocked_total
                .saturating_add(r.consent_enforcement_report_only_total);
            let body_events = r
                .body_rewrite_total
                .saturating_add(r.body_rewrite_report_only_total);
            let body_attempted = body_events.saturating_add(r.body_rewrite_skipped_total);

            writeln!(&mut out, "Host: {host}").ok();
            writeln!(
                &mut out,
                "  routing: seen_total={} mitm={} passthrough={}",
                r.seen_total, r.routing_mitm_total, r.routing_passthrough_total
            )
            .ok();
            writeln!(
                &mut out,
                "  mitm: attempts={} success={} failure={} tls_reject={} auto_pinned={} success_rate={}",
                r.mitm_attempt_total,
                r.mitm_success_total,
                r.mitm_failure_total,
                r.mitm_client_tls_reject_total,
                r.host_auto_pinned_total,
                fmt_percent(r.mitm_success_total, r.mitm_attempt_total)
            )
            .ok();
            writeln!(
                &mut out,
                "  dns: blocked={} report_only={} cname_uncloaked={} enforce_ratio={}",
                r.dns_blocked_total,
                r.dns_report_only_total,
                r.dns_cname_uncloaked_total,
                fmt_percent(r.dns_blocked_total, dns_events)
            )
            .ok();
            writeln!(
                &mut out,
                "  cookies: set_cookie_headers_total={} stripped_events={} report_only_events={} enforce_ratio={}",
                r.policy_set_cookie_headers_total,
                r.policy_set_cookie_stripped_total,
                r.policy_set_cookie_would_strip_total,
                fmt_percent(r.policy_set_cookie_stripped_total, cookie_events)
            )
            .ok();
            if r.consent_enforcement_blocked_total > 0
                || r.consent_enforcement_report_only_total > 0
            {
                writeln!(
                    &mut out,
                    "  consent: blocked={} report_only={} enforce_ratio={}",
                    r.consent_enforcement_blocked_total,
                    r.consent_enforcement_report_only_total,
                    fmt_percent(r.consent_enforcement_blocked_total, consent_events)
                )
                .ok();
            }
            writeln!(
                &mut out,
                "  html_rewrite: enforce={} report_only={} skipped={} enforce_ratio={} skip_rate={}",
                r.body_rewrite_total,
                r.body_rewrite_report_only_total,
                r.body_rewrite_skipped_total,
                fmt_percent(r.body_rewrite_total, body_events),
                fmt_percent(r.body_rewrite_skipped_total, body_attempted)
            )
            .ok();
            if r.body_rewrite_removed_script_total > 0
                || r.body_rewrite_removed_pixel_total > 0
                || r.body_rewrite_removed_cosmetic_total > 0
                || r.body_rewrite_bytes_saved_total > 0
            {
                writeln!(
                    &mut out,
                    "  html_removed_enforce: scripts={} pixels={} cosmetic={} bytes_saved={}",
                    r.body_rewrite_removed_script_total,
                    r.body_rewrite_removed_pixel_total,
                    r.body_rewrite_removed_cosmetic_total,
                    r.body_rewrite_bytes_saved_total
                )
                .ok();
            }
            if r.body_rewrite_removed_script_report_only_total > 0
                || r.body_rewrite_removed_pixel_report_only_total > 0
                || r.body_rewrite_removed_cosmetic_report_only_total > 0
                || r.body_rewrite_bytes_saved_report_only_total > 0
            {
                writeln!(
                    &mut out,
                    "  html_removed_report_only: scripts={} pixels={} cosmetic={} bytes_saved={}",
                    r.body_rewrite_removed_script_report_only_total,
                    r.body_rewrite_removed_pixel_report_only_total,
                    r.body_rewrite_removed_cosmetic_report_only_total,
                    r.body_rewrite_bytes_saved_report_only_total
                )
                .ok();
            }
            if r.websocket_blocked_total > 0
                || r.referer_spoofed_total > 0
                || r.cert_pin_violation_total > 0
            {
                writeln!(
                    &mut out,
                    "  other: websocket_blocked={} referer_spoofed={} cert_pin_violations={}",
                    r.websocket_blocked_total, r.referer_spoofed_total, r.cert_pin_violation_total
                )
                .ok();
            }
            writeln!(
                &mut out,
                "  last: unix={} flow={:?} action={:?} reason={:?}",
                r.last_seen_unix, r.last_flow, r.last_action, r.last_reason
            )
            .ok();
            writeln!(&mut out).ok();
        }

        return Ok(out);
    }

    let mut totals = ComplianceTotals::default();
    for (_, r) in &hosts {
        totals.add(r);
    }

    let cookie_events = totals
        .cookie_stripped_events_total
        .saturating_add(totals.cookie_report_only_events_total);
    let dns_events = totals
        .dns_blocked_total
        .saturating_add(totals.dns_report_only_total);
    let consent_events = totals
        .consent_blocked_total
        .saturating_add(totals.consent_report_only_total);
    let body_events = totals
        .body_rewrite_enforce_total
        .saturating_add(totals.body_rewrite_report_only_total);
    let body_attempted = body_events.saturating_add(totals.body_rewrite_skipped_total);

    writeln!(&mut out, "hosts: {}", totals.hosts).ok();
    writeln!(&mut out, "seen_total: {}", totals.seen_total).ok();
    writeln!(
        &mut out,
        "routing: mitm={} passthrough={}",
        totals.routing_mitm_total, totals.routing_passthrough_total
    )
    .ok();
    writeln!(
        &mut out,
        "mitm: attempts={} success={} failure={} tls_reject={} auto_pinned={} success_rate={}",
        totals.mitm_attempt_total,
        totals.mitm_success_total,
        totals.mitm_failure_total,
        totals.mitm_client_tls_reject_total,
        totals.host_auto_pinned_total,
        fmt_percent(totals.mitm_success_total, totals.mitm_attempt_total)
    )
    .ok();
    writeln!(
        &mut out,
        "dns: blocked={} report_only={} cname_uncloaked={} enforce_ratio={}",
        totals.dns_blocked_total,
        totals.dns_report_only_total,
        totals.dns_cname_uncloaked_total,
        fmt_percent(totals.dns_blocked_total, dns_events)
    )
    .ok();
    writeln!(
        &mut out,
        "cookies: set_cookie_headers_total={} stripped_events={} report_only_events={} enforce_ratio={}",
        totals.set_cookie_headers_total,
        totals.cookie_stripped_events_total,
        totals.cookie_report_only_events_total,
        fmt_percent(totals.cookie_stripped_events_total, cookie_events)
    )
    .ok();
    writeln!(
        &mut out,
        "consent: blocked={} report_only={} enforce_ratio={}",
        totals.consent_blocked_total,
        totals.consent_report_only_total,
        fmt_percent(totals.consent_blocked_total, consent_events)
    )
    .ok();
    writeln!(
        &mut out,
        "html_rewrite: enforce={} report_only={} skipped={} enforce_ratio={} skip_rate={}",
        totals.body_rewrite_enforce_total,
        totals.body_rewrite_report_only_total,
        totals.body_rewrite_skipped_total,
        fmt_percent(totals.body_rewrite_enforce_total, body_events),
        fmt_percent(totals.body_rewrite_skipped_total, body_attempted)
    )
    .ok();
    if totals.body_rewrite_removed_script_total > 0
        || totals.body_rewrite_removed_pixel_total > 0
        || totals.body_rewrite_removed_cosmetic_total > 0
        || totals.body_rewrite_bytes_saved_total > 0
    {
        writeln!(
            &mut out,
            "html_removed_enforce: scripts={} pixels={} cosmetic={} bytes_saved={}",
            totals.body_rewrite_removed_script_total,
            totals.body_rewrite_removed_pixel_total,
            totals.body_rewrite_removed_cosmetic_total,
            totals.body_rewrite_bytes_saved_total
        )
        .ok();
    }
    if totals.body_rewrite_removed_script_report_only_total > 0
        || totals.body_rewrite_removed_pixel_report_only_total > 0
        || totals.body_rewrite_removed_cosmetic_report_only_total > 0
        || totals.body_rewrite_bytes_saved_report_only_total > 0
    {
        writeln!(
            &mut out,
            "html_removed_report_only: scripts={} pixels={} cosmetic={} bytes_saved={}",
            totals.body_rewrite_removed_script_report_only_total,
            totals.body_rewrite_removed_pixel_report_only_total,
            totals.body_rewrite_removed_cosmetic_report_only_total,
            totals.body_rewrite_bytes_saved_report_only_total
        )
        .ok();
    }
    writeln!(&mut out).ok();

    let top_hosts = top_hosts.clamp(1, 200);

    // DNS enforcement table
    let mut dns_rows: Vec<(&str, &HostReceipt, u64)> = Vec::new();
    for (host, r) in &hosts {
        let total = r
            .dns_blocked_total
            .saturating_add(r.dns_report_only_total)
            .saturating_add(r.dns_cname_uncloaked_total);
        if total > 0 {
            dns_rows.push((host.as_str(), r, total));
        }
    }
    dns_rows.sort_by_key(|(_, _, total)| std::cmp::Reverse(*total));
    writeln!(
        &mut out,
        "DNS enforcement (top {n} by total actions):",
        n = top_hosts.min(dns_rows.len())
    )
    .ok();
    writeln!(
        &mut out,
        "{:<35} {:>7} {:>11} {:>14} {:>6} {:>7} last_reason",
        "host", "blocked", "report_only", "cname_uncloaked", "total", "enf%"
    )
    .ok();
    for (host, r, total) in dns_rows.into_iter().take(top_hosts) {
        let denom = r.dns_blocked_total.saturating_add(r.dns_report_only_total);
        let enf = percent_u64(r.dns_blocked_total, denom);
        writeln!(
            &mut out,
            "{:<35} {:>7} {:>11} {:>14} {:>6} {:>7} {}",
            host,
            r.dns_blocked_total,
            r.dns_report_only_total,
            r.dns_cname_uncloaked_total,
            total,
            enf.map(|p| format!("{p}%"))
                .unwrap_or_else(|| "-".to_string()),
            r.last_reason.as_deref().unwrap_or("-")
        )
        .ok();
    }
    writeln!(&mut out).ok();

    // Cookie enforcement table
    let mut cookie_rows: Vec<(&str, &HostReceipt, u64)> = Vec::new();
    for (host, r) in &hosts {
        let cookie_events = r
            .policy_set_cookie_stripped_total
            .saturating_add(r.policy_set_cookie_would_strip_total);
        if r.policy_set_cookie_headers_total > 0 || cookie_events > 0 {
            cookie_rows.push((host.as_str(), r, r.policy_set_cookie_headers_total));
        }
    }
    cookie_rows.sort_by_key(|(_, _, hdrs)| std::cmp::Reverse(*hdrs));
    writeln!(
        &mut out,
        "Cookie policy (top {n} by Set-Cookie headers observed on matched domains):",
        n = top_hosts.min(cookie_rows.len())
    )
    .ok();
    writeln!(
        &mut out,
        "{:<35} {:>9} {:>12} {:>14} {:>7} {:>12} last_reason",
        "host", "ck_hdrs", "strip_events", "report_events", "enf%", "consent_blk"
    )
    .ok();
    for (host, r, hdrs) in cookie_rows.into_iter().take(top_hosts) {
        let cookie_events = r
            .policy_set_cookie_stripped_total
            .saturating_add(r.policy_set_cookie_would_strip_total);
        let enf = percent_u64(r.policy_set_cookie_stripped_total, cookie_events);
        writeln!(
            &mut out,
            "{:<35} {:>9} {:>12} {:>14} {:>7} {:>12} {}",
            host,
            hdrs,
            r.policy_set_cookie_stripped_total,
            r.policy_set_cookie_would_strip_total,
            enf.map(|p| format!("{p}%"))
                .unwrap_or_else(|| "-".to_string()),
            r.consent_enforcement_blocked_total,
            r.last_reason.as_deref().unwrap_or("-")
        )
        .ok();
    }
    writeln!(&mut out).ok();

    // HTML rewrite table (event counts + per-element removal totals from enforce mode)
    let mut body_rows: Vec<(&str, &HostReceipt, u64)> = Vec::new();
    for (host, r) in &hosts {
        let total = r
            .body_rewrite_total
            .saturating_add(r.body_rewrite_report_only_total)
            .saturating_add(r.body_rewrite_skipped_total);
        if total > 0 {
            body_rows.push((host.as_str(), r, total));
        }
    }
    body_rows.sort_by_key(|(_, _, total)| std::cmp::Reverse(*total));
    writeln!(
        &mut out,
        "HTML rewrite (top {n} by rewrite+skip events):",
        n = top_hosts.min(body_rows.len())
    )
    .ok();
    writeln!(
        &mut out,
        "{:<35} {:>8} {:>11} {:>8} {:>7} {:>7} {:>7} {:>11} last_reason",
        "host", "enforce", "report_only", "skipped", "scr_rm", "pix_rm", "cos_rm", "bytes_saved"
    )
    .ok();
    for (host, r, _) in body_rows.into_iter().take(top_hosts) {
        writeln!(
            &mut out,
            "{:<35} {:>8} {:>11} {:>8} {:>7} {:>7} {:>7} {:>11} {}",
            host,
            r.body_rewrite_total,
            r.body_rewrite_report_only_total,
            r.body_rewrite_skipped_total,
            r.body_rewrite_removed_script_total,
            r.body_rewrite_removed_pixel_total,
            r.body_rewrite_removed_cosmetic_total,
            r.body_rewrite_bytes_saved_total,
            r.last_reason.as_deref().unwrap_or("-")
        )
        .ok();
    }
    writeln!(&mut out).ok();

    // Passthrough/pinning table
    let mut route_rows: Vec<(&str, &HostReceipt, u64)> = Vec::new();
    for (host, r) in &hosts {
        let total = r
            .routing_passthrough_total
            .saturating_add(r.mitm_client_tls_reject_total)
            .saturating_add(r.host_auto_pinned_total);
        if total > 0 {
            route_rows.push((host.as_str(), r, total));
        }
    }
    route_rows.sort_by_key(|(_, _, total)| std::cmp::Reverse(*total));
    writeln!(
        &mut out,
        "Passthrough/pinning (top {n} by passthrough/tls_reject/auto_pin):",
        n = top_hosts.min(route_rows.len())
    )
    .ok();
    writeln!(
        &mut out,
        "{:<35} {:>11} {:>6} {:>9} {:>9} last_reason",
        "host", "passthrough", "mitm", "tls_reject", "auto_pin"
    )
    .ok();
    for (host, r, _) in route_rows.into_iter().take(top_hosts) {
        writeln!(
            &mut out,
            "{:<35} {:>11} {:>6} {:>9} {:>9} {}",
            host,
            r.routing_passthrough_total,
            r.routing_mitm_total,
            r.mitm_client_tls_reject_total,
            r.host_auto_pinned_total,
            r.last_reason.as_deref().unwrap_or("-")
        )
        .ok();
    }

    writeln!(&mut out).ok();
    writeln!(
        &mut out,
        "Notes: html_rewrite event counters track rewritten responses; removal counters track elements removed (best-effort). Cookie counters track Set-Cookie headers observed on matched domains plus event counts for enforce/report_only."
    )
    .ok();

    Ok(out)
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

pub fn render_compliance_report_html(
    path: &Path,
    top_hosts: usize,
    host_filter: Option<&str>,
) -> io::Result<String> {
    let data = load_receipts_for_reporting(path)?;
    let version = data.version;
    let generated_unix = data.generated_unix;
    let hosts = data.hosts;

    let mut out = String::new();
    out.push_str("<!doctype html><html><head><meta charset=\"utf-8\">");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
    out.push_str("<title>Privacy Compliance Report</title>");
    out.push_str("<style>");
    out.push_str("body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.35;margin:24px;color:#111;background:#fafafa;}");
    out.push_str("h1,h2{margin:0 0 12px 0;}h2{margin-top:24px;font-size:18px;}");
    out.push_str(".meta{color:#444;margin-bottom:16px}.card{background:#fff;border:1px solid #e5e5e5;border-radius:10px;padding:14px 16px;margin:10px 0;}");
    out.push_str("table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5e5e5;border-radius:10px;overflow:hidden;}");
    out.push_str(
        "th,td{padding:8px 10px;border-bottom:1px solid #eee;font-size:13px;vertical-align:top;}",
    );
    out.push_str("th{background:#f3f4f6;text-align:left;font-weight:600;color:#222;}");
    out.push_str("tr:last-child td{border-bottom:none;}");
    out.push_str(".num{text-align:right;white-space:nowrap;}");
    out.push_str(".muted{color:#666;}");
    out.push_str("</style></head><body>");

    out.push_str("<h1>Privacy Compliance Report</h1>");
    out.push_str("<div class=\"meta\">");
    out.push_str(&format!(
        "<div><strong>Receipts file:</strong> <code>{}</code></div>",
        escape_html(&path.display().to_string())
    ));
    if let Some(v) = version {
        out.push_str(&format!("<div><strong>Version:</strong> {v}</div>"));
    }
    if let Some(ts) = generated_unix {
        out.push_str(&format!(
            "<div><strong>Generated (unix):</strong> {ts}</div>"
        ));
    }
    out.push_str("</div>");

    if hosts.is_empty() {
        out.push_str("<div class=\"card\"><em>(no hosts recorded yet)</em></div>");
        out.push_str("</body></html>");
        return Ok(out);
    }

    if let Some(filter) = host_filter {
        let filter = normalize_host(filter);
        let mut matched: Vec<(String, HostReceipt)> = hosts
            .into_iter()
            .filter(|(h, _)| h == &filter || h.ends_with(&format!(".{filter}")))
            .collect();
        matched.sort_by_key(|(_, r)| std::cmp::Reverse(r.last_seen_unix));

        out.push_str(&format!(
            "<div class=\"card\"><div><strong>Host filter:</strong> <code>{}</code></div><div class=\"muted\">Matches: {}</div></div>",
            escape_html(&filter),
            matched.len()
        ));

        out.push_str("<table><thead><tr>");
        out.push_str("<th>Host</th><th class=\"num\">Seen</th><th class=\"num\">MITM</th><th class=\"num\">Pass</th><th class=\"num\">DNS blk</th><th class=\"num\">CK hdrs</th><th class=\"num\">HTML rw</th><th class=\"num\">Scr rm</th><th class=\"num\">Pix rm</th><th class=\"num\">Cos rm</th><th class=\"num\">Bytes saved</th><th>Last reason</th>");
        out.push_str("</tr></thead><tbody>");
        for (host, r) in matched {
            let body_total = r
                .body_rewrite_total
                .saturating_add(r.body_rewrite_report_only_total);
            out.push_str("<tr>");
            out.push_str(&format!("<td><code>{}</code></td>", escape_html(&host)));
            out.push_str(&format!("<td class=\"num\">{}</td>", r.seen_total));
            out.push_str(&format!("<td class=\"num\">{}</td>", r.routing_mitm_total));
            out.push_str(&format!(
                "<td class=\"num\">{}</td>",
                r.routing_passthrough_total
            ));
            out.push_str(&format!("<td class=\"num\">{}</td>", r.dns_blocked_total));
            out.push_str(&format!(
                "<td class=\"num\">{}</td>",
                r.policy_set_cookie_headers_total
            ));
            out.push_str(&format!("<td class=\"num\">{}</td>", body_total));
            out.push_str(&format!(
                "<td class=\"num\">{}</td>",
                r.body_rewrite_removed_script_total
            ));
            out.push_str(&format!(
                "<td class=\"num\">{}</td>",
                r.body_rewrite_removed_pixel_total
            ));
            out.push_str(&format!(
                "<td class=\"num\">{}</td>",
                r.body_rewrite_removed_cosmetic_total
            ));
            out.push_str(&format!(
                "<td class=\"num\">{}</td>",
                r.body_rewrite_bytes_saved_total
            ));
            out.push_str(&format!(
                "<td>{}</td>",
                escape_html(r.last_reason.as_deref().unwrap_or("-"))
            ));
            out.push_str("</tr>");
        }
        out.push_str("</tbody></table>");
        out.push_str("</body></html>");
        return Ok(out);
    }

    let mut totals = ComplianceTotals::default();
    for (_, r) in &hosts {
        totals.add(r);
    }

    let cookie_events = totals
        .cookie_stripped_events_total
        .saturating_add(totals.cookie_report_only_events_total);
    let dns_events = totals
        .dns_blocked_total
        .saturating_add(totals.dns_report_only_total);
    let consent_events = totals
        .consent_blocked_total
        .saturating_add(totals.consent_report_only_total);
    let body_events = totals
        .body_rewrite_enforce_total
        .saturating_add(totals.body_rewrite_report_only_total);
    let body_attempted = body_events.saturating_add(totals.body_rewrite_skipped_total);

    out.push_str("<div class=\"card\">");
    out.push_str(&format!(
        "<div><strong>Hosts:</strong> {}</div>",
        totals.hosts
    ));
    out.push_str(&format!(
        "<div><strong>Seen total:</strong> {}</div>",
        totals.seen_total
    ));
    out.push_str(&format!(
        "<div><strong>MITM success rate:</strong> {}</div>",
        escape_html(&fmt_percent(
            totals.mitm_success_total,
            totals.mitm_attempt_total
        ))
    ));
    out.push_str(&format!(
        "<div><strong>DNS enforce ratio:</strong> {}</div>",
        escape_html(&fmt_percent(totals.dns_blocked_total, dns_events))
    ));
    out.push_str(&format!(
        "<div><strong>Cookie enforce ratio:</strong> {}</div>",
        escape_html(&fmt_percent(
            totals.cookie_stripped_events_total,
            cookie_events
        ))
    ));
    out.push_str(&format!(
        "<div><strong>Consent enforce ratio:</strong> {}</div>",
        escape_html(&fmt_percent(totals.consent_blocked_total, consent_events))
    ));
    out.push_str(&format!(
        "<div><strong>HTML rewrite enforce ratio:</strong> {}</div>",
        escape_html(&fmt_percent(totals.body_rewrite_enforce_total, body_events))
    ));
    out.push_str(&format!(
        "<div><strong>HTML rewrite skip rate:</strong> {}</div>",
        escape_html(&fmt_percent(
            totals.body_rewrite_skipped_total,
            body_attempted
        ))
    ));
    if totals.body_rewrite_removed_script_total > 0
        || totals.body_rewrite_removed_pixel_total > 0
        || totals.body_rewrite_removed_cosmetic_total > 0
        || totals.body_rewrite_bytes_saved_total > 0
    {
        out.push_str(&format!(
            "<div><strong>HTML removed (enforce):</strong> scripts={} pixels={} cosmetic={} bytes_saved={}</div>",
            totals.body_rewrite_removed_script_total,
            totals.body_rewrite_removed_pixel_total,
            totals.body_rewrite_removed_cosmetic_total,
            totals.body_rewrite_bytes_saved_total
        ));
    }
    if totals.body_rewrite_removed_script_report_only_total > 0
        || totals.body_rewrite_removed_pixel_report_only_total > 0
        || totals.body_rewrite_removed_cosmetic_report_only_total > 0
        || totals.body_rewrite_bytes_saved_report_only_total > 0
    {
        out.push_str(&format!(
            "<div><strong>HTML removed (report_only):</strong> scripts={} pixels={} cosmetic={} bytes_saved={}</div>",
            totals.body_rewrite_removed_script_report_only_total,
            totals.body_rewrite_removed_pixel_report_only_total,
            totals.body_rewrite_removed_cosmetic_report_only_total,
            totals.body_rewrite_bytes_saved_report_only_total
        ));
    }
    out.push_str("</div>");

    let top_hosts = top_hosts.clamp(1, 200);
    let mut rows: Vec<(&str, &HostReceipt, u64)> = Vec::new();
    for (host, r) in &hosts {
        let actions = r
            .dns_blocked_total
            .saturating_add(r.dns_report_only_total)
            .saturating_add(r.dns_cname_uncloaked_total)
            .saturating_add(r.policy_set_cookie_stripped_total)
            .saturating_add(r.policy_set_cookie_would_strip_total)
            .saturating_add(r.body_rewrite_total)
            .saturating_add(r.body_rewrite_report_only_total)
            .saturating_add(r.body_rewrite_skipped_total)
            .saturating_add(r.consent_enforcement_blocked_total)
            .saturating_add(r.consent_enforcement_report_only_total);
        if actions > 0 {
            rows.push((host.as_str(), r, actions));
        }
    }
    rows.sort_by_key(|(_, _, actions)| std::cmp::Reverse(*actions));

    out.push_str("<h2>Top Domains (by compliance actions)</h2>");
    out.push_str("<table><thead><tr>");
    out.push_str("<th>Host</th><th class=\"num\">Actions</th><th class=\"num\">DNS blk</th><th class=\"num\">CNAME</th><th class=\"num\">CK hdrs</th><th class=\"num\">HTML rw</th><th class=\"num\">HTML skip</th><th class=\"num\">Scr rm</th><th class=\"num\">Pix rm</th><th class=\"num\">Cos rm</th><th class=\"num\">Bytes saved</th><th>Last reason</th>");
    out.push_str("</tr></thead><tbody>");
    for (host, r, actions) in rows.into_iter().take(top_hosts) {
        let html_rw = r
            .body_rewrite_total
            .saturating_add(r.body_rewrite_report_only_total);
        out.push_str("<tr>");
        out.push_str(&format!("<td><code>{}</code></td>", escape_html(host)));
        out.push_str(&format!("<td class=\"num\">{actions}</td>"));
        out.push_str(&format!("<td class=\"num\">{}</td>", r.dns_blocked_total));
        out.push_str(&format!(
            "<td class=\"num\">{}</td>",
            r.dns_cname_uncloaked_total
        ));
        out.push_str(&format!(
            "<td class=\"num\">{}</td>",
            r.policy_set_cookie_headers_total
        ));
        out.push_str(&format!("<td class=\"num\">{html_rw}</td>"));
        out.push_str(&format!(
            "<td class=\"num\">{}</td>",
            r.body_rewrite_skipped_total
        ));
        out.push_str(&format!(
            "<td class=\"num\">{}</td>",
            r.body_rewrite_removed_script_total
        ));
        out.push_str(&format!(
            "<td class=\"num\">{}</td>",
            r.body_rewrite_removed_pixel_total
        ));
        out.push_str(&format!(
            "<td class=\"num\">{}</td>",
            r.body_rewrite_removed_cosmetic_total
        ));
        out.push_str(&format!(
            "<td class=\"num\">{}</td>",
            r.body_rewrite_bytes_saved_total
        ));
        out.push_str(&format!(
            "<td>{}</td>",
            escape_html(r.last_reason.as_deref().unwrap_or("-"))
        ));
        out.push_str("</tr>");
    }
    out.push_str("</tbody></table>");

    out.push_str("<p class=\"muted\">html_rewrite counters track rewritten responses; element removals are best-effort and may undercount/overcount due to selector overlap.</p>");
    out.push_str("</body></html>");
    Ok(out)
}

pub struct ReceiptStore {
    path: PathBuf,
    hosts: RwLock<HashMap<String, HostReceipt>>,
    dirty: AtomicBool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BodyRewriteDetails {
    pub removed_scripts: u64,
    pub removed_pixels: u64,
    pub removed_cosmetic: u64,
    pub bytes_saved: u64,
}

impl ReceiptStore {
    pub fn load(path: &Path) -> io::Result<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            hosts: RwLock::new(load_receipts(path)?),
            dirty: AtomicBool::new(false),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record_tls_routing_decision(
        &self,
        flow: &'static str,
        host: &str,
        action: &'static str,
        reason: &'static str,
    ) {
        let normalized = normalize_host(host);
        if normalized.is_empty() {
            return;
        }

        if let Ok(mut guard) = self.hosts.write() {
            let entry = guard.entry(normalized).or_default();
            entry.touch(flow, action, reason);
            self.dirty.store(true, Ordering::Release);
        }
    }

    pub fn record_mitm_attempt(&self, host: &str) {
        self.inc_counter(host, |r| {
            r.mitm_attempt_total = r.mitm_attempt_total.saturating_add(1)
        });
    }

    pub fn record_mitm_success(&self, host: &str) {
        self.inc_counter(host, |r| {
            r.mitm_success_total = r.mitm_success_total.saturating_add(1)
        });
    }

    pub fn record_mitm_failure(&self, host: &str) {
        self.inc_counter(host, |r| {
            r.mitm_failure_total = r.mitm_failure_total.saturating_add(1)
        });
    }

    pub fn record_client_tls_reject(&self, host: &str) {
        self.inc_counter(host, |r| {
            r.mitm_client_tls_reject_total = r.mitm_client_tls_reject_total.saturating_add(1)
        });
    }

    pub fn record_host_auto_pinned(&self, host: &str) {
        self.inc_counter(host, |r| {
            r.host_auto_pinned_total = r.host_auto_pinned_total.saturating_add(1)
        });
    }

    pub fn record_policy_set_cookie(
        &self,
        host: &str,
        mode: &'static str,
        set_cookie_count: usize,
    ) {
        let set_cookie_count = u64::try_from(set_cookie_count).unwrap_or(u64::MAX);
        self.inc_counter(host, |r| {
            r.policy_set_cookie_headers_total = r
                .policy_set_cookie_headers_total
                .saturating_add(set_cookie_count);
            match mode {
                "enforce" => {
                    r.policy_set_cookie_stripped_total =
                        r.policy_set_cookie_stripped_total.saturating_add(1);
                }
                "report_only" => {
                    r.policy_set_cookie_would_strip_total =
                        r.policy_set_cookie_would_strip_total.saturating_add(1);
                }
                _ => {}
            }
        });
    }

    pub fn record_dns_block(&self, host: &str) {
        self.inc_counter(host, |r| {
            r.dns_blocked_total = r.dns_blocked_total.saturating_add(1)
        });
    }

    pub fn record_dns_report_only(&self, host: &str) {
        self.inc_counter(host, |r| {
            r.dns_report_only_total = r.dns_report_only_total.saturating_add(1)
        });
    }

    pub fn record_dns_cname_uncloaked(&self, host: &str) {
        self.inc_counter(host, |r| {
            r.dns_cname_uncloaked_total = r.dns_cname_uncloaked_total.saturating_add(1)
        });
    }

    pub fn record_consent_enforcement(&self, host: &str, mode: &str, set_cookie_count: usize) {
        let count = u64::try_from(set_cookie_count).unwrap_or(u64::MAX);
        self.inc_counter(host, |r| {
            r.policy_set_cookie_headers_total =
                r.policy_set_cookie_headers_total.saturating_add(count);
            match mode {
                "enforce" => {
                    r.consent_enforcement_blocked_total =
                        r.consent_enforcement_blocked_total.saturating_add(1);
                    r.policy_set_cookie_stripped_total =
                        r.policy_set_cookie_stripped_total.saturating_add(1);
                }
                "report_only" => {
                    r.consent_enforcement_report_only_total =
                        r.consent_enforcement_report_only_total.saturating_add(1);
                    r.policy_set_cookie_would_strip_total =
                        r.policy_set_cookie_would_strip_total.saturating_add(1);
                }
                _ => {}
            }
        });
    }

    pub fn record_body_rewrite(&self, host: &str, mode: &str, details: BodyRewriteDetails) {
        self.inc_counter(host, |r| match mode {
            "enforce" => {
                r.body_rewrite_total = r.body_rewrite_total.saturating_add(1);
                r.body_rewrite_removed_script_total = r
                    .body_rewrite_removed_script_total
                    .saturating_add(details.removed_scripts);
                r.body_rewrite_removed_pixel_total = r
                    .body_rewrite_removed_pixel_total
                    .saturating_add(details.removed_pixels);
                r.body_rewrite_removed_cosmetic_total = r
                    .body_rewrite_removed_cosmetic_total
                    .saturating_add(details.removed_cosmetic);
                r.body_rewrite_bytes_saved_total = r
                    .body_rewrite_bytes_saved_total
                    .saturating_add(details.bytes_saved);
            }
            "report_only" => {
                r.body_rewrite_report_only_total =
                    r.body_rewrite_report_only_total.saturating_add(1);
                r.body_rewrite_removed_script_report_only_total = r
                    .body_rewrite_removed_script_report_only_total
                    .saturating_add(details.removed_scripts);
                r.body_rewrite_removed_pixel_report_only_total = r
                    .body_rewrite_removed_pixel_report_only_total
                    .saturating_add(details.removed_pixels);
                r.body_rewrite_removed_cosmetic_report_only_total = r
                    .body_rewrite_removed_cosmetic_report_only_total
                    .saturating_add(details.removed_cosmetic);
                r.body_rewrite_bytes_saved_report_only_total = r
                    .body_rewrite_bytes_saved_report_only_total
                    .saturating_add(details.bytes_saved);
            }
            _ => {}
        });
    }

    pub fn record_body_rewrite_skipped(&self, host: &str) {
        self.inc_counter(host, |r| {
            r.body_rewrite_skipped_total = r.body_rewrite_skipped_total.saturating_add(1)
        });
    }

    pub fn record_websocket_blocked(&self, host: &str) {
        self.inc_counter(host, |r| {
            r.websocket_blocked_total = r.websocket_blocked_total.saturating_add(1)
        });
    }

    pub fn record_referer_spoofed(&self, host: &str) {
        self.inc_counter(host, |r| {
            r.referer_spoofed_total = r.referer_spoofed_total.saturating_add(1)
        });
    }

    pub fn record_cert_pin_violation(&self, host: &str) {
        self.inc_counter(host, |r| {
            r.cert_pin_violation_total = r.cert_pin_violation_total.saturating_add(1)
        });
    }

    pub fn record_query_params_stripped(&self, host: &str) {
        self.inc_counter(host, |r| {
            r.query_params_stripped_total = r.query_params_stripped_total.saturating_add(1)
        });
    }

    pub fn record_cache_headers_stripped(&self, host: &str) {
        self.inc_counter(host, |r| {
            r.cache_headers_stripped_total = r.cache_headers_stripped_total.saturating_add(1)
        });
    }

    fn inc_counter(&self, host: &str, update: impl FnOnce(&mut HostReceipt)) {
        let normalized = normalize_host(host);
        if normalized.is_empty() {
            return;
        }

        match self.hosts.write() {
            Ok(mut guard) => {
                let entry = guard.entry(normalized).or_default();
                update(entry);
                entry.last_seen_unix = now_unix_seconds();
                self.dirty.store(true, Ordering::Release);
            }
            Err(_) => {
                // We'll surface the lock poison during flush, but do not crash the proxy on telemetry.
            }
        }
    }

    /// Returns the full host receipts map as a JSON Value (for dashboard API).
    pub fn hosts_as_json(&self) -> Value {
        let snapshot = match self.hosts.read() {
            Ok(guard) => guard.clone(),
            Err(_) => return json!({}),
        };
        let mut hosts_json = serde_json::Map::new();
        for (host, receipt) in snapshot {
            hosts_json.insert(host, receipt.as_json());
        }
        Value::Object(hosts_json)
    }

    pub fn flush_if_dirty(&self) -> io::Result<bool> {
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return Ok(false);
        }

        // Prune stale hosts (older than 6 hours) under write lock
        {
            if let Ok(mut guard) = self.hosts.write() {
                prune_stale_hosts(&mut guard, 6 * 3600);
            }
        }

        let snapshot = self.hosts.read().map_err(lock_error)?.clone();

        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut hosts_json = serde_json::Map::new();
            for (host, receipt) in snapshot {
                hosts_json.insert(host, receipt.as_json());
            }

            let root = json!({
                "version": 1,
                "generated_unix": now_unix_seconds(),
                "hosts": Value::Object(hosts_json),
            });

            if let Err(e) = persist_receipts(&path, &root) {
                tracing::warn!(event = "receipts_flush_error", error = %e);
            }
        });

        Ok(true)
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

    #[tokio::test]
    async fn load_missing_file_is_empty() {
        let path = temp_file("receipts_missing");
        let store = ReceiptStore::load(&path).expect("load should succeed");
        assert_eq!(store.flush_if_dirty().expect("flush"), false);
    }

    #[tokio::test]
    async fn decision_recording_marks_dirty_and_flushes() {
        let path = temp_file("receipts_write");
        let store = ReceiptStore::load(&path).expect("load");
        store.record_tls_routing_decision("connect", "Example.COM.", "mitm", "test");
        assert!(store.flush_if_dirty().expect("flush should write"));

        // Wait for background task
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let raw = fs::read_to_string(&path).expect("read receipts file");
        assert!(raw.contains("example.com"));
        assert!(raw.contains("routing_mitm_total"));
    }

    #[tokio::test]
    async fn policy_counters_increment() {
        let path = temp_file("receipts_policy");
        let store = ReceiptStore::load(&path).expect("load");
        store.record_policy_set_cookie("doubleclick.net", "report_only", 2);
        store.record_policy_set_cookie("doubleclick.net", "enforce", 1);
        assert!(store.flush_if_dirty().expect("flush"));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let raw = fs::read_to_string(&path).expect("read receipts file");
        assert!(raw.contains("policy_set_cookie_would_strip_total"));
        assert!(raw.contains("policy_set_cookie_stripped_total"));
        assert!(raw.contains("policy_set_cookie_headers_total"));
    }

    #[tokio::test]
    async fn report_renders_top_hosts_table() {
        let path = temp_file("receipts_report");
        let store = ReceiptStore::load(&path).expect("load");
        store.record_tls_routing_decision("connect", "a.example.com", "mitm", "test");
        store.record_tls_routing_decision(
            "connect",
            "b.example.com",
            "passthrough",
            "mitm_disabled",
        );
        store.record_policy_set_cookie("a.example.com", "enforce", 1);
        assert!(store.flush_if_dirty().expect("flush"));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let report = render_receipts_report(&path, 10, None).expect("report");
        assert!(report.contains("Top hosts"));
        assert!(report.contains("a.example.com"));
        assert!(report.contains("b.example.com"));
    }

    #[tokio::test]
    async fn compliance_report_text_renders_sections() {
        let path = temp_file("receipts_compliance");
        let store = ReceiptStore::load(&path).expect("load");
        store.record_tls_routing_decision("connect", "a.example.com", "mitm", "ok");
        store.record_dns_block("ads.example.com");
        store.record_policy_set_cookie("a.example.com", "enforce", 2);
        store.record_body_rewrite("a.example.com", "enforce", BodyRewriteDetails::default());
        assert!(store.flush_if_dirty().expect("flush"));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let report = render_compliance_report_text(&path, 10, None).expect("report");
        assert!(report.contains("Privacy compliance report"));
        assert!(report.contains("DNS enforcement"));
        assert!(report.contains("Cookie policy"));
        assert!(report.contains("HTML rewrite"));
    }

    #[tokio::test]
    async fn compliance_report_html_renders_basic_structure() {
        let path = temp_file("receipts_compliance_html");
        let store = ReceiptStore::load(&path).expect("load");
        store.record_tls_routing_decision("connect", "a.example.com", "mitm", "ok");
        store.record_policy_set_cookie("a.example.com", "enforce", 1);
        assert!(store.flush_if_dirty().expect("flush"));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let report = render_compliance_report_html(&path, 10, None).expect("report");
        assert!(report.contains("<!doctype html>"));
        assert!(report.contains("Privacy Compliance Report"));
        assert!(report.contains("a.example.com"));
        assert!(report.contains("<table"));
    }

    #[tokio::test]
    async fn flush_prunes_stale_hosts() {
        let path = temp_file("receipts_prune");
        let store = ReceiptStore::load(&path).expect("load");

        // Add a fresh host
        store.record_mitm_attempt("fresh.com");

        // Add a stale host manually to the map to simulate time passing
        {
            let mut guard = store.hosts.write().expect("write lock");
            let entry = guard.entry("stale.com".to_string()).or_default();
            entry.last_seen_unix = now_unix_seconds() - (7 * 3600); // 7 hours ago
            store.dirty.store(true, Ordering::Relaxed);
        }

        assert!(store.flush_if_dirty().expect("flush"));

        // Allow some time for background task
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Reload and verify
        let loaded = load_receipts(&path).expect("reload");
        assert!(loaded.contains_key("fresh.com"));
        assert!(!loaded.contains_key("stale.com"));
    }
}
