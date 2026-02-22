use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

#[derive(Debug, Default)]
pub struct Metrics {
    connection_total: AtomicU64,
    passthrough_tunnel_total: AtomicU64,
    mitm_attempt_total: AtomicU64,
    mitm_success_total: AtomicU64,
    mitm_failure_total: AtomicU64,
    mitm_client_tls_reject_total: AtomicU64,
    host_auto_pinned_total: AtomicU64,
    dns_query_total: AtomicU64,
    dns_blocked_total: AtomicU64,
    dns_report_only_total: AtomicU64,
    body_rewrite_total: AtomicU64,
    body_rewrite_skipped_total: AtomicU64,
    filter_list_refresh_total: AtomicU64,
    filter_list_refresh_failed_total: AtomicU64,
    filter_list_rules_active: AtomicU64,
    dns_cname_uncloaked_total: AtomicU64,
    consent_enforcement_blocked_total: AtomicU64,
    websocket_blocked_total: AtomicU64,
    referer_spoofed_total: AtomicU64,
    cert_pin_violation_total: AtomicU64,
    query_params_stripped_total: AtomicU64,
    cache_headers_stripped_total: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub connection_total: u64,
    pub passthrough_tunnel_total: u64,
    pub mitm_attempt_total: u64,
    pub mitm_success_total: u64,
    pub mitm_failure_total: u64,
    pub mitm_client_tls_reject_total: u64,
    pub host_auto_pinned_total: u64,
    pub dns_query_total: u64,
    pub dns_blocked_total: u64,
    pub dns_report_only_total: u64,
    pub body_rewrite_total: u64,
    pub body_rewrite_skipped_total: u64,
    pub filter_list_refresh_total: u64,
    pub filter_list_refresh_failed_total: u64,
    pub filter_list_rules_active: u64,
    pub dns_cname_uncloaked_total: u64,
    pub consent_enforcement_blocked_total: u64,
    pub websocket_blocked_total: u64,
    pub referer_spoofed_total: u64,
    pub cert_pin_violation_total: u64,
    pub query_params_stripped_total: u64,
    pub cache_headers_stripped_total: u64,
}

impl Metrics {
    pub fn inc_connection_total(&self) {
        self.connection_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_passthrough_tunnel_total(&self) {
        self.passthrough_tunnel_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_mitm_attempt_total(&self) {
        self.mitm_attempt_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_mitm_success_total(&self) {
        self.mitm_success_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_mitm_failure_total(&self) {
        self.mitm_failure_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_mitm_client_tls_reject_total(&self) {
        self.mitm_client_tls_reject_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_host_auto_pinned_total(&self) {
        self.host_auto_pinned_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_dns_query_total(&self) {
        self.dns_query_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_dns_blocked_total(&self) {
        self.dns_blocked_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_dns_report_only_total(&self) {
        self.dns_report_only_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_body_rewrite_total(&self) {
        self.body_rewrite_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_body_rewrite_skipped_total(&self) {
        self.body_rewrite_skipped_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_filter_list_refresh_total(&self) {
        self.filter_list_refresh_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_filter_list_refresh_failed_total(&self) {
        self.filter_list_refresh_failed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_filter_list_rules_active(&self, val: u64) {
        self.filter_list_rules_active.store(val, Ordering::Relaxed);
    }

    pub fn inc_dns_cname_uncloaked_total(&self) {
        self.dns_cname_uncloaked_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_consent_enforcement_blocked_total(&self) {
        self.consent_enforcement_blocked_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_websocket_blocked_total(&self) {
        self.websocket_blocked_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_referer_spoofed_total(&self) {
        self.referer_spoofed_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_cert_pin_violation_total(&self) {
        self.cert_pin_violation_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_query_params_stripped_total(&self) {
        self.query_params_stripped_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_cache_headers_stripped_total(&self) {
        self.cache_headers_stripped_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            connection_total: self.connection_total.load(Ordering::Relaxed),
            passthrough_tunnel_total: self.passthrough_tunnel_total.load(Ordering::Relaxed),
            mitm_attempt_total: self.mitm_attempt_total.load(Ordering::Relaxed),
            mitm_success_total: self.mitm_success_total.load(Ordering::Relaxed),
            mitm_failure_total: self.mitm_failure_total.load(Ordering::Relaxed),
            mitm_client_tls_reject_total: self.mitm_client_tls_reject_total.load(Ordering::Relaxed),
            host_auto_pinned_total: self.host_auto_pinned_total.load(Ordering::Relaxed),
            dns_query_total: self.dns_query_total.load(Ordering::Relaxed),
            dns_blocked_total: self.dns_blocked_total.load(Ordering::Relaxed),
            dns_report_only_total: self.dns_report_only_total.load(Ordering::Relaxed),
            body_rewrite_total: self.body_rewrite_total.load(Ordering::Relaxed),
            body_rewrite_skipped_total: self.body_rewrite_skipped_total.load(Ordering::Relaxed),
            filter_list_refresh_total: self.filter_list_refresh_total.load(Ordering::Relaxed),
            filter_list_refresh_failed_total: self
                .filter_list_refresh_failed_total
                .load(Ordering::Relaxed),
            filter_list_rules_active: self.filter_list_rules_active.load(Ordering::Relaxed),
            dns_cname_uncloaked_total: self.dns_cname_uncloaked_total.load(Ordering::Relaxed),
            consent_enforcement_blocked_total: self
                .consent_enforcement_blocked_total
                .load(Ordering::Relaxed),
            websocket_blocked_total: self.websocket_blocked_total.load(Ordering::Relaxed),
            referer_spoofed_total: self.referer_spoofed_total.load(Ordering::Relaxed),
            cert_pin_violation_total: self.cert_pin_violation_total.load(Ordering::Relaxed),
            query_params_stripped_total: self.query_params_stripped_total.load(Ordering::Relaxed),
            cache_headers_stripped_total: self.cache_headers_stripped_total.load(Ordering::Relaxed),
        }
    }

    pub fn log_snapshot(&self, trigger: &'static str) {
        let s = self.snapshot();
        info!(
            event = "metrics_snapshot",
            trigger,
            connection_total = s.connection_total,
            passthrough_tunnel_total = s.passthrough_tunnel_total,
            mitm_attempt_total = s.mitm_attempt_total,
            mitm_success_total = s.mitm_success_total,
            mitm_failure_total = s.mitm_failure_total,
            mitm_client_tls_reject_total = s.mitm_client_tls_reject_total,
            host_auto_pinned_total = s.host_auto_pinned_total,
            dns_query_total = s.dns_query_total,
            dns_blocked_total = s.dns_blocked_total,
            dns_report_only_total = s.dns_report_only_total,
            body_rewrite_total = s.body_rewrite_total,
            body_rewrite_skipped_total = s.body_rewrite_skipped_total,
            filter_list_refresh_total = s.filter_list_refresh_total,
            filter_list_refresh_failed_total = s.filter_list_refresh_failed_total,
            filter_list_rules_active = s.filter_list_rules_active,
            dns_cname_uncloaked_total = s.dns_cname_uncloaked_total,
            consent_enforcement_blocked_total = s.consent_enforcement_blocked_total,
            websocket_blocked_total = s.websocket_blocked_total,
            referer_spoofed_total = s.referer_spoofed_total,
            cert_pin_violation_total = s.cert_pin_violation_total,
            query_params_stripped_total = s.query_params_stripped_total,
            cache_headers_stripped_total = s.cache_headers_stripped_total,
            "runtime metrics snapshot"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_snapshot_tracks_incremented_counters() {
        let m = Metrics::default();
        m.inc_connection_total();
        m.inc_passthrough_tunnel_total();
        m.inc_mitm_attempt_total();
        m.inc_mitm_success_total();
        m.inc_mitm_failure_total();
        m.inc_mitm_client_tls_reject_total();
        m.inc_host_auto_pinned_total();
        m.inc_dns_query_total();
        m.inc_dns_blocked_total();
        m.inc_dns_report_only_total();
        m.inc_body_rewrite_total();
        m.inc_body_rewrite_skipped_total();
        m.inc_filter_list_refresh_total();
        m.inc_filter_list_refresh_failed_total();
        m.set_filter_list_rules_active(42);
        m.inc_dns_cname_uncloaked_total();
        m.inc_consent_enforcement_blocked_total();
        m.inc_websocket_blocked_total();
        m.inc_referer_spoofed_total();
        m.inc_cert_pin_violation_total();
        m.inc_query_params_stripped_total();
        m.inc_cache_headers_stripped_total();

        let s = m.snapshot();
        assert_eq!(s.connection_total, 1);
        assert_eq!(s.passthrough_tunnel_total, 1);
        assert_eq!(s.mitm_attempt_total, 1);
        assert_eq!(s.mitm_success_total, 1);
        assert_eq!(s.mitm_failure_total, 1);
        assert_eq!(s.mitm_client_tls_reject_total, 1);
        assert_eq!(s.host_auto_pinned_total, 1);
        assert_eq!(s.dns_query_total, 1);
        assert_eq!(s.dns_blocked_total, 1);
        assert_eq!(s.dns_report_only_total, 1);
        assert_eq!(s.body_rewrite_total, 1);
        assert_eq!(s.body_rewrite_skipped_total, 1);
        assert_eq!(s.filter_list_refresh_total, 1);
        assert_eq!(s.filter_list_refresh_failed_total, 1);
        assert_eq!(s.filter_list_rules_active, 42);
        assert_eq!(s.dns_cname_uncloaked_total, 1);
        assert_eq!(s.consent_enforcement_blocked_total, 1);
        assert_eq!(s.websocket_blocked_total, 1);
        assert_eq!(s.referer_spoofed_total, 1);
        assert_eq!(s.cert_pin_violation_total, 1);
        assert_eq!(s.query_params_stripped_total, 1);
        assert_eq!(s.cache_headers_stripped_total, 1);
    }
}
