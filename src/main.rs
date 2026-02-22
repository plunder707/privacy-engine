mod cert_pin;
mod dashboard;
mod dns_filter;
mod engine_config;
mod filter_list;
mod filter_list_parser;
mod host_store;
mod metrics;
mod mitm;
mod policy;
mod receipts;
mod tls_parser;

use clap::Parser;
use std::fs;
use std::io::{self, ErrorKind};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

const MAX_PEEK_BYTES: usize = 8192;
const MAX_CONNECT_HEADER_BYTES: usize = 16 * 1024;
const AUTO_PIN_GRACE_PERIOD_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ComplianceFormat {
    Text,
    Html,
}

#[derive(Debug, Parser)]
#[command(
    name = "privacy-engine-rust",
    version,
    about = "Selective privacy proxy foundation with CONNECT + transparent TLS tunneling"
)]
struct Args {
    /// Optional engine runtime configuration JSON file. When provided, values from this file
    /// override the default CLI values to avoid long startup commands.
    #[arg(long)]
    engine_config: Option<PathBuf>,

    /// Host/interface to bind the proxy listener.
    #[arg(long, default_value = "127.0.0.1")]
    listen_host: String,

    /// Port to bind the proxy listener.
    #[arg(long, default_value_t = 8080)]
    listen_port: u16,

    /// JSON file path containing pinned/passthrough hostnames.
    #[arg(long, default_value = "sni_pinned_hosts.json")]
    pinned_hosts_file: PathBuf,

    /// Enable MITM interception path for non-pinned TLS hosts.
    #[arg(long, default_value_t = false)]
    enable_mitm: bool,

    /// MITM CA certificate PEM file.
    #[arg(long, default_value = "mitm_ca_cert.pem")]
    mitm_ca_cert_file: PathBuf,

    /// MITM CA private key PEM file.
    #[arg(long, default_value = "mitm_ca_key.pem")]
    mitm_ca_key_file: PathBuf,

    /// Auto-generate MITM CA files if both are missing.
    #[arg(long, default_value_t = true)]
    mitm_ca_generate_if_missing: bool,

    /// Optional path to export the active MITM CA certificate PEM.
    #[arg(long)]
    mitm_ca_export_cert_file: Option<PathBuf>,

    /// Periodic runtime metrics log interval in seconds. Set to 0 to disable.
    #[arg(long, default_value_t = 30)]
    metrics_log_interval_secs: u64,

    /// Optional policy configuration JSON file.
    #[arg(long)]
    policy_config_file: Option<PathBuf>,

    /// Policy mode override. When set, overrides the mode in --policy-config-file.
    #[arg(long, value_enum)]
    policy_mode: Option<policy::PolicyMode>,

    /// Policy config reload interval in seconds. Only applies when --policy-config-file is set. Set to 0 to disable.
    #[arg(long, default_value_t = 5)]
    policy_reload_interval_secs: u64,

    /// Optional JSON file path for aggregated "privacy receipts".
    #[arg(long)]
    receipts_file: Option<PathBuf>,

    /// Periodic receipt flush interval in seconds. Only applies when --receipts-file is set. Set to 0 to disable.
    #[arg(long, default_value_t = 60)]
    receipts_flush_interval_secs: u64,

    /// Print a human-readable receipts report to stdout and exit. Requires --receipts-file.
    #[arg(long, default_value_t = false)]
    dump_receipts: bool,

    /// Print a compliance-focused report to stdout and exit. Requires --receipts-file.
    #[arg(long, default_value_t = false)]
    dump_compliance: bool,

    /// Compliance report output format (text or html). Only applies with --dump-compliance.
    #[arg(long, value_enum, default_value_t = ComplianceFormat::Text)]
    compliance_format: ComplianceFormat,

    /// Limit receipts report to the top N hosts (by seen_total).
    #[arg(long)]
    top_hosts: Option<usize>,

    /// Show receipts for a specific host only (exact or subdomain will match normalized host key).
    #[arg(long)]
    receipt_host: Option<String>,

    /// TLS cipher suite profile for upstream connections. "chrome" reorders cipher suites
    /// to match Chrome's preference order, reducing JA3/JA4 fingerprint variance.
    #[arg(long, value_enum, default_value_t = mitm::TlsProfile::Default)]
    tls_profile: mitm::TlsProfile,

    /// Enable DNS pre-filter to block tracker domains at DNS level.
    #[arg(long, default_value_t = false)]
    enable_dns_filter: bool,

    /// Host/interface to bind the DNS filter listener.
    #[arg(long, default_value = "127.0.0.1")]
    dns_listen_host: String,

    /// Port to bind the DNS filter listener.
    #[arg(long, default_value_t = 5353)]
    dns_listen_port: u16,

    /// Upstream DNS server address for forwarding non-blocked queries.
    #[arg(long, default_value = "8.8.8.8:53")]
    dns_upstream: String,

    /// Optional upstream DNS-over-HTTPS URL (e.g. "https://1.1.1.1/dns-query").
    /// If provided, replaces the plaintext UDP upstream.
    #[arg(long)]
    dns_upstream_doh: Option<String>,

    /// Load ABP/EasyList filter list from a local file (repeatable).
    #[arg(long, value_name = "PATH")]
    filter_list_file: Vec<PathBuf>,

    /// Load ABP/EasyList filter list from a URL (repeatable).
    #[arg(long, value_name = "URL")]
    filter_list_url: Vec<String>,

    /// Directory to cache downloaded filter lists.
    #[arg(long, default_value = "filter_list_cache")]
    filter_list_cache_dir: PathBuf,

    /// Refresh interval for filter lists in seconds. Set to 0 to disable periodic refresh.
    #[arg(long, default_value_t = 86400)]
    filter_list_refresh_secs: u64,

    /// Per-download timeout in seconds for URL filter lists.
    #[arg(long, default_value_t = 30)]
    filter_list_download_timeout_secs: u64,

    /// Enable the web dashboard on this port (e.g. 9090). Binds to 127.0.0.1.
    #[arg(long)]
    dashboard_port: Option<u16>,

    /// Path for MITM certificate transparency log (JSON-lines). Logs every generated leaf cert.
    #[arg(long)]
    cert_log_file: Option<PathBuf>,

    /// Path for TOFU cert pinning database (JSON). Records upstream cert fingerprints.
    #[arg(long)]
    cert_pin_file: Option<PathBuf>,

    /// Enable DoH server on this port (e.g. 5443).
    #[arg(long)]
    doh_server_port: Option<u16>,

    /// Path to certificate for DoH server (defaults to mitm_ca_cert_file).
    #[arg(long)]
    doh_server_cert_file: Option<PathBuf>,

    /// Path to private key for DoH server (defaults to mitm_ca_key_file).
    #[arg(long)]
    doh_server_key_file: Option<PathBuf>,
}

fn apply_engine_config(args: &mut Args, cfg: engine_config::EngineConfig) {
    args.listen_host = cfg.listen_host;
    args.listen_port = cfg.listen_port;
    args.pinned_hosts_file = cfg.pinned_hosts_file;

    args.enable_mitm = cfg.enable_mitm;
    args.mitm_ca_cert_file = cfg.mitm_ca_cert_file;
    args.mitm_ca_key_file = cfg.mitm_ca_key_file;
    args.mitm_ca_generate_if_missing = cfg.mitm_ca_generate_if_missing;
    args.mitm_ca_export_cert_file = cfg.mitm_ca_export_cert_file;
    args.tls_profile = cfg.tls_profile;

    args.metrics_log_interval_secs = cfg.metrics_log_interval_secs;

    args.policy_config_file = cfg.policy_config_file;
    args.policy_mode = cfg.policy_mode;
    args.policy_reload_interval_secs = cfg.policy_reload_interval_secs;

    args.receipts_file = cfg.receipts_file;
    args.receipts_flush_interval_secs = cfg.receipts_flush_interval_secs;

    args.enable_dns_filter = cfg.enable_dns_filter;
    args.dns_listen_host = cfg.dns_listen_host;
    args.dns_listen_port = cfg.dns_listen_port;
    args.dns_upstream = cfg.dns_upstream;
    if cfg.dns_upstream_doh.is_some() {
        args.dns_upstream_doh = cfg.dns_upstream_doh;
    }

    args.filter_list_file = cfg.filter_list_file;
    args.filter_list_url = cfg.filter_list_url;
    args.filter_list_cache_dir = cfg.filter_list_cache_dir;
    args.filter_list_refresh_secs = cfg.filter_list_refresh_secs;
    args.filter_list_download_timeout_secs = cfg.filter_list_download_timeout_secs;

    args.dashboard_port = cfg.dashboard_port;
    args.cert_log_file = cfg.cert_log_file;
    args.cert_pin_file = cfg.cert_pin_file;

    args.doh_server_port = cfg.doh_server_port;
    args.doh_server_cert_file = cfg.doh_server_cert_file;
    args.doh_server_key_file = cfg.doh_server_key_file;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = Args::parse();
    if let Some(path) = args.engine_config.as_ref() {
        let cfg = engine_config::EngineConfig::load_from_file(path)?;
        info!(
            event = "engine_config_loaded",
            engine_config_file = %path.display(),
            "engine runtime config loaded"
        );
        apply_engine_config(&mut args, cfg);
    }
    if args.dump_compliance {
        if args.dump_receipts {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "cannot combine --dump-receipts and --dump-compliance",
            )
            .into());
        }
        let path = args.receipts_file.as_ref().ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "--dump-compliance requires --receipts-file",
            )
        })?;
        let report = match args.compliance_format {
            ComplianceFormat::Text => receipts::render_compliance_report_text(
                path,
                args.top_hosts.unwrap_or(20),
                args.receipt_host.as_deref(),
            )?,
            ComplianceFormat::Html => receipts::render_compliance_report_html(
                path,
                args.top_hosts.unwrap_or(20),
                args.receipt_host.as_deref(),
            )?,
        };
        print!("{report}");
        return Ok(());
    }
    if args.dump_receipts {
        let path = args.receipts_file.as_ref().ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "--dump-receipts requires --receipts-file",
            )
        })?;
        let report = receipts::render_receipts_report(
            path,
            args.top_hosts.unwrap_or(20),
            args.receipt_host.as_deref(),
        )?;
        print!("{report}");
        return Ok(());
    }

    tracing_subscriber::fmt::init();

    let metrics = Arc::new(metrics::Metrics::default());
    let policy_engine = if let Some(path) = args.policy_config_file.as_ref() {
        let engine = Arc::new(policy::PolicyEngine::load_from_file(
            path,
            args.policy_mode,
        )?);
        let s = engine.summary();
        info!(
            event = "policy_engine_initialized",
            source = "file",
            policy_config_file = %path.display(),
            policy_version = s.version,
            policy_mode = s.mode.as_str(),
            tracker_set_cookie_enabled = s.tracker_rule_enabled,
            tracker_domain_count = s.tracker_domain_count,
            dns_block_enabled = s.dns_block_enabled,
            dns_block_domain_count = s.dns_block_domain_count,
            consent_enforcement_enabled = s.consent_enforcement_enabled,
            consent_default_consent = s.consent_default_consent,
            consent_analytics_domain_count = s.consent_analytics_domain_count,
            consent_user_profile_count = s.consent_user_profile_count,
            "policy engine initialized"
        );
        engine
    } else {
        let mode = args.policy_mode.unwrap_or(policy::PolicyMode::Disabled);
        let engine = Arc::new(policy::PolicyEngine::new(mode));
        let s = engine.summary();
        info!(
            event = "policy_engine_initialized",
            source = "defaults",
            policy_version = s.version,
            policy_mode = s.mode.as_str(),
            tracker_set_cookie_enabled = s.tracker_rule_enabled,
            tracker_domain_count = s.tracker_domain_count,
            dns_block_enabled = s.dns_block_enabled,
            dns_block_domain_count = s.dns_block_domain_count,
            consent_enforcement_enabled = s.consent_enforcement_enabled,
            consent_default_consent = s.consent_default_consent,
            consent_analytics_domain_count = s.consent_analytics_domain_count,
            consent_user_profile_count = s.consent_user_profile_count,
            "policy engine initialized"
        );
        engine
    };

    if let Some(path) = args.policy_config_file.as_ref() {
        if args.policy_reload_interval_secs > 0 {
            let interval = Duration::from_secs(args.policy_reload_interval_secs);
            let engine_for_task = Arc::clone(&policy_engine);
            let path_for_task = path.clone();
            let mode_override = args.policy_mode;
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                let mut last_mtime: Option<SystemTime> = None;
                loop {
                    ticker.tick().await;
                    let prev_mtime = last_mtime;
                    let engine_for_blocking = Arc::clone(&engine_for_task);
                    let path_for_blocking = path_for_task.clone();
                    let res = tokio::task::spawn_blocking(
                        move || -> io::Result<(Option<SystemTime>, bool)> {
                            let meta = fs::metadata(&path_for_blocking)?;
                            let mtime = meta.modified().ok();
                            if mtime.is_some() && mtime == prev_mtime {
                                return Ok((prev_mtime, false));
                            }
                            let _summary = engine_for_blocking
                                .replace_from_file(&path_for_blocking, mode_override)?;
                            Ok((mtime, true))
                        },
                    )
                    .await;

                    match res {
                        Ok(Ok((new_mtime, true))) => {
                            last_mtime = new_mtime;
                            let s = engine_for_task.summary();
                            info!(
                                event = "policy_reload_applied",
                                policy_config_file = %path_for_task.display(),
                                policy_version = s.version,
                                policy_mode = s.mode.as_str(),
                                tracker_set_cookie_enabled = s.tracker_rule_enabled,
                                tracker_domain_count = s.tracker_domain_count,
                                consent_enforcement_enabled = s.consent_enforcement_enabled,
                                consent_default_consent = s.consent_default_consent,
                                consent_user_profile_count = s.consent_user_profile_count,
                                "policy config reloaded"
                            );
                        }
                        Ok(Ok((new_mtime, false))) => {
                            last_mtime = new_mtime;
                        }
                        Ok(Err(e)) => {
                            warn!(
                                event = "policy_reload_failed",
                                policy_config_file = %path_for_task.display(),
                                error = %e,
                                "policy config reload failed (keeping last good config)"
                            );
                        }
                        Err(e) => {
                            warn!(
                                event = "policy_reload_task_failed",
                                policy_config_file = %path_for_task.display(),
                                error = %e,
                                "policy reload task failed"
                            );
                        }
                    }
                }
            });
        } else {
            info!("Policy reload disabled");
        }
    }

    // --- Filter list rules (ABP / EasyList) ---
    let mut filter_list_sources: Vec<filter_list::FilterListSource> = Vec::new();
    for path in &args.filter_list_file {
        filter_list_sources.push(filter_list::FilterListSource::local_file(
            path.display().to_string(),
        ));
    }
    for url in &args.filter_list_url {
        filter_list_sources.push(filter_list::FilterListSource::url(url.clone()));
    }
    if let Some(path) = args.policy_config_file.as_ref() {
        match policy::parse_filter_list_sources_from_config(path) {
            Ok(mut sources_from_config) => {
                if !sources_from_config.is_empty() {
                    info!(
                        event = "filter_list_sources_from_policy",
                        policy_config_file = %path.display(),
                        count = sources_from_config.len(),
                        "loaded filter list sources from policy config"
                    );
                }
                filter_list_sources.append(&mut sources_from_config);
            }
            Err(e) => {
                warn!(
                    event = "filter_list_sources_parse_failed",
                    policy_config_file = %path.display(),
                    error = %e,
                    "failed to parse filter list sources from policy config"
                );
            }
        }
    }

    if filter_list_sources.is_empty() {
        info!("Filter list integration disabled (no sources configured)");
    } else {
        let download_timeout = Duration::from_secs(args.filter_list_download_timeout_secs);
        metrics.inc_filter_list_refresh_total();
        match filter_list::refresh_filter_lists(
            &filter_list_sources,
            &args.filter_list_cache_dir,
            download_timeout,
        )
        .await
        {
            Ok(rules) => {
                let active_count = rules.block_domains.len()
                    + rules.tracker_script_patterns.len()
                    + rules.cosmetic_selectors.len();
                metrics.set_filter_list_rules_active(active_count as u64);
                policy_engine.replace_filter_list_rules(rules);

                let st = policy_engine.filter_list_stats();
                info!(
                    event = "filter_list_loaded",
                    cache_dir = %args.filter_list_cache_dir.display(),
                    sources_loaded = st.source_count,
                    total_lines = st.total_lines,
                    domain_blocks = st.domain_blocks,
                    url_patterns = st.url_patterns,
                    cosmetic_global = st.cosmetic_global,
                    cosmetic_domain_scoped = st.cosmetic_domain_scoped,
                    exceptions = st.exceptions,
                    skipped_unsupported = st.skipped_unsupported,
                    skipped_comments = st.skipped_comments,
                    "filter list rules loaded"
                );

                if args.filter_list_refresh_secs > 0 {
                    filter_list::spawn_refresh_task(
                        Arc::clone(&policy_engine),
                        filter_list_sources,
                        args.filter_list_cache_dir.clone(),
                        Duration::from_secs(args.filter_list_refresh_secs),
                        download_timeout,
                        Arc::clone(&metrics),
                    );
                    info!(
                        event = "filter_list_refresh_task_spawned",
                        refresh_secs = args.filter_list_refresh_secs,
                        "filter list refresh task spawned"
                    );
                } else {
                    info!("Filter list refresh disabled");
                }
            }
            Err(e) => {
                metrics.inc_filter_list_refresh_failed_total();
                warn!(
                    event = "filter_list_load_failed",
                    cache_dir = %args.filter_list_cache_dir.display(),
                    error = %e,
                    "filter list load failed (continuing with empty rules)"
                );
            }
        }
    }

    let pinned_hosts = Arc::new(host_store::PinnedHosts::load(&args.pinned_hosts_file)?);
    info!(
        "Loaded {} pinned hosts from {}",
        pinned_hosts.len()?,
        pinned_hosts.path().display()
    );

    let receipts_store = if let Some(path) = args.receipts_file.as_ref() {
        let store = Arc::new(receipts::ReceiptStore::load(path)?);
        info!(
            event = "receipts_initialized",
            receipts_file = %store.path().display(),
            "privacy receipts enabled"
        );
        Some(store)
    } else {
        info!("Privacy receipts disabled");
        None
    };
    let mitm_engine = if args.enable_mitm {
        info!(
            tls_profile = args.tls_profile.as_str(),
            tls_profile_details = args.tls_profile.describe(),
            "MITM mode enabled for non-pinned TLS hosts"
        );
        let ca_cfg = mitm::CaFilesConfig {
            cert_path: args.mitm_ca_cert_file.clone(),
            key_path: args.mitm_ca_key_file.clone(),
            generate_if_missing: args.mitm_ca_generate_if_missing,
        };
        let cert_log = if let Some(ref path) = args.cert_log_file {
            let log = mitm::CertLog::open(path)
                .map_err(|e| io::Error::other(format!("cert log open failed: {e}")))?;
            info!(cert_log_file = %path.display(), "MITM certificate transparency log enabled");
            Some(Arc::new(log))
        } else {
            None
        };
        let cert_pin_db = if let Some(ref path) = args.cert_pin_file {
            let db = cert_pin::CertPinDb::load(path)?;
            info!(cert_pin_file = %path.display(), pins = db.len()?, "TOFU cert pin database loaded");
            Some(Arc::new(db))
        } else {
            None
        };
        let engine = mitm::MitmEngine::new(Some(&ca_cfg), args.tls_profile, cert_log, cert_pin_db)
            .map_err(io::Error::other)?;
        match engine.ca_init_mode() {
            mitm::CaInitMode::LoadedFromFiles => {
                info!(
                    "MITM CA loaded from cert='{}' key='{}'",
                    ca_cfg.cert_path.display(),
                    ca_cfg.key_path.display()
                );
            }
            mitm::CaInitMode::GeneratedAndPersisted => {
                warn!(
                    "MITM CA generated and persisted to cert='{}' key='{}'",
                    ca_cfg.cert_path.display(),
                    ca_cfg.key_path.display()
                );
            }
            mitm::CaInitMode::GeneratedEphemeral => {
                warn!("MITM CA generated ephemerally (not persisted)");
            }
        }
        if let Some(export_path) = args.mitm_ca_export_cert_file.as_ref() {
            engine
                .export_ca_cert_pem(export_path)
                .map_err(io::Error::other)?;
            info!("Exported MITM CA certificate to {}", export_path.display());
        }
        Some(Arc::new(engine))
    } else {
        info!("MITM mode disabled (tunnel-only mode)");
        None
    };

    let bind_target = format!("{}:{}", args.listen_host, args.listen_port);
    let bind_addr = bind_target.to_socket_addrs()?.next().ok_or_else(|| {
        io::Error::new(ErrorKind::InvalidInput, "Could not resolve listen address")
    })?;
    let listener = TcpListener::bind(bind_addr).await?;

    info!(
        "🛡️ Privacy Engine (Rust) listening on {}",
        listener.local_addr()?
    );

    if args.metrics_log_interval_secs > 0 {
        let interval = Duration::from_secs(args.metrics_log_interval_secs);
        let metrics_for_task = Arc::clone(&metrics);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                metrics_for_task.log_snapshot("periodic");
            }
        });
    } else {
        info!("Periodic metrics logging disabled");
    }

    if let Some(store) = receipts_store.as_ref() {
        if args.receipts_flush_interval_secs > 0 {
            let interval = Duration::from_secs(args.receipts_flush_interval_secs);
            let store_for_task = Arc::clone(store);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                loop {
                    ticker.tick().await;
                    let store_for_blocking = Arc::clone(&store_for_task);
                    let res =
                        tokio::task::spawn_blocking(move || store_for_blocking.flush_if_dirty())
                            .await;
                    match res {
                        Ok(Ok(true)) => {
                            info!(
                                event = "receipts_flushed",
                                receipts_file = %store_for_task.path().display(),
                                "privacy receipts flushed"
                            );
                        }
                        Ok(Ok(false)) => {}
                        Ok(Err(e)) => {
                            warn!(
                                event = "receipts_flush_error",
                                receipts_file = %store_for_task.path().display(),
                                error = %e,
                                "privacy receipts flush failed"
                            );
                        }
                        Err(e) => {
                            warn!(
                                event = "receipts_flush_task_error",
                                receipts_file = %store_for_task.path().display(),
                                error = %e,
                                "privacy receipts flush task failed"
                            );
                        }
                    }
                }
            });
        } else {
            info!("Periodic receipts flushing disabled");
        }
    }

    let doh_stats = if args.doh_server_port.is_some() {
        Some(Arc::new(dns_filter::DohStats::default()))
    } else {
        None
    };

    if let Some(port) = args.dashboard_port {
        let dash_addr: SocketAddr = format!("127.0.0.1:{port}").parse().map_err(|e| {
            io::Error::new(ErrorKind::InvalidInput, format!("bad dashboard port: {e}"))
        })?;
        let dash_metrics = Arc::clone(&metrics);
        let dash_policy = Arc::clone(&policy_engine);
        let dash_receipts = receipts_store.clone();
        let dash_pinned_hosts = Arc::clone(&pinned_hosts);
        let dash_options = dashboard::DashboardOptions {
            doh_stats: doh_stats.clone(),
            mitm_ca_export_cert_file: args.mitm_ca_export_cert_file.clone(),
            auto_pin_grace_period_secs: AUTO_PIN_GRACE_PERIOD_SECS,
        };
        tokio::spawn(async move {
            dashboard::run(
                dash_addr,
                dash_metrics,
                dash_policy,
                dash_receipts,
                dash_pinned_hosts,
                dash_options,
            )
            .await;
        });
    }

    if args.enable_dns_filter {
        let dns_listen_addr: SocketAddr =
            format!("{}:{}", args.dns_listen_host, args.dns_listen_port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::InvalidInput,
                        "Could not resolve DNS listen address",
                    )
                })?;
        let dns_upstream_addr: SocketAddr =
            args.dns_upstream.to_socket_addrs()?.next().ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidInput,
                    "Could not resolve DNS upstream address",
                )
            })?;
        let dns_config = dns_filter::DnsFilterConfig {
            listen_addr: dns_listen_addr,
            upstream_addr: dns_upstream_addr,
            upstream_doh: args.dns_upstream_doh.clone(),
            policy_engine: Arc::clone(&policy_engine),
            metrics: Arc::clone(&metrics),
            receipts_store: receipts_store.clone(),
        };
        tokio::spawn(async move {
            dns_filter::run_dns_filter(dns_config).await;
        });
        if let Some(doh) = &args.dns_upstream_doh {
            info!(
                event = "dns_filter_enabled",
                dns_listen = %format!("{}:{}", args.dns_listen_host, args.dns_listen_port),
                dns_upstream_doh = %doh,
                "DNS pre-filter task spawned (DoH)"
            );
        } else {
            info!(
                event = "dns_filter_enabled",
                dns_listen = %format!("{}:{}", args.dns_listen_host, args.dns_listen_port),
                dns_upstream = %args.dns_upstream,
                "DNS pre-filter task spawned (UDP)"
            );
        }
    } else {
        info!("DNS pre-filter disabled");
    }

    if let Some(port) = args.doh_server_port {
        let addr: SocketAddr = format!("0.0.0.0:{port}").parse().map_err(|e| {
            io::Error::new(ErrorKind::InvalidInput, format!("bad DoH server port: {e}"))
        })?;

        let cert_path = args
            .doh_server_cert_file
            .unwrap_or_else(|| args.mitm_ca_cert_file.clone());
        let key_path = args
            .doh_server_key_file
            .unwrap_or_else(|| args.mitm_ca_key_file.clone());

        // We need to load these certs. Re-using mitm code or loading manually.
        // For simplicity, let's just use rustls-pemfile here since we need Vec<CertificateDer>.
        let certs = {
            let f = fs::File::open(&cert_path).map_err(|e| {
                io::Error::new(
                    ErrorKind::NotFound,
                    format!("failed to open DoH cert {}: {e}", cert_path.display()),
                )
            })?;
            let mut reader = io::BufReader::new(f);
            rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?
        };

        let key = {
            let f = fs::File::open(&key_path).map_err(|e| {
                io::Error::new(
                    ErrorKind::NotFound,
                    format!("failed to open DoH key {}: {e}", key_path.display()),
                )
            })?;
            let mut reader = io::BufReader::new(f);
            // Try pkcs8 first then rsa
            match rustls_pemfile::private_key(&mut reader)? {
                Some(k) => k,
                None => {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "no private key found in DoH key file",
                    )
                    .into())
                }
            }
        };

        let dns_upstream_addr: SocketAddr =
            args.dns_upstream.to_socket_addrs()?.next().ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidInput,
                    "Could not resolve DNS upstream address for DoH server",
                )
            })?;

        let doh_config = dns_filter::DohServerConfig {
            addr,
            cert: certs,
            key,
            upstream_addr: dns_upstream_addr,
            upstream_doh: args.dns_upstream_doh.clone(),
            stats: doh_stats
                .as_ref()
                .map(Arc::clone)
                .expect("doh stats must exist when doh server is enabled"),
            policy_engine: Arc::clone(&policy_engine),
            metrics: Arc::clone(&metrics),
            receipts_store: receipts_store.clone(),
        };

        tokio::spawn(async move {
            dns_filter::run_doh_server(doh_config).await;
        });
    }

    loop {
        let (mut client_stream, client_addr) = listener.accept().await?;
        let pinned_hosts = Arc::clone(&pinned_hosts);
        let mitm_engine = mitm_engine.clone();
        let metrics = Arc::clone(&metrics);
        let policy_engine = Arc::clone(&policy_engine);
        let receipts_store = receipts_store.clone();
        metrics.inc_connection_total();

        tokio::spawn(async move {
            match handle_connection(
                &mut client_stream,
                client_addr,
                &pinned_hosts,
                mitm_engine.as_deref(),
                metrics.as_ref(),
                policy_engine.as_ref(),
                receipts_store.as_deref(),
            )
            .await
            {
                Ok(()) => {
                    info!(
                        event = "connection_completed",
                        client_addr = %client_addr,
                        "connection handled"
                    );
                }
                Err(e) => {
                    error!(
                        event = "connection_error",
                        client_addr = %client_addr,
                        error = %e,
                        "connection error"
                    );
                }
            }
            metrics.log_snapshot("connection_end");
        });
    }
}

async fn handle_connection(
    client_stream: &mut TcpStream,
    client_addr: SocketAddr,
    pinned_hosts: &host_store::PinnedHosts,
    mitm_engine: Option<&mitm::MitmEngine>,
    metrics: &metrics::Metrics,
    policy_engine: &policy::PolicyEngine,
    receipts_store: Option<&receipts::ReceiptStore>,
) -> io::Result<()> {
    // Peek at incoming bytes to determine protocol mode.
    let mut buffer = [0u8; MAX_PEEK_BYTES];

    // peek() reads without consuming from the socket buffer.
    // The data remains available for the tunnel or interception logic.
    let n = client_stream.peek(&mut buffer).await?;

    if n == 0 {
        return Ok(()); // Connection closed
    }

    let peeked = &buffer[..n];

    // Explicit proxy mode: "CONNECT host:port HTTP/1.1"
    if starts_with_ascii_case_insensitive(peeked, b"CONNECT ") {
        info!(
            event = "protocol_detected",
            client_addr = %client_addr,
            mode = "explicit_connect",
            "protocol mode detected"
        );
        return handle_connect_tunnel(
            client_stream,
            client_addr,
            pinned_hosts,
            mitm_engine,
            metrics,
            policy_engine,
            receipts_store,
        )
        .await;
    }

    // Transparent mode fallback: parse SNI from TLS ClientHello
    if let Some(sni) = tls_parser::parse_sni(peeked) {
        let target_addr = format!("{}:443", sni);
        let normalized_sni = sni.to_ascii_lowercase();
        let host_is_pinned = pinned_hosts.contains(&normalized_sni)?;
        let decision = decide_tls_routing(host_is_pinned, mitm_engine.is_some());

        match decision {
            TlsRoutingDecision::AttemptMitm => {
                log_tls_routing_decision(
                    client_addr,
                    "transparent",
                    &normalized_sni,
                    &target_addr,
                    decision,
                    "host_not_pinned_and_mitm_enabled",
                    receipts_store,
                );
                if let Some(engine) = mitm_engine {
                    let ctx = MitmInterceptCtx {
                        client_addr,
                        flow: "transparent",
                        target_addr: &target_addr,
                        host: &normalized_sni,
                    };
                    let deps = MitmInterceptDeps {
                        pinned_hosts,
                        engine,
                        metrics,
                        policy_engine,
                        receipts_store,
                    };
                    return run_mitm_intercept(client_stream, ctx, deps).await;
                }
            }
            TlsRoutingDecision::Passthrough => {
                let reason = if host_is_pinned {
                    "host_is_pinned"
                } else {
                    "mitm_disabled"
                };
                log_tls_routing_decision(
                    client_addr,
                    "transparent",
                    &normalized_sni,
                    &target_addr,
                    decision,
                    reason,
                    receipts_store,
                );
                tunnel(client_stream, &target_addr, None, metrics).await?;
                return Ok(());
            }
        }
    }

    // Plain HTTP proxy request (GET http://..., POST http://..., etc.)
    if looks_like_http_request(peeked) {
        info!(
            event = "protocol_detected",
            client_addr = %client_addr,
            mode = "explicit_http_proxy",
            "protocol mode detected"
        );
        return handle_http_proxy(client_stream, client_addr, metrics).await;
    }

    warn!(
        event = "connection_rejected",
        client_addr = %client_addr,
        reason = "unclassified_traffic",
        "could not classify traffic (no CONNECT and no TLS SNI)"
    );
    Ok(())
}

async fn handle_connect_tunnel(
    client_stream: &mut TcpStream,
    client_addr: SocketAddr,
    pinned_hosts: &host_store::PinnedHosts,
    mitm_engine: Option<&mitm::MitmEngine>,
    metrics: &metrics::Metrics,
    policy_engine: &policy::PolicyEngine,
    receipts_store: Option<&receipts::ReceiptStore>,
) -> io::Result<()> {
    let (request_head, buffered_after_headers) = read_until_headers_complete(client_stream).await?;

    let request_line = first_request_line(&request_head).ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidData,
            "Malformed CONNECT request: missing request line",
        )
    })?;

    let target_addr = parse_connect_target(request_line).ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("Malformed CONNECT request line: {}", request_line),
        )
    })?;

    info!(
        "Connection from {}: CONNECT target parsed as {}",
        client_addr, target_addr
    );
    let has_early_tunnel_bytes = !buffered_after_headers.is_empty();
    let mut connect_host = None;
    let mut host_is_pinned = false;
    if let Some(host) = host_store::host_from_authority(&target_addr) {
        host_is_pinned = pinned_hosts.contains(&host)?;
        connect_host = Some(host.clone());
        let mut decision = decide_tls_routing(host_is_pinned, mitm_engine.is_some());
        let mut reason = if host_is_pinned {
            "host_is_pinned"
        } else if mitm_engine.is_some() {
            "host_not_pinned_and_mitm_enabled"
        } else {
            "mitm_disabled"
        };
        if decision == TlsRoutingDecision::AttemptMitm && has_early_tunnel_bytes {
            decision = TlsRoutingDecision::Passthrough;
            reason = "early_tunnel_bytes";
        }
        log_tls_routing_decision(
            client_addr,
            "connect",
            &host,
            &target_addr,
            decision,
            reason,
            receipts_store,
        );
    }

    if let (Some(engine), Some(host)) = (mitm_engine, connect_host.as_deref()) {
        if can_attempt_connect_mitm(host_is_pinned, true, has_early_tunnel_bytes) {
            client_stream
                .write_all(
                    b"HTTP/1.1 200 Connection established\r\n\
                      Proxy-Agent: privacy-engine-rust/0.1\r\n\
                      \r\n",
                )
                .await?;

            run_mitm_intercept(
                client_stream,
                MitmInterceptCtx {
                    client_addr,
                    flow: "connect",
                    target_addr: &target_addr,
                    host,
                },
                MitmInterceptDeps {
                    pinned_hosts,
                    engine,
                    metrics,
                    policy_engine,
                    receipts_store,
                },
            )
            .await?;
            return Ok(());
        }

        if has_early_tunnel_bytes
            && decide_tls_routing(host_is_pinned, true) == TlsRoutingDecision::AttemptMitm
        {
            warn!(
                event = "mitm_skipped",
                flow = "connect",
                client_addr = %client_addr,
                host = host,
                target_addr = target_addr,
                reason = "early_tunnel_bytes",
                "CONNECT had early tunnel bytes; using passthrough"
            );
        }
    }

    metrics.inc_passthrough_tunnel_total();
    match TcpStream::connect(&target_addr).await {
        Ok(mut server_stream) => {
            client_stream
                .write_all(
                    b"HTTP/1.1 200 Connection established\r\n\
                      Proxy-Agent: privacy-engine-rust/0.1\r\n\
                      \r\n",
                )
                .await?;

            // Some clients may already have sent early tunnel bytes in the same TCP frame.
            if !buffered_after_headers.is_empty() {
                server_stream.write_all(&buffered_after_headers).await?;
            }

            match tokio::io::copy_bidirectional(client_stream, &mut server_stream).await {
                Ok((sent, received)) => {
                    info!(
                        "CONNECT tunnel closed ({}). Sent: {} bytes, Received: {} bytes",
                        target_addr, sent, received
                    );
                }
                Err(e) => {
                    warn!("CONNECT tunnel error for {}: {}", target_addr, e);
                }
            }
            Ok(())
        }
        Err(e) => {
            warn!("Failed to connect CONNECT target {}: {}", target_addr, e);
            send_http_error(
                client_stream,
                "502 Bad Gateway",
                "Failed to connect to upstream target.",
            )
            .await?;
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsRoutingDecision {
    AttemptMitm,
    Passthrough,
}

impl TlsRoutingDecision {
    fn as_action(self) -> &'static str {
        match self {
            Self::AttemptMitm => "mitm",
            Self::Passthrough => "passthrough",
        }
    }
}

fn decide_tls_routing(host_is_pinned: bool, mitm_enabled: bool) -> TlsRoutingDecision {
    if !host_is_pinned && mitm_enabled {
        TlsRoutingDecision::AttemptMitm
    } else {
        TlsRoutingDecision::Passthrough
    }
}

fn can_attempt_connect_mitm(
    host_is_pinned: bool,
    mitm_enabled: bool,
    has_early_tunnel_bytes: bool,
) -> bool {
    !has_early_tunnel_bytes
        && decide_tls_routing(host_is_pinned, mitm_enabled) == TlsRoutingDecision::AttemptMitm
}

fn pin_host_after_tls_rejection(
    pinned_hosts: &host_store::PinnedHosts,
    host: &str,
) -> io::Result<bool> {
    pinned_hosts.add_and_persist(host)
}

fn log_tls_routing_decision(
    client_addr: SocketAddr,
    flow: &'static str,
    host: &str,
    target_addr: &str,
    decision: TlsRoutingDecision,
    reason: &'static str,
    receipts_store: Option<&receipts::ReceiptStore>,
) {
    if let Some(store) = receipts_store {
        store.record_tls_routing_decision(flow, host, decision.as_action(), reason);
    }
    info!(
        event = "tls_routing_decision",
        flow,
        client_addr = %client_addr,
        host = host,
        target_addr = target_addr,
        action = decision.as_action(),
        reason,
        "TLS routing decision"
    );
}

#[derive(Clone, Copy)]
struct MitmInterceptCtx<'a> {
    client_addr: SocketAddr,
    flow: &'static str,
    target_addr: &'a str,
    host: &'a str,
}

#[derive(Clone, Copy)]
struct MitmInterceptDeps<'a> {
    pinned_hosts: &'a host_store::PinnedHosts,
    engine: &'a mitm::MitmEngine,
    metrics: &'a metrics::Metrics,
    policy_engine: &'a policy::PolicyEngine,
    receipts_store: Option<&'a receipts::ReceiptStore>,
}

async fn run_mitm_intercept(
    client_stream: &mut TcpStream,
    ctx: MitmInterceptCtx<'_>,
    deps: MitmInterceptDeps<'_>,
) -> io::Result<()> {
    let _ = deps
        .policy_engine
        .on_mitm_session_start(ctx.flow, ctx.host, ctx.target_addr);
    deps.metrics.inc_mitm_attempt_total();
    if let Some(store) = deps.receipts_store {
        store.record_mitm_attempt(ctx.host);
    }
    let source_ip_str = ctx.client_addr.ip().to_string();
    match deps
        .engine
        .intercept_tls_tunnel(
            client_stream,
            ctx.target_addr,
            ctx.host,
            Some(source_ip_str.as_str()),
            deps.policy_engine,
            deps.receipts_store,
            deps.metrics,
        )
        .await
    {
        Ok(()) => {
            deps.metrics.inc_mitm_success_total();
            if let Some(store) = deps.receipts_store {
                store.record_mitm_success(ctx.host);
            }
            info!(
                event = "mitm_result",
                flow = ctx.flow,
                client_addr = %ctx.client_addr,
                host = ctx.host,
                target_addr = ctx.target_addr,
                outcome = "success",
                "MITM relay completed"
            );
            Ok(())
        }
        Err(e) => {
            if e.is_benign_peer_close() {
                deps.metrics.inc_mitm_success_total();
                if let Some(store) = deps.receipts_store {
                    store.record_mitm_success(ctx.host);
                }
                info!(
                    event = "mitm_result",
                    flow = ctx.flow,
                    client_addr = %ctx.client_addr,
                    host = ctx.host,
                    target_addr = ctx.target_addr,
                    outcome = "benign_peer_close",
                    error = %e,
                    "MITM relay closed normally"
                );
                return Ok(());
            }

            // Upstream TLS failure — since we now probe upstream BEFORE the client
            // TLS handshake, the client stream is still raw TCP. We can fall back
            // to passthrough transparently so the browser never sees an error.
            if e.is_upstream_tls_handshake_failure() {
                warn!(
                    event = "mitm_upstream_fallback",
                    flow = ctx.flow,
                    client_addr = %ctx.client_addr,
                    host = ctx.host,
                    target_addr = ctx.target_addr,
                    error = %e,
                    "upstream TLS failed, falling back to passthrough"
                );
                if deps
                    .pinned_hosts
                    .in_grace_period(Duration::from_secs(AUTO_PIN_GRACE_PERIOD_SECS))
                {
                    warn!(
                        event = "host_auto_pin_suppressed",
                        flow = ctx.flow,
                        client_addr = %ctx.client_addr,
                        host = ctx.host,
                        target_addr = ctx.target_addr,
                        pinned_hosts_file = %deps.pinned_hosts.path().display(),
                        grace_period_secs = AUTO_PIN_GRACE_PERIOD_SECS,
                        reason = "startup_grace_period",
                        reject_type = "upstream_tls_reject",
                        "suppressed auto-pin after upstream TLS rejection (startup grace period)"
                    );
                } else if pin_host_after_tls_rejection(deps.pinned_hosts, ctx.host)? {
                    deps.metrics.inc_host_auto_pinned_total();
                    if let Some(store) = deps.receipts_store {
                        store.record_host_auto_pinned(ctx.host);
                    }
                    info!(
                        event = "host_auto_pinned",
                        flow = ctx.flow,
                        client_addr = %ctx.client_addr,
                        host = ctx.host,
                        target_addr = ctx.target_addr,
                        pinned_hosts_file = %deps.pinned_hosts.path().display(),
                        reason = "upstream_tls_reject",
                        "auto-pinned host after upstream TLS failure"
                    );
                }
                // Fall back to passthrough — browser's TLS goes directly to the real server
                deps.metrics.inc_passthrough_tunnel_total();
                tunnel(client_stream, ctx.target_addr, None, deps.metrics).await?;
                return Ok(());
            }

            deps.metrics.inc_mitm_failure_total();
            if let Some(store) = deps.receipts_store {
                store.record_mitm_failure(ctx.host);
            }
            warn!(
                event = "mitm_result",
                flow = ctx.flow,
                client_addr = %ctx.client_addr,
                host = ctx.host,
                target_addr = ctx.target_addr,
                outcome = "failure",
                error = %e,
                "MITM attempt failed"
            );

            if e.is_client_tls_handshake_failure() {
                deps.metrics.inc_mitm_client_tls_reject_total();
                if let Some(store) = deps.receipts_store {
                    store.record_client_tls_reject(ctx.host);
                }
                if deps
                    .pinned_hosts
                    .in_grace_period(Duration::from_secs(AUTO_PIN_GRACE_PERIOD_SECS))
                {
                    warn!(
                        event = "host_auto_pin_suppressed",
                        flow = ctx.flow,
                        client_addr = %ctx.client_addr,
                        host = ctx.host,
                        target_addr = ctx.target_addr,
                        pinned_hosts_file = %deps.pinned_hosts.path().display(),
                        grace_period_secs = AUTO_PIN_GRACE_PERIOD_SECS,
                        reason = "startup_grace_period",
                        "suppressed auto-pin after client TLS rejection (startup grace period)"
                    );
                } else if pin_host_after_tls_rejection(deps.pinned_hosts, ctx.host)? {
                    deps.metrics.inc_host_auto_pinned_total();
                    if let Some(store) = deps.receipts_store {
                        store.record_host_auto_pinned(ctx.host);
                    }
                    warn!(
                        event = "host_auto_pinned",
                        flow = ctx.flow,
                        client_addr = %ctx.client_addr,
                        host = ctx.host,
                        target_addr = ctx.target_addr,
                        pinned_hosts_file = %deps.pinned_hosts.path().display(),
                        reason = "client_tls_reject",
                        "added host to pinned list after TLS rejection"
                    );
                }
            }
            Ok(())
        }
    }
}

async fn handle_http_proxy(
    client_stream: &mut TcpStream,
    client_addr: SocketAddr,
    _metrics: &metrics::Metrics,
) -> io::Result<()> {
    let (request_head, body_after_headers) = read_until_headers_complete(client_stream).await?;

    let request_line = first_request_line(&request_head)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "Malformed HTTP proxy request"))?;

    // Parse: "GET http://host/path HTTP/1.1"
    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() < 3 {
        send_http_error(client_stream, "400 Bad Request", "Malformed request line.").await?;
        return Ok(());
    }
    let method = parts[0];
    let full_url = parts[1];
    let http_version = parts[2];

    // Extract host and path from absolute URL
    let url_without_scheme = if let Some(rest) = full_url.strip_prefix("http://") {
        rest
    } else {
        // Not an absolute HTTP URL — reject
        send_http_error(
            client_stream,
            "400 Bad Request",
            "Only absolute HTTP URLs are supported for plain HTTP proxy.",
        )
        .await?;
        return Ok(());
    };

    let (host_port, path) = match url_without_scheme.find('/') {
        Some(idx) => (&url_without_scheme[..idx], &url_without_scheme[idx..]),
        None => (url_without_scheme, "/"),
    };

    let target_addr = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };

    info!(
        event = "http_proxy_request",
        client_addr = %client_addr,
        method = method,
        host = host_port,
        path = path,
        target_addr = %target_addr,
        "forwarding plain HTTP proxy request"
    );

    // Rewrite request line to relative path
    let rewritten_request_line = format!("{method} {path} {http_version}");
    let headers_str = String::from_utf8_lossy(&request_head);
    let first_crlf = headers_str.find("\r\n").unwrap_or(headers_str.len());
    let remaining_headers = &request_head[first_crlf..];
    let mut rewritten_request =
        Vec::with_capacity(rewritten_request_line.len() + remaining_headers.len());
    rewritten_request.extend_from_slice(rewritten_request_line.as_bytes());
    rewritten_request.extend_from_slice(remaining_headers);

    // Connect upstream and forward
    match TcpStream::connect(&target_addr).await {
        Ok(mut server_stream) => {
            server_stream.write_all(&rewritten_request).await?;
            if !body_after_headers.is_empty() {
                server_stream.write_all(&body_after_headers).await?;
            }
            match tokio::io::copy_bidirectional(client_stream, &mut server_stream).await {
                Ok((sent, received)) => {
                    info!(
                        event = "http_proxy_completed",
                        client_addr = %client_addr,
                        host = host_port,
                        sent_bytes = sent,
                        received_bytes = received,
                        "HTTP proxy request completed"
                    );
                }
                Err(e) => {
                    warn!(
                        event = "http_proxy_error",
                        client_addr = %client_addr,
                        host = host_port,
                        error = %e,
                        "HTTP proxy tunnel error"
                    );
                }
            }
            Ok(())
        }
        Err(e) => {
            warn!(
                event = "http_proxy_connect_failed",
                client_addr = %client_addr,
                target_addr = %target_addr,
                error = %e,
                "failed to connect to HTTP proxy target"
            );
            send_http_error(
                client_stream,
                "502 Bad Gateway",
                "Failed to connect to upstream target.",
            )
            .await?;
            Ok(())
        }
    }
}

async fn tunnel(
    client_stream: &mut TcpStream,
    target_addr: &str,
    initial_client_bytes: Option<&[u8]>,
    metrics: &metrics::Metrics,
) -> io::Result<()> {
    metrics.inc_passthrough_tunnel_total();
    match TcpStream::connect(target_addr).await {
        Ok(mut server_stream) => {
            if let Some(buf) = initial_client_bytes {
                if !buf.is_empty() {
                    server_stream.write_all(buf).await?;
                }
            }

            match tokio::io::copy_bidirectional(client_stream, &mut server_stream).await {
                Ok((sent, received)) => {
                    info!(
                        "Tunnel closed ({}). Sent: {} bytes, Received: {} bytes",
                        target_addr, sent, received
                    );
                }
                Err(e) => {
                    warn!("Tunnel error for {}: {}", target_addr, e);
                }
            }
            Ok(())
        }
        Err(e) => {
            warn!("Failed to connect to target {}: {}", target_addr, e);
            Err(e)
        }
    }
}

async fn read_until_headers_complete(
    client_stream: &mut TcpStream,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    loop {
        let n = client_stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "Client disconnected before CONNECT headers completed",
            ));
        }

        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_CONNECT_HEADER_BYTES {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "CONNECT headers exceed maximum allowed size",
            ));
        }

        if let Some(headers_end) = find_headers_end(&buf) {
            let buffered_after_headers = buf.split_off(headers_end);
            return Ok((buf, buffered_after_headers));
        }
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

fn first_request_line(buf: &[u8]) -> Option<&str> {
    let line_end = buf.windows(2).position(|w| w == b"\r\n")?;
    std::str::from_utf8(&buf[..line_end]).ok()
}

fn parse_connect_target(request_line: &str) -> Option<String> {
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let authority = parts.next()?;
    let _http_version = parts.next()?;

    if parts.next().is_some() {
        return None;
    }
    if !method.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    if authority.is_empty() || authority.contains('/') {
        return None;
    }

    normalize_authority(authority)
}

fn normalize_authority(authority: &str) -> Option<String> {
    if authority.is_empty() || authority.contains('/') {
        return None;
    }

    // Bracketed IPv6 authority: [::1] or [::1]:443
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = &authority[..=end];
        let rest = &authority[end + 1..];
        return if rest.is_empty() {
            Some(format!("{host}:443"))
        } else if let Some(port) = rest.strip_prefix(':') {
            let parsed_port: u16 = port.parse().ok()?;
            Some(format!("{host}:{parsed_port}"))
        } else {
            None
        };
    }

    // Hostname / IPv4 with optional port.
    if let Some((host, port)) = authority.rsplit_once(':') {
        if host.is_empty() || port.is_empty() || host.contains(':') {
            return None;
        }
        let parsed_port: u16 = port.parse().ok()?;
        return Some(format!("{host}:{parsed_port}"));
    }

    Some(format!("{authority}:443"))
}

fn starts_with_ascii_case_insensitive(buf: &[u8], prefix: &[u8]) -> bool {
    if buf.len() < prefix.len() {
        return false;
    }
    buf[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn looks_like_http_request(buf: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"PATCH ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"TRACE ",
        b"CONNECT ",
    ];
    METHODS
        .iter()
        .any(|m| starts_with_ascii_case_insensitive(buf, m))
}

async fn send_http_error(
    client_stream: &mut TcpStream,
    status: &str,
    message: &str,
) -> io::Result<()> {
    let body = format!("{message}\n");
    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );
    client_stream.write_all(response.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file(name: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}_{ts}.json"))
    }

    #[test]
    fn parse_connect_target_with_port() {
        let line = "CONNECT google.com:443 HTTP/1.1";
        assert_eq!(
            parse_connect_target(line),
            Some("google.com:443".to_string())
        );
    }

    #[test]
    fn parse_connect_target_without_port_defaults_to_443() {
        let line = "CONNECT google.com HTTP/1.1";
        assert_eq!(
            parse_connect_target(line),
            Some("google.com:443".to_string())
        );
    }

    #[test]
    fn parse_connect_target_rejects_bad_method() {
        let line = "GET google.com:443 HTTP/1.1";
        assert_eq!(parse_connect_target(line), None);
    }

    #[test]
    fn parse_connect_target_rejects_path_target() {
        let line = "CONNECT https://google.com/ HTTP/1.1";
        assert_eq!(parse_connect_target(line), None);
    }

    #[test]
    fn parse_connect_target_rejects_non_numeric_port() {
        let line = "CONNECT google.com:abc HTTP/1.1";
        assert_eq!(parse_connect_target(line), None);
    }

    #[test]
    fn parse_connect_target_accepts_bracketed_ipv6() {
        let line = "CONNECT [::1]:8443 HTTP/1.1";
        assert_eq!(parse_connect_target(line), Some("[::1]:8443".to_string()));
    }

    #[test]
    fn find_headers_end_works() {
        let data = b"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\ntail";
        assert_eq!(find_headers_end(data), Some(39));
    }

    #[test]
    fn first_request_line_works() {
        let data = b"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n";
        assert_eq!(first_request_line(data), Some("CONNECT a:443 HTTP/1.1"));
    }

    #[test]
    fn decide_tls_routing_prefers_mitm_for_non_pinned_hosts() {
        assert_eq!(
            decide_tls_routing(false, true),
            TlsRoutingDecision::AttemptMitm
        );
    }

    #[test]
    fn decide_tls_routing_prefers_passthrough_for_pinned_hosts() {
        assert_eq!(
            decide_tls_routing(true, true),
            TlsRoutingDecision::Passthrough
        );
    }

    #[test]
    fn decide_tls_routing_passthrough_when_mitm_disabled() {
        assert_eq!(
            decide_tls_routing(false, false),
            TlsRoutingDecision::Passthrough
        );
    }

    #[test]
    fn connect_mitm_is_skipped_when_early_tunnel_bytes_exist() {
        assert!(!can_attempt_connect_mitm(false, true, true));
    }

    #[test]
    fn connect_mitm_is_allowed_without_early_tunnel_bytes() {
        assert!(can_attempt_connect_mitm(false, true, false));
    }

    #[test]
    fn connect_mitm_is_blocked_for_pinned_host() {
        assert!(!can_attempt_connect_mitm(true, true, false));
    }

    #[test]
    fn mitm_to_autopin_to_passthrough_transition() {
        let path = temp_file("pinned_transition");
        let pinned_hosts = host_store::PinnedHosts::load(&path).expect("load");
        let host = "Example.COM";

        let initially_pinned = pinned_hosts.contains(host).expect("contains");
        assert_eq!(
            decide_tls_routing(initially_pinned, true),
            TlsRoutingDecision::AttemptMitm
        );

        assert!(
            pin_host_after_tls_rejection(&pinned_hosts, host).expect("persist pin"),
            "host should be newly pinned"
        );

        let now_pinned = pinned_hosts.contains(host).expect("contains after pin");
        assert!(now_pinned);
        assert_eq!(
            decide_tls_routing(now_pinned, true),
            TlsRoutingDecision::Passthrough
        );

        let json = fs::read_to_string(&path).expect("read pinned file");
        assert!(json.contains("example.com"));
    }
}
