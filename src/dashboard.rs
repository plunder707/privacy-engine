use crate::{dns_filter, host_store, metrics, policy, receipts};
use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;
use std::fmt::Write;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

/// Shared state available to every dashboard request handler.
struct DashboardState {
    metrics: Arc<metrics::Metrics>,
    doh_stats: Option<Arc<dns_filter::DohStats>>,
    policy_engine: Arc<policy::PolicyEngine>,
    receipts_store: Option<Arc<receipts::ReceiptStore>>,
    pinned_hosts: Arc<host_store::PinnedHosts>,
    mitm_ca_export_cert_file: Option<PathBuf>,
    auto_pin_grace_period_secs: u64,
    admin_token: String,
    start_time: SystemTime,
}

#[derive(Clone)]
pub struct DashboardOptions {
    pub doh_stats: Option<Arc<dns_filter::DohStats>>,
    pub mitm_ca_export_cert_file: Option<PathBuf>,
    pub auto_pin_grace_period_secs: u64,
}

fn make_admin_token() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    if rng.fill(&mut bytes).is_err() {
        // Extremely unlikely; avoid hard-failing the dashboard on RNG issues.
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        return format!("insecure-{ts}");
    }
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

/// Start the dashboard HTTP server. Call from a tokio::spawn.
pub async fn run(
    addr: SocketAddr,
    metrics: Arc<metrics::Metrics>,
    policy_engine: Arc<policy::PolicyEngine>,
    receipts_store: Option<Arc<receipts::ReceiptStore>>,
    pinned_hosts: Arc<host_store::PinnedHosts>,
    options: DashboardOptions,
) {
    let state = Arc::new(DashboardState {
        metrics,
        doh_stats: options.doh_stats,
        policy_engine,
        receipts_store,
        pinned_hosts,
        mitm_ca_export_cert_file: options.mitm_ca_export_cert_file,
        auto_pin_grace_period_secs: options.auto_pin_grace_period_secs,
        admin_token: make_admin_token(),
        start_time: SystemTime::now(),
    });

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(event = "dashboard_bind_error", addr = %addr, error = %e, "failed to bind dashboard listener");
            return;
        }
    };
    info!(event = "dashboard_started", addr = %addr, "dashboard listening");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!(event = "dashboard_accept_error", error = %e);
                continue;
            }
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let state = Arc::clone(&state);
                async move { handle_request(req, &state) }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                // Connection reset / broken pipe is normal for browsers
                let msg = e.to_string();
                if !msg.contains("connection reset") && !msg.contains("broken pipe") {
                    warn!(event = "dashboard_conn_error", error = %e);
                }
            }
        });
    }
}

fn handle_request<B>(
    req: Request<B>,
    state: &DashboardState,
) -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => serve_html(),
        (&Method::GET, "/api/metrics") => serve_metrics(state),
        (&Method::GET, "/api/doh") => serve_doh(state),
        (&Method::GET, "/api/receipts") => serve_receipts(state),
        (&Method::GET, "/api/status") => serve_status(state),
        (&Method::GET, "/download/ca.crt") => serve_ca_cert_pem(state),
        (&Method::POST, "/api/pins/reset") => serve_pins_reset(req.headers(), state),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(r#"{"error":"not_found"}"#))),
    }
}

fn json_response_with_status(
    status: StatusCode,
    value: serde_json::Value,
) -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    let body = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-cache")
        .body(Full::new(Bytes::from(body)))
}

fn json_response(value: serde_json::Value) -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    json_response_with_status(StatusCode::OK, value)
}

fn serve_metrics(state: &DashboardState) -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    let s = state.metrics.snapshot();
    let doh = state
        .doh_stats
        .as_ref()
        .map(|stats| stats.snapshot(dns_filter::DOH_TOP_CLIENTS_DEFAULT));
    json_response(json!({
        "connection_total": s.connection_total,
        "passthrough_tunnel_total": s.passthrough_tunnel_total,
        "mitm_attempt_total": s.mitm_attempt_total,
        "mitm_success_total": s.mitm_success_total,
        "mitm_failure_total": s.mitm_failure_total,
        "mitm_client_tls_reject_total": s.mitm_client_tls_reject_total,
        "host_auto_pinned_total": s.host_auto_pinned_total,
        "dns_query_total": s.dns_query_total,
        "dns_blocked_total": s.dns_blocked_total,
        "dns_report_only_total": s.dns_report_only_total,
        "body_rewrite_total": s.body_rewrite_total,
        "body_rewrite_skipped_total": s.body_rewrite_skipped_total,
        "filter_list_refresh_total": s.filter_list_refresh_total,
        "filter_list_refresh_failed_total": s.filter_list_refresh_failed_total,
        "filter_list_rules_active": s.filter_list_rules_active,
        "dns_cname_uncloaked_total": s.dns_cname_uncloaked_total,
        "consent_enforcement_blocked_total": s.consent_enforcement_blocked_total,
        "websocket_blocked_total": s.websocket_blocked_total,
        "referer_spoofed_total": s.referer_spoofed_total,
        "cert_pin_violation_total": s.cert_pin_violation_total,
        "query_params_stripped_total": s.query_params_stripped_total,
        "cache_headers_stripped_total": s.cache_headers_stripped_total,
        "doh_query_total": doh.as_ref().map(|x| x.doh_query_total).unwrap_or(0),
        "doh_unique_client_total": doh.as_ref().map(|x| x.doh_unique_client_total).unwrap_or(0),
    }))
}

fn serve_doh(state: &DashboardState) -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    if let Some(stats) = state.doh_stats.as_ref() {
        let snap = stats.snapshot(dns_filter::DOH_TOP_CLIENTS_DEFAULT);
        let top_clients: Vec<serde_json::Value> = snap
            .top_clients
            .into_iter()
            .map(|c| {
                json!({
                    "client_ip": c.client_ip,
                    "query_total": c.query_total,
                    "last_seen_unix": c.last_seen_unix,
                })
            })
            .collect();
        return json_response(json!({
            "enabled": true,
            "doh_query_total": snap.doh_query_total,
            "doh_unique_client_total": snap.doh_unique_client_total,
            "top_clients": top_clients,
        }));
    }
    json_response(json!({
        "enabled": false,
        "doh_query_total": 0,
        "doh_unique_client_total": 0,
        "top_clients": [],
    }))
}

fn serve_receipts(state: &DashboardState) -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    let hosts = state
        .receipts_store
        .as_ref()
        .map(|s| s.hosts_as_json())
        .unwrap_or_else(|| json!({}));
    json_response(json!({ "hosts": hosts }))
}

fn serve_status(state: &DashboardState) -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    let uptime_secs = state.start_time.elapsed().map(|d| d.as_secs()).unwrap_or(0);
    let summary = state.policy_engine.summary();
    let pinned_hosts_count = match state.pinned_hosts.len() {
        Ok(n) => n,
        Err(e) => {
            warn!(event = "pinned_hosts_len_error", error = %e);
            0
        }
    };
    let grace_period = Duration::from_secs(state.auto_pin_grace_period_secs);
    let grace_active = state.pinned_hosts.in_grace_period(grace_period);
    let grace_elapsed_secs = state.pinned_hosts.age().as_secs();
    let grace_remaining_secs = state
        .auto_pin_grace_period_secs
        .saturating_sub(grace_elapsed_secs);
    let (ca_export_path, ca_export_exists) = match state.mitm_ca_export_cert_file.as_ref() {
        Some(p) => (Some(p.display().to_string()), p.exists()),
        None => (None, false),
    };
    let doh = state
        .doh_stats
        .as_ref()
        .map(|stats| stats.snapshot(dns_filter::DOH_TOP_CLIENTS_DEFAULT));
    json_response(json!({
        "uptime_secs": uptime_secs,
        "policy_mode": format!("{:?}", summary.mode),
        "policy_version": summary.version,
        "tracker_rule_enabled": summary.tracker_rule_enabled,
        "tracker_domain_count": summary.tracker_domain_count,
        "dns_block_enabled": summary.dns_block_enabled,
        "dns_block_domain_count": summary.dns_block_domain_count,
        "consent_enforcement_enabled": summary.consent_enforcement_enabled,
        "consent_default_consent": summary.consent_default_consent,
        "consent_analytics_domain_count": summary.consent_analytics_domain_count,
        "consent_user_profile_count": summary.consent_user_profile_count,
        "pinned_hosts_file": state.pinned_hosts.path().display().to_string(),
        "pinned_hosts_count": pinned_hosts_count,
        "auto_pin_grace_period_secs": state.auto_pin_grace_period_secs,
        "auto_pin_grace_active": grace_active,
        "auto_pin_grace_elapsed_secs": grace_elapsed_secs,
        "auto_pin_grace_remaining_secs": grace_remaining_secs,
        "mitm_ca_export_cert_file": ca_export_path,
        "mitm_ca_export_cert_exists": ca_export_exists,
        "doh_server_enabled": state.doh_stats.is_some(),
        "doh_query_total": doh.as_ref().map(|x| x.doh_query_total).unwrap_or(0),
        "doh_unique_client_total": doh.as_ref().map(|x| x.doh_unique_client_total).unwrap_or(0),
        "admin_token": state.admin_token,
    }))
}

fn serve_ca_cert_pem(state: &DashboardState) -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    let Some(path) = state.mitm_ca_export_cert_file.as_ref() else {
        return json_response_with_status(
            StatusCode::NOT_FOUND,
            json!({"error":"ca_export_not_configured"}),
        );
    };
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            return json_response_with_status(
                StatusCode::NOT_FOUND,
                json!({"error":"ca_export_missing","path":path.display().to_string(),"detail":e.to_string()}),
            );
        }
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-x509-ca-cert")
        .header("Cache-Control", "no-cache")
        .header(
            "Content-Disposition",
            "attachment; filename=\"privacy-engine-ca.crt\"",
        )
        .body(Full::new(Bytes::from(bytes)))
}

fn serve_pins_reset(
    headers: &hyper::header::HeaderMap,
    state: &DashboardState,
) -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    let token = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if token != state.admin_token {
        return json_response_with_status(StatusCode::FORBIDDEN, json!({"error":"forbidden"}));
    }

    match state.pinned_hosts.clear_and_persist() {
        Ok(removed) => json_response(json!({"ok":true,"removed":removed})),
        Err(e) => {
            warn!(event = "pins_reset_failed", error = %e);
            json_response_with_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error":"pins_reset_failed"}),
            )
        }
    }
}

fn serve_html() -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-cache")
        .body(Full::new(Bytes::from(DASHBOARD_HTML)))
}

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Privacy Engine Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0f1117;--surface:#1a1d27;--border:#2a2d3a;--text:#e1e4ed;--dim:#7a7f94;
--accent:#6c63ff;--green:#22c55e;--red:#ef4444;--amber:#f59e0b;--blue:#3b82f6;--cyan:#06b6d4}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
background:var(--bg);color:var(--text);line-height:1.5;min-height:100vh}
header{background:var(--surface);border-bottom:1px solid var(--border);padding:1rem 2rem;
display:flex;align-items:center;justify-content:space-between}
header h1{font-size:1.25rem;font-weight:600;letter-spacing:-.02em}
header h1 span{color:var(--accent);font-weight:700}
.status-bar{display:flex;gap:1.5rem;align-items:center;font-size:.8rem;color:var(--dim)}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--green);display:inline-block;
margin-right:4px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
main{max-width:1400px;margin:0 auto;padding:1.5rem}
.setup{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1rem 1.25rem;margin-bottom:1rem}
.setup h2{font-size:.9rem;letter-spacing:.04em;text-transform:uppercase;color:var(--dim);margin-bottom:.5rem}
.setup-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.75rem}
.setup-item{font-size:.85rem;color:var(--text)}
.setup-item .label{color:var(--dim);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
.setup-actions{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.75rem}
.btn{border:1px solid var(--border);background:var(--bg);color:var(--text);padding:.45rem .7rem;border-radius:8px;font-size:.8rem;cursor:pointer}
.btn:hover{border-color:var(--accent)}
.btn-danger{border-color:#7f1d1d;color:#fecaca}
.btn-primary{border-color:#1d4ed8;color:#bfdbfe}
.mono{font-family:'SF Mono',Consolas,monospace;font-size:.78rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem;margin-bottom:1.5rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.25rem}
.card h2{font-size:.75rem;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin-bottom:.75rem}
.metric-row{display:flex;justify-content:space-between;align-items:baseline;padding:.25rem 0}
.metric-label{font-size:.85rem;color:var(--dim)}
.metric-value{font-size:1.1rem;font-weight:600;font-variant-numeric:tabular-nums;transition:color .3s}
.metric-value.changed{color:var(--accent)}
.big-number{font-size:2rem;font-weight:700;color:var(--accent);line-height:1}
.card-accent-green .big-number{color:var(--green)}
.card-accent-red .big-number{color:var(--red)}
.card-accent-blue .big-number{color:var(--blue)}
.card-accent-cyan .big-number{color:var(--cyan)}
.card-accent-amber .big-number{color:var(--amber)}
.section-title{font-size:1rem;font-weight:600;margin:1.5rem 0 .75rem;color:var(--text)}
table{width:100%;border-collapse:collapse;font-size:.85rem;background:var(--surface);
border:1px solid var(--border);border-radius:12px;overflow:hidden}
thead th{background:var(--bg);text-align:left;padding:.6rem .75rem;font-size:.7rem;
text-transform:uppercase;letter-spacing:.06em;color:var(--dim);cursor:pointer;user-select:none;
border-bottom:1px solid var(--border);position:sticky;top:0}
thead th:hover{color:var(--text)}
thead th.sorted-asc::after{content:" \u25B2";font-size:.6rem}
thead th.sorted-desc::after{content:" \u25BC";font-size:.6rem}
tbody td{padding:.5rem .75rem;border-bottom:1px solid var(--border)}
tbody tr:hover{background:rgba(108,99,255,.06)}
.host-name{font-family:'SF Mono',Consolas,monospace;font-size:.8rem;color:var(--cyan)}
.table-wrap{overflow-x:auto;border-radius:12px;max-height:500px;overflow-y:auto}
.search-box{background:var(--surface);border:1px solid var(--border);border-radius:8px;
padding:.5rem .75rem;color:var(--text);font-size:.85rem;width:300px;margin-bottom:.75rem;outline:none}
.search-box:focus{border-color:var(--accent)}
.tag{display:inline-block;padding:.1rem .45rem;border-radius:4px;font-size:.7rem;font-weight:600}
.tag-enforce{background:rgba(34,197,94,.15);color:var(--green)}
.tag-report{background:rgba(245,158,11,.15);color:var(--amber)}
.tag-disabled{background:rgba(122,127,148,.15);color:var(--dim)}
.ca-warning{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);border-radius:8px;
padding:.85rem 1rem;margin-top:.75rem;font-size:.82rem;line-height:1.6}
.ca-warning-title{font-weight:700;color:var(--amber);font-size:.85rem;margin-bottom:.35rem}
.ca-warning-text{color:var(--text);margin-bottom:.5rem}
.ca-warning-list{margin:0 0 .6rem 1.2rem;color:var(--dim)}
.ca-warning-list li{margin-bottom:.2rem}
.ca-warning-list strong{color:var(--text)}
.ca-accept-label{display:flex;align-items:center;gap:.5rem;cursor:pointer;color:var(--text);font-size:.82rem}
.ca-accept-label input{accent-color:var(--accent);width:16px;height:16px}
.btn-disabled{opacity:.35;pointer-events:none}
footer{text-align:center;padding:2rem;font-size:.75rem;color:var(--dim)}
.research-notice{margin-top:.35rem;font-size:.68rem;max-width:700px;margin-left:auto;margin-right:auto;line-height:1.5;color:var(--dim)}
</style>
</head>
<body>
<header>
  <h1><span>Privacy Engine</span> Dashboard</h1>
  <div class="status-bar">
    <span><span class="status-dot"></span>Live</span>
    <span id="uptime">--</span>
    <span id="policy-mode">--</span>
  </div>
</header>
<main>
  <section class="setup">
    <h2>Setup</h2>
    <div class="setup-grid">
      <div class="setup-item"><div class="label">CA Export</div><div id="ca-path" class="mono">--</div></div>
      <div class="setup-item"><div class="label">CA File</div><div id="ca-state">--</div></div>
      <div class="setup-item"><div class="label">Pinned Hosts</div><div id="pins-count">--</div></div>
      <div class="setup-item"><div class="label">Auto-Pin Grace</div><div id="grace-state">--</div></div>
      <div class="setup-item"><div class="label">User Profiles</div><div id="user-profiles-count">--</div></div>
    </div>
    <div class="ca-warning" id="ca-warning">
      <div class="ca-warning-title">Root CA Certificate</div>
      <div class="ca-warning-text">
        You are about to download a local Root CA certificate. Installing this certificate
        allows the Privacy Engine to intercept and modify encrypted (HTTPS) traffic on this device.
      </div>
      <ul class="ca-warning-list">
        <li><strong>Control:</strong> Only install this on devices and networks you own and control.</li>
        <li><strong>Visibility:</strong> Once installed, this engine can inspect and modify network data (cookies, headers, HTML content).</li>
        <li><strong>Scope:</strong> This is intended for privacy research, security auditing, and personal data-sovereignty experimentation.</li>
      </ul>
      <label class="ca-accept-label">
        <input type="checkbox" id="ca-accept-risk"> I understand the risks and take responsibility for installing this certificate.
      </label>
    </div>
    <div class="setup-actions">
      <a class="btn btn-primary btn-disabled" href="/download/ca.crt" download id="ca-download-btn">Download CA Cert</a>
      <button class="btn btn-danger" id="reset-pins-btn" type="button">Reset Pinned Hosts</button>
    </div>
  </section>
  <div class="cards" id="metric-cards"></div>
  <div class="section-title">DoH Clients</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Client IP</th><th>Queries</th><th>Last Seen</th></tr></thead>
      <tbody id="doh-tbody">
        <tr><td colspan="3" style="text-align:center;color:var(--dim);padding:1rem">DoH server disabled</td></tr>
      </tbody>
    </table>
  </div>
  <div class="section-title">Per-Host Activity</div>
  <input class="search-box" id="host-search" placeholder="Filter hosts..." autocomplete="off">
  <div class="table-wrap">
    <table>
      <thead id="host-thead"></thead>
      <tbody id="host-tbody"></tbody>
    </table>
  </div>
</main>
<footer>
  <div>Privacy Engine &mdash; auto-refreshes every 3s</div>
  <div class="research-notice">For network security auditing, privacy compliance research, and personal data-sovereignty experimentation. Users are responsible for compliance with applicable laws and third-party terms of service.</div>
</footer>
<script>
const $ = s => document.querySelector(s);
let prevMetrics = {};
let sortCol = 'seen_total';
let sortAsc = false;
let filterText = '';
let adminToken = '';
let lastDoh = {enabled:false, top_clients:[]};

const CARDS = [
  {id:'connections', title:'Connections', accent:'', metrics:[
    ['connection_total','Total',true],['passthrough_tunnel_total','Passthrough'],
    ['mitm_attempt_total','MITM Attempts'],['mitm_success_total','MITM Success'],
    ['mitm_failure_total','MITM Failures'],['host_auto_pinned_total','Auto-Pinned']]},
  {id:'dns', title:'DNS Filtering', accent:'green', metrics:[
    ['dns_query_total','Queries',true],['dns_blocked_total','Blocked'],
    ['dns_report_only_total','Report Only'],['dns_cname_uncloaked_total','CNAME Uncloaked']]},
  {id:'content', title:'Content Rewriting', accent:'blue', metrics:[
    ['body_rewrite_total','Rewrites',true],['body_rewrite_skipped_total','Skipped'],
    ['filter_list_rules_active','Filter Rules Active']]},
  {id:'privacy', title:'Privacy Enforcement', accent:'cyan', metrics:[
    ['consent_enforcement_blocked_total','Consent Blocked',true],
    ['websocket_blocked_total','WebSocket Blocked'],
    ['referer_spoofed_total','Headers Modified'],
    ['cert_pin_violation_total','Cert Pin Violations'],
    ['query_params_stripped_total','Query Params Stripped'],
    ['cache_headers_stripped_total','Cache Hdrs Stripped'],
    ['mitm_client_tls_reject_total','TLS Rejected']]},
  {id:'doh', title:'DoH Server', accent:'amber', metrics:[
    ['doh_query_total','Queries',true],['doh_unique_client_total','Unique Clients']]},
];

function initCards(){
  let html = '';
  for(const c of CARDS){
    const accentClass = c.accent ? ` card-accent-${c.accent}` : '';
    html += `<div class="card${accentClass}" id="card-${c.id}"><h2>${c.title}</h2>`;
    for(const [key,label,big] of c.metrics){
      if(big) html += `<div class="big-number" id="v-${key}">0</div>`;
      else html += `<div class="metric-row"><span class="metric-label">${label}</span><span class="metric-value" id="v-${key}">0</span></div>`;
    }
    html += '</div>';
  }
  $('#metric-cards').innerHTML = html;
}

function updateMetrics(data){
  for(const [key] of CARDS.flatMap(c=>c.metrics)){
    const el = document.getElementById('v-'+key);
    if(!el) continue;
    const val = data[key] ?? 0;
    const prev = prevMetrics[key] ?? 0;
    el.textContent = val.toLocaleString();
    if(val !== prev){el.classList.add('changed');setTimeout(()=>el.classList.remove('changed'),600);}
  }
  prevMetrics = {...data};
}

function fmtUptime(s){
  if(s<60) return s+'s';
  if(s<3600) return Math.floor(s/60)+'m '+s%60+'s';
  const h=Math.floor(s/3600),m=Math.floor((s%3600)/60);
  return h+'h '+m+'m';
}

function updateStatus(data){
  $('#uptime').textContent = 'Uptime: '+fmtUptime(data.uptime_secs||0);
  const mode = (data.policy_mode||'Unknown').toLowerCase();
  let tag = 'tag-disabled';
  if(mode.includes('enforce')) tag = 'tag-enforce';
  else if(mode.includes('report')) tag = 'tag-report';
  $('#policy-mode').innerHTML = `<span class="tag ${tag}">${data.policy_mode||'--'}</span>`;

  adminToken = data.admin_token || '';
  $('#ca-path').textContent = data.mitm_ca_export_cert_file || '(not configured)';
  $('#ca-state').textContent = data.mitm_ca_export_cert_exists ? 'Present' : 'Missing';
  $('#pins-count').textContent = (data.pinned_hosts_count ?? 0).toLocaleString();
  if(data.auto_pin_grace_active){
    $('#grace-state').textContent = `ACTIVE (${data.auto_pin_grace_remaining_secs || 0}s left)`;
  }else{
    $('#grace-state').textContent = `Inactive (${data.auto_pin_grace_period_secs || 0}s window)`;
  }
  $('#user-profiles-count').textContent = (data.consent_user_profile_count ?? 0).toString();
}

function updateDoh(data){
  lastDoh = data || {enabled:false,top_clients:[]};
  const rows = (lastDoh.top_clients || []);
  if(!lastDoh.enabled){
    $('#doh-tbody').innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--dim);padding:1rem">DoH server disabled</td></tr>';
    return;
  }
  if(!rows.length){
    $('#doh-tbody').innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--dim);padding:1rem">No DoH queries yet</td></tr>';
    return;
  }
  let html = '';
  for(const c of rows){
    html += `<tr><td class="host-name">${esc(c.client_ip || '--')}</td><td>${(c.query_total || 0).toLocaleString()}</td><td>${fmtTime(c.last_seen_unix)}</td></tr>`;
  }
  $('#doh-tbody').innerHTML = html;
}

const HOST_COLS = [
  ['host','Host'],['seen_total','Seen'],['dns_blocked_total','DNS Blk'],
  ['policy_set_cookie_stripped_total','Cookies Stripped'],
  ['consent_enforcement_blocked_total','Consent Blk'],
  ['websocket_blocked_total','WS Blk'],['referer_spoofed_total','Hdr Mod'],['cert_pin_violation_total','Pin Viol'],
  ['query_params_stripped_total','QP Strip'],['cache_headers_stripped_total','Cache Strip'],
  ['body_rewrite_total','Rewrites'],['body_rewrite_bytes_saved_total','Bytes Saved'],
  ['last_seen_unix','Last Seen']
];

function initTable(){
  let th = '<tr>';
  for(const [key,label] of HOST_COLS){
    th += `<th data-col="${key}">${label}</th>`;
  }
  th += '</tr>';
  $('#host-thead').innerHTML = th;
  document.querySelectorAll('#host-thead th').forEach(el=>{
    el.addEventListener('click',()=>{
      const col = el.dataset.col;
      if(sortCol===col) sortAsc=!sortAsc; else{sortCol=col;sortAsc=false;}
      renderTable(lastHosts);
    });
  });
}

let lastHosts = {};
function updateHosts(data){
  lastHosts = data.hosts||{};
  renderTable(lastHosts);
}

function renderTable(hosts){
  // Update header sort indicators
  document.querySelectorAll('#host-thead th').forEach(th=>{
    th.classList.remove('sorted-asc','sorted-desc');
    if(th.dataset.col===sortCol) th.classList.add(sortAsc?'sorted-asc':'sorted-desc');
  });
  let rows = Object.entries(hosts).map(([host,d])=>({host,...d}));
  if(filterText) rows = rows.filter(r=>r.host.includes(filterText));
  rows.sort((a,b)=>{
    let va=a[sortCol]??0, vb=b[sortCol]??0;
    if(sortCol==='host'){va=a.host;vb=b.host;return sortAsc?va.localeCompare(vb):vb.localeCompare(va);}
    return sortAsc?va-vb:vb-va;
  });
  let html = '';
  for(const r of rows.slice(0,200)){
    html += '<tr>';
    for(const [key] of HOST_COLS){
      if(key==='host') html += `<td class="host-name">${esc(r.host)}</td>`;
      else if(key==='last_seen_unix') html += `<td>${fmtTime(r[key])}</td>`;
      else if(key==='body_rewrite_bytes_saved_total') html += `<td>${fmtBytes(r[key]||0)}</td>`;
      else html += `<td>${(r[key]||0).toLocaleString()}</td>`;
    }
    html += '</tr>';
  }
  if(!rows.length) html = '<tr><td colspan="9" style="text-align:center;color:var(--dim);padding:2rem">No host data yet</td></tr>';
  $('#host-tbody').innerHTML = html;
}

function fmtTime(unix){
  if(!unix) return '--';
  return new Date(unix*1000).toLocaleTimeString();
}
function fmtBytes(b){
  if(b<1024) return b+'B';
  if(b<1048576) return (b/1024).toFixed(1)+'KB';
  return (b/1048576).toFixed(1)+'MB';
}
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

$('#host-search').addEventListener('input',e=>{filterText=e.target.value.toLowerCase();renderTable(lastHosts);});
$('#ca-accept-risk').addEventListener('change',e=>{
  const btn=$('#ca-download-btn');
  if(e.target.checked){btn.classList.remove('btn-disabled');}
  else{btn.classList.add('btn-disabled');}
});
$('#reset-pins-btn').addEventListener('click', async ()=>{
  if(!adminToken){ alert('Admin token unavailable yet; wait for status refresh.'); return; }
  if(!confirm('Clear all pinned hosts? This cannot be undone.')) return;
  try{
    const res = await fetch('/api/pins/reset', {method:'POST', headers:{'x-admin-token': adminToken}});
    const body = await res.json().catch(()=>({}));
    if(!res.ok){ alert('Pin reset failed'); return; }
    alert(`Pinned hosts reset. Removed: ${body.removed || 0}`);
    await refresh();
  }catch(_){ alert('Pin reset failed'); }
});

async function refresh(){
  try{
    const [mRes,dRes,rRes,sRes] = await Promise.all([
      fetch('/api/metrics'),fetch('/api/doh'),fetch('/api/receipts'),fetch('/api/status')
    ]);
    if(mRes.ok) updateMetrics(await mRes.json());
    if(dRes.ok) updateDoh(await dRes.json());
    if(rRes.ok) updateHosts(await rRes.json());
    if(sRes.ok) updateStatus(await sRes.json());
  }catch(e){console.warn('refresh error',e);}
}

initCards();
initTable();
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use hyper::header::{HeaderMap, HeaderValue};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_state() -> DashboardState {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("privacy_engine_dashboard_test_pins_{ts}.json"));
        DashboardState {
            metrics: Arc::new(metrics::Metrics::default()),
            doh_stats: None,
            policy_engine: Arc::new(policy::PolicyEngine::new(policy::PolicyMode::Enforce)),
            receipts_store: None,
            pinned_hosts: Arc::new(
                host_store::PinnedHosts::load(&path).expect("load pinned hosts"),
            ),
            mitm_ca_export_cert_file: None,
            auto_pin_grace_period_secs: 60,
            admin_token: "test-token".to_string(),
            start_time: SystemTime::now(),
        }
    }

    #[tokio::test]
    async fn dashboard_html_returns_200_with_html_content_type() {
        let resp = serve_html().unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("text/html"), "expected text/html, got {ct}");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&bytes);
        assert!(html.contains("Privacy Engine Dashboard"));
    }

    #[tokio::test]
    async fn dashboard_metrics_returns_json_with_counters() {
        let state = make_state();
        state.metrics.inc_connection_total();
        state.metrics.inc_dns_blocked_total();
        let resp = serve_metrics(&state).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["connection_total"], 1);
        assert_eq!(v["dns_blocked_total"], 1);
        assert_eq!(v["body_rewrite_total"], 0);
        assert_eq!(v["doh_query_total"], 0);
        assert_eq!(v["doh_unique_client_total"], 0);
    }

    #[tokio::test]
    async fn dashboard_status_returns_policy_mode() {
        let state = make_state();
        let resp = serve_status(&state).unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["uptime_secs"].as_u64().is_some());
        assert_eq!(v["policy_mode"], "Enforce");
        assert_eq!(v["auto_pin_grace_period_secs"], 60);
        assert_eq!(v["doh_server_enabled"], false);
        assert!(v["admin_token"].as_str().is_some());
    }

    #[tokio::test]
    async fn dashboard_receipts_without_store_returns_empty() {
        let state = make_state();
        let resp = serve_receipts(&state).unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["hosts"].as_object().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dashboard_pins_reset_requires_token() {
        let state = make_state();
        state
            .pinned_hosts
            .add_and_persist("blocked.example")
            .expect("add pin");
        assert_eq!(state.pinned_hosts.len().expect("len before"), 1);

        let headers = HeaderMap::new();
        let resp = serve_pins_reset(&headers, &state).unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(state.pinned_hosts.len().expect("len after"), 1);
    }

    #[tokio::test]
    async fn dashboard_pins_reset_clears_when_token_valid() {
        let state = make_state();
        state
            .pinned_hosts
            .add_and_persist("a.example")
            .expect("add a");
        state
            .pinned_hosts
            .add_and_persist("b.example")
            .expect("add b");
        assert_eq!(state.pinned_hosts.len().expect("len before"), 2);

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-admin-token",
            HeaderValue::from_str(&state.admin_token).expect("token header"),
        );
        let resp = serve_pins_reset(&headers, &state).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.pinned_hosts.len().expect("len after"), 0);
    }

    #[tokio::test]
    async fn dashboard_doh_returns_disabled_when_not_configured() {
        let state = make_state();
        let resp = serve_doh(&state).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["enabled"], false);
        assert_eq!(v["doh_query_total"], 0);
        assert_eq!(v["doh_unique_client_total"], 0);
    }

    #[tokio::test]
    async fn dashboard_doh_reports_client_activity() {
        let mut state = make_state();
        let stats = Arc::new(dns_filter::DohStats::default());
        stats.record_query(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        stats.record_query(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        stats.record_query(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)));
        state.doh_stats = Some(stats);

        let resp = serve_doh(&state).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["enabled"], true);
        assert_eq!(v["doh_query_total"], 3);
        assert_eq!(v["doh_unique_client_total"], 2);
        assert!(v["top_clients"].is_array());
    }
}
