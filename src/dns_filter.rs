use crate::metrics;
use crate::policy;
use crate::receipts;
use base64::Engine;
use bytes::Bytes;
use hickory_proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RData;
use hickory_proto::serialize::binary::BinDecodable;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};

const MAX_DNS_PACKET: usize = 4096;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
const DOH_CLIENT_STALE_SECS: u64 = 24 * 60 * 60;
const DOH_SNAPSHOT_TOP_CLIENTS: usize = 20;

#[derive(Debug, Clone)]
pub struct DohClientSnapshot {
    pub client_ip: String,
    pub query_total: u64,
    pub last_seen_unix: u64,
}

#[derive(Debug, Clone)]
pub struct DohStatsSnapshot {
    pub doh_query_total: u64,
    pub doh_unique_client_total: u64,
    pub top_clients: Vec<DohClientSnapshot>,
}

#[derive(Debug)]
struct DohClientEntry {
    query_total: u64,
    last_seen: SystemTime,
}

#[derive(Debug, Default)]
pub struct DohStats {
    query_total: AtomicU64,
    clients: RwLock<HashMap<String, DohClientEntry>>,
}

impl DohStats {
    pub fn record_query(&self, client_ip: IpAddr) {
        let now = SystemTime::now();
        let total = self.query_total.fetch_add(1, Ordering::Relaxed) + 1;
        let mut clients = self
            .clients
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = client_ip.to_string();
        let entry = clients.entry(key).or_insert(DohClientEntry {
            query_total: 0,
            last_seen: now,
        });
        entry.query_total = entry.query_total.saturating_add(1);
        entry.last_seen = now;

        // Opportunistic pruning to avoid unbounded map growth in long-running instances.
        if total.is_multiple_of(256) {
            Self::prune_locked(
                &mut clients,
                now,
                Duration::from_secs(DOH_CLIENT_STALE_SECS),
            );
        }
    }

    pub fn snapshot(&self, top_n: usize) -> DohStatsSnapshot {
        let now = SystemTime::now();
        let mut clients = self
            .clients
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::prune_locked(
            &mut clients,
            now,
            Duration::from_secs(DOH_CLIENT_STALE_SECS),
        );

        let mut top_clients: Vec<DohClientSnapshot> = clients
            .iter()
            .map(|(client_ip, entry)| DohClientSnapshot {
                client_ip: client_ip.clone(),
                query_total: entry.query_total,
                last_seen_unix: entry
                    .last_seen
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            })
            .collect();

        top_clients.sort_by(|a, b| {
            b.query_total
                .cmp(&a.query_total)
                .then_with(|| a.client_ip.cmp(&b.client_ip))
        });
        top_clients.truncate(top_n);

        DohStatsSnapshot {
            doh_query_total: self.query_total.load(Ordering::Relaxed),
            doh_unique_client_total: clients.len() as u64,
            top_clients,
        }
    }

    fn prune_locked(
        clients: &mut HashMap<String, DohClientEntry>,
        now: SystemTime,
        max_age: Duration,
    ) {
        clients
            .retain(|_, entry| now.duration_since(entry.last_seen).unwrap_or_default() <= max_age);
    }
}

fn make_tls_client_config() -> io::Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("TLS config error: {e}")))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

async fn doh_query(url: &str, query_data: &[u8]) -> io::Result<Vec<u8>> {
    let uri: Uri = url.parse().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("invalid DoH URL: {e}"))
    })?;
    let host = uri
        .host()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "DoH URL missing host"))?;
    let port = uri.port_u16().unwrap_or(443);
    let path = uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/dns-query");

    let tcp = TcpStream::connect((host, port)).await?;
    let tls_cfg = make_tls_client_config()?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS name"))?;
    let connector = TlsConnector::from(tls_cfg);
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| io::Error::other(format!("DoH TLS handshake failed: {e}")))?;

    let content_length = query_data.len();
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: privacy-engine-rust/0.1\r\n\
         Content-Type: application/dns-message\r\n\
         Content-Length: {content_length}\r\n\
         Accept: application/dns-message\r\n\
         \r\n"
    );

    stream.write_all(req.as_bytes()).await?;
    stream.write_all(query_data).await?;
    stream.flush().await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;

    // Simple HTTP parser to find body
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP response"))?;

    // We could parse Content-Length, but read_to_end handles the whole body if connection closes or we trust the server.
    // For proper HTTP/1.1 keep-alive we should parse CL. But standard DoH often closes or we can just grab body.
    // Let's just grab the body after headers.
    let body = buf.split_off(header_end + 4);

    Ok(body)
}

fn process_dns_query(
    query_data: &[u8],
    policy_engine: &policy::PolicyEngine,
    metrics: &metrics::Metrics,
    receipts_store: Option<&receipts::ReceiptStore>,
) -> Option<Vec<u8>> {
    metrics.inc_dns_query_total();

    let msg = match Message::from_bytes(query_data) {
        Ok(m) => m,
        Err(e) => {
            warn!(event = "dns_parse_error", error = %e, "failed to parse DNS query");
            return None;
        }
    };

    if msg.message_type() != MessageType::Query || msg.op_code() != OpCode::Query {
        return None; // Forward as-is
    }

    let query_name = match msg.queries().first() {
        Some(q) => {
            let name = q.name().to_ascii();
            normalize_dns_name(&name)
        }
        None => return None, // Forward as-is
    };

    let query_type = msg.queries().first().map(|q| q.query_type());
    let plan = policy_engine.plan_for_dns_query(&query_name);

    if plan.should_block {
        match plan.mode {
            policy::PolicyMode::Enforce => {
                metrics.inc_dns_blocked_total();
                if let Some(store) = receipts_store {
                    store.record_dns_block(&query_name);
                }
                info!(
                    event = "dns_blocked",
                    query_name = query_name,
                    query_type = ?query_type,
                    mode = "enforce",
                    "DNS query blocked (NXDOMAIN)"
                );
                return Some(build_nxdomain(&msg));
            }
            policy::PolicyMode::ReportOnly => {
                metrics.inc_dns_report_only_total();
                if let Some(store) = receipts_store {
                    store.record_dns_report_only(&query_name);
                }
                info!(
                    event = "dns_would_block",
                    query_name = query_name,
                    query_type = ?query_type,
                    mode = "report_only",
                    "DNS query would be blocked (forwarding)"
                );
            }
            policy::PolicyMode::Disabled => {}
        }
    }

    // CNAME uncloaking is handled in response path, so we return None here to indicate "forward upstream"
    None
}

pub struct DnsFilterConfig {
    pub listen_addr: SocketAddr,
    pub upstream_addr: SocketAddr,
    pub upstream_doh: Option<String>,
    pub policy_engine: Arc<policy::PolicyEngine>,
    pub metrics: Arc<metrics::Metrics>,
    pub receipts_store: Option<Arc<receipts::ReceiptStore>>,
}

pub async fn run_dns_filter(config: DnsFilterConfig) {
    let socket = match UdpSocket::bind(config.listen_addr).await {
        Ok(s) => {
            info!(
                event = "dns_filter_started",
                listen_addr = %config.listen_addr,
                upstream_addr = %config.upstream_addr,
                "DNS pre-filter listening"
            );
            s
        }
        Err(e) => {
            warn!(
                event = "dns_filter_bind_failed",
                listen_addr = %config.listen_addr,
                error = %e,
                "failed to bind DNS filter listener"
            );
            return;
        }
    };

    // Reuse a single upstream socket to avoid per-query bind overhead and ephemeral port churn.
    let upstream_bind = if config.upstream_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let upstream_socket = match UdpSocket::bind(upstream_bind).await {
        Ok(s) => s,
        Err(e) => {
            warn!(
                event = "dns_upstream_bind_failed",
                bind_addr = upstream_bind,
                error = %e,
                "failed to bind upstream DNS socket"
            );
            return;
        }
    };
    if let Err(e) = upstream_socket.connect(config.upstream_addr).await {
        warn!(
            event = "dns_upstream_connect_failed",
            upstream_addr = %config.upstream_addr,
            error = %e,
            "failed to connect upstream DNS socket"
        );
        return;
    }

    let mut buf = [0u8; MAX_DNS_PACKET];
    loop {
        let (len, client_addr) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                warn!(event = "dns_recv_error", error = %e, "DNS recv_from error");
                continue;
            }
        };

        let query_data = &buf[..len];

        // Try filter
        if let Some(response) = process_dns_query(
            query_data,
            &config.policy_engine,
            &config.metrics,
            config.receipts_store.as_deref(),
        ) {
            let _ = socket.send_to(&response, client_addr).await;
            continue;
        }

        // If not blocked, extract name for CNAME uncloaking context later
        let mut query_name = String::new();
        if let Ok(msg) = Message::from_bytes(query_data) {
            if let Some(q) = msg.queries().first() {
                query_name = normalize_dns_name(&q.name().to_ascii());
            }
        }

        let cname_ctx = CnameCheckContext {
            policy_engine: &config.policy_engine,
            metrics: &config.metrics,
            receipts_store: config.receipts_store.as_deref(),
            query_name: &query_name,
        };

        forward_and_reply(
            &socket,
            query_data,
            &upstream_socket,
            config.upstream_doh.as_deref(),
            client_addr,
            Some(&cname_ctx),
        )
        .await;
    }
}

pub struct DohServerConfig {
    pub addr: SocketAddr,
    pub cert: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub upstream_addr: SocketAddr,
    pub upstream_doh: Option<String>,
    pub stats: Arc<DohStats>,
    pub policy_engine: Arc<policy::PolicyEngine>,
    pub metrics: Arc<metrics::Metrics>,
    pub receipts_store: Option<Arc<receipts::ReceiptStore>>,
}

impl Clone for DohServerConfig {
    fn clone(&self) -> Self {
        Self {
            addr: self.addr,
            cert: self.cert.clone(),
            key: self.key.clone_key(),
            upstream_addr: self.upstream_addr,
            upstream_doh: self.upstream_doh.clone(),
            stats: self.stats.clone(),
            policy_engine: self.policy_engine.clone(),
            metrics: self.metrics.clone(),
            receipts_store: self.receipts_store.clone(),
        }
    }
}

pub async fn run_doh_server(config: DohServerConfig) {
    let tls_config = match rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(config.cert.clone(), config.key.clone_key())
    {
        Ok(c) => Arc::new(c),
        Err(e) => {
            error!(event = "doh_server_tls_error", error = %e, "failed to build TLS config for DoH server");
            return;
        }
    };

    let listener = match TcpListener::bind(config.addr).await {
        Ok(l) => {
            info!(event = "doh_server_started", listen_addr = %config.addr, "DoH server listening");
            l
        }
        Err(e) => {
            error!(event = "doh_server_bind_error", error = %e, "failed to bind DoH server listener");
            return;
        }
    };

    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(event = "doh_accept_error", error = %e);
                continue;
            }
        };

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config.clone());
        let config = config.clone();
        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(event = "doh_tls_handshake_error", remote_addr = %remote_addr, error = %e);
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let service =
                service_fn(move |req| handle_doh_request(req, config.clone(), remote_addr));

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                warn!(event = "doh_conn_error", remote_addr = %remote_addr, error = %e);
            }
        });
    }
}

async fn handle_doh_request(
    req: Request<Incoming>,
    config: DohServerConfig,
    client_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let (parts, body) = req.into_parts();

    let query_bytes = if parts.method == hyper::Method::POST {
        if parts.headers.get("content-type").map(|v| v.as_bytes())
            != Some(b"application/dns-message")
        {
            return Ok(doh_text_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Unsupported Media Type",
            ));
        }
        let bytes = BodyExt::collect(body).await?.to_bytes();
        bytes.to_vec()
    } else if parts.method == hyper::Method::GET {
        let query = parts.uri.query().unwrap_or("");
        let mut dns_param = None;
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "dns" {
                    dns_param = Some(v);
                    break;
                }
            }
        }
        let Some(b64) = dns_param else {
            return Ok(doh_text_response(
                StatusCode::BAD_REQUEST,
                "Missing 'dns' query parameter",
            ));
        };
        match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64) {
            Ok(b) => b,
            Err(_) => {
                return Ok(doh_text_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid base64url DNS query",
                ));
            }
        }
    } else {
        return Ok(doh_text_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method Not Allowed",
        ));
    };

    // Count valid DoH queries per client.
    config.stats.record_query(client_addr.ip());

    // 1. Check Policy
    if let Some(response) = process_dns_query(
        &query_bytes,
        &config.policy_engine,
        &config.metrics,
        config.receipts_store.as_deref(),
    ) {
        return Ok(doh_dns_response(StatusCode::OK, response));
    }

    // 2. Forward Upstream (UDP or DoH)
    // Note: Reusing UDP forward_and_reply requires a dummy listener socket which we don't want to bind per request.
    // Instead we reimplement basic forwarding logic here since we need to return HTTP response, not send to UDP socket.

    let reply_bytes: Option<Vec<u8>> = if let Some(doh_url) = &config.upstream_doh {
        match tokio::time::timeout(UPSTREAM_TIMEOUT, doh_query(doh_url, &query_bytes)).await {
            Ok(Ok(data)) => Some(data),
            Ok(Err(e)) => {
                warn!(event = "doh_server_upstream_doh_error", error = %e);
                None
            }
            Err(_) => {
                warn!(event = "doh_server_upstream_timeout");
                None
            }
        }
    } else {
        // UDP forwarding.
        // Use a per-request socket to avoid reply races across concurrent DoH requests.
        let upstream_bind = if config.upstream_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let upstream_socket = match UdpSocket::bind(upstream_bind).await {
            Ok(s) => s,
            Err(e) => {
                warn!(event = "doh_server_upstream_bind_error", error = %e);
                return Ok(doh_text_response(StatusCode::BAD_GATEWAY, "Upstream Error"));
            }
        };
        if let Err(e) = upstream_socket.connect(config.upstream_addr).await {
            warn!(event = "doh_server_upstream_connect_error", error = %e);
            return Ok(doh_text_response(StatusCode::BAD_GATEWAY, "Upstream Error"));
        }
        if let Err(e) = upstream_socket.send(&query_bytes).await {
            warn!(event = "doh_server_udp_send_error", error = %e);
            return Ok(doh_text_response(StatusCode::BAD_GATEWAY, "Upstream Error"));
        }
        let mut buf = [0u8; MAX_DNS_PACKET];
        match tokio::time::timeout(UPSTREAM_TIMEOUT, upstream_socket.recv(&mut buf)).await {
            Ok(Ok(len)) => Some(buf[..len].to_vec()),
            Ok(Err(e)) => {
                warn!(event = "doh_server_udp_recv_error", error = %e);
                None
            }
            Err(_) => {
                warn!(event = "doh_server_upstream_timeout");
                None
            }
        }
    };

    if let Some(reply) = reply_bytes {
        // CNAME uncloaking check (simplified context)
        let targets = extract_cname_targets(&reply);
        for target in &targets {
            let plan = config.policy_engine.plan_for_dns_query(target);
            if plan.should_block && plan.mode == policy::PolicyMode::Enforce {
                config.metrics.inc_dns_cname_uncloaked_total();
                if let Some(store) = config.receipts_store.as_deref() {
                    // We don't have the original query name easily available here without reparsing
                    // but we can log the target.
                    store.record_dns_cname_uncloaked(target);
                }
                if let Ok(original_msg) = Message::from_bytes(&query_bytes) {
                    let nx = build_nxdomain(&original_msg);
                    return Ok(doh_dns_response(StatusCode::OK, nx));
                }
            }
        }

        Ok(doh_dns_response(StatusCode::OK, reply))
    } else {
        Ok(doh_text_response(
            StatusCode::BAD_GATEWAY,
            "Upstream Timeout",
        ))
    }
}

pub const DOH_TOP_CLIENTS_DEFAULT: usize = DOH_SNAPSHOT_TOP_CLIENTS;

fn doh_dns_response(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/dns-message")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn doh_text_response(status: StatusCode, msg: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(msg.as_bytes().to_vec())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

struct CnameCheckContext<'a> {
    policy_engine: &'a policy::PolicyEngine,
    metrics: &'a metrics::Metrics,
    receipts_store: Option<&'a receipts::ReceiptStore>,
    query_name: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueryKey {
    id: u16,
    name: String,
    qtype: hickory_proto::rr::RecordType,
    qclass: hickory_proto::rr::DNSClass,
}

impl QueryKey {
    fn from_query_bytes(query: &[u8]) -> Option<Self> {
        let msg = Message::from_bytes(query).ok()?;
        if msg.message_type() != MessageType::Query || msg.op_code() != OpCode::Query {
            return None;
        }
        let q = msg.queries().first()?;
        Some(Self {
            id: msg.id(),
            name: normalize_dns_name(&q.name().to_ascii()),
            qtype: q.query_type(),
            qclass: q.query_class(),
        })
    }

    fn matches_reply_bytes(&self, reply: &[u8]) -> bool {
        let msg = match Message::from_bytes(reply) {
            Ok(m) => m,
            Err(_) => return false,
        };
        if msg.id() != self.id {
            return false;
        }
        // Some upstreams omit the question section. If present, validate it too.
        if let Some(q) = msg.queries().first() {
            let name = normalize_dns_name(&q.name().to_ascii());
            if name != self.name || q.query_type() != self.qtype || q.query_class() != self.qclass {
                return false;
            }
        }
        true
    }
}

fn extract_cname_targets(response_bytes: &[u8]) -> Vec<String> {
    let msg = match Message::from_bytes(response_bytes) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };

    msg.answers()
        .iter()
        .filter_map(|record| {
            if let RData::CNAME(ref cname) = *record.data() {
                Some(normalize_dns_name(&cname.0.to_ascii()))
            } else {
                None
            }
        })
        .collect()
}

async fn forward_and_reply(
    listener: &UdpSocket,
    query: &[u8],
    upstream_socket: &UdpSocket,
    doh_url: Option<&str>,
    client: SocketAddr,
    cname_ctx: Option<&CnameCheckContext<'_>>,
) {
    let expected = QueryKey::from_query_bytes(query);

    let reply_data: Option<Vec<u8>> = if let Some(url) = doh_url {
        match tokio::time::timeout(UPSTREAM_TIMEOUT, doh_query(url, query)).await {
            Ok(Ok(data)) => Some(data),
            Ok(Err(e)) => {
                warn!(event = "doh_query_error", url = url, error = %e, "DoH query failed");
                None
            }
            Err(_) => {
                warn!(
                    event = "doh_query_timeout",
                    url = url,
                    "DoH query timed out"
                );
                None
            }
        }
    } else {
        // UDP Fallback / Standard Path
        if let Err(e) = upstream_socket.send(query).await {
            warn!(
                event = "dns_forward_send_error",
                error = %e,
                "failed to send to upstream DNS"
            );
            return;
        }

        let mut reply_buf = [0u8; MAX_DNS_PACKET];
        match tokio::time::timeout(UPSTREAM_TIMEOUT, upstream_socket.recv(&mut reply_buf)).await {
            Ok(Ok(len)) => Some(reply_buf[..len].to_vec()),
            Ok(Err(e)) => {
                warn!(
                    event = "dns_upstream_recv_error",
                    error = %e,
                    "failed to receive from upstream DNS"
                );
                return;
            }
            Err(_) => {
                warn!(event = "dns_upstream_timeout", "upstream DNS timed out");
                return;
            }
        }
    };

    if let Some(ref reply_bytes) = reply_data {
        if let Some(ref key) = expected {
            if !key.matches_reply_bytes(reply_bytes) {
                warn!(
                    event = "dns_upstream_reply_mismatch",
                    expected_id = key.id,
                    expected_name = %key.name,
                    expected_type = ?key.qtype,
                    "ignoring mismatched upstream DNS reply"
                );
                return;
            }
        }

        if let Some(ctx) = cname_ctx {
            let targets = extract_cname_targets(reply_bytes);
            for target in &targets {
                let plan = ctx.policy_engine.plan_for_dns_query(target);
                if plan.should_block {
                    match plan.mode {
                        policy::PolicyMode::Enforce => {
                            ctx.metrics.inc_dns_cname_uncloaked_total();
                            if let Some(store) = ctx.receipts_store {
                                store.record_dns_cname_uncloaked(ctx.query_name);
                            }
                            info!(
                                event = "dns_cname_uncloaked",
                                query_name = ctx.query_name,
                                cname_target = target.as_str(),
                                mode = "enforce",
                                "CNAME target blocked (NXDOMAIN)"
                            );
                            // Build NXDOMAIN from the original query
                            if let Ok(original_query) = Message::from_bytes(query) {
                                let nxdomain = build_nxdomain(&original_query);
                                let _ = listener.send_to(&nxdomain, client).await;
                            }
                            return;
                        }
                        policy::PolicyMode::ReportOnly => {
                            ctx.metrics.inc_dns_report_only_total();
                            if let Some(store) = ctx.receipts_store {
                                store.record_dns_report_only(ctx.query_name);
                            }
                            info!(
                                event = "dns_cname_would_block",
                                query_name = ctx.query_name,
                                cname_target = target.as_str(),
                                mode = "report_only",
                                "CNAME target would be blocked (forwarding)"
                            );
                        }
                        policy::PolicyMode::Disabled => {}
                    }
                }
            }
        }
        let _ = listener.send_to(reply_bytes, client).await;
    }
}

fn build_nxdomain(query: &Message) -> Vec<u8> {
    let mut response = Message::new();
    let mut header = Header::response_from_request(query.header());
    header.set_response_code(ResponseCode::NXDomain);
    header.set_recursion_available(true);
    response.set_header(header);

    for q in query.queries() {
        response.add_query(q.clone());
    }

    response.to_vec().unwrap_or_default()
}

fn normalize_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::rdata::CNAME;
    use hickory_proto::rr::{DNSClass, Name, Record, RecordType};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    #[test]
    fn normalize_dns_name_strips_trailing_dot() {
        assert_eq!(normalize_dns_name("example.com."), "example.com");
        assert_eq!(normalize_dns_name("EXAMPLE.COM."), "example.com");
        assert_eq!(normalize_dns_name("example.com"), "example.com");
    }

    #[test]
    fn build_nxdomain_returns_valid_response() {
        let mut query = Message::new();
        query.set_id(1234);
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        let q = Query::query(Name::from_str("doubleclick.net.").unwrap(), RecordType::A);
        query.add_query(q);

        let response_bytes = build_nxdomain(&query);
        let response = Message::from_bytes(&response_bytes).expect("parse response");
        assert_eq!(response.id(), 1234);
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.response_code(), ResponseCode::NXDomain);
        assert_eq!(response.queries().len(), 1);
    }

    #[test]
    fn policy_evaluates_dns_block() {
        let engine = policy::PolicyEngine::new(policy::PolicyMode::Enforce);
        // Default engine has no dns_block rule, so nothing should be blocked
        let plan = engine.plan_for_dns_query("doubleclick.net");
        assert!(!plan.should_block);
    }

    fn build_dns_response_with_cnames(cnames: &[(&str, &str)]) -> Vec<u8> {
        let mut response = Message::new();
        response.set_message_type(MessageType::Response);
        response.set_id(1234);
        for (name, target) in cnames {
            let record = Record::from_rdata(
                Name::from_str(name).unwrap(),
                300,
                RData::CNAME(CNAME(Name::from_str(target).unwrap())),
            );
            response.add_answer(record);
        }
        response.to_vec().unwrap()
    }

    #[test]
    fn extract_cname_targets_finds_cname_record() {
        let bytes = build_dns_response_with_cnames(&[(
            "tracker.example.com.",
            "ads.tracking-service.com.",
        )]);
        let targets = extract_cname_targets(&bytes);
        assert_eq!(targets, vec!["ads.tracking-service.com"]);
    }

    #[test]
    fn extract_cname_targets_returns_empty_for_a_record_only() {
        use hickory_proto::rr::rdata::A;
        let mut response = Message::new();
        response.set_message_type(MessageType::Response);
        let record = Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(93, 184, 216, 34))),
        );
        response.add_answer(record);
        let bytes = response.to_vec().unwrap();

        let targets = extract_cname_targets(&bytes);
        assert!(targets.is_empty());
    }

    #[test]
    fn extract_cname_targets_handles_multiple_cnames() {
        let bytes = build_dns_response_with_cnames(&[
            ("a.example.com.", "tracker1.ads.com."),
            ("tracker1.ads.com.", "tracker2.cdn.com."),
        ]);
        let targets = extract_cname_targets(&bytes);
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&"tracker1.ads.com".to_string()));
        assert!(targets.contains(&"tracker2.cdn.com".to_string()));
    }

    #[test]
    fn extract_cname_targets_returns_empty_on_invalid_bytes() {
        let garbage = vec![0xFF, 0xFE, 0x00, 0x01, 0xAB];
        let targets = extract_cname_targets(&garbage);
        assert!(targets.is_empty());
    }

    #[test]
    fn extract_cname_targets_normalizes_names() {
        let mut response = Message::new();
        response.set_message_type(MessageType::Response);
        let record = Record::from_rdata(
            Name::from_str("Tracker.EXAMPLE.com.").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_str("ADS.Tracking-Service.COM.").unwrap())),
        );
        response.add_answer(record);
        let bytes = response.to_vec().unwrap();

        let targets = extract_cname_targets(&bytes);
        assert_eq!(targets, vec!["ads.tracking-service.com"]);
    }

    #[test]
    fn cname_uncloaking_metric_increments() {
        let m = metrics::Metrics::default();
        assert_eq!(m.snapshot().dns_cname_uncloaked_total, 0);
        m.inc_dns_cname_uncloaked_total();
        m.inc_dns_cname_uncloaked_total();
        assert_eq!(m.snapshot().dns_cname_uncloaked_total, 2);
    }

    #[test]
    fn query_key_parses_query_bytes() {
        let mut query = Message::new();
        query.set_id(0x1234);
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        query.add_query(Query::query(
            Name::from_str("Example.COM.").unwrap(),
            RecordType::A,
        ));

        let bytes = query.to_vec().unwrap();
        let key = QueryKey::from_query_bytes(&bytes).expect("key");
        assert_eq!(key.id, 0x1234);
        assert_eq!(key.name, "example.com");
        assert_eq!(key.qtype, RecordType::A);
        assert_eq!(key.qclass, DNSClass::IN);
    }

    #[test]
    fn query_key_matches_reply_id_and_question() {
        let mut query = Message::new();
        query.set_id(0x2222);
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        query.add_query(Query::query(
            Name::from_str("a.example.com.").unwrap(),
            RecordType::A,
        ));
        let query_bytes = query.to_vec().unwrap();
        let key = QueryKey::from_query_bytes(&query_bytes).expect("key");

        let mut reply = Message::new();
        reply.set_message_type(MessageType::Response);
        reply.set_id(0x2222);
        reply.add_query(Query::query(
            Name::from_str("a.example.com.").unwrap(),
            RecordType::A,
        ));
        let reply_bytes = reply.to_vec().unwrap();

        assert!(key.matches_reply_bytes(&reply_bytes));
    }

    #[test]
    fn query_key_rejects_mismatched_reply() {
        let mut query = Message::new();
        query.set_id(0x3333);
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        query.add_query(Query::query(
            Name::from_str("a.example.com.").unwrap(),
            RecordType::A,
        ));
        let query_bytes = query.to_vec().unwrap();
        let key = QueryKey::from_query_bytes(&query_bytes).expect("key");

        let mut reply_wrong_id = Message::new();
        reply_wrong_id.set_message_type(MessageType::Response);
        reply_wrong_id.set_id(0x4444);
        reply_wrong_id.add_query(Query::query(
            Name::from_str("a.example.com.").unwrap(),
            RecordType::A,
        ));
        let reply_wrong_id_bytes = reply_wrong_id.to_vec().unwrap();
        assert!(!key.matches_reply_bytes(&reply_wrong_id_bytes));

        let mut reply_wrong_q = Message::new();
        reply_wrong_q.set_message_type(MessageType::Response);
        reply_wrong_q.set_id(0x3333);
        reply_wrong_q.add_query(Query::query(
            Name::from_str("b.example.com.").unwrap(),
            RecordType::A,
        ));
        let reply_wrong_q_bytes = reply_wrong_q.to_vec().unwrap();
        assert!(!key.matches_reply_bytes(&reply_wrong_q_bytes));
    }

    #[test]
    fn max_dns_packet_supports_edns_size() {
        assert_eq!(MAX_DNS_PACKET, 4096);
    }

    #[tokio::test]
    async fn doh_dns_response_preserves_binary_payload() {
        let payload = vec![0x00, 0x80, 0xff, 0x01, 0x7f];
        let response = doh_dns_response(StatusCode::OK, payload.clone());

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/dns-message")
        );

        let body = BodyExt::collect(response.into_body())
            .await
            .expect("collect body")
            .to_bytes();
        assert_eq!(body.as_ref(), payload.as_slice());
    }

    #[test]
    fn doh_stats_tracks_queries_and_top_clients() {
        let stats = DohStats::default();
        stats.record_query(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        stats.record_query(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        stats.record_query(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let snap = stats.snapshot(10);
        assert_eq!(snap.doh_query_total, 3);
        assert_eq!(snap.doh_unique_client_total, 2);
        assert_eq!(
            snap.top_clients.first().map(|c| c.client_ip.as_str()),
            Some("10.0.0.1")
        );
        assert_eq!(snap.top_clients.first().map(|c| c.query_total), Some(2));
    }

    #[test]
    fn doh_stats_snapshot_prunes_stale_clients() {
        let stats = DohStats::default();
        {
            let mut clients = stats
                .clients
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            clients.insert(
                "10.0.0.9".to_string(),
                DohClientEntry {
                    query_total: 1,
                    last_seen: SystemTime::now()
                        .checked_sub(Duration::from_secs(DOH_CLIENT_STALE_SECS + 10))
                        .expect("past"),
                },
            );
            clients.insert(
                "10.0.0.8".to_string(),
                DohClientEntry {
                    query_total: 2,
                    last_seen: SystemTime::now(),
                },
            );
        }

        let snap = stats.snapshot(10);
        assert_eq!(snap.doh_unique_client_total, 1);
        assert_eq!(snap.top_clients.len(), 1);
        assert_eq!(snap.top_clients[0].client_ip, "10.0.0.8");
    }
}
