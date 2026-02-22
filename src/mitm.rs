use crate::metrics;
use crate::policy;
use crate::receipts;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::client::Resumption;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{info, warn};

/// TLS cipher suite profile for upstream connections.
///
/// Controls the cipher suite ordering in the TLS ClientHello sent to upstream
/// servers, which affects JA3/JA4 fingerprint values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum TlsProfile {
    /// Use the rustls default cipher suite ordering.
    #[default]
    Default,
    /// Reorder cipher suites to match Chrome's preference order,
    /// reducing JA3/JA4 fingerprint variance across proxied connections.
    Chrome,
}

impl TlsProfile {
    /// Returns a `CryptoProvider` with cipher suites and key exchange groups
    /// ordered according to this profile.
    ///
    /// For Chrome profile, this matches Chrome's ClientHello for the components
    /// that rustls allows control over:
    /// - Cipher suite preference order (JA3 field 2)
    /// - Named groups / elliptic curves (JA3 field 4): X25519, P-256, P-384
    ///
    /// **Not controllable via rustls** (would require boring-ssl or raw TLS):
    /// - GREASE values (RFC 8701) in ciphers, extensions, named groups
    /// - TLS extension ordering
    fn crypto_provider(self) -> CryptoProvider {
        let mut provider = rustls::crypto::ring::default_provider();
        if self == TlsProfile::Chrome {
            use rustls::crypto::ring::{cipher_suite, kx_group};

            // Chrome cipher suite preference order:
            //   TLS 1.3: AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305
            //   TLS 1.2: ECDHE_ECDSA/RSA interleaved, 128 before 256
            provider.cipher_suites = vec![
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                cipher_suite::TLS13_AES_256_GCM_SHA384,
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ];

            // Chrome named group order: X25519, P-256, P-384
            // (Explicitly set to guard against rustls default changes)
            provider.kx_groups = vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1];
        }
        provider
    }

    /// Apply profile-specific settings to a `ClientConfig` after construction.
    /// Sets session resumption, extended master secret, etc.
    fn configure_client(self, config: &mut ClientConfig) {
        if self == TlsProfile::Chrome {
            // Chrome requires Extended Master Secret for TLS 1.2 (RFC 7627)
            config.require_ems = true;
            // Chrome uses session tickets for TLS resumption
            config.resumption = Resumption::in_memory_sessions(256);
        }
    }

    #[cfg(test)]
    fn cipher_suites(self) -> Vec<rustls::SupportedCipherSuite> {
        self.crypto_provider().cipher_suites
    }

    #[cfg(test)]
    fn kx_group_ids(self) -> Vec<rustls::NamedGroup> {
        self.crypto_provider()
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TlsProfile::Default => "default",
            TlsProfile::Chrome => "chrome",
        }
    }

    /// Returns a human-readable summary of what this profile configures.
    pub fn describe(self) -> &'static str {
        match self {
            TlsProfile::Default => "rustls defaults (no fingerprint normalization)",
            TlsProfile::Chrome => "Chrome-like: cipher order, named groups (X25519/P-256/P-384), EMS required, session tickets",
        }
    }
}

const MAX_HTTP1_HEADER_BYTES: usize = 64 * 1024;
const MAX_COSMETIC_SELECTORS_PER_REWRITE: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum MitmError {
    #[error("MITM certificate generation failed: {0}")]
    CertGeneration(String),

    #[error("Client TLS handshake failed: {0}")]
    ClientTlsHandshake(String),

    #[error("Upstream TCP connect failed: {0}")]
    UpstreamConnect(#[source] io::Error),

    #[error("Invalid upstream server name: {0}")]
    InvalidServerName(String),

    #[error("Upstream TLS handshake failed: {0}")]
    UpstreamTlsHandshake(String),

    #[error("MITM relay failed: {0}")]
    Relay(#[source] io::Error),

    #[error("MITM CA config error: {0}")]
    CaConfig(String),

    #[error("MITM CA file I/O failed: {0}")]
    CaIo(#[source] io::Error),
}

impl MitmError {
    pub fn is_client_tls_handshake_failure(&self) -> bool {
        matches!(self, Self::ClientTlsHandshake(_))
    }

    pub fn is_upstream_tls_handshake_failure(&self) -> bool {
        matches!(self, Self::UpstreamTlsHandshake(_))
    }

    pub fn is_benign_peer_close(&self) -> bool {
        match self {
            Self::Relay(e) => {
                if matches!(
                    e.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                ) {
                    return true;
                }

                let msg = e.to_string();
                msg.contains("without sending TLS close_notify")
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CaFilesConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub generate_if_missing: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaInitMode {
    LoadedFromFiles,
    GeneratedAndPersisted,
    GeneratedEphemeral,
}

/// Append-only JSON-lines log of every MITM leaf certificate generated.
pub struct CertLog {
    file: Mutex<fs::File>,
}

impl CertLog {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    fn record(&self, host: &str, serial_hex: &str, fingerprint_sha256: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = serde_json::json!({
            "ts": now,
            "host": host,
            "serial_hex": serial_hex,
            "fingerprint_sha256": fingerprint_sha256,
        });
        if let Ok(mut f) = self.file.lock() {
            let _ = writeln!(f, "{line}");
        }
    }
}

pub struct MitmEngine {
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_init_mode: CaInitMode,
    ca_cert_pem_for_export: String,
    cert_cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
    upstream_client_config: Arc<ClientConfig>,
    upstream_client_config_http1: Arc<ClientConfig>,
    cert_log: Option<Arc<CertLog>>,
    cert_pin_db: Option<Arc<crate::cert_pin::CertPinDb>>,
}

impl MitmEngine {
    pub fn new(
        ca_files: Option<&CaFilesConfig>,
        tls_profile: TlsProfile,
        cert_log: Option<Arc<CertLog>>,
        cert_pin_db: Option<Arc<crate::cert_pin::CertPinDb>>,
    ) -> Result<Self, MitmError> {
        let (ca_cert, ca_key, ca_cert_pem_for_export, ca_init_mode) = match ca_files {
            Some(cfg) => load_or_create_ca(cfg)?,
            None => {
                let (ca_cert, ca_key) = generate_root_ca()?;
                let ca_cert_pem = ca_cert.pem();
                (ca_cert, ca_key, ca_cert_pem, CaInitMode::GeneratedEphemeral)
            }
        };
        let provider = Arc::new(tls_profile.crypto_provider());
        let root_store = build_root_cert_store();
        let mut upstream_client_config = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| MitmError::CaConfig(format!("TLS config error: {e}")))?
            .with_root_certificates(root_store)
            .with_no_client_auth();
        upstream_client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        tls_profile.configure_client(&mut upstream_client_config);
        let upstream_client_config = Arc::new(upstream_client_config);
        let mut upstream_client_config_http1 = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| MitmError::CaConfig(format!("TLS config error: {e}")))?
            .with_root_certificates(build_root_cert_store())
            .with_no_client_auth();
        upstream_client_config_http1.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls_profile.configure_client(&mut upstream_client_config_http1);
        let upstream_client_config_http1 = Arc::new(upstream_client_config_http1);

        Ok(Self {
            ca_cert,
            ca_key,
            ca_init_mode,
            ca_cert_pem_for_export,
            cert_cache: Mutex::new(HashMap::new()),
            upstream_client_config,
            upstream_client_config_http1,
            cert_log,
            cert_pin_db,
        })
    }

    pub fn ca_init_mode(&self) -> CaInitMode {
        self.ca_init_mode
    }

    pub fn export_ca_cert_pem(&self, path: &Path) -> Result<(), MitmError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(MitmError::CaIo)?;
        }
        fs::write(path, &self.ca_cert_pem_for_export).map_err(MitmError::CaIo)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn intercept_tls_tunnel(
        &self,
        client_stream: &mut TcpStream,
        target_addr: &str,
        target_host: &str,
        source_ip: Option<&str>,
        policy_engine: &policy::PolicyEngine,
        receipts_store: Option<&receipts::ReceiptStore>,
        metrics: &metrics::Metrics,
    ) -> Result<(), MitmError> {
        let plan = policy_engine.plan_for_host_with_source_ip(target_host, source_ip);
        let body_rewrite_plan = policy_engine.plan_for_body_rewrite(target_host);
        let manual_rewrite_active = body_rewrite_plan.strip_tracking_pixels
            || !body_rewrite_plan.manual_script_patterns.is_empty()
            || !body_rewrite_plan.manual_remove_selectors.is_empty();
        // Only force HTTP/1.1 when we must (Set-Cookie policy) or when the user explicitly
        // configured body rewriting rules. Filter-list-driven rewriting is best-effort.
        let force_http1 = plan.enable_http1_set_cookie_filter || manual_rewrite_active;

        // Probe upstream FIRST — if upstream TLS fails, we can fall back to passthrough
        // before touching the client's TLS handshake, so the browser never sees an error.
        let upstream_tcp = TcpStream::connect(target_addr)
            .await
            .map_err(MitmError::UpstreamConnect)?;

        let server_name = ServerName::try_from(target_host.to_string())
            .map_err(|_| MitmError::InvalidServerName(target_host.to_string()))?;
        let upstream_cfg = if force_http1 {
            Arc::clone(&self.upstream_client_config_http1)
        } else {
            Arc::clone(&self.upstream_client_config)
        };
        let tls_connector = TlsConnector::from(upstream_cfg);

        let mut upstream_tls = tls_connector
            .connect(server_name, upstream_tcp)
            .await
            .map_err(|e| MitmError::UpstreamTlsHandshake(e.to_string()))?;

        // TOFU cert pin check: verify upstream leaf cert fingerprint
        if let Some(ref pin_db) = self.cert_pin_db {
            if let Some(certs) = upstream_tls.get_ref().1.peer_certificates() {
                if let Some(leaf) = certs.first() {
                    let fingerprint = crate::cert_pin::cert_der_fingerprint(leaf.as_ref());
                    match pin_db.check_and_update(target_host, &fingerprint) {
                        Ok(crate::cert_pin::PinCheckResult::FirstSeen) => {
                            info!(
                                event = "cert_pin_first_seen",
                                host = target_host,
                                fingerprint = %fingerprint,
                                "recorded initial cert pin"
                            );
                        }
                        Ok(crate::cert_pin::PinCheckResult::Match) => {}
                        Ok(crate::cert_pin::PinCheckResult::Mismatch { expected, got }) => {
                            warn!(
                                event = "cert_pin_mismatch",
                                host = target_host,
                                expected = ?expected,
                                got = %got,
                                "upstream certificate fingerprint changed"
                            );
                            metrics.inc_cert_pin_violation_total();
                            if let Some(store) = receipts_store {
                                store.record_cert_pin_violation(target_host);
                            }
                        }
                        Err(e) => {
                            warn!(
                                event = "cert_pin_error",
                                host = target_host,
                                error = %e,
                                "cert pin DB error"
                            );
                        }
                    }
                }
            }
        }

        // Upstream TLS succeeded — now accept the client's TLS handshake with our MITM cert
        let server_config = self.server_config_for_host(target_host, force_http1)?;
        let tls_acceptor = TlsAcceptor::from(server_config);

        let mut client_tls = tls_acceptor
            .accept(client_stream)
            .await
            .map_err(|e| MitmError::ClientTlsHandshake(e.to_string()))?;

        if force_http1 {
            relay_with_first_response_header_policy(
                &mut client_tls,
                &mut upstream_tls,
                policy_engine,
                target_host,
                source_ip,
                receipts_store,
                metrics,
            )
            .await
            .map_err(MitmError::Relay)?;
        } else {
            // Opportunistic HTTP/1.1 relay: if both sides negotiated HTTP/1.1 (or no ALPN),
            // we can still apply body rewriting without forcing HTTP/1.1 globally.
            let client_alpn = client_tls.get_ref().1.alpn_protocol();
            let upstream_alpn = upstream_tls.get_ref().1.alpn_protocol();
            let client_http1 = client_alpn.is_none() || client_alpn == Some(b"http/1.1");
            let upstream_http1 = upstream_alpn.is_none() || upstream_alpn == Some(b"http/1.1");
            if client_http1 && upstream_http1 && body_rewrite_plan.should_rewrite {
                relay_with_first_response_header_policy(
                    &mut client_tls,
                    &mut upstream_tls,
                    policy_engine,
                    target_host,
                    source_ip,
                    receipts_store,
                    metrics,
                )
                .await
                .map_err(MitmError::Relay)?;
            } else {
                tokio::io::copy_bidirectional(&mut client_tls, &mut upstream_tls)
                    .await
                    .map_err(MitmError::Relay)?;
            }
        }
        Ok(())
    }

    fn server_config_for_host(
        &self,
        target_host: &str,
        force_http1: bool,
    ) -> Result<Arc<ServerConfig>, MitmError> {
        let normalized_host = target_host.trim().to_ascii_lowercase();
        if normalized_host.is_empty() {
            return Err(MitmError::CertGeneration("empty target host".to_string()));
        }
        let cache_key = if force_http1 {
            format!("{normalized_host}|h1")
        } else {
            format!("{normalized_host}|h2h1")
        };

        if let Ok(cache) = self.cert_cache.lock() {
            if let Some(cfg) = cache.get(&cache_key) {
                return Ok(Arc::clone(cfg));
            }
        }

        let mut params = CertificateParams::new(vec![normalized_host.clone()])
            .map_err(|e| MitmError::CertGeneration(e.to_string()))?;
        params.is_ca = IsCa::ExplicitNoCa;
        params
            .distinguished_name
            .push(DnType::CommonName, normalized_host.clone());
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);

        let leaf_key = KeyPair::generate().map_err(|e| MitmError::CertGeneration(e.to_string()))?;
        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|e| MitmError::CertGeneration(e.to_string()))?;

        // Log cert generation if cert transparency log is configured
        if let Some(ref log) = self.cert_log {
            let der = leaf_cert.der();
            let serial_hex = leaf_cert
                .params()
                .serial_number
                .as_ref()
                .map(|s| format!("{s:?}"))
                .unwrap_or_else(|| "auto".to_string());
            let fp = ring::digest::digest(&ring::digest::SHA256, der);
            let fingerprint = fp
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":");
            log.record(&normalized_host, &serial_hex, &fingerprint);
        }

        let cert_chain = vec![CertificateDer::from(leaf_cert.der().to_vec())];
        let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| MitmError::CertGeneration(e.to_string()))?;
        server_config.alpn_protocols = if force_http1 {
            vec![b"http/1.1".to_vec()]
        } else {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        };
        let server_config = Arc::new(server_config);

        if let Ok(mut cache) = self.cert_cache.lock() {
            cache.insert(cache_key, Arc::clone(&server_config));
        }

        Ok(server_config)
    }
}

async fn relay_with_first_response_header_policy<C, S>(
    client_tls: &mut C,
    upstream_tls: &mut S,
    policy_engine: &policy::PolicyEngine,
    target_host: &str,
    source_ip: Option<&str>,
    receipts_store: Option<&receipts::ReceiptStore>,
    metrics: &metrics::Metrics,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client_tls);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_tls);

    let mut client_to_server_bytes = 0u64;
    let mut server_to_client_bytes = 0u64;

    let mut client_closed = false;
    let mut upstream_closed = false;

    let mut client_buf = [0u8; 8192];
    let mut upstream_buf = [0u8; 8192];

    // State machine:
    //   BufferingHeaders -> headers parsed -> send headers
    //     -> if body rewrite active: BufferingBody -> rewrite + send
    //     -> else: Passthrough
    let mut first_response_filtered = false;
    let mut pending = Vec::new();
    let mut first_request_checked = false;

    // Body rewriting state
    let mut buffering_body = false;
    let mut body_buffer: Vec<u8> = Vec::new();
    let mut body_rewrite_plan: Option<policy::BodyRewritePlan> = None;
    let mut deferred_headers: Option<Vec<u8>> = None;
    let mut expected_body_len: Option<usize> = None;
    let mut buffered_content_encoding: Option<String> = None;
    let mut buffering_chunked = false;

    loop {
        tokio::select! {
            res = client_read.read(&mut client_buf), if !client_closed => {
                let n = res?;
                if n == 0 {
                    client_closed = true;
                    upstream_write.shutdown().await?;
                } else {
                    // Check first request for WebSocket upgrade to tracker domains
                    // and apply Referer header normalization for configured domains
                    if !first_request_checked {
                        first_request_checked = true;
                        let plan = policy_engine.plan_for_host_with_source_ip(target_host, source_ip);
                        if let Some(ref profile) = plan.user_profile_name {
                            info!(
                                event = "user_profile_applied",
                                host = target_host,
                                profile = %profile,
                                "using user consent profile"
                            );
                        }
                        if plan.tracker_match && plan.websocket_blocking_enabled && request_has_websocket_upgrade(&client_buf[..n]) {
                            info!(
                                event = "websocket_blocked",
                                host = target_host,
                                "blocked WebSocket upgrade to tracker domain"
                            );
                            if let Some(store) = receipts_store {
                                store.record_websocket_blocked(target_host);
                            }
                            metrics.inc_websocket_blocked_total();
                            let response = b"HTTP/1.1 403 Forbidden\r\n\
                                Content-Length: 0\r\n\
                                Connection: close\r\n\
                                \r\n";
                            client_write.write_all(response).await?;
                            return Ok(());
                        }

                        // Referer header normalization for configured domains
                        let bw_plan = policy_engine.plan_for_body_rewrite(target_host);
                        let mut outgoing: Option<Vec<u8>> = None;

                        if bw_plan.referer_spoof {
                            if let Some(modified) = inject_google_referer(&client_buf[..n]) {
                                info!(
                                    event = "referer_spoofed",
                                    host = target_host,
                                    "applied referer header normalization"
                                );
                                if let Some(store) = receipts_store {
                                    store.record_referer_spoofed(target_host);
                                }
                                metrics.inc_referer_spoofed_total();
                                outgoing = Some(modified);
                            }
                        }

                        // Query parameter stripping
                        if bw_plan.query_param_strip {
                            let src = outgoing.as_deref().unwrap_or(&client_buf[..n]);
                            if let Some(stripped) = strip_tracking_query_params(src) {
                                info!(
                                    event = "query_params_stripped",
                                    host = target_host,
                                    "stripped tracking query params"
                                );
                                if let Some(store) = receipts_store {
                                    store.record_query_params_stripped(target_host);
                                }
                                metrics.inc_query_params_stripped_total();
                                outgoing = Some(stripped);
                            }
                        }

                        // Cache request header stripping for tracker domains
                        if plan.tracker_match {
                            let src = outgoing.as_deref().unwrap_or(&client_buf[..n]);
                            if let Some(stripped) = strip_cache_request_headers(src) {
                                info!(
                                    event = "cache_request_headers_stripped",
                                    host = target_host,
                                    "stripped conditional cache headers from request"
                                );
                                if let Some(store) = receipts_store {
                                    store.record_cache_headers_stripped(target_host);
                                }
                                metrics.inc_cache_headers_stripped_total();
                                outgoing = Some(stripped);
                            }
                        }

                        if let Some(modified) = outgoing {
                            upstream_write.write_all(&modified).await?;
                            client_to_server_bytes += modified.len() as u64;
                            continue;
                        }
                    }
                    upstream_write.write_all(&client_buf[..n]).await?;
                    client_to_server_bytes += n as u64;
                }
            }
            res = upstream_read.read(&mut upstream_buf), if !upstream_closed => {
                let n = res?;
                if n == 0 {
                    upstream_closed = true;

                    // Flush any pending header or body buffers
                    if !pending.is_empty() {
                        client_write.write_all(&pending).await?;
                        server_to_client_bytes += pending.len() as u64;
                        pending.clear();
                        first_response_filtered = true;
                    }

                    if buffering_body {
                        // Stream ended while buffering body - do the rewrite now
                        if let Some(plan) = body_rewrite_plan.take() {
                                let mut headers = deferred_headers.take().unwrap_or_default();
                                if buffering_chunked {
                                    if let Some((decoded, consumed_len)) =
                                        try_decode_chunked_message(&body_buffer)
                                    {
                                        let overflow = &body_buffer[consumed_len..];
                                        match attempt_body_rewrite(
                                            &decoded,
                                            &plan,
                                            target_host,
                                            receipts_store,
                                            metrics,
                                            buffered_content_encoding.as_deref(),
                                        ) {
                                            Some(rewritten) => {
                                                headers = replace_chunked_with_content_length(&headers, rewritten.len());
                                                client_write.write_all(&headers).await?;
                                                client_write.write_all(&rewritten).await?;
                                                server_to_client_bytes += (headers.len() + rewritten.len()) as u64;
                                                if !overflow.is_empty() {
                                                    client_write.write_all(overflow).await?;
                                                    server_to_client_bytes += overflow.len() as u64;
                                                }
                                            }
                                            None => {
                                                client_write.write_all(&headers).await?;
                                                client_write.write_all(&body_buffer).await?;
                                                server_to_client_bytes += (headers.len() + body_buffer.len()) as u64;
                                        }
                                    }
                                } else {
                                    // Incomplete chunked stream, send raw
                                    client_write.write_all(&headers).await?;
                                    client_write.write_all(&body_buffer).await?;
                                    server_to_client_bytes += (headers.len() + body_buffer.len()) as u64;
                                }
                            } else {
                                match attempt_body_rewrite(&body_buffer, &plan, target_host, receipts_store, metrics, buffered_content_encoding.as_deref()) {
                                    Some(rewritten) => {
                                        headers = replace_content_length(&headers, rewritten.len());
                                        client_write.write_all(&headers).await?;
                                        client_write.write_all(&rewritten).await?;
                                        server_to_client_bytes += (headers.len() + rewritten.len()) as u64;
                                    }
                                    None => {
                                        client_write.write_all(&headers).await?;
                                        client_write.write_all(&body_buffer).await?;
                                        server_to_client_bytes += (headers.len() + body_buffer.len()) as u64;
                                    }
                                }
                            }
                        }
                        buffering_body = false;
                        buffering_chunked = false;
                    }

                    client_write.shutdown().await?;
                } else if buffering_body {
                    body_buffer.extend_from_slice(&upstream_buf[..n]);

                    let plan = body_rewrite_plan.as_ref().unwrap();
                    let at_limit = body_buffer.len() >= plan.max_body_bytes;
                    let at_content_length = expected_body_len.is_some_and(|cl| body_buffer.len() >= cl);

                        // For chunked: try full decode (including trailers), returning consumed length for overflow.
                        let chunked_parsed = if buffering_chunked && !at_limit {
                            try_decode_chunked_message(&body_buffer)
                        } else {
                            None
                        };

                        if at_limit && chunked_parsed.is_none() && !at_content_length {
                            // Body too large, skip rewrite — send raw (chunked or not)
                            let headers = deferred_headers.take().unwrap_or_default();
                            metrics.inc_body_rewrite_skipped_total();
                            if let Some(store) = receipts_store { store.record_body_rewrite_skipped(target_host); }
                        warn!(event = "body_rewrite_skipped", host = target_host, reason = "body_too_large", "body rewrite skipped");
                        client_write.write_all(&headers).await?;
                        client_write.write_all(&body_buffer).await?;
                        server_to_client_bytes += (headers.len() + body_buffer.len()) as u64;

                        body_rewrite_plan = None;
                        buffering_body = false;
                            buffering_chunked = false;
                            first_response_filtered = true;
                        } else if let Some((decoded, consumed_len)) = chunked_parsed {
                            // Chunked body complete — decode, rewrite, send with Content-Length
                            let mut headers = deferred_headers.take().unwrap_or_default();
                            let overflow = &body_buffer[consumed_len..];
                            match attempt_body_rewrite(
                                &decoded,
                                plan,
                                target_host,
                                receipts_store,
                                metrics,
                                buffered_content_encoding.as_deref(),
                            ) {
                                Some(rewritten) => {
                                    headers = replace_chunked_with_content_length(&headers, rewritten.len());
                                    client_write.write_all(&headers).await?;
                                    client_write.write_all(&rewritten).await?;
                                    server_to_client_bytes += (headers.len() + rewritten.len()) as u64;
                                    if !overflow.is_empty() {
                                        client_write.write_all(overflow).await?;
                                        server_to_client_bytes += overflow.len() as u64;
                                    }
                                }
                                None => {
                                    // report_only or error — send original chunked response
                                    client_write.write_all(&headers).await?;
                                client_write.write_all(&body_buffer).await?;
                                server_to_client_bytes += (headers.len() + body_buffer.len()) as u64;
                            }
                        }

                        body_rewrite_plan = None;
                        buffering_body = false;
                        buffering_chunked = false;
                        first_response_filtered = true;
                    } else if at_content_length {
                        let mut headers = deferred_headers.take().unwrap_or_default();
                        let body = &body_buffer[..expected_body_len.unwrap()];
                        let overflow = if body_buffer.len() > expected_body_len.unwrap() {
                            Some(&body_buffer[expected_body_len.unwrap()..])
                        } else {
                            None
                        };

                        match attempt_body_rewrite(body, plan, target_host, receipts_store, metrics, buffered_content_encoding.as_deref()) {
                            Some(rewritten) => {
                                headers = replace_content_length(&headers, rewritten.len());
                                client_write.write_all(&headers).await?;
                                client_write.write_all(&rewritten).await?;
                                server_to_client_bytes += (headers.len() + rewritten.len()) as u64;
                            }
                            None => {
                                client_write.write_all(&headers).await?;
                                client_write.write_all(body).await?;
                                server_to_client_bytes += (headers.len() + body.len()) as u64;
                            }
                        }
                        if let Some(extra) = overflow {
                            client_write.write_all(extra).await?;
                            server_to_client_bytes += extra.len() as u64;
                        }

                        body_rewrite_plan = None;
                        buffering_body = false;
                        first_response_filtered = true;
                    }
                } else if first_response_filtered {
                    client_write.write_all(&upstream_buf[..n]).await?;
                    server_to_client_bytes += n as u64;
                } else {
                    pending.extend_from_slice(&upstream_buf[..n]);

                    if pending.len() > MAX_HTTP1_HEADER_BYTES {
                        warn!(
                            event = "policy_filter_fallback",
                            host = target_host,
                            reason = "response_headers_too_large_or_non_http1",
                            pending_bytes = pending.len(),
                            "falling back to unmodified relay for first response"
                        );
                        client_write.write_all(&pending).await?;
                        server_to_client_bytes += pending.len() as u64;
                        pending.clear();
                        first_response_filtered = true;
                        continue;
                    }

                    if let Some(header_end) = find_headers_end(&pending) {
                        let header_block = &pending[..header_end];
                        let remainder = &pending[header_end..];
                        let outcome =
                            policy_engine.apply_http1_response_header_policy(target_host, header_block, source_ip);

                        if outcome.report_only_hit || outcome.enforcement_applied {
                            let mode = if outcome.enforcement_applied {
                                "enforce"
                            } else {
                                "report_only"
                            };
                            if outcome.consent_enforcement_active && outcome.enforcement_applied {
                                metrics.inc_consent_enforcement_blocked_total();
                            }
                            if let Some(store) = receipts_store {
                                if outcome.consent_enforcement_active {
                                    store.record_consent_enforcement(
                                        target_host,
                                        mode,
                                        outcome.set_cookie_count,
                                    );
                                } else {
                                    store.record_policy_set_cookie(
                                        target_host,
                                        mode,
                                        outcome.set_cookie_count,
                                    );
                                }
                            }
                            info!(
                                event = "policy_set_cookie_rule",
                                host = target_host,
                                mode = mode,
                                set_cookie_count = outcome.set_cookie_count,
                                tracker_match = outcome.tracker_match,
                                consent_enforcement = outcome.consent_enforcement_active,
                                consent_level = outcome.consent_level.map(|l| l.as_str()),
                                domain_category = outcome.domain_category.map(|c| c.as_str()),
                                user_profile = outcome.user_profile_name.as_deref(),
                                action = if outcome.enforcement_applied { "stripped" } else { "would_strip" },
                                "tracker Set-Cookie policy evaluated on first response headers"
                            );
                        }

                        // Strip cache-tracking response headers on tracker domains
                        let cache_stripped_headers: Option<Vec<u8>> = if outcome.tracker_match {
                            let header_str = String::from_utf8_lossy(&outcome.output_headers);
                            let mut lines: Vec<String> = header_str
                                .split("\r\n")
                                .filter(|s| !s.is_empty())
                                .map(|s| s.to_string())
                                .collect();
                            let orig_len = lines.len();
                            strip_cache_tracking_headers(&mut lines);
                            if lines.len() < orig_len {
                                info!(
                                    event = "cache_response_headers_stripped",
                                    host = target_host,
                                    "stripped cache-tracking headers from response"
                                );
                                if let Some(store) = receipts_store {
                                    store.record_cache_headers_stripped(target_host);
                                }
                                metrics.inc_cache_headers_stripped_total();
                                let mut rebuilt = lines.join("\r\n");
                                rebuilt.push_str("\r\n\r\n");
                                Some(rebuilt.into_bytes())
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        let output_headers = cache_stripped_headers.as_deref()
                            .unwrap_or(&outcome.output_headers);

                        // Check if body rewrite should be attempted
                        let bw_plan = policy_engine.plan_for_body_rewrite(target_host);
                        let content_encoding = extract_content_encoding(output_headers);
                        let encoding_ok = match content_encoding.as_deref() {
                            None | Some("identity") => true,
                            Some("gzip") | Some("x-gzip") | Some("deflate") | Some("br") => true,
                            _ => false, // zstd, unknown — skip
                        };
                        let is_chunked = has_transfer_encoding_chunked(output_headers);
                        let can_rewrite = bw_plan.should_rewrite
                            && response_is_html(output_headers)
                            && encoding_ok;

                        if can_rewrite {
                            let content_length = extract_content_length(output_headers);
                            if content_length.is_some_and(|cl| cl > bw_plan.max_body_bytes) {
                                // Content-Length exceeds max, skip body rewrite
                                metrics.inc_body_rewrite_skipped_total();
                                if let Some(store) = receipts_store { store.record_body_rewrite_skipped(target_host); }
                                client_write.write_all(output_headers).await?;
                                server_to_client_bytes += output_headers.len() as u64;
                                if !remainder.is_empty() {
                                    client_write.write_all(remainder).await?;
                                    server_to_client_bytes += remainder.len() as u64;
                                }
                            } else {
                                // Enter body buffering mode
                                deferred_headers = Some(output_headers.to_vec());
                                expected_body_len = if is_chunked { None } else { content_length };
                                body_rewrite_plan = Some(bw_plan);
                                buffering_body = true;
                                buffering_chunked = is_chunked;
                                buffered_content_encoding = content_encoding.clone();
                                body_buffer = remainder.to_vec();
                            }
                        } else {
                            client_write.write_all(output_headers).await?;
                            server_to_client_bytes += output_headers.len() as u64;
                            if !remainder.is_empty() {
                                client_write.write_all(remainder).await?;
                                server_to_client_bytes += remainder.len() as u64;
                            }
                        }

                        pending.clear();
                        first_response_filtered = true;
                    }
                }
            }
        }

        if client_closed && upstream_closed {
            break;
        }
    }

    info!(
        event = "mitm_http1_relay",
        host = target_host,
        client_to_server_bytes = client_to_server_bytes,
        server_to_client_bytes = server_to_client_bytes,
        "HTTP/1.1 MITM relay with first-response header policy completed"
    );
    Ok(())
}

fn attempt_body_rewrite(
    body: &[u8],
    plan: &policy::BodyRewritePlan,
    target_host: &str,
    receipts_store: Option<&receipts::ReceiptStore>,
    metrics: &metrics::Metrics,
    content_encoding: Option<&str>,
) -> Option<Vec<u8>> {
    attempt_body_rewrite_with_codec(
        body,
        plan,
        target_host,
        receipts_store,
        metrics,
        content_encoding,
        decompress_body,
        compress_body,
    )
}

#[allow(clippy::too_many_arguments)]
fn attempt_body_rewrite_with_codec(
    body: &[u8],
    plan: &policy::BodyRewritePlan,
    target_host: &str,
    receipts_store: Option<&receipts::ReceiptStore>,
    metrics: &metrics::Metrics,
    content_encoding: Option<&str>,
    decompress: fn(&[u8], &str) -> io::Result<Vec<u8>>,
    compress: fn(&[u8], &str) -> io::Result<Vec<u8>>,
) -> Option<Vec<u8>> {
    // Decompress if needed
    let decompressed;
    let html_bytes: &[u8] = match content_encoding {
        Some(enc @ ("gzip" | "x-gzip" | "deflate" | "br")) => match decompress(body, enc) {
            Ok(d) => {
                decompressed = d;
                &decompressed
            }
            Err(e) => {
                warn!(event = "body_decompress_error", host = target_host, encoding = enc, error = %e, "failed to decompress body, sending original");
                metrics.inc_body_rewrite_skipped_total();
                if let Some(store) = receipts_store {
                    store.record_body_rewrite_skipped(target_host);
                }
                return None;
            }
        },
        _ => body,
    };

    let mode_str = plan.mode.as_str();
    match rewrite_html_body(html_bytes, plan) {
        Ok((rewritten_html, mut details)) => {
            if plan.mode == policy::PolicyMode::ReportOnly {
                metrics.inc_body_rewrite_total();
                if let Some(store) = receipts_store {
                    // For compressed responses, we don't compute on-wire savings in report_only.
                    if content_encoding.is_none() {
                        details.bytes_saved =
                            u64::try_from(body.len().saturating_sub(rewritten_html.len()))
                                .unwrap_or(u64::MAX);
                    }
                    store.record_body_rewrite(target_host, mode_str, details);
                }
                info!(
                    event = "body_rewrite",
                    host = target_host,
                    mode = "report_only",
                    original_len = body.len(),
                    rewritten_html_len = rewritten_html.len(),
                    removed_scripts = details.removed_scripts,
                    removed_pixels = details.removed_pixels,
                    removed_cosmetic = details.removed_cosmetic,
                    bytes_saved = details.bytes_saved,
                    "body rewrite evaluated (report_only, sending original)"
                );
                None // report_only: send original
            } else {
                // Recompress if the original was compressed
                let final_body = match content_encoding {
                    Some(enc @ ("gzip" | "x-gzip" | "deflate" | "br")) => {
                        match compress(&rewritten_html, enc) {
                            Ok(compressed) => compressed,
                            Err(e) => {
                                warn!(event = "body_recompress_error", host = target_host, encoding = enc, error = %e, "failed to recompress body, sending original");
                                metrics.inc_body_rewrite_skipped_total();
                                if let Some(store) = receipts_store {
                                    store.record_body_rewrite_skipped(target_host);
                                }
                                return None;
                            }
                        }
                    }
                    _ => rewritten_html,
                };
                metrics.inc_body_rewrite_total();
                details.bytes_saved =
                    u64::try_from(body.len().saturating_sub(final_body.len())).unwrap_or(u64::MAX);
                if let Some(store) = receipts_store {
                    store.record_body_rewrite(target_host, mode_str, details);
                }
                info!(
                    event = "body_rewrite",
                    host = target_host,
                    mode = "enforce",
                    original_len = body.len(),
                    rewritten_len = final_body.len(),
                    removed_scripts = details.removed_scripts,
                    removed_pixels = details.removed_pixels,
                    removed_cosmetic = details.removed_cosmetic,
                    bytes_saved = details.bytes_saved,
                    "body rewrite applied"
                );
                Some(final_body)
            }
        }
        Err(e) => {
            metrics.inc_body_rewrite_skipped_total();
            if let Some(store) = receipts_store {
                store.record_body_rewrite_skipped(target_host);
            }
            warn!(event = "body_rewrite_error", host = target_host, error = %e, "body rewrite failed, sending original");
            None
        }
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

fn response_is_html(header_block: &[u8]) -> bool {
    let header_str = String::from_utf8_lossy(header_block);
    for line in header_str.split("\r\n") {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case("content-type") {
                return value.trim().to_ascii_lowercase().starts_with("text/html");
            }
        }
    }
    false
}

/// Extracts the Content-Encoding value (lowercased) from an HTTP header block.
/// Returns None if the header is absent.
fn extract_content_encoding(header_block: &[u8]) -> Option<String> {
    let header_str = String::from_utf8_lossy(header_block);
    for line in header_str.split("\r\n") {
        if line.to_ascii_lowercase().starts_with("content-encoding:") {
            let value = line.split_once(':')?.1.trim().to_ascii_lowercase();
            return Some(value);
        }
    }
    None
}

/// Removes the Content-Encoding header line from the header block.
#[cfg(test)]
fn strip_content_encoding_header(header_block: &[u8]) -> Vec<u8> {
    let header_str = String::from_utf8_lossy(header_block);
    let mut result = Vec::new();
    for line in header_str.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if line.to_ascii_lowercase().starts_with("content-encoding:") {
            continue;
        }
        result.extend_from_slice(line.as_bytes());
        result.extend_from_slice(b"\r\n");
    }
    result
}

/// Decompresses a body buffer using the specified Content-Encoding.
/// Supports "gzip", "deflate", and "br" (brotli). Returns the original bytes for other encodings.
fn decompress_body(body: &[u8], encoding: &str) -> io::Result<Vec<u8>> {
    use flate2::read::{DeflateDecoder, GzDecoder};
    use std::io::Read;

    match encoding {
        "gzip" | "x-gzip" => {
            let mut decoder = GzDecoder::new(body);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            Ok(decompressed)
        }
        "deflate" => {
            let mut decoder = DeflateDecoder::new(body);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            Ok(decompressed)
        }
        "br" => {
            let mut decompressed = Vec::new();
            brotli::BrotliDecompress(&mut &body[..], &mut decompressed)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(decompressed)
        }
        _ => Ok(body.to_vec()),
    }
}

/// Compresses a body buffer using the specified Content-Encoding.
/// Supports "gzip", "deflate", and "br" (brotli). Returns the original bytes for other encodings.
fn compress_body(body: &[u8], encoding: &str) -> io::Result<Vec<u8>> {
    use flate2::read::{DeflateEncoder, GzEncoder};
    use flate2::Compression;
    use std::io::{Read, Write};

    match encoding {
        "gzip" | "x-gzip" => {
            let mut encoder = GzEncoder::new(body, Compression::default());
            let mut compressed = Vec::new();
            encoder.read_to_end(&mut compressed)?;
            Ok(compressed)
        }
        "deflate" => {
            let mut encoder = DeflateEncoder::new(body, Compression::default());
            let mut compressed = Vec::new();
            encoder.read_to_end(&mut compressed)?;
            Ok(compressed)
        }
        "br" => {
            let mut compressed = Vec::new();
            {
                let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 6, 22);
                writer.write_all(body)?;
            }
            Ok(compressed)
        }
        _ => Ok(body.to_vec()),
    }
}

fn has_transfer_encoding_chunked(header_block: &[u8]) -> bool {
    let header_str = String::from_utf8_lossy(header_block).to_ascii_lowercase();
    header_str.contains("transfer-encoding:") && header_str.contains("chunked")
}

/// Attempts to decode an HTTP/1.1 chunked transfer-encoded message body.
///
/// On success, returns `(decoded_body, consumed_len)` where `consumed_len` is the number
/// of bytes consumed from `data` (including trailers and the final CRLF).
///
/// Returns `None` if the chunked body is incomplete or malformed.
fn try_decode_chunked_message(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut result = Vec::new();
    let mut pos = 0;
    loop {
        let remaining = data.get(pos..)?;
        let crlf = remaining.windows(2).position(|w| w == b"\r\n")?;
        let size_line = std::str::from_utf8(&remaining[..crlf]).ok()?;
        let size_str = size_line.split(';').next()?.trim();
        let chunk_size = usize::from_str_radix(size_str, 16).ok()?;
        pos += crlf + 2; // skip "<hex>[;ext]\r\n"

        if chunk_size == 0 {
            // Trailer part is terminated by a single CRLF. If there are trailer headers, the
            // buffer ends with "\r\n\r\n" (last header CRLF + final empty-line CRLF).
            if data.get(pos..pos + 2)? == b"\r\n" {
                pos += 2;
                return Some((result, pos));
            }
            let trailer = data.get(pos..)?;
            let end = trailer.windows(4).position(|w| w == b"\r\n\r\n")?;
            pos += end + 4;
            return Some((result, pos));
        }

        let chunk_end = pos.checked_add(chunk_size)?;
        let crlf_end = chunk_end.checked_add(2)?;
        if crlf_end > data.len() {
            return None;
        }
        result.extend_from_slice(&data[pos..chunk_end]);
        if &data[chunk_end..crlf_end] != b"\r\n" {
            return None;
        }
        pos = crlf_end;
    }
}

/// Strips headers that become invalid when the response body is modified.
fn strip_body_integrity_headers(lines: &mut Vec<String>) {
    lines.retain(|line| {
        let lower = line.to_ascii_lowercase();
        !lower.starts_with("etag:")
            && !lower.starts_with("digest:")
            && !lower.starts_with("content-md5:")
            && !lower.starts_with("accept-ranges:")
            && !lower.starts_with("trailer:")
    });
}

/// Replaces `Transfer-Encoding: chunked` with `Content-Length: <len>` in the header block.
fn replace_chunked_with_content_length(header_block: &[u8], body_len: usize) -> Vec<u8> {
    let header_str = String::from_utf8_lossy(header_block);
    let mut lines: Vec<String> = header_str
        .split("\r\n")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    // Remove headers that are incompatible with fixed-length rewritten body
    lines.retain(|line| {
        let lower = line.to_ascii_lowercase();
        !lower.starts_with("transfer-encoding:") && !lower.starts_with("content-length:")
    });
    strip_body_integrity_headers(&mut lines);

    lines.push(format!("Content-Length: {body_len}"));

    let mut result = lines.join("\r\n");
    result.push_str("\r\n\r\n");
    result.into_bytes()
}

fn extract_content_length(header_block: &[u8]) -> Option<usize> {
    let header_str = String::from_utf8_lossy(header_block);
    for line in header_str.split("\r\n") {
        if line.to_ascii_lowercase().starts_with("content-length:") {
            let value = line.split_once(':')?.1.trim();
            return value.parse().ok();
        }
    }
    None
}

fn replace_content_length(header_block: &[u8], new_length: usize) -> Vec<u8> {
    let header_str = String::from_utf8_lossy(header_block);
    let mut lines: Vec<String> = header_str
        .split("\r\n")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    lines.retain(|line| !line.to_ascii_lowercase().starts_with("content-length:"));
    strip_body_integrity_headers(&mut lines);

    lines.push(format!("Content-Length: {new_length}"));

    let mut result = lines.join("\r\n");
    result.push_str("\r\n\r\n");
    result.into_bytes()
}

fn rewrite_html_body(
    body: &[u8],
    plan: &policy::BodyRewritePlan,
) -> Result<(Vec<u8>, receipts::BodyRewriteDetails), String> {
    use lol_html::{HtmlRewriter, Settings};
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};

    let mut output = Vec::with_capacity(body.len());

    let mut pairs: Vec<(Cow<lol_html::Selector>, lol_html::ElementContentHandlers)> = Vec::new();

    fn parse_selector_cached(selector_str: &str) -> Result<lol_html::Selector, String> {
        const MAX_CACHE: usize = 50_000;
        static CACHE: OnceLock<Mutex<HashMap<String, lol_html::Selector>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

        if let Ok(mut guard) = cache.lock() {
            if let Some(sel) = guard.get(selector_str) {
                return Ok(sel.clone());
            }
            let sel: lol_html::Selector = selector_str
                .parse()
                .map_err(|e| format!("invalid CSS selector '{selector_str}': {e}"))?;
            if guard.len() < MAX_CACHE {
                guard.insert(selector_str.to_string(), sel.clone());
            }
            Ok(sel)
        } else {
            selector_str
                .parse()
                .map_err(|e| format!("invalid CSS selector '{selector_str}': {e}"))
        }
    }

    let removed_scripts = Arc::new(AtomicU64::new(0));
    let removed_pixels = Arc::new(AtomicU64::new(0));
    let removed_cosmetic = Arc::new(AtomicU64::new(0));

    // Tracker script patterns: remove <script src="..."> when src contains any configured pattern.
    //
    // This avoids generating/parsing one CSS selector per pattern, which gets expensive at EasyList scale.
    if !plan.manual_script_patterns.is_empty() || !plan.filter_script_patterns.is_empty() {
        let sel = parse_selector_cached("script[src]")?;
        let manual_patterns = Arc::clone(&plan.manual_script_patterns);
        let filter_patterns = Arc::clone(&plan.filter_script_patterns);
        let counter = Arc::clone(&removed_scripts);
        pairs.push((
            Cow::Owned(sel),
            lol_html::ElementContentHandlers::default().element(
                move |el: &mut lol_html::html_content::Element| {
                    let Some(src) = el.get_attribute("src") else {
                        return Ok(());
                    };
                    let src: &str = src.as_ref();

                    let mut matched = false;
                    for pat in manual_patterns.iter().chain(filter_patterns.iter()) {
                        if src.contains(pat) {
                            matched = true;
                            break;
                        }
                    }
                    if matched {
                        counter.fetch_add(1, Ordering::Relaxed);
                        el.remove();
                    }
                    Ok(())
                },
            ),
        ));
    }

    // Tracking pixels: <img> with width="1" height="1"
    if plan.strip_tracking_pixels {
        let sel = parse_selector_cached("img[width=\"1\"][height=\"1\"]")
            .map_err(|e| format!("pixel selector error: {e}"))?;
        let counter = Arc::clone(&removed_pixels);
        pairs.push((
            Cow::Owned(sel),
            lol_html::ElementContentHandlers::default().element(
                move |el: &mut lol_html::html_content::Element| {
                    counter.fetch_add(1, Ordering::Relaxed);
                    el.remove();
                    Ok(())
                },
            ),
        ));
    }

    // Cosmetic CSS selectors: bound the number we apply per response for safety.
    //
    // Priority order: domain-scoped selectors first, then manual config, then global filter lists.
    let total_cosmetic = plan.manual_remove_selectors.len()
        + plan.filter_remove_selectors.len()
        + plan
            .domain_remove_selectors
            .iter()
            .map(|v| v.len())
            .sum::<usize>();
    let mut cosmetic_added = 0usize;
    let cosmetic_iter = plan
        .domain_remove_selectors
        .iter()
        .flat_map(|v| v.iter())
        .chain(plan.manual_remove_selectors.iter())
        .chain(plan.filter_remove_selectors.iter())
        .map(String::as_str);

    for selector_str in cosmetic_iter {
        if cosmetic_added >= MAX_COSMETIC_SELECTORS_PER_REWRITE {
            break;
        }
        let sel = parse_selector_cached(selector_str)?;
        let counter = Arc::clone(&removed_cosmetic);
        pairs.push((
            Cow::Owned(sel),
            lol_html::ElementContentHandlers::default().element(
                move |el: &mut lol_html::html_content::Element| {
                    counter.fetch_add(1, Ordering::Relaxed);
                    el.remove();
                    Ok(())
                },
            ),
        ));
        cosmetic_added += 1;
    }
    if total_cosmetic > cosmetic_added {
        tracing::debug!(
            total = total_cosmetic,
            applied = cosmetic_added,
            cap = MAX_COSMETIC_SELECTORS_PER_REWRITE,
            "cosmetic selector cap reached; applying subset"
        );
    }

    // CSS injection: inject scroll/overflow restoration + display:none rules into <head>.
    // This defeats JavaScript that sets overflow:hidden on body to lock scrolling,
    // and hides dynamically-injected elements (registration walls, overlays, iframes)
    // that lol_html DOM removal can't catch because they're created by JS after page load.
    //
    // css_inject_selectors are configured separately from remove_selectors because
    // CSS display:none hides the element AND all descendants. Broad selectors like
    // div[class*='gateway'] can hide article content (white screen). Only specific,
    // high-precision selectors should go in css_inject_selectors.
    let has_css_inject = !plan.css_inject_selectors.is_empty();
    if cosmetic_added > 0 || has_css_inject {
        // Build display:none rules from css_inject_selectors config
        let inject_css: String = plan
            .css_inject_selectors
            .iter()
            .map(|s| format!("{s}{{display:none!important}}"))
            .collect::<Vec<_>>()
            .join("");
        // JS shim: aggressive scroll-lock prevention + overlay killing.
        // Fixes: overflow:hidden, position:fixed on body, pointer-events:none,
        // and removes high-z-index overlay divs that block interaction.
        let scroll_js = concat!(
            "<script data-pe=\"1\">(function(){",
            "function fix(){",
            "var d=document.documentElement,b=document.body;",
            "[d,b].forEach(function(el){if(!el)return;",
            "var c=getComputedStyle(el);",
            "if(c.overflow==='hidden'||c.overflow==='clip')el.style.setProperty('overflow','auto','important');",
            "if(c.overflowY==='hidden'||c.overflowY==='clip')el.style.setProperty('overflow-y','auto','important');",
            "if(c.position==='fixed')el.style.setProperty('position','static','important');",
            "if(c.pointerEvents==='none')el.style.setProperty('pointer-events','auto','important');",
            "el.style.removeProperty('touch-action');",
            "});",
            "if(b){",
            "var overlays=b.querySelectorAll('div');",
            "for(var i=0;i<overlays.length;i++){",
            "var el=overlays[i];var c=getComputedStyle(el);",
            "var z=parseInt(c.zIndex,10);",
            "if(z>999999&&(c.position==='fixed'||c.position==='absolute')){",
            "el.style.setProperty('display','none','important');",
            "}}",
            "}",
            "}",
            "var o=new MutationObserver(function(){fix()});",
            "fix();",
            "o.observe(document.documentElement,{attributes:true,attributeFilter:['style','class'],subtree:false,childList:true});",
            "var bi=setInterval(function(){",
            "if(document.body){",
            "clearInterval(bi);fix();",
            "o.observe(document.body,{attributes:true,attributeFilter:['style','class'],subtree:false,childList:true});",
            "}},20);",
            "setInterval(fix,800);",
            "})()</script>"
        );
        let style_tag = if inject_css.is_empty() {
            format!("{scroll_js}<style data-pe=\"1\">html,body{{overflow:auto!important}}</style>")
        } else {
            format!(
                "{scroll_js}<style data-pe=\"1\">html,body{{overflow:auto!important}}{inject_css}</style>"
            )
        };
        let head_sel = parse_selector_cached("head")?;
        pairs.push((
            Cow::Owned(head_sel),
            lol_html::ElementContentHandlers::default().element(
                move |el: &mut lol_html::html_content::Element| {
                    el.prepend(&style_tag, lol_html::html_content::ContentType::Html);
                    Ok(())
                },
            ),
        ));
    }

    let mut rewriter = HtmlRewriter::new(
        Settings {
            element_content_handlers: pairs,
            ..Settings::new()
        },
        |chunk: &[u8]| output.extend_from_slice(chunk),
    );

    rewriter
        .write(body)
        .map_err(|e| format!("lol_html write error: {e}"))?;
    rewriter
        .end()
        .map_err(|e| format!("lol_html end error: {e}"))?;

    Ok((
        output,
        receipts::BodyRewriteDetails {
            removed_scripts: removed_scripts.load(Ordering::Relaxed),
            removed_pixels: removed_pixels.load(Ordering::Relaxed),
            removed_cosmetic: removed_cosmetic.load(Ordering::Relaxed),
            bytes_saved: 0,
        },
    ))
}

fn root_ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "privacy-engine-rust");
    dn.push(DnType::OrganizationName, "privacy-engine-rust");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params
}

/// Normalizes the Referer header to a search-engine origin for configured domains.
/// Returns None if the buffer is not valid UTF-8 or has no headers end marker.
fn inject_google_referer(buf: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(buf).ok()?;
    let header_end = s.find("\r\n\r\n")?;
    let header_section = &s[..header_end];
    let after_headers = &s[header_end..]; // includes \r\n\r\n + body

    let mut lines: Vec<&str> = header_section.split("\r\n").collect();
    // Remove existing Referer header (case-insensitive)
    lines.retain(|line| {
        if let Some((key, _)) = line.split_once(':') {
            !key.trim().eq_ignore_ascii_case("referer")
        } else {
            true
        }
    });
    // Add Google referer
    lines.push("Referer: https://www.google.com/");

    let mut result = lines.join("\r\n");
    result.push_str(after_headers);
    Some(result.into_bytes())
}

const TRACKING_QUERY_PARAMS: &[&str] = &[
    "fbclid",
    "gclid",
    "gbraid",
    "wbraid",
    "dclid",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "_ga",
    "_gl",
    "msclkid",
    "twclid",
    "li_fat_id",
    "mc_eid",
];

/// Strip tracking query parameters from an HTTP request.
/// Returns `Some(modified)` if tracking params were found and removed, `None` otherwise.
fn strip_tracking_query_params(buf: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(buf).ok()?;
    let first_line_end = s.find("\r\n")?;
    let first_line = &s[..first_line_end];
    let rest = &s[first_line_end..]; // includes \r\n + remaining headers + body

    // Parse: "GET /path?query HTTP/1.1"
    let space1 = first_line.find(' ')?;
    let after_method = &first_line[space1 + 1..];
    let space2 = after_method.find(' ')?;
    let uri = &after_method[..space2];
    let http_version = &after_method[space2..]; // " HTTP/1.1"

    let question = uri.find('?')?;
    let path = &uri[..question];
    let query_str = &uri[question + 1..];

    let mut kept: Vec<&str> = Vec::new();
    let mut stripped_any = false;
    for param in query_str.split('&') {
        let key = param.split('=').next().unwrap_or(param);
        if TRACKING_QUERY_PARAMS
            .iter()
            .any(|t| t.eq_ignore_ascii_case(key))
        {
            stripped_any = true;
        } else {
            kept.push(param);
        }
    }

    if !stripped_any {
        return None;
    }

    let method = &first_line[..space1];
    let new_first_line = if kept.is_empty() {
        format!("{method} {path}{http_version}")
    } else {
        format!("{method} {path}?{}{http_version}", kept.join("&"))
    };

    let mut result = new_first_line;
    result.push_str(rest);
    Some(result.into_bytes())
}

/// Strip cache-based tracking headers from response header lines.
fn strip_cache_tracking_headers(lines: &mut Vec<String>) {
    lines.retain(|line| {
        let lower = line.to_ascii_lowercase();
        !lower.starts_with("last-modified:")
            && !lower.starts_with("x-cache:")
            && !lower.starts_with("x-request-id:")
    });
}

/// Strip conditional cache headers from request bytes (If-None-Match, If-Modified-Since).
/// Returns `Some(modified)` if headers were stripped, `None` otherwise.
fn strip_cache_request_headers(buf: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(buf).ok()?;
    let header_end = s.find("\r\n\r\n")?;
    let header_section = &s[..header_end];
    let after_headers = &s[header_end..];

    let mut lines: Vec<&str> = header_section.split("\r\n").collect();
    let orig_len = lines.len();
    lines.retain(|line| {
        if let Some((key, _)) = line.split_once(':') {
            let k = key.trim();
            !k.eq_ignore_ascii_case("if-none-match") && !k.eq_ignore_ascii_case("if-modified-since")
        } else {
            true
        }
    });

    if lines.len() == orig_len {
        return None;
    }

    let mut result = lines.join("\r\n");
    result.push_str(after_headers);
    Some(result.into_bytes())
}

fn request_has_websocket_upgrade(buf: &[u8]) -> bool {
    // Fast scan for "upgrade" header with "websocket" value (case-insensitive)
    let s = match std::str::from_utf8(buf) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in s.split("\r\n") {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case("upgrade")
                && value.trim().eq_ignore_ascii_case("websocket")
            {
                return true;
            }
        }
    }
    false
}

fn build_root_cert_store() -> RootCertStore {
    let mut store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let result = rustls_native_certs::load_native_certs();
    let mut added = 0u32;
    for cert in result.certs {
        if store.add(cert).is_ok() {
            added += 1;
        }
    }
    if added > 0 {
        tracing::info!(
            event = "native_certs_loaded",
            added,
            "loaded native OS root certificates"
        );
    }
    if !result.errors.is_empty() {
        tracing::warn!(
            event = "native_certs_partial",
            error_count = result.errors.len(),
            "some native OS certs failed to load"
        );
    }
    store
}

fn generate_root_ca() -> Result<(Certificate, KeyPair), MitmError> {
    let ca_key = KeyPair::generate().map_err(|e| MitmError::CertGeneration(e.to_string()))?;
    let ca_cert = root_ca_params()
        .self_signed(&ca_key)
        .map_err(|e| MitmError::CertGeneration(e.to_string()))?;
    Ok((ca_cert, ca_key))
}

fn load_or_create_ca(
    cfg: &CaFilesConfig,
) -> Result<(Certificate, KeyPair, String, CaInitMode), MitmError> {
    let cert_exists = cfg.cert_path.exists();
    let key_exists = cfg.key_path.exists();

    match (cert_exists, key_exists) {
        (true, true) => {
            let cert_pem = fs::read_to_string(&cfg.cert_path).map_err(MitmError::CaIo)?;
            let key_pem = fs::read_to_string(&cfg.key_path).map_err(MitmError::CaIo)?;
            if !cert_pem.contains("BEGIN CERTIFICATE") {
                return Err(MitmError::CaConfig(format!(
                    "CA cert file does not look like PEM: '{}'",
                    cfg.cert_path.display()
                )));
            }

            let ca_key =
                KeyPair::from_pem(&key_pem).map_err(|e| MitmError::CaConfig(e.to_string()))?;
            let ca_cert = root_ca_params()
                .self_signed(&ca_key)
                .map_err(|e| MitmError::CaConfig(e.to_string()))?;

            Ok((ca_cert, ca_key, cert_pem, CaInitMode::LoadedFromFiles))
        }
        (false, false) => {
            if !cfg.generate_if_missing {
                return Err(MitmError::CaConfig(format!(
                    "CA files missing and auto-generation disabled: cert='{}' key='{}'",
                    cfg.cert_path.display(),
                    cfg.key_path.display()
                )));
            }

            let (ca_cert, ca_key) = generate_root_ca()?;
            persist_ca_files(cfg, &ca_cert, &ca_key)?;
            let ca_cert_pem = ca_cert.pem();
            Ok((
                ca_cert,
                ca_key,
                ca_cert_pem,
                CaInitMode::GeneratedAndPersisted,
            ))
        }
        _ => Err(MitmError::CaConfig(format!(
            "Partial CA file state detected (both cert and key are required): cert='{}' key='{}'",
            cfg.cert_path.display(),
            cfg.key_path.display()
        ))),
    }
}

fn persist_ca_files(
    cfg: &CaFilesConfig,
    ca_cert: &Certificate,
    ca_key: &KeyPair,
) -> Result<(), MitmError> {
    if let Some(parent) = cfg.cert_path.parent() {
        fs::create_dir_all(parent).map_err(MitmError::CaIo)?;
    }
    if let Some(parent) = cfg.key_path.parent() {
        fs::create_dir_all(parent).map_err(MitmError::CaIo)?;
    }

    fs::write(&cfg.cert_path, ca_cert.pem()).map_err(MitmError::CaIo)?;
    fs::write(&cfg.key_path, ca_key.serialize_pem()).map_err(MitmError::CaIo)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn mitm_engine_builds_server_config_for_dns_host() {
        let engine = MitmEngine::new(None, TlsProfile::Default, None, None).expect("new engine");
        let _cfg = engine
            .server_config_for_host("example.com", false)
            .expect("server config");
    }

    #[test]
    fn server_config_alpn_differs_for_forced_http1() {
        let engine = MitmEngine::new(None, TlsProfile::Default, None, None).expect("new engine");
        let h1 = engine
            .server_config_for_host("example.com", true)
            .expect("server config h1");
        let h2 = engine
            .server_config_for_host("example.com", false)
            .expect("server config h2h1");

        let h1_alpn: HashSet<Vec<u8>> = h1.alpn_protocols.iter().cloned().collect();
        assert!(h1_alpn.contains(&b"http/1.1".to_vec()));
        assert!(!h1_alpn.contains(&b"h2".to_vec()));

        let h2_alpn: HashSet<Vec<u8>> = h2.alpn_protocols.iter().cloned().collect();
        assert!(h2_alpn.contains(&b"http/1.1".to_vec()));
        assert!(h2_alpn.contains(&b"h2".to_vec()));
    }

    fn temp_file(prefix: &str, suffix: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}_{ts}.{suffix}"))
    }

    #[test]
    fn ca_files_are_generated_and_then_loaded() {
        let cert_path = temp_file("mitm_ca_cert", "pem");
        let key_path = temp_file("mitm_ca_key", "pem");
        let cfg = CaFilesConfig {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
            generate_if_missing: true,
        };

        let engine_generated =
            MitmEngine::new(Some(&cfg), TlsProfile::Default, None, None).expect("generated");
        assert_eq!(
            engine_generated.ca_init_mode(),
            CaInitMode::GeneratedAndPersisted
        );
        assert!(cert_path.exists());
        assert!(key_path.exists());

        let engine_loaded =
            MitmEngine::new(Some(&cfg), TlsProfile::Default, None, None).expect("loaded");
        assert_eq!(engine_loaded.ca_init_mode(), CaInitMode::LoadedFromFiles);
    }

    #[test]
    fn mitm_engine_builds_with_chrome_profile() {
        let engine =
            MitmEngine::new(None, TlsProfile::Chrome, None, None).expect("new engine with chrome");
        let _cfg = engine
            .server_config_for_host("example.com", false)
            .expect("server config");
    }

    #[test]
    fn chrome_profile_cipher_suite_order() {
        use rustls::CipherSuite;
        let suites = TlsProfile::Chrome.cipher_suites();
        let ids: Vec<CipherSuite> = suites.iter().map(|s| s.suite()).collect();
        // Chrome sends AES_128 before AES_256 for TLS 1.3
        let pos_128 = ids
            .iter()
            .position(|s| *s == CipherSuite::TLS13_AES_128_GCM_SHA256)
            .expect("TLS13_AES_128");
        let pos_256 = ids
            .iter()
            .position(|s| *s == CipherSuite::TLS13_AES_256_GCM_SHA384)
            .expect("TLS13_AES_256");
        assert!(
            pos_128 < pos_256,
            "Chrome profile should prefer AES_128 before AES_256 for TLS 1.3"
        );
    }

    #[test]
    fn default_profile_cipher_suite_order() {
        use rustls::CipherSuite;
        let suites = TlsProfile::Default.cipher_suites();
        let ids: Vec<CipherSuite> = suites.iter().map(|s| s.suite()).collect();
        // Default rustls ordering has AES_256 before AES_128 for TLS 1.3
        let pos_256 = ids
            .iter()
            .position(|s| *s == CipherSuite::TLS13_AES_256_GCM_SHA384)
            .expect("TLS13_AES_256");
        let pos_128 = ids
            .iter()
            .position(|s| *s == CipherSuite::TLS13_AES_128_GCM_SHA256)
            .expect("TLS13_AES_128");
        assert!(
            pos_256 < pos_128,
            "Default profile should have AES_256 before AES_128 for TLS 1.3"
        );
    }

    #[test]
    fn tls_profile_as_str() {
        assert_eq!(TlsProfile::Default.as_str(), "default");
        assert_eq!(TlsProfile::Chrome.as_str(), "chrome");
    }

    #[test]
    fn chrome_profile_kx_group_order() {
        use rustls::NamedGroup;
        let groups = TlsProfile::Chrome.kx_group_ids();
        // Chrome: X25519 first, then P-256, then P-384
        assert_eq!(
            groups,
            vec![
                NamedGroup::X25519,
                NamedGroup::secp256r1,
                NamedGroup::secp384r1
            ],
            "Chrome profile should use X25519, P-256, P-384 in that order"
        );
    }

    #[test]
    fn cert_log_records_generated_certs() {
        let dir = std::env::temp_dir();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let log_path = dir.join(format!("cert_log_test_{ts}.jsonl"));
        let cert_log = Arc::new(CertLog::open(&log_path).expect("open cert log"));
        let engine =
            MitmEngine::new(None, TlsProfile::Default, Some(cert_log), None).expect("new engine");
        let _cfg = engine
            .server_config_for_host("example.com", false)
            .expect("server config");
        let _cfg2 = engine
            .server_config_for_host("test.org", false)
            .expect("server config 2");
        // example.com is cached, test.org is new — should have 2 log entries
        let contents = std::fs::read_to_string(&log_path).expect("read log");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "should have 2 cert log entries");
        let entry: serde_json::Value = serde_json::from_str(lines[0]).expect("parse json");
        assert_eq!(entry["host"], "example.com");
        assert!(entry["fingerprint_sha256"].as_str().unwrap().contains(":"));
        let entry2: serde_json::Value = serde_json::from_str(lines[1]).expect("parse json");
        assert_eq!(entry2["host"], "test.org");
        let _ = std::fs::remove_file(&log_path);
    }

    #[test]
    fn chrome_profile_describe_is_nonempty() {
        let desc = TlsProfile::Chrome.describe();
        assert!(desc.contains("Chrome"), "describe should mention Chrome");
        assert!(desc.contains("X25519"), "describe should mention X25519");
    }

    #[test]
    fn benign_peer_close_detects_unexpected_eof() {
        let err = MitmError::Relay(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
        assert!(err.is_benign_peer_close());
    }

    #[test]
    fn benign_peer_close_detects_close_notify_message() {
        let err = MitmError::Relay(io::Error::other(
            "peer closed connection without sending TLS close_notify",
        ));
        assert!(err.is_benign_peer_close());
    }

    // --- Body rewriting helper tests ---

    fn make_body_rewrite_plan(
        mode: policy::PolicyMode,
        script_patterns: &[&str],
        remove_selectors: &[&str],
        strip_tracking_pixels: bool,
    ) -> policy::BodyRewritePlan {
        make_body_rewrite_plan_with_css(
            mode,
            script_patterns,
            remove_selectors,
            &[],
            strip_tracking_pixels,
        )
    }

    fn make_body_rewrite_plan_with_css(
        mode: policy::PolicyMode,
        script_patterns: &[&str],
        remove_selectors: &[&str],
        css_inject_selectors: &[&str],
        strip_tracking_pixels: bool,
    ) -> policy::BodyRewritePlan {
        use std::sync::Arc;
        policy::BodyRewritePlan {
            mode,
            should_rewrite: true,
            manual_script_patterns: Arc::new(
                script_patterns
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>(),
            ),
            filter_script_patterns: Arc::new(Vec::new()),
            manual_remove_selectors: Arc::new(
                remove_selectors
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>(),
            ),
            filter_remove_selectors: Arc::new(Vec::new()),
            domain_remove_selectors: Vec::new(),
            css_inject_selectors: Arc::new(
                css_inject_selectors
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>(),
            ),
            strip_tracking_pixels,
            max_body_bytes: 2 * 1024 * 1024,
            referer_spoof: false,
            query_param_strip: false,
        }
    }

    #[test]
    fn response_is_html_detects_text_html() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n";
        assert!(response_is_html(headers));
    }

    #[test]
    fn response_is_html_rejects_json() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
        assert!(!response_is_html(headers));
    }

    #[test]
    fn response_is_html_rejects_javascript() {
        let headers =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript; charset=utf-8\r\n\r\n";
        assert!(!response_is_html(headers));
    }

    #[test]
    fn response_is_html_ignores_text_html_in_other_headers() {
        // text/html appearing in a Link header or other non-Content-Type context
        let headers =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nLink: <https://example.com>; type=\"text/html\"\r\n\r\n";
        assert!(!response_is_html(headers));
    }

    #[test]
    fn extract_content_encoding_detects_gzip_in_headers() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n";
        assert_eq!(extract_content_encoding(headers), Some("gzip".to_string()));
    }

    #[test]
    fn extract_content_encoding_absent_returns_none() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        assert_eq!(extract_content_encoding(headers), None);
    }

    #[test]
    fn extract_content_length_parses_value() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n";
        assert_eq!(extract_content_length(headers), Some(1234));
    }

    #[test]
    fn extract_content_length_missing_returns_none() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        assert_eq!(extract_content_length(headers), None);
    }

    #[test]
    fn replace_content_length_updates_value() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\nServer: test\r\n\r\n";
        let updated = replace_content_length(headers, 999);
        let s = String::from_utf8(updated).unwrap();
        assert!(s.contains("Content-Length: 999"));
        assert!(s.contains("Server: test"));
        assert!(!s.contains("1234"));
    }

    #[test]
    fn rewrite_html_body_strips_tracker_script() {
        let html = br#"<html><head><script src="https://google-analytics.com/analytics.js"></script></head><body>Hello</body></html>"#;
        let plan = make_body_rewrite_plan(
            policy::PolicyMode::Enforce,
            &["google-analytics.com/analytics.js"],
            &[],
            false,
        );
        let (result, details) = rewrite_html_body(html, &plan).expect("rewrite");
        let result_str = String::from_utf8(result).unwrap();
        assert_eq!(details.removed_scripts, 1, "should remove one script");
        assert!(
            !result_str.contains("google-analytics.com"),
            "tracker script should be removed"
        );
        assert!(result_str.contains("Hello"), "page content should remain");
    }

    #[test]
    fn rewrite_html_body_strips_tracking_pixel() {
        let html = br#"<html><body>Hello<img width="1" height="1" src="https://tracker.com/pixel.gif"></body></html>"#;
        let plan = make_body_rewrite_plan(policy::PolicyMode::Enforce, &[], &[], true);
        let (result, details) = rewrite_html_body(html, &plan).expect("rewrite");
        let result_str = String::from_utf8(result).unwrap();
        assert_eq!(details.removed_pixels, 1, "should remove one pixel");
        assert!(
            !result_str.contains("pixel.gif"),
            "tracking pixel should be removed"
        );
        assert!(result_str.contains("Hello"), "page content should remain");
    }

    #[test]
    fn rewrite_html_body_strips_css_selector() {
        let html =
            br#"<html><body><div id="google_ads_123">Ad here</div><p>Content</p></body></html>"#;
        let plan = make_body_rewrite_plan(
            policy::PolicyMode::Enforce,
            &[],
            &["div[id^=\"google_ads\"]"],
            false,
        );
        let (result, details) = rewrite_html_body(html, &plan).expect("rewrite");
        let result_str = String::from_utf8(result).unwrap();
        assert_eq!(
            details.removed_cosmetic, 1,
            "should remove one cosmetic element"
        );
        assert!(!result_str.contains("Ad here"), "ad div should be removed");
        assert!(
            result_str.contains("Content"),
            "non-ad content should remain"
        );
    }

    #[test]
    fn has_transfer_encoding_chunked_detects_chunked() {
        let headers = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(has_transfer_encoding_chunked(headers));
    }

    #[test]
    fn has_transfer_encoding_chunked_absent_returns_false() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        assert!(!has_transfer_encoding_chunked(headers));
    }

    // --- Gzip/deflate/brotli decompression tests ---

    #[test]
    fn decompress_gzip_roundtrip() {
        let original = b"<html><body>Hello, world!</body></html>";
        let compressed = compress_body(original, "gzip").expect("compress");
        assert_ne!(
            compressed,
            original.to_vec(),
            "compressed should differ from original"
        );
        let decompressed = decompress_body(&compressed, "gzip").expect("decompress");
        assert_eq!(decompressed, original.to_vec());
    }

    #[test]
    fn decompress_deflate_roundtrip() {
        let original = b"<html><body>Hello, deflate!</body></html>";
        let compressed = compress_body(original, "deflate").expect("compress");
        assert_ne!(
            compressed,
            original.to_vec(),
            "compressed should differ from original"
        );
        let decompressed = decompress_body(&compressed, "deflate").expect("decompress");
        assert_eq!(decompressed, original.to_vec());
    }

    #[test]
    fn decompress_brotli_roundtrip() {
        let original = b"<html><body>Hello, brotli!</body></html>";
        let compressed = compress_body(original, "br").expect("compress");
        assert_ne!(
            compressed,
            original.to_vec(),
            "compressed should differ from original"
        );
        let decompressed = decompress_body(&compressed, "br").expect("decompress");
        assert_eq!(decompressed, original.to_vec());
    }

    #[test]
    fn rewrite_brotli_html_body() {
        let html = b"<html><head><script src=\"https://google-analytics.com/analytics.js\"></script></head><body>Hello</body></html>";
        let compressed = compress_body(html, "br").expect("compress");
        let plan = make_body_rewrite_plan(
            policy::PolicyMode::Enforce,
            &["google-analytics.com/analytics.js"],
            &[],
            false,
        );
        let metrics = metrics::Metrics::default();
        let result = attempt_body_rewrite(
            &compressed,
            &plan,
            "example.com",
            None,
            &metrics,
            Some("br"),
        );
        let rewritten_compressed = result.expect("should produce rewritten body");
        let rewritten = decompress_body(&rewritten_compressed, "br").expect("decompress result");
        let rewritten_str = String::from_utf8(rewritten).unwrap();
        assert!(
            !rewritten_str.contains("google-analytics.com"),
            "tracker script should be removed"
        );
        assert!(
            rewritten_str.contains("Hello"),
            "page content should remain"
        );
    }

    #[test]
    fn rewrite_gzipped_html_body() {
        let html = b"<html><head><script src=\"https://google-analytics.com/analytics.js\"></script></head><body>Hello</body></html>";
        let compressed = compress_body(html, "gzip").expect("compress");
        let plan = make_body_rewrite_plan(
            policy::PolicyMode::Enforce,
            &["google-analytics.com/analytics.js"],
            &[],
            false,
        );
        let metrics = metrics::Metrics::default();
        let result = attempt_body_rewrite(
            &compressed,
            &plan,
            "example.com",
            None,
            &metrics,
            Some("gzip"),
        );
        let rewritten_compressed = result.expect("should produce rewritten body");
        let rewritten = decompress_body(&rewritten_compressed, "gzip").expect("decompress result");
        let rewritten_str = String::from_utf8(rewritten).unwrap();
        assert!(
            !rewritten_str.contains("google-analytics.com"),
            "tracker script should be removed"
        );
        assert!(
            rewritten_str.contains("Hello"),
            "page content should remain"
        );
    }

    #[test]
    fn rewrite_recompress_error_counts_as_skipped() {
        fn fail_compress(_body: &[u8], _encoding: &str) -> io::Result<Vec<u8>> {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "forced compress failure",
            ))
        }

        let html = b"<html><head><script src=\"https://google-analytics.com/analytics.js\"></script></head><body>Hello</body></html>";
        let compressed = compress_body(html, "gzip").expect("compress");
        let plan = make_body_rewrite_plan(
            policy::PolicyMode::Enforce,
            &["google-analytics.com/analytics.js"],
            &[],
            false,
        );
        let metrics = metrics::Metrics::default();
        let result = attempt_body_rewrite_with_codec(
            &compressed,
            &plan,
            "example.com",
            None,
            &metrics,
            Some("gzip"),
            decompress_body,
            fail_compress,
        );
        assert!(
            result.is_none(),
            "should fall back to sending original body"
        );
        let s = metrics.snapshot();
        assert_eq!(s.body_rewrite_total, 0, "should not count as rewrite_total");
        assert_eq!(s.body_rewrite_skipped_total, 1, "should count as skipped");
    }

    // --- Chunked transfer-encoding tests ---

    #[test]
    fn decode_chunked_simple() {
        // "Hello" in one chunk
        let chunked = b"5\r\nHello\r\n0\r\n\r\n";
        let (decoded, consumed) = try_decode_chunked_message(chunked).expect("should decode");
        assert_eq!(decoded, b"Hello");
        assert_eq!(consumed, chunked.len());
    }

    #[test]
    fn decode_chunked_multiple_chunks() {
        let chunked = b"5\r\nHello\r\n7\r\n, World\r\n0\r\n\r\n";
        let (decoded, consumed) = try_decode_chunked_message(chunked).expect("should decode");
        assert_eq!(decoded, b"Hello, World");
        assert_eq!(consumed, chunked.len());
    }

    #[test]
    fn decode_chunked_incomplete_returns_none() {
        let chunked = b"5\r\nHel";
        assert!(try_decode_chunked_message(chunked).is_none());
    }

    #[test]
    fn decode_chunked_with_extensions() {
        // Chunk extensions after size (RFC 7230 §4.1.1)
        let chunked = b"5;ext=val\r\nHello\r\n0\r\n\r\n";
        let (decoded, consumed) =
            try_decode_chunked_message(chunked).expect("should decode with extensions");
        assert_eq!(decoded, b"Hello");
        assert_eq!(consumed, chunked.len());
    }

    #[test]
    fn decode_chunked_with_trailers() {
        let chunked = b"5\r\nHello\r\n0\r\nExpires: Wed, 21 Oct 2015 07:28:00 GMT\r\n\r\n";
        let (decoded, consumed) =
            try_decode_chunked_message(chunked).expect("should decode with trailers");
        assert_eq!(decoded, b"Hello");
        assert_eq!(consumed, chunked.len());
    }

    #[test]
    fn try_decode_chunked_message_detects_terminal() {
        assert!(try_decode_chunked_message(b"5\r\nHello\r\n0\r\n\r\n").is_some());
        assert!(try_decode_chunked_message(b"5\r\nHello\r\n").is_none());
        assert!(try_decode_chunked_message(b"").is_none());
    }

    #[test]
    fn replace_chunked_headers_with_content_length() {
        let headers =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html\r\n\r\n";
        let result = replace_chunked_with_content_length(headers, 42);
        let result_str = String::from_utf8(result).unwrap();
        assert!(
            result_str.contains("Content-Length: 42"),
            "should have Content-Length"
        );
        assert!(
            !result_str
                .to_ascii_lowercase()
                .contains("transfer-encoding"),
            "should not have Transfer-Encoding"
        );
        assert!(
            result_str.contains("Content-Type: text/html"),
            "should preserve other headers"
        );
    }

    #[test]
    fn extract_content_encoding_gzip() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n";
        assert_eq!(extract_content_encoding(headers), Some("gzip".to_string()));
    }

    #[test]
    fn extract_content_encoding_deflate() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\n\r\n";
        assert_eq!(
            extract_content_encoding(headers),
            Some("deflate".to_string())
        );
    }

    #[test]
    fn extract_content_encoding_none() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        assert_eq!(extract_content_encoding(headers), None);
    }

    #[test]
    fn extract_content_encoding_br() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n\r\n";
        assert_eq!(extract_content_encoding(headers), Some("br".to_string()));
    }

    #[test]
    fn strip_content_encoding_removes_header() {
        let headers =
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: text/html\r\n\r\n";
        let stripped = strip_content_encoding_header(headers);
        let stripped_str = String::from_utf8(stripped).unwrap();
        assert!(
            !stripped_str
                .to_ascii_lowercase()
                .contains("content-encoding"),
            "Content-Encoding header should be removed"
        );
        assert!(
            stripped_str.contains("Content-Type: text/html"),
            "other headers should remain"
        );
    }

    #[test]
    fn replace_content_length_strips_integrity_headers() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nETag: \"abc\"\r\nDigest: sha-256=xyz\r\nAccept-Ranges: bytes\r\n\r\n";
        let result = replace_content_length(headers, 50);
        let s = String::from_utf8(result).unwrap();
        assert!(s.contains("Content-Length: 50"));
        assert!(!s.contains("ETag:"));
        assert!(!s.contains("Digest:"));
        assert!(!s.contains("Accept-Ranges:"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn websocket_upgrade_detected() {
        let req = b"GET /ws HTTP/1.1\r\nHost: tracker.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        assert!(request_has_websocket_upgrade(req));
    }

    #[test]
    fn websocket_upgrade_case_insensitive() {
        let req =
            b"GET /ws HTTP/1.1\r\nHost: x.com\r\nUPGRADE: WebSocket\r\nConnection: Upgrade\r\n\r\n";
        assert!(request_has_websocket_upgrade(req));
    }

    #[test]
    fn normal_request_not_websocket() {
        let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n";
        assert!(!request_has_websocket_upgrade(req));
    }

    // --- Referer spoofing tests ---

    #[test]
    fn inject_google_referer_adds_header() {
        let req = b"GET /article HTTP/1.1\r\nHost: nytimes.com\r\nAccept: text/html\r\n\r\n";
        let modified = inject_google_referer(req).expect("should modify");
        let s = String::from_utf8(modified).unwrap();
        assert!(s.contains("Referer: https://www.google.com/"));
        assert!(s.contains("Host: nytimes.com"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn inject_google_referer_replaces_existing() {
        let req = b"GET /article HTTP/1.1\r\nHost: nytimes.com\r\nReferer: https://old.com/\r\nAccept: text/html\r\n\r\n";
        let modified = inject_google_referer(req).expect("should modify");
        let s = String::from_utf8(modified).unwrap();
        assert!(s.contains("Referer: https://www.google.com/"));
        assert!(!s.contains("https://old.com/"));
    }

    #[test]
    fn inject_google_referer_preserves_body() {
        let req = b"POST /login HTTP/1.1\r\nHost: nytimes.com\r\nContent-Length: 5\r\n\r\nhello";
        let modified = inject_google_referer(req).expect("should modify");
        let s = String::from_utf8(modified).unwrap();
        assert!(s.contains("Referer: https://www.google.com/"));
        assert!(s.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn css_injection_adds_scroll_restoration_to_head() {
        let html = br#"<html><head><title>Test</title></head><body><div class="paywall-overlay">Block</div><p>Content</p></body></html>"#;
        let plan = make_body_rewrite_plan(
            policy::PolicyMode::Enforce,
            &[],
            &["div[class*='paywall-overlay']"],
            false,
        );
        let (result, details) = rewrite_html_body(html, &plan).expect("rewrite");
        let result_str = String::from_utf8(result).unwrap();
        // CSS injection should add scroll restoration only (no display:none rules)
        assert!(
            result_str.contains("data-pe=\"1\""),
            "should inject style block with data-pe marker"
        );
        assert!(
            result_str.contains("overflow:auto!important"),
            "should contain scroll restoration rule"
        );
        assert!(
            !result_str.contains("display:none"),
            "should NOT contain display:none rules (DOM removal handles that)"
        );
        // DOM removal should also work
        assert_eq!(
            details.removed_cosmetic, 1,
            "should remove one cosmetic element"
        );
        assert!(
            !result_str.contains("Block"),
            "overlay div should be removed"
        );
        assert!(result_str.contains("Content"), "page content should remain");
    }

    #[test]
    fn css_injection_includes_display_none_for_css_inject_selectors() {
        let html = br#"<html><head><title>Test</title></head><body><p>Content</p></body></html>"#;
        let plan = make_body_rewrite_plan_with_css(
            policy::PolicyMode::Enforce,
            &[],
            &["div[class*='paywall']"],
            &["div.vi-gateway-container", "iframe[src*='regiwall']"],
            false,
        );
        let (result, _details) = rewrite_html_body(html, &plan).expect("rewrite");
        let result_str = String::from_utf8(result).unwrap();
        // css_inject_selectors should get display:none CSS
        assert!(
            result_str.contains("div.vi-gateway-container{display:none!important}"),
            "should inject display:none for gateway container: {result_str}"
        );
        assert!(
            result_str.contains("iframe[src*='regiwall']{display:none!important}"),
            "should inject display:none for iframe regiwall selector"
        );
        // remove_selectors should NOT appear in CSS
        assert!(
            !result_str.contains("div[class*='paywall']{display:none"),
            "remove_selectors should NOT get CSS injection"
        );
    }

    #[test]
    fn css_inject_selectors_work_without_cosmetic_selectors() {
        // css_inject_selectors should inject even when no remove_selectors exist
        let html = br#"<html><head><title>Test</title></head><body><p>Content</p></body></html>"#;
        let plan = make_body_rewrite_plan_with_css(
            policy::PolicyMode::Enforce,
            &[],
            &[],
            &["div#gateway-content"],
            false,
        );
        let (result, _details) = rewrite_html_body(html, &plan).expect("rewrite");
        let result_str = String::from_utf8(result).unwrap();
        assert!(
            result_str.contains("div#gateway-content{display:none!important}"),
            "should inject CSS even without cosmetic selectors: {result_str}"
        );
    }

    #[test]
    fn css_injection_skipped_when_no_cosmetic_selectors() {
        let html = br#"<html><head><title>Test</title></head><body>Content</body></html>"#;
        let plan = make_body_rewrite_plan(
            policy::PolicyMode::Enforce,
            &["google-analytics.com/analytics.js"],
            &[],
            false,
        );
        let (result, _details) = rewrite_html_body(html, &plan).expect("rewrite");
        let result_str = String::from_utf8(result).unwrap();
        assert!(
            !result_str.contains("data-pe"),
            "should NOT inject style block when no cosmetic selectors"
        );
    }

    #[test]
    fn strip_tracking_params_removes_fbclid() {
        let req = b"GET /article?fbclid=abc123 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = strip_tracking_query_params(req).expect("should strip");
        let s = String::from_utf8(result).unwrap();
        assert!(s.starts_with("GET /article HTTP/1.1\r\n"), "got: {s}");
        assert!(!s.contains("fbclid"));
    }

    #[test]
    fn strip_tracking_params_preserves_non_tracking() {
        let req = b"GET /article?page=2 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(strip_tracking_query_params(req).is_none());
    }

    #[test]
    fn strip_tracking_params_mixed_params() {
        let req =
            b"GET /article?fbclid=abc&page=2&utm_source=test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = strip_tracking_query_params(req).expect("should strip");
        let s = String::from_utf8(result).unwrap();
        assert!(
            s.starts_with("GET /article?page=2 HTTP/1.1\r\n"),
            "got: {s}"
        );
        assert!(!s.contains("fbclid"));
        assert!(!s.contains("utm_source"));
    }

    #[test]
    fn strip_tracking_params_no_query_returns_none() {
        let req = b"GET /article HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(strip_tracking_query_params(req).is_none());
    }

    #[test]
    fn strip_cache_response_headers_removes_tracking() {
        let mut lines = vec![
            "HTTP/1.1 200 OK".to_string(),
            "Content-Type: text/html".to_string(),
            "Last-Modified: Tue, 01 Jan 2025 00:00:00 GMT".to_string(),
            "X-Cache: HIT".to_string(),
            "X-Request-Id: abc123".to_string(),
        ];
        strip_cache_tracking_headers(&mut lines);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("HTTP/1.1"));
        assert!(lines[1].starts_with("Content-Type"));
    }

    #[test]
    fn strip_cache_request_headers_removes_conditional() {
        let req = b"GET /page HTTP/1.1\r\nHost: tracker.com\r\nIf-None-Match: \"abc\"\r\nIf-Modified-Since: Mon, 01 Jan 2024 00:00:00 GMT\r\n\r\n";
        let result = strip_cache_request_headers(req).expect("should strip");
        let s = String::from_utf8(result).unwrap();
        assert!(!s.contains("If-None-Match"));
        assert!(!s.contains("If-Modified-Since"));
        assert!(s.contains("Host: tracker.com"));
    }
}
