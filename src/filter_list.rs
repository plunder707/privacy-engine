/// Filter list orchestrator: download, cache, parse, aggregate, and refresh.
///
/// Manages multiple filter list sources (local files or URLs), aggregates
/// parsed rules into a single `FilterListRules` struct, and provides a
/// background refresh task for periodic re-downloads.
use crate::filter_list_parser::{self, ParseStats, ParsedRule};
use hyper::Uri;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};

/// Aggregated rules from all filter lists, ready for policy engine consumption.
#[derive(Debug, Clone, Default)]
pub struct FilterListRules {
    /// Domains to block at DNS level and strip cookies for.
    pub block_domains: HashSet<String>,
    /// URL path patterns to match for body rewrite script removal.
    pub tracker_script_patterns: Arc<Vec<String>>,
    /// Global CSS selectors to remove from all pages.
    pub cosmetic_selectors: Arc<Vec<String>>,
    /// Domain-scoped CSS selectors (domain → selectors).
    pub domain_cosmetic_map: HashMap<String, Arc<Vec<String>>>,
    /// Exception domains that override filter-list blocks (NOT manual config).
    pub exception_domains: HashSet<String>,
    /// Aggregate stats from parsing.
    pub stats: FilterListAggregateStats,
}

/// Aggregate statistics across all filter list sources.
#[derive(Debug, Clone, Default)]
pub struct FilterListAggregateStats {
    pub source_count: usize,
    pub total_lines: usize,
    pub domain_blocks: usize,
    pub url_patterns: usize,
    pub cosmetic_global: usize,
    pub cosmetic_domain_scoped: usize,
    pub exceptions: usize,
    pub skipped_unsupported: usize,
    pub skipped_comments: usize,
}

/// Describes a filter list source (local file or remote URL).
#[derive(Debug, Clone)]
pub struct FilterListSource {
    pub origin: String,
    pub kind: FilterListSourceKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterListSourceKind {
    LocalFile,
    Url,
}

impl FilterListSource {
    pub fn local_file(path: impl Into<String>) -> Self {
        Self {
            origin: path.into(),
            kind: FilterListSourceKind::LocalFile,
        }
    }

    pub fn url(url: impl Into<String>) -> Self {
        Self {
            origin: url.into(),
            kind: FilterListSourceKind::Url,
        }
    }
}

/// Aggregate parsed rules from multiple sources into a single `FilterListRules`.
pub fn aggregate_rules(all_results: &[(Vec<ParsedRule>, ParseStats)]) -> FilterListRules {
    let mut rules = FilterListRules::default();
    let mut tracker_script_patterns: Vec<String> = Vec::new();
    let mut cosmetic_selectors: Vec<String> = Vec::new();
    let mut domain_cosmetic_map: HashMap<String, Vec<String>> = HashMap::new();
    rules.stats.source_count = all_results.len();

    for (parsed_rules, stats) in all_results {
        rules.stats.total_lines += stats.total_lines;
        rules.stats.domain_blocks += stats.domain_blocks;
        rules.stats.url_patterns += stats.url_patterns;
        rules.stats.cosmetic_global += stats.cosmetic_global;
        rules.stats.cosmetic_domain_scoped += stats.cosmetic_domain_scoped;
        rules.stats.exceptions += stats.exceptions;
        rules.stats.skipped_unsupported += stats.skipped_unsupported;
        rules.stats.skipped_comments += stats.skipped_comments;

        for rule in parsed_rules {
            match rule {
                ParsedRule::DomainBlock { domain } => {
                    rules.block_domains.insert(domain.clone());
                }
                ParsedRule::UrlPattern { domain, path } => {
                    // Keep domain context to avoid overbroad path-only matches.
                    tracker_script_patterns.push(format!("{domain}{path}"));
                }
                ParsedRule::CosmeticGlobal { selector } => {
                    cosmetic_selectors.push(selector.clone());
                }
                ParsedRule::CosmeticDomainScoped { domain, selector } => {
                    domain_cosmetic_map
                        .entry(domain.clone())
                        .or_default()
                        .push(selector.clone());
                }
                ParsedRule::Exception { domain } => {
                    rules.exception_domains.insert(domain.clone());
                }
            }
        }
    }

    tracker_script_patterns.sort();
    tracker_script_patterns.dedup();
    cosmetic_selectors.sort();
    cosmetic_selectors.dedup();
    for selectors in domain_cosmetic_map.values_mut() {
        selectors.sort();
        selectors.dedup();
    }

    rules.tracker_script_patterns = Arc::new(tracker_script_patterns);
    rules.cosmetic_selectors = Arc::new(cosmetic_selectors);
    rules.domain_cosmetic_map = domain_cosmetic_map
        .into_iter()
        .map(|(k, v)| (k, Arc::new(v)))
        .collect();

    rules
}

const MAX_DOWNLOAD_BYTES: usize = 32 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone)]
struct ParsedUrl {
    scheme: String,
    host: String,
    port: u16,
    path_and_query: String,
}

#[derive(Debug)]
struct Downloaded {
    status_code: u16,
    location: Option<String>,
    body: Vec<u8>,
}

fn parse_url(url: &str) -> io::Result<ParsedUrl> {
    let uri: Uri = url.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid URL '{url}': {e}"),
        )
    })?;
    let scheme = uri.scheme_str().unwrap_or("http").to_ascii_lowercase();
    let host = uri
        .host()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URL missing host"))?
        .to_string();
    let port = uri
        .port_u16()
        .unwrap_or_else(|| if scheme == "https" { 443 } else { 80 });
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    Ok(ParsedUrl {
        scheme,
        host,
        port,
        path_and_query,
    })
}

fn resolve_redirect(base: &ParsedUrl, location: &str) -> io::Result<String> {
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(location.to_string());
    }
    if location.starts_with('/') {
        let default_port = if base.scheme == "https" { 443 } else { 80 };
        let port_part = if base.port == default_port {
            String::new()
        } else {
            format!(":{}", base.port)
        };
        return Ok(format!(
            "{}://{}{}{}",
            base.scheme, base.host, port_part, location
        ));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unsupported redirect location: '{location}'"),
    ))
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

async fn http1_get_over_stream<S>(
    stream: &mut S,
    host: &str,
    path_and_query: &str,
) -> io::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: privacy-engine-rust/0.1\r\nAccept: text/plain,*/*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        path = path_and_query
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        if out.len() > MAX_DOWNLOAD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("download exceeded max bytes ({MAX_DOWNLOAD_BYTES})"),
            ));
        }
    }
    Ok(out)
}

fn decode_chunked(body: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        let line_end = body[i..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid chunked encoding")
            })?
            + i;
        let size_line = &body[i..line_end];
        let size_str = String::from_utf8_lossy(size_line);
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        i = line_end + 2; // skip \r\n
        if size == 0 {
            break;
        }
        let end = i
            .checked_add(size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk size overflow"))?;
        if end > body.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "chunked body truncated",
            ));
        }
        out.extend_from_slice(&body[i..end]);
        i = end;
        if body.get(i..i + 2) != Some(b"\r\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid chunk terminator",
            ));
        }
        i += 2;
    }
    Ok(out)
}

fn parse_http1_response(raw: &[u8]) -> io::Result<Downloaded> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP response"))?;
    let (header_bytes, body_bytes) = raw.split_at(header_end + 4);
    let header_str = String::from_utf8_lossy(header_bytes);

    let mut lines = header_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing status line"))?;
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid status line"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid status code"))?;

    let mut location: Option<String> = None;
    let mut content_encoding: Option<String> = None;
    let mut transfer_encoding_chunked = false;
    let mut content_length: Option<usize> = None;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let value = v.trim();
        match key.as_str() {
            "location" => location = Some(value.to_string()),
            "content-encoding" => content_encoding = Some(value.to_ascii_lowercase()),
            "transfer-encoding" => {
                if value.to_ascii_lowercase().contains("chunked") {
                    transfer_encoding_chunked = true;
                }
            }
            "content-length" => {
                content_length = value.parse().ok();
            }
            _ => {}
        }
    }

    if let Some(enc) = content_encoding.as_deref() {
        if enc != "identity" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported Content-Encoding: {enc}"),
            ));
        }
    }

    let body = if transfer_encoding_chunked {
        decode_chunked(body_bytes)?
    } else if let Some(cl) = content_length {
        if body_bytes.len() < cl {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP body truncated",
            ));
        }
        body_bytes[..cl].to_vec()
    } else {
        body_bytes.to_vec()
    };

    Ok(Downloaded {
        status_code,
        location,
        body,
    })
}

async fn download_once(url: &str) -> io::Result<Downloaded> {
    let parsed = parse_url(url)?;
    let tcp = TcpStream::connect((parsed.host.as_str(), parsed.port)).await?;

    let raw = if parsed.scheme == "https" {
        let tls_cfg = make_tls_client_config()?;
        let server_name = ServerName::try_from(parsed.host.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS name"))?;
        let connector = TlsConnector::from(tls_cfg);
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| io::Error::other(format!("TLS handshake failed: {e}")))?;
        http1_get_over_stream(&mut tls, &parsed.host, &parsed.path_and_query).await?
    } else {
        let mut tcp = tcp;
        http1_get_over_stream(&mut tcp, &parsed.host, &parsed.path_and_query).await?
    };

    parse_http1_response(&raw)
}

/// Download a filter list from a URL (HTTP/1.1 only).
pub async fn download_filter_list(url: &str, timeout: Duration) -> io::Result<String> {
    let url_for_err = url.to_string();
    let url_for_task = url_for_err.clone();
    let res = tokio::time::timeout(timeout, async move {
        let mut current = url_for_task;
        for _ in 0..=MAX_REDIRECTS {
            let base = parse_url(&current)?;
            let downloaded = download_once(&current).await?;
            if (200..300).contains(&downloaded.status_code) {
                return Ok(downloaded.body);
            }
            if (300..400).contains(&downloaded.status_code) {
                let Some(loc) = downloaded.location else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "redirect without Location header",
                    ));
                };
                current = resolve_redirect(&base, &loc)?;
                continue;
            }
            return Err(io::Error::other(format!(
                "unexpected HTTP status: {}",
                downloaded.status_code
            )));
        }
        Err(io::Error::other("too many redirects"))
    })
    .await;

    match res {
        Ok(Ok(body_bytes)) => Ok(String::from_utf8_lossy(&body_bytes).into_owned()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("download timed out for {url_for_err}"),
        )),
    }
}

/// Derive a cache filename from a URL (non-alphanum → underscore).
fn cache_filename(url: &str) -> String {
    url.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
}

/// Cache a downloaded filter list to disk atomically (write .tmp then rename).
pub fn cache_to_disk(cache_dir: &Path, url: &str, body: &str) -> io::Result<PathBuf> {
    std::fs::create_dir_all(cache_dir)?;
    let filename = cache_filename(url);
    let target = cache_dir.join(&filename);
    let tmp = cache_dir.join(format!("{filename}.tmp"));
    std::fs::write(&tmp, body)?;
    match std::fs::rename(&tmp, &target) {
        Ok(()) => {}
        Err(e) => {
            // On Windows, rename does not overwrite an existing destination.
            if matches!(
                e.kind(),
                io::ErrorKind::AlreadyExists | io::ErrorKind::PermissionDenied
            ) {
                let _ = std::fs::remove_file(&target);
                std::fs::rename(&tmp, &target)?;
            } else {
                return Err(e);
            }
        }
    }
    debug!(path = %target.display(), "cached filter list to disk");
    Ok(target)
}

/// Try to load a cached filter list from disk.
pub fn load_from_cache(cache_dir: &Path, url: &str) -> io::Result<Option<String>> {
    let filename = cache_filename(url);
    let path = cache_dir.join(filename);
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            info!(path = %path.display(), "loaded filter list from cache");
            Ok(Some(content))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Load and parse a single source. For URLs, tries download first then cache fallback.
async fn load_source(
    source: &FilterListSource,
    cache_dir: &Path,
    download_timeout: Duration,
) -> Option<(Vec<ParsedRule>, ParseStats)> {
    match source.kind {
        FilterListSourceKind::LocalFile => match std::fs::read_to_string(&source.origin) {
            Ok(text) => {
                let (rules, stats) = filter_list_parser::parse_filter_list(&text);
                info!(
                    source = %source.origin,
                    kind = "local_file",
                    total_lines = stats.total_lines,
                    domain_blocks = stats.domain_blocks,
                    url_patterns = stats.url_patterns,
                    cosmetic_global = stats.cosmetic_global,
                    exceptions = stats.exceptions,
                    skipped_unsupported = stats.skipped_unsupported,
                    "parsed filter list"
                );
                Some((rules, stats))
            }
            Err(e) => {
                error!(source = %source.origin, error = %e, "failed to read local filter list");
                None
            }
        },
        FilterListSourceKind::Url => {
            // Try download first
            match download_filter_list(&source.origin, download_timeout).await {
                Ok(text) => {
                    // Cache to disk
                    if let Err(e) = cache_to_disk(cache_dir, &source.origin, &text) {
                        warn!(url = %source.origin, error = %e, "failed to cache filter list");
                    }
                    let (rules, stats) = filter_list_parser::parse_filter_list(&text);
                    info!(
                        source = %source.origin,
                        kind = "url_download",
                        total_lines = stats.total_lines,
                        domain_blocks = stats.domain_blocks,
                        url_patterns = stats.url_patterns,
                        cosmetic_global = stats.cosmetic_global,
                        exceptions = stats.exceptions,
                        skipped_unsupported = stats.skipped_unsupported,
                        "parsed filter list"
                    );
                    Some((rules, stats))
                }
                Err(e) => {
                    warn!(url = %source.origin, error = %e, "download failed, trying cache");
                    // Fallback to cache
                    match load_from_cache(cache_dir, &source.origin) {
                        Ok(Some(text)) => {
                            let (rules, stats) = filter_list_parser::parse_filter_list(&text);
                            info!(
                                source = %source.origin,
                                kind = "url_cached_fallback",
                                total_lines = stats.total_lines,
                                domain_blocks = stats.domain_blocks,
                                "parsed filter list from cache fallback"
                            );
                            Some((rules, stats))
                        }
                        Ok(None) => {
                            error!(
                                url = %source.origin,
                                "no cached copy available, skipping source"
                            );
                            None
                        }
                        Err(cache_err) => {
                            error!(
                                url = %source.origin,
                                error = %cache_err,
                                "cache read failed, skipping source"
                            );
                            None
                        }
                    }
                }
            }
        }
    }
}

/// Load and aggregate all filter list sources.
pub async fn refresh_filter_lists(
    sources: &[FilterListSource],
    cache_dir: &Path,
    download_timeout: Duration,
) -> io::Result<FilterListRules> {
    if sources.is_empty() {
        return Ok(FilterListRules::default());
    }

    let mut all_results = Vec::with_capacity(sources.len());

    for source in sources {
        if let Some(result) = load_source(source, cache_dir, download_timeout).await {
            all_results.push(result);
        }
    }

    if all_results.is_empty() {
        return Err(io::Error::other("all filter list sources failed"));
    }

    let rules = aggregate_rules(&all_results);
    info!(
        source_count = rules.stats.source_count,
        block_domains = rules.block_domains.len(),
        tracker_script_patterns = rules.tracker_script_patterns.len(),
        cosmetic_selectors = rules.cosmetic_selectors.len(),
        domain_cosmetic_entries = rules.domain_cosmetic_map.len(),
        exception_domains = rules.exception_domains.len(),
        "filter list rules aggregated"
    );
    Ok(rules)
}

/// Spawn a background task that periodically refreshes filter lists.
///
/// Uses the same pattern as the policy config hot-reload in main.rs.
pub fn spawn_refresh_task(
    policy_engine: Arc<crate::policy::PolicyEngine>,
    sources: Vec<FilterListSource>,
    cache_dir: PathBuf,
    interval: Duration,
    download_timeout: Duration,
    metrics: Arc<crate::metrics::Metrics>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip the immediate first tick (initial load already done)
        ticker.tick().await;

        loop {
            ticker.tick().await;
            info!("filter list refresh starting");
            metrics.inc_filter_list_refresh_total();

            match refresh_filter_lists(&sources, &cache_dir, download_timeout).await {
                Ok(new_rules) => {
                    let active_count = new_rules.block_domains.len()
                        + new_rules.tracker_script_patterns.len()
                        + new_rules.cosmetic_selectors.len();
                    metrics.set_filter_list_rules_active(active_count as u64);

                    policy_engine.replace_filter_list_rules(new_rules);
                    info!("filter list refresh completed");
                }
                Err(e) => {
                    metrics.inc_filter_list_refresh_failed_total();
                    warn!(error = %e, "filter list refresh failed (keeping previous rules)");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_empty_input() {
        let rules = aggregate_rules(&[]);
        assert!(rules.block_domains.is_empty());
        assert!(rules.tracker_script_patterns.is_empty());
        assert!(rules.cosmetic_selectors.is_empty());
        assert!(rules.exception_domains.is_empty());
        assert_eq!(rules.stats.source_count, 0);
    }

    #[test]
    fn aggregate_single_source() {
        let text = "\
||doubleclick.net^
||ads.example.com^
||cdn.example.com/tracking.js
@@||safe.example.com^
##.ad-banner
example.com##.sidebar-ad
";
        let result = filter_list_parser::parse_filter_list(text);
        let rules = aggregate_rules(&[result]);

        assert_eq!(rules.block_domains.len(), 2);
        assert!(rules.block_domains.contains("doubleclick.net"));
        assert!(rules.block_domains.contains("ads.example.com"));
        assert_eq!(rules.tracker_script_patterns.len(), 1);
        assert_eq!(
            rules.tracker_script_patterns[0],
            "cdn.example.com/tracking.js"
        );
        assert_eq!(rules.cosmetic_selectors.len(), 1);
        assert_eq!(rules.cosmetic_selectors[0], ".ad-banner");
        assert_eq!(rules.exception_domains.len(), 1);
        assert!(rules.exception_domains.contains("safe.example.com"));
        assert_eq!(rules.domain_cosmetic_map.len(), 1);
        assert_eq!(
            rules
                .domain_cosmetic_map
                .get("example.com")
                .unwrap()
                .as_ref(),
            &vec![".sidebar-ad".to_string()]
        );
    }

    #[test]
    fn aggregate_multiple_sources_merges() {
        let text1 = "||a.com^\n||b.com^\n##.ad\n";
        let text2 = "||c.com^\n||a.com^\n@@||safe.com^\n";

        let r1 = filter_list_parser::parse_filter_list(text1);
        let r2 = filter_list_parser::parse_filter_list(text2);
        let rules = aggregate_rules(&[r1, r2]);

        assert_eq!(rules.block_domains.len(), 3); // a, b, c (deduped)
        assert!(rules.block_domains.contains("a.com"));
        assert!(rules.block_domains.contains("b.com"));
        assert!(rules.block_domains.contains("c.com"));
        assert_eq!(rules.cosmetic_selectors.len(), 1);
        assert_eq!(rules.exception_domains.len(), 1);
        assert_eq!(rules.stats.source_count, 2);
    }

    #[test]
    fn cache_filename_derivation() {
        let name = cache_filename("https://easylist.to/easylist/easylist.txt");
        assert!(!name.contains(':'));
        assert!(!name.contains('/'));
        assert!(name.contains("easylist"));
    }

    #[test]
    fn cache_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "filter_cache_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let url = "https://example.com/list.txt";
        let body = "||test.com^\n##.ad\n";

        cache_to_disk(&dir, url, body).unwrap();
        let loaded = load_from_cache(&dir, url).unwrap();
        assert_eq!(loaded, Some(body.to_string()));

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_miss_returns_none() {
        let dir = std::env::temp_dir().join("filter_cache_miss_test");
        let loaded = load_from_cache(&dir, "https://nonexistent.example.com/list.txt").unwrap();
        assert_eq!(loaded, None);
    }

    #[test]
    fn filter_list_source_constructors() {
        let local = FilterListSource::local_file("/path/to/list.txt");
        assert_eq!(local.kind, FilterListSourceKind::LocalFile);
        assert_eq!(local.origin, "/path/to/list.txt");

        let remote = FilterListSource::url("https://example.com/list.txt");
        assert_eq!(remote.kind, FilterListSourceKind::Url);
        assert_eq!(remote.origin, "https://example.com/list.txt");
    }

    #[test]
    fn aggregate_stats_accumulate() {
        let text1 = "! comment\n||a.com^\n||b.com^\n";
        let text2 = "! another\n||c.com^\n##.ad\n/regex/\n";

        let r1 = filter_list_parser::parse_filter_list(text1);
        let r2 = filter_list_parser::parse_filter_list(text2);
        let rules = aggregate_rules(&[r1, r2]);

        assert_eq!(rules.stats.total_lines, 7);
        assert_eq!(rules.stats.domain_blocks, 3);
        assert_eq!(rules.stats.cosmetic_global, 1);
        assert_eq!(rules.stats.skipped_comments, 2);
        assert_eq!(rules.stats.skipped_unsupported, 1);
    }

    #[test]
    fn domain_cosmetic_map_accumulates_per_domain() {
        let text = "example.com##.ad1\nexample.com##.ad2\nother.com##.banner\n";
        let result = filter_list_parser::parse_filter_list(text);
        let rules = aggregate_rules(&[result]);

        let example_sels = rules.domain_cosmetic_map.get("example.com").unwrap();
        assert_eq!(example_sels.len(), 2);
        assert!(example_sels.contains(&".ad1".to_string()));
        assert!(example_sels.contains(&".ad2".to_string()));

        let other_sels = rules.domain_cosmetic_map.get("other.com").unwrap();
        assert_eq!(other_sels.len(), 1);
    }
}
