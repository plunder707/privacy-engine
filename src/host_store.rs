use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock};
use std::time::{Duration, Instant};

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn lock_error<T>(err: PoisonError<T>) -> io::Error {
    io::Error::other(format!("pinned-host lock poisoned: {err}"))
}

fn persist_pinned_hosts(path: &Path, hosts: &HashSet<String>) -> io::Result<()> {
    let mut sorted_hosts: Vec<_> = hosts.iter().cloned().collect();
    sorted_hosts.sort();

    let json = serde_json::to_string_pretty(&sorted_hosts).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to serialize pinned hosts: {e}"),
        )
    })?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Best-effort atomic persistence via temp file + rename.
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, json)?;
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

fn load_pinned_hosts(path: &Path) -> io::Result<HashSet<String>> {
    if !path.exists() {
        return Ok(HashSet::new());
    }

    let raw = fs::read_to_string(path)?;
    let parsed: Vec<String> = serde_json::from_str(&raw).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid pinned-hosts JSON: {e}"),
        )
    })?;

    let mut hosts = HashSet::new();
    for host in parsed {
        let normalized = normalize_host(&host);
        if !normalized.is_empty() {
            hosts.insert(normalized);
        }
    }
    Ok(hosts)
}

pub struct PinnedHosts {
    path: PathBuf,
    hosts: RwLock<HashSet<String>>,
    created_at: Instant,
}

impl PinnedHosts {
    pub fn load(path: &Path) -> io::Result<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            hosts: RwLock::new(load_pinned_hosts(path)?),
            created_at: Instant::now(),
        })
    }

    pub fn len(&self) -> io::Result<usize> {
        Ok(self.hosts.read().map_err(lock_error)?.len())
    }

    pub fn contains(&self, host: &str) -> io::Result<bool> {
        let normalized = normalize_host(host);
        Ok(self.hosts.read().map_err(lock_error)?.contains(&normalized))
    }

    /// Insert host and persist if this is a new host.
    pub fn add_and_persist(&self, host: &str) -> io::Result<bool> {
        let normalized = normalize_host(host);
        if normalized.is_empty() {
            return Ok(false);
        }

        let mut guard = self.hosts.write().map_err(lock_error)?;
        if !guard.insert(normalized) {
            return Ok(false);
        }

        persist_pinned_hosts(&self.path, &guard)?;
        Ok(true)
    }

    /// Clear all pinned hosts and persist an empty list.
    ///
    /// Returns the number of entries removed.
    pub fn clear_and_persist(&self) -> io::Result<usize> {
        let mut guard = self.hosts.write().map_err(lock_error)?;
        let removed = guard.len();
        guard.clear();
        persist_pinned_hosts(&self.path, &guard)?;
        Ok(removed)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns true if the store was created less than `duration` ago.
    ///
    /// This is used to suppress auto-pinning during an initial startup grace period
    /// (e.g., while a user is installing/trusting the MITM CA).
    pub fn in_grace_period(&self, duration: Duration) -> bool {
        self.created_at.elapsed() < duration
    }

    /// Age of this store instance (time since process start / store load).
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

/// Normalize and extract host portion from "host:port" or "[ipv6]:port".
pub fn host_from_authority(authority: &str) -> Option<String> {
    if authority.is_empty() {
        return None;
    }

    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = &authority[1..end];
        return Some(normalize_host(host));
    }

    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    Some(normalize_host(host))
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
    fn host_from_authority_hostname() {
        assert_eq!(
            host_from_authority("Example.COM:443"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn host_from_authority_ipv6() {
        assert_eq!(host_from_authority("[::1]:8443"), Some("::1".to_string()));
    }

    #[test]
    fn load_missing_file_is_empty() {
        let path = temp_file("pinned_hosts_missing");
        let store = PinnedHosts::load(&path).expect("missing file should not fail");
        assert_eq!(store.len().expect("len"), 0);
    }

    #[test]
    fn add_and_persist_writes_json_file() {
        let path = temp_file("pinned_hosts_write");
        let store = PinnedHosts::load(&path).expect("load");
        assert!(store.add_and_persist("Example.COM.").expect("persist"));

        let json = fs::read_to_string(&path).expect("read");
        assert!(json.contains("example.com"));
    }

    #[test]
    fn clear_and_persist_removes_all_hosts() {
        let path = temp_file("pinned_hosts_clear");
        let store = PinnedHosts::load(&path).expect("load");
        assert!(store.add_and_persist("a.example").expect("add a"));
        assert!(store.add_and_persist("b.example").expect("add b"));

        let removed = store.clear_and_persist().expect("clear");
        assert_eq!(removed, 2);
        assert_eq!(store.len().expect("len"), 0);

        let json = fs::read_to_string(&path).expect("read");
        assert!(json.contains("[]"), "expected empty JSON array, got {json}");
    }

    #[test]
    fn grace_period_is_true_immediately_after_load() {
        let path = temp_file("pinned_hosts_grace");
        let store = PinnedHosts::load(&path).expect("load");
        assert!(store.in_grace_period(Duration::from_secs(60)));
        assert!(!store.in_grace_period(Duration::ZERO));
    }
}
