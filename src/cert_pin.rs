use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

fn lock_error<T>(err: PoisonError<T>) -> io::Error {
    io::Error::other(format!("cert-pin lock poisoned: {err}"))
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// SHA-256 fingerprint of DER-encoded certificate bytes, as colon-separated hex.
pub fn cert_der_fingerprint(der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    digest
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone)]
pub struct CertPin {
    pub fingerprints: Vec<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub hit_count: u64,
}

impl CertPin {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "fingerprints": self.fingerprints,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "hit_count": self.hit_count,
        })
    }

    fn from_json(val: &serde_json::Value) -> Option<Self> {
        let obj = val.as_object()?;
        let fingerprints = obj
            .get("fingerprints")?
            .as_array()?
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        Some(Self {
            fingerprints,
            first_seen: obj.get("first_seen").and_then(|v| v.as_u64()).unwrap_or(0),
            last_seen: obj.get("last_seen").and_then(|v| v.as_u64()).unwrap_or(0),
            hit_count: obj.get("hit_count").and_then(|v| v.as_u64()).unwrap_or(0),
        })
    }
}

#[derive(Debug)]
pub enum PinCheckResult {
    /// First time seeing this host — pin recorded.
    FirstSeen,
    /// Known host, fingerprint matches a recorded pin.
    Match,
    /// Known host, fingerprint does NOT match any recorded pin.
    Mismatch { expected: Vec<String>, got: String },
}

pub struct CertPinDb {
    path: PathBuf,
    pins: RwLock<HashMap<String, CertPin>>,
}

impl CertPinDb {
    /// Load pin database from a JSON file, or create an empty database if the file is missing.
    pub fn load(path: &Path) -> io::Result<Self> {
        let pins = if path.exists() {
            let raw = std::fs::read_to_string(path)?;
            let parsed: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid cert-pin JSON: {e}"),
                )
            })?;
            let obj = parsed.as_object().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cert-pin JSON must be an object",
                )
            })?;
            let mut map = HashMap::new();
            for (host, val) in obj {
                if let Some(pin) = CertPin::from_json(val) {
                    map.insert(host.clone(), pin);
                }
            }
            map
        } else {
            HashMap::new()
        };
        Ok(Self {
            path: path.to_path_buf(),
            pins: RwLock::new(pins),
        })
    }

    /// TOFU check: verify fingerprint against stored pins, or record a new pin.
    pub fn check_and_update(&self, host: &str, fingerprint: &str) -> io::Result<PinCheckResult> {
        let normalized = normalize_host(host);
        let now = now_unix();

        // Fast path: read lock check
        {
            let guard = self.pins.read().map_err(lock_error)?;
            if let Some(pin) = guard.get(&normalized) {
                if pin.fingerprints.contains(&fingerprint.to_string()) {
                    // Match — need write lock to update last_seen/hit_count
                    drop(guard);
                    let mut wguard = self.pins.write().map_err(lock_error)?;
                    if let Some(pin) = wguard.get_mut(&normalized) {
                        pin.last_seen = now;
                        pin.hit_count = pin.hit_count.saturating_add(1);
                    }
                    persist(&self.path, &wguard)?;
                    return Ok(PinCheckResult::Match);
                } else {
                    return Ok(PinCheckResult::Mismatch {
                        expected: pin.fingerprints.clone(),
                        got: fingerprint.to_string(),
                    });
                }
            }
        }

        // Not found — write lock, insert new pin
        let mut guard = self.pins.write().map_err(lock_error)?;
        // Double-check after acquiring write lock
        if let Some(pin) = guard.get(&normalized) {
            if pin.fingerprints.contains(&fingerprint.to_string()) {
                return Ok(PinCheckResult::Match);
            } else {
                return Ok(PinCheckResult::Mismatch {
                    expected: pin.fingerprints.clone(),
                    got: fingerprint.to_string(),
                });
            }
        }
        guard.insert(
            normalized,
            CertPin {
                fingerprints: vec![fingerprint.to_string()],
                first_seen: now,
                last_seen: now,
                hit_count: 1,
            },
        );
        persist(&self.path, &guard)?;
        Ok(PinCheckResult::FirstSeen)
    }

    /// Add an additional fingerprint for a host (e.g., after cert rotation acceptance).
    #[allow(dead_code)]
    pub fn add_fingerprint(&self, host: &str, fingerprint: &str) -> io::Result<()> {
        let normalized = normalize_host(host);
        let mut guard = self.pins.write().map_err(lock_error)?;
        let now = now_unix();
        let entry = guard.entry(normalized).or_insert_with(|| CertPin {
            fingerprints: Vec::new(),
            first_seen: now,
            last_seen: now,
            hit_count: 0,
        });
        let fp = fingerprint.to_string();
        if !entry.fingerprints.contains(&fp) {
            entry.fingerprints.push(fp);
        }
        entry.last_seen = now;
        persist(&self.path, &guard)?;
        Ok(())
    }

    pub fn len(&self) -> io::Result<usize> {
        Ok(self.pins.read().map_err(lock_error)?.len())
    }

    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn persist(path: &Path, pins: &HashMap<String, CertPin>) -> io::Result<()> {
    let mut map = serde_json::Map::new();
    for (host, pin) in pins {
        map.insert(host.clone(), pin.to_json());
    }
    let json = serde_json::to_string_pretty(&serde_json::Value::Object(map)).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to serialize cert pins: {e}"),
        )
    })?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, json)?;
    match std::fs::rename(&tmp_path, path) {
        Ok(()) => {}
        Err(e) => {
            if matches!(
                e.kind(),
                io::ErrorKind::AlreadyExists | io::ErrorKind::PermissionDenied
            ) {
                let _ = std::fs::remove_file(path);
                std::fs::rename(&tmp_path, path)?;
            } else {
                return Err(e);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("cert_pin_{name}_{ts}.json"))
    }

    #[test]
    fn load_missing_file_creates_empty() {
        let path = temp_file("missing");
        let db = CertPinDb::load(&path).expect("load");
        assert_eq!(db.len().unwrap(), 0);
    }

    #[test]
    fn first_seen_records_pin() {
        let path = temp_file("first");
        let db = CertPinDb::load(&path).expect("load");
        let result = db
            .check_and_update("example.com", "aa:bb:cc")
            .expect("check");
        assert!(matches!(result, PinCheckResult::FirstSeen));
        assert_eq!(db.len().unwrap(), 1);
        // Verify file was written
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("aa:bb:cc"));
    }

    #[test]
    fn matching_pin_returns_match() {
        let path = temp_file("match");
        let db = CertPinDb::load(&path).expect("load");
        db.check_and_update("example.com", "aa:bb:cc").unwrap();
        let result = db
            .check_and_update("example.com", "aa:bb:cc")
            .expect("check");
        assert!(matches!(result, PinCheckResult::Match));
    }

    #[test]
    fn mismatched_pin_returns_mismatch() {
        let path = temp_file("mismatch");
        let db = CertPinDb::load(&path).expect("load");
        db.check_and_update("example.com", "aa:bb:cc").unwrap();
        let result = db
            .check_and_update("example.com", "dd:ee:ff")
            .expect("check");
        match result {
            PinCheckResult::Mismatch { expected, got } => {
                assert_eq!(expected, vec!["aa:bb:cc"]);
                assert_eq!(got, "dd:ee:ff");
            }
            _ => panic!("expected Mismatch"),
        }
    }

    #[test]
    fn fingerprint_computation() {
        // SHA-256 of empty input is well-known
        let fp = cert_der_fingerprint(b"");
        assert_eq!(
            fp,
            "e3:b0:c4:42:98:fc:1c:14:9a:fb:f4:c8:99:6f:b9:24:\
             27:ae:41:e4:64:9b:93:4c:a4:95:99:1b:78:52:b8:55"
        );
    }

    #[test]
    fn multiple_hosts_independent() {
        let path = temp_file("multi");
        let db = CertPinDb::load(&path).expect("load");
        db.check_and_update("a.com", "fp-a").unwrap();
        db.check_and_update("b.com", "fp-b").unwrap();
        assert_eq!(db.len().unwrap(), 2);
        assert!(matches!(
            db.check_and_update("a.com", "fp-a").unwrap(),
            PinCheckResult::Match
        ));
        assert!(matches!(
            db.check_and_update("b.com", "fp-b").unwrap(),
            PinCheckResult::Match
        ));
        assert!(matches!(
            db.check_and_update("a.com", "fp-b").unwrap(),
            PinCheckResult::Mismatch { .. }
        ));
    }

    #[test]
    fn persistence_survives_reload() {
        let path = temp_file("reload");
        {
            let db = CertPinDb::load(&path).expect("load");
            db.check_and_update("example.com", "aa:bb:cc").unwrap();
        }
        let db2 = CertPinDb::load(&path).expect("reload");
        assert_eq!(db2.len().unwrap(), 1);
        assert!(matches!(
            db2.check_and_update("example.com", "aa:bb:cc").unwrap(),
            PinCheckResult::Match
        ));
    }

    #[test]
    fn add_fingerprint_allows_rotation() {
        let path = temp_file("rotate");
        let db = CertPinDb::load(&path).expect("load");
        db.check_and_update("example.com", "old-fp").unwrap();
        assert!(matches!(
            db.check_and_update("example.com", "new-fp").unwrap(),
            PinCheckResult::Mismatch { .. }
        ));
        db.add_fingerprint("example.com", "new-fp").unwrap();
        assert!(matches!(
            db.check_and_update("example.com", "new-fp").unwrap(),
            PinCheckResult::Match
        ));
    }
}
