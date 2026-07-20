use std::collections::HashMap;
use std::io;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoPinObservation {
    pub failure_count: u64,
    pub should_pin: bool,
}

#[derive(Debug, Clone, Copy)]
struct FailureWindow {
    started_at: Instant,
    count: u64,
}

pub struct AutoPinTracker {
    threshold: u64,
    window: Duration,
    hosts: Mutex<HashMap<String, FailureWindow>>,
}

impl AutoPinTracker {
    pub fn new(threshold: u64, window: Duration) -> io::Result<Self> {
        if threshold == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "auto-pin reject threshold must be at least 1",
            ));
        }
        if window.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "auto-pin reject window must be at least 1 second",
            ));
        }
        Ok(Self {
            threshold,
            window,
            hosts: Mutex::new(HashMap::new()),
        })
    }

    pub fn threshold(&self) -> u64 {
        self.threshold
    }

    pub fn window(&self) -> Duration {
        self.window
    }

    pub fn observe(&self, host: &str) -> io::Result<AutoPinObservation> {
        self.observe_at(host, Instant::now())
    }

    fn observe_at(&self, host: &str, now: Instant) -> io::Result<AutoPinObservation> {
        let normalized = normalize_host(host);
        let mut hosts = self.hosts.lock().map_err(lock_error)?;
        let entry = hosts.entry(normalized.clone()).or_insert(FailureWindow {
            started_at: now,
            count: 0,
        });
        if now.duration_since(entry.started_at) > self.window {
            *entry = FailureWindow {
                started_at: now,
                count: 0,
            };
        }
        entry.count = entry.count.saturating_add(1);
        let observation = AutoPinObservation {
            failure_count: entry.count,
            should_pin: entry.count >= self.threshold,
        };
        if observation.should_pin {
            hosts.remove(&normalized);
        }
        Ok(observation)
    }
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn lock_error<T>(error: PoisonError<T>) -> io::Error {
    io::Error::other(format!("auto-pin tracker lock poisoned: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_requires_repeated_failure() {
        let tracker = AutoPinTracker::new(2, Duration::from_secs(60)).expect("tracker");
        let start = Instant::now();
        assert_eq!(
            tracker.observe_at("Example.COM", start).expect("first"),
            AutoPinObservation {
                failure_count: 1,
                should_pin: false,
            }
        );
        assert_eq!(
            tracker
                .observe_at("example.com.", start + Duration::from_secs(1))
                .expect("second"),
            AutoPinObservation {
                failure_count: 2,
                should_pin: true,
            }
        );
    }

    #[test]
    fn expired_window_resets_count() {
        let tracker = AutoPinTracker::new(2, Duration::from_secs(5)).expect("tracker");
        let start = Instant::now();
        tracker.observe_at("example.com", start).expect("first");
        assert_eq!(
            tracker
                .observe_at("example.com", start + Duration::from_secs(6))
                .expect("expired"),
            AutoPinObservation {
                failure_count: 1,
                should_pin: false,
            }
        );
    }

    #[test]
    fn invalid_tracker_contract_is_rejected() {
        assert!(AutoPinTracker::new(0, Duration::from_secs(1)).is_err());
        assert!(AutoPinTracker::new(1, Duration::ZERO).is_err());
    }
}
