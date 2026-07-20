use ipnet::IpNet;
use std::collections::HashSet;
use std::io;
use std::net::IpAddr;

const BUILTIN_HOSTS: &[&str] = &["localhost"];
const BUILTIN_CIDRS: &[&str] = &["127.0.0.0/8", "::1/128"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassReason {
    BuiltinLoopback,
    ConfiguredHost,
    ConfiguredCidr,
}

impl BypassReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuiltinLoopback => "builtin_loopback_bypass",
            Self::ConfiguredHost => "configured_never_intercept_host",
            Self::ConfiguredCidr => "configured_never_intercept_cidr",
        }
    }
}

#[derive(Debug, Clone)]
pub struct InterceptBypass {
    configured_hosts: HashSet<String>,
    configured_cidrs: Vec<IpNet>,
}

impl InterceptBypass {
    pub fn new(hosts: &[String], cidrs: &[String]) -> io::Result<Self> {
        let configured_hosts = hosts
            .iter()
            .map(|host| normalize_host(host))
            .filter(|host| !host.is_empty())
            .collect();
        let configured_cidrs = cidrs
            .iter()
            .map(|cidr| {
                cidr.parse::<IpNet>().map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid never-intercept CIDR '{cidr}': {error}"),
                    )
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            configured_hosts,
            configured_cidrs,
        })
    }

    pub fn reason_for_host(&self, host: &str) -> Option<BypassReason> {
        let normalized = normalize_host(host);
        if BUILTIN_HOSTS.contains(&normalized.as_str()) {
            return Some(BypassReason::BuiltinLoopback);
        }
        if self.configured_hosts.contains(&normalized) {
            return Some(BypassReason::ConfiguredHost);
        }
        let ip = normalized.parse::<IpAddr>().ok()?;
        if ip.is_loopback() || builtin_cidrs().iter().any(|cidr| cidr.contains(&ip)) {
            return Some(BypassReason::BuiltinLoopback);
        }
        self.configured_cidrs
            .iter()
            .any(|cidr| cidr.contains(&ip))
            .then_some(BypassReason::ConfiguredCidr)
    }
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn builtin_cidrs() -> Vec<IpNet> {
    BUILTIN_CIDRS
        .iter()
        .map(|cidr| cidr.parse().expect("built-in CIDRs must be valid"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_always_bypassed() {
        let policy = InterceptBypass::new(&[], &[]).expect("policy");
        for host in [
            "localhost",
            "LOCALHOST.",
            "127.0.0.1",
            "127.42.0.9",
            "::1",
            "[::1]",
        ] {
            assert_eq!(
                policy.reason_for_host(host),
                Some(BypassReason::BuiltinLoopback),
                "host={host}"
            );
        }
        assert_eq!(policy.reason_for_host("128.0.0.1"), None);
    }

    #[test]
    fn configured_hosts_and_cidrs_are_bypassed() {
        let policy = InterceptBypass::new(
            &["service.internal".to_string()],
            &["10.20.0.0/16".to_string()],
        )
        .expect("policy");
        assert_eq!(
            policy.reason_for_host("SERVICE.INTERNAL."),
            Some(BypassReason::ConfiguredHost)
        );
        assert_eq!(
            policy.reason_for_host("10.20.4.8"),
            Some(BypassReason::ConfiguredCidr)
        );
        assert_eq!(policy.reason_for_host("10.21.4.8"), None);
    }

    #[test]
    fn invalid_cidr_fails_closed_at_startup() {
        let error = InterceptBypass::new(&[], &["127.0.0.0/nope".to_string()]).unwrap_err();
        assert!(error.to_string().contains("invalid never-intercept CIDR"));
    }
}
