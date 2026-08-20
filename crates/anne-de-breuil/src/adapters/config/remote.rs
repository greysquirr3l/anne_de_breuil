//! `[remote]` section: SSH fan-out concurrency and host-key policy.

use std::{path::PathBuf, time::Duration};

/// Remote fan-out settings: how many hosts to scan concurrently and how to
/// treat SSH host keys.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    /// Maximum number of hosts scanned concurrently.
    pub concurrency: usize,
    /// Per-host connect-and-collect timeout.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Path to the SSH known-hosts file used for strict host-key verification.
    pub known_hosts: PathBuf,
    /// Whether an unrecognised host key is trusted on first connect rather
    /// than rejected outright.
    pub accept_new: bool,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            concurrency: 8,
            timeout: Duration::from_mins(2),
            known_hosts: home::home_dir()
                .unwrap_or_default()
                .join(".ssh")
                .join("known_hosts"),
            accept_new: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_timeout_is_two_minutes() {
        assert_eq!(RemoteConfig::default().timeout, Duration::from_mins(2));
    }

    #[test]
    fn default_rejects_unrecognised_host_keys() {
        assert!(!RemoteConfig::default().accept_new);
    }
}
