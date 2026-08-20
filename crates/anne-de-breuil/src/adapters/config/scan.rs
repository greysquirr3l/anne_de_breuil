//! `[scan]` section: local endpoint collection knobs.

use crate::domain::PolicyStore;

/// Local collection settings: which endpoints to enumerate and how
/// strictly to require a verified binary signature.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    /// Include UDP listeners alongside TCP.
    pub include_udp: bool,
    /// Include endpoints bound only to loopback.
    pub include_loopback: bool,
    /// Skip Authenticode/codesign verification of the owning process binary.
    pub skip_signature: bool,
    /// Which firewall policy store to read rules from.
    pub policy_store: PolicyStore,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            include_udp: false,
            include_loopback: false,
            skip_signature: false,
            policy_store: PolicyStore::Local,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let config = ScanConfig::default();
        assert!(!config.include_udp);
        assert!(!config.include_loopback);
        assert!(!config.skip_signature);
        assert_eq!(config.policy_store, PolicyStore::Local);
    }
}
