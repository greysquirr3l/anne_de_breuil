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
    /// Include process command lines in the snapshot. Off by default --
    /// command lines routinely carry credentials, connection strings, and
    /// tokens.
    pub include_command_line: bool,
    /// Include process executable paths in the snapshot. Off by default --
    /// install paths can leak customer names and sensitive directory
    /// layouts.
    pub include_executable_path: bool,
    /// Include hosted-service `PathName` values (systemd `ExecStart=` / the
    /// Windows service `PathName`) in the snapshot. Off by default -- these
    /// can carry arguments and embedded secrets.
    pub include_service_path: bool,
    /// Include firewall rules that are present but disabled. Off by
    /// default -- disabled rules don't shape connectivity, but their
    /// program/service filter strings can still leak.
    pub include_disabled_firewall_rules: bool,
    /// Which firewall policy store to read rules from.
    pub policy_store: PolicyStore,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            include_udp: false,
            include_loopback: false,
            skip_signature: false,
            include_command_line: false,
            include_executable_path: false,
            include_service_path: false,
            include_disabled_firewall_rules: false,
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
        assert!(!config.include_command_line);
        assert!(!config.include_executable_path);
        assert!(!config.include_service_path);
        assert!(!config.include_disabled_firewall_rules);
        assert_eq!(config.policy_store, PolicyStore::Local);
    }
}
