//! [`TargetStrategy`]: which collection tier produced a snapshot.

/// Which collection tier a host was actually scanned at.
///
/// Recorded directly on [`crate::domain::ScanSnapshot`] so a report reader
/// never has to guess whether a host section is authoritative or inferred.
/// There are two fidelity tiers: `Execute` is authoritative — a collector
/// ran on the target and returned PID, process path, service, and firewall
/// policy directly. `Probe` is inferential — the scanner observed the
/// target's behaviour from outside, without ever running code on it.
/// `LocalOnly` is the scanning host examining itself, which is authoritative
/// by construction (no transport was involved at all). A probe-only fleet
/// scan is the expected default in most Windows environments, since OpenSSH
/// is an optional feature and `WinRM` is out of scope by decision — this is
/// not a degraded mode to apologise for, it is the normal case a report
/// must represent honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TargetStrategy {
    /// A collector ran on the target through a remote execute transport.
    /// PID, process path, service, and firewall policy are authoritative.
    Execute,
    /// Only the network was reachable; findings are inferred from outside
    /// observation, never confirmed by code running on the target.
    Probe,
    /// The scanning host scanned itself; no transport was involved.
    LocalOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_json() {
        for strategy in [
            TargetStrategy::Execute,
            TargetStrategy::Probe,
            TargetStrategy::LocalOnly,
        ] {
            let json = serde_json::to_string(&strategy).unwrap();
            let back: TargetStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(strategy, back);
        }
    }
}
