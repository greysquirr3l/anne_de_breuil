//! [`diff`]: pure baseline-versus-current comparison of two [`ScanSnapshot`]s.

use std::collections::HashMap;

use crate::domain::bind_address::BindAddress;
use crate::domain::endpoint::Endpoint;
use crate::domain::exposure::Exposure;
use crate::domain::port::Port;
use crate::domain::protocol::Protocol;
use crate::domain::reachability::{Reachability, evaluate};
use crate::domain::snapshot::ScanSnapshot;

/// The port above which an ephemeral, OS-assigned port is expected to churn
/// on every reboot — never itself a sign of drift.
const EPHEMERAL_PORT_THRESHOLD: u16 = 49_152;

/// The join key for correlating an endpoint between two snapshots.
///
/// Deliberately excludes the owning process: a PID is reassigned on every
/// reboot and must never drive identity or the join between a baseline and a
/// rescan.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointKey {
    /// Transport protocol the socket is bound with.
    pub protocol: Protocol,
    /// Address the socket is bound to.
    pub bind_address: BindAddress,
    /// Port the socket is bound to.
    pub port: Port,
}

impl From<&Endpoint> for EndpointKey {
    fn from(endpoint: &Endpoint) -> Self {
        Self {
            protocol: endpoint.protocol,
            bind_address: endpoint.bind_address,
            port: endpoint.port,
        }
    }
}

/// The classification of one detected change between a baseline and a rescan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftKind {
    /// An endpoint present in the current scan was absent from the baseline.
    EndpointAppeared,
    /// An endpoint present in the baseline is absent from the current scan.
    EndpointDisappeared,
    /// The same endpoint's reachability verdict differs between the two
    /// snapshots, each evaluated against its own firewall rules and profiles.
    ReachabilityChanged {
        /// Reachability under the baseline's own firewall policy.
        before: Reachability,
        /// Reachability under the current scan's firewall policy.
        after: Reachability,
    },
    /// The same endpoint's owning process identity changed — judged by
    /// `process_path`, never by a bare PID, since a PID alone is expected to
    /// change across every reboot.
    ProcessChanged,
    /// The same endpoint's binary signature status changed.
    SignatureChanged,
    /// The firewall rule set itself changed between the two snapshots. A
    /// snapshot-level signal, not tied to any one endpoint.
    RuleSetChanged,
}

/// How urgently a [`DriftEntry`] warrants review, weakest first.
///
/// Declaration order is derivation order for [`Ord`] — `Low` is the weakest
/// tier and `Critical` the strongest, so `Severity::Low < Severity::Critical`
/// holds without a hand-written comparator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational; no action expected.
    Low,
    /// Worth a look, not urgent.
    Medium,
    /// Should be reviewed promptly.
    High,
    /// Top of the list — review first.
    Critical,
}

/// One detected change between a baseline and a rescan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftEntry {
    /// What kind of change this is.
    pub kind: DriftKind,
    /// The endpoint this entry concerns, or `None` for a snapshot-level
    /// signal such as [`DriftKind::RuleSetChanged`].
    pub endpoint_key: Option<EndpointKey>,
    /// How urgently this entry warrants review.
    pub severity: Severity,
}

/// The full result of comparing a baseline snapshot against a current one.
#[derive(Debug, Clone, Default)]
pub struct DriftReport {
    /// Real drift entries, ephemeral-port churn already filtered out.
    pub entries: Vec<DriftEntry>,
    /// Count of `EndpointAppeared`/`EndpointDisappeared` entries suppressed
    /// as expected ephemeral-port churn. Never silently dropped — a reader
    /// can always tell "nothing changed" apart from "everything was
    /// filtered" by checking this count.
    pub suppressed_ephemeral: usize,
}

/// Compares `baseline` against `current` and classifies every change.
///
/// Pure: no I/O, no clock. Reachability is recomputed for each shared
/// endpoint against each snapshot's own firewall rules and profiles, rather
/// than diffing endpoint fields directly, so a `ReachabilityChanged` entry
/// reflects a genuine change in effective policy outcome.
#[must_use]
pub fn diff(baseline: &ScanSnapshot, current: &ScanSnapshot) -> DriftReport {
    let before: HashMap<EndpointKey, &Endpoint> = baseline
        .endpoints
        .iter()
        .map(|endpoint| (EndpointKey::from(endpoint), endpoint))
        .collect();
    let after: HashMap<EndpointKey, &Endpoint> = current
        .endpoints
        .iter()
        .map(|endpoint| (EndpointKey::from(endpoint), endpoint))
        .collect();

    let mut entries = Vec::new();

    // Iterate the snapshots' own (already-sorted) endpoint vectors rather
    // than the lookup maps, so entry order is deterministic regardless of
    // hasher iteration order.
    for endpoint in &current.endpoints {
        let key = EndpointKey::from(endpoint);
        if !before.contains_key(&key) {
            entries.push(DriftEntry {
                kind: DriftKind::EndpointAppeared,
                severity: severity_for(&DriftKind::EndpointAppeared, endpoint.exposure),
                endpoint_key: Some(key),
            });
        }
    }
    for endpoint in &baseline.endpoints {
        let key = EndpointKey::from(endpoint);
        if !after.contains_key(&key) {
            entries.push(DriftEntry {
                kind: DriftKind::EndpointDisappeared,
                severity: severity_for(&DriftKind::EndpointDisappeared, endpoint.exposure),
                endpoint_key: Some(key),
            });
        }
    }

    for current_endpoint in &current.endpoints {
        let key = EndpointKey::from(current_endpoint);
        let Some(&baseline_endpoint) = before.get(&key) else {
            continue;
        };

        if baseline_endpoint.process_path != current_endpoint.process_path {
            entries.push(DriftEntry {
                kind: DriftKind::ProcessChanged,
                severity: severity_for(&DriftKind::ProcessChanged, current_endpoint.exposure),
                endpoint_key: Some(key.clone()),
            });
        }

        if baseline_endpoint.signature_status != current_endpoint.signature_status {
            entries.push(DriftEntry {
                kind: DriftKind::SignatureChanged,
                severity: severity_for(&DriftKind::SignatureChanged, current_endpoint.exposure),
                endpoint_key: Some(key.clone()),
            });
        }

        let before_reachability = evaluate(
            baseline_endpoint,
            &baseline.firewall_rules,
            &baseline.profiles,
        )
        .reachability;
        let after_reachability =
            evaluate(current_endpoint, &current.firewall_rules, &current.profiles).reachability;
        if before_reachability != after_reachability {
            let kind = DriftKind::ReachabilityChanged {
                before: before_reachability,
                after: after_reachability,
            };
            entries.push(DriftEntry {
                severity: severity_for(&kind, current_endpoint.exposure),
                kind,
                endpoint_key: Some(key),
            });
        }
    }

    if baseline.firewall_rules != current.firewall_rules {
        entries.push(DriftEntry {
            kind: DriftKind::RuleSetChanged,
            // Exposure does not apply to a snapshot-level signal; severity
            // for this kind ignores the exposure argument entirely.
            severity: severity_for(&DriftKind::RuleSetChanged, Exposure::SpecificInterface),
            endpoint_key: None,
        });
    }

    let suppressed: Vec<DriftEntry> = entries
        .extract_if(.., |entry| is_ephemeral_churn(entry))
        .collect();

    DriftReport {
        entries,
        suppressed_ephemeral: suppressed.len(),
    }
}

/// Reports whether `entry` is expected ephemeral-port churn: an endpoint
/// appearing or disappearing on a port above [`EPHEMERAL_PORT_THRESHOLD`].
fn is_ephemeral_churn(entry: &DriftEntry) -> bool {
    matches!(
        entry.kind,
        DriftKind::EndpointAppeared | DriftKind::EndpointDisappeared
    ) && entry
        .endpoint_key
        .as_ref()
        .is_some_and(|key| key.port.get() > EPHEMERAL_PORT_THRESHOLD)
}

/// Derives the severity of one drift kind, given the exposure of the
/// endpoint it concerns.
///
/// A newly `Allowed` port on `AllInterfaces` is the top of the list; a
/// loopback port appearing is near the bottom. `RuleSetChanged` has no
/// associated endpoint, so its exposure argument is ignored.
#[must_use]
pub fn severity_for(kind: &DriftKind, exposure: Exposure) -> Severity {
    match kind {
        DriftKind::EndpointAppeared => match exposure {
            Exposure::AllInterfaces => Severity::Critical,
            Exposure::SpecificInterface => Severity::High,
            Exposure::Loopback => Severity::Low,
        },
        DriftKind::EndpointDisappeared => Severity::Low,
        DriftKind::ReachabilityChanged { before, after } => {
            reachability_change_severity(*before, *after, exposure)
        }
        DriftKind::ProcessChanged | DriftKind::SignatureChanged => match exposure {
            Exposure::AllInterfaces => Severity::High,
            Exposure::SpecificInterface | Exposure::Loopback => Severity::Medium,
        },
        DriftKind::RuleSetChanged => Severity::Medium,
    }
}

/// Derives the severity of a reachability change: newly `Allowed` traffic is
/// treated like a newly appeared endpoint (worse the wider its exposure);
/// newly `Blocked` traffic is a improvement, not a regression; anything else
/// (e.g. `Blocked` to `Indeterminate`) is a moderate signal worth a look.
fn reachability_change_severity(
    before: Reachability,
    after: Reachability,
    exposure: Exposure,
) -> Severity {
    let newly_allowed = after == Reachability::Allowed && before != Reachability::Allowed;
    let newly_blocked = before == Reachability::Allowed && after != Reachability::Allowed;

    if newly_allowed {
        match exposure {
            Exposure::AllInterfaces => Severity::Critical,
            Exposure::SpecificInterface => Severity::High,
            Exposure::Loopback => Severity::Low,
        }
    } else if newly_blocked {
        Severity::Low
    } else {
        Severity::Medium
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;

    use super::*;
    use crate::domain::firewall_rule::{Direction, FirewallRule, RuleAction};
    use crate::domain::ids::{HostId, ProcessId, RuleId, ScanId};
    use crate::domain::policy_store::PolicyStore;
    use crate::domain::port_spec::PortSpec;
    use crate::domain::process::ProcessPath;
    use crate::domain::publisher::{PublisherName, SignatureStatus};
    use crate::domain::target_strategy::TargetStrategy;

    fn endpoint_at(protocol: Protocol, addr: &str, port: u16) -> Endpoint {
        Endpoint::new(
            protocol,
            BindAddress::from_str(addr).unwrap(),
            Port::try_from(port).unwrap(),
            None,
            None,
            vec![],
            SignatureStatus::Unknown,
            None,
        )
    }

    fn build_snapshot(endpoints: Vec<Endpoint>, firewall_rules: Vec<FirewallRule>) -> ScanSnapshot {
        ScanSnapshot::new(
            HostId::generate(),
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "1.0.0".to_owned(),
            endpoints,
            firewall_rules,
            vec![],
            TargetStrategy::LocalOnly,
        )
    }

    fn allow_rule_for(port: u16) -> FirewallRule {
        FirewallRule {
            rule_id: RuleId::generate(),
            display_name: "allow".to_owned(),
            direction: Direction::Inbound,
            action: RuleAction::Allow,
            protocol: Protocol::Tcp,
            port_spec: PortSpec::Single(Port::try_from(port).unwrap()),
            program_filter: None,
            service_filter: None,
            enabled: true,
            policy_store: PolicyStore::Local,
        }
    }

    mod fixtures {
        use super::{
            Endpoint, ProcessId, Protocol, ScanSnapshot, allow_rule_for, build_snapshot,
            endpoint_at,
        };
        use crate::domain::drift::{DriftKind, Exposure, Reachability, Severity};

        pub(super) fn sample_snapshot() -> ScanSnapshot {
            build_snapshot(
                vec![
                    endpoint_at(Protocol::Tcp, "0.0.0.0", 443),
                    endpoint_at(Protocol::Tcp, "127.0.0.1", 8080),
                ],
                vec![],
            )
        }

        pub(super) fn same_endpoint_different_pid(endpoint: &Endpoint) -> Endpoint {
            let next_pid = endpoint.process_id.map_or(1, |pid| pid.get() + 1);
            Endpoint::new(
                endpoint.protocol,
                endpoint.bind_address,
                endpoint.port,
                Some(ProcessId::try_from(next_pid).unwrap()),
                endpoint.process_path.clone(),
                endpoint.hosted_services.clone(),
                endpoint.signature_status.clone(),
                endpoint.command_line.clone(),
            )
        }

        pub(super) fn snapshot_without_ephemeral_port(_port: u16) -> ScanSnapshot {
            build_snapshot(vec![endpoint_at(Protocol::Tcp, "0.0.0.0", 443)], vec![])
        }

        pub(super) fn snapshot_with_ephemeral_port(port: u16) -> ScanSnapshot {
            build_snapshot(
                vec![
                    endpoint_at(Protocol::Tcp, "0.0.0.0", 443),
                    endpoint_at(Protocol::Tcp, "10.0.0.5", port),
                ],
                vec![],
            )
        }

        pub(super) struct SeverityCase {
            pub name: &'static str,
            pub kind: DriftKind,
            pub exposure: Exposure,
            pub expected: Severity,
        }

        fn case(
            name: &'static str,
            kind: DriftKind,
            exposure: Exposure,
            expected: Severity,
        ) -> SeverityCase {
            SeverityCase {
                name,
                kind,
                exposure,
                expected,
            }
        }

        fn appeared_and_disappeared_cases() -> Vec<SeverityCase> {
            use DriftKind::{EndpointAppeared, EndpointDisappeared};
            use Exposure::{AllInterfaces, Loopback, SpecificInterface};
            vec![
                case(
                    "appeared/all-interfaces",
                    EndpointAppeared,
                    AllInterfaces,
                    Severity::Critical,
                ),
                case(
                    "appeared/specific-interface",
                    EndpointAppeared,
                    SpecificInterface,
                    Severity::High,
                ),
                case(
                    "appeared/loopback",
                    EndpointAppeared,
                    Loopback,
                    Severity::Low,
                ),
                case(
                    "disappeared/all-interfaces",
                    EndpointDisappeared,
                    AllInterfaces,
                    Severity::Low,
                ),
                case(
                    "disappeared/specific-interface",
                    EndpointDisappeared,
                    SpecificInterface,
                    Severity::Low,
                ),
                case(
                    "disappeared/loopback",
                    EndpointDisappeared,
                    Loopback,
                    Severity::Low,
                ),
            ]
        }

        fn newly_allowed(
            exposure: Exposure,
            expected: Severity,
            name: &'static str,
        ) -> SeverityCase {
            case(
                name,
                DriftKind::ReachabilityChanged {
                    before: Reachability::DefaultAction,
                    after: Reachability::Allowed,
                },
                exposure,
                expected,
            )
        }

        fn reachability_cases() -> Vec<SeverityCase> {
            use Exposure::AllInterfaces;
            use Reachability::{Allowed, Blocked, Indeterminate};
            vec![
                newly_allowed(
                    AllInterfaces,
                    Severity::Critical,
                    "newly-allowed/all-interfaces",
                ),
                newly_allowed(
                    Exposure::SpecificInterface,
                    Severity::High,
                    "newly-allowed/specific-interface",
                ),
                newly_allowed(Exposure::Loopback, Severity::Low, "newly-allowed/loopback"),
                case(
                    "newly-blocked/all-interfaces",
                    DriftKind::ReachabilityChanged {
                        before: Allowed,
                        after: Blocked,
                    },
                    AllInterfaces,
                    Severity::Low,
                ),
                case(
                    "reachability-shuffle-without-allow/all-interfaces",
                    DriftKind::ReachabilityChanged {
                        before: Blocked,
                        after: Indeterminate,
                    },
                    AllInterfaces,
                    Severity::Medium,
                ),
            ]
        }

        fn process_and_signature_cases() -> Vec<SeverityCase> {
            use DriftKind::{ProcessChanged, SignatureChanged};
            use Exposure::{AllInterfaces, Loopback, SpecificInterface};
            vec![
                case(
                    "process-changed/all-interfaces",
                    ProcessChanged,
                    AllInterfaces,
                    Severity::High,
                ),
                case(
                    "process-changed/specific-interface",
                    ProcessChanged,
                    SpecificInterface,
                    Severity::Medium,
                ),
                case(
                    "process-changed/loopback",
                    ProcessChanged,
                    Loopback,
                    Severity::Medium,
                ),
                case(
                    "signature-changed/all-interfaces",
                    SignatureChanged,
                    AllInterfaces,
                    Severity::High,
                ),
                case(
                    "signature-changed/specific-interface",
                    SignatureChanged,
                    SpecificInterface,
                    Severity::Medium,
                ),
                case(
                    "signature-changed/loopback",
                    SignatureChanged,
                    Loopback,
                    Severity::Medium,
                ),
            ]
        }

        fn rule_set_cases() -> Vec<SeverityCase> {
            vec![
                case(
                    "rule-set-changed/all-interfaces",
                    DriftKind::RuleSetChanged,
                    Exposure::AllInterfaces,
                    Severity::Medium,
                ),
                case(
                    "rule-set-changed/loopback",
                    DriftKind::RuleSetChanged,
                    Exposure::Loopback,
                    Severity::Medium,
                ),
            ]
        }

        /// A genuine cross product of drift kind and exposure — every kind
        /// against every exposure it can meaningfully occur under,
        /// including several representative `before`/`after` reachability
        /// pairs, not just the two cases the task's sketch shows in full.
        pub(super) fn severity_matrix() -> Vec<SeverityCase> {
            let mut cases = appeared_and_disappeared_cases();
            cases.extend(reachability_cases());
            cases.extend(process_and_signature_cases());
            cases.extend(rule_set_cases());
            cases
        }

        pub(super) fn loopback_endpoints() -> Vec<Endpoint> {
            vec![endpoint_at(Protocol::Tcp, "127.0.0.1", 22)]
        }

        pub(super) fn snapshot_with_rule_on_port(port: u16) -> ScanSnapshot {
            build_snapshot(loopback_endpoints(), vec![allow_rule_for(port)])
        }

        pub(super) fn snapshot_without_rules() -> ScanSnapshot {
            build_snapshot(loopback_endpoints(), vec![])
        }
    }

    #[test]
    fn self_diff_is_empty() {
        let snap = fixtures::sample_snapshot();
        let report = diff(&snap, &snap);
        assert!(report.entries.is_empty());
        assert_eq!(report.suppressed_ephemeral, 0);
    }

    /// Adapted from the task's own sketch, which referenced a nonexistent
    /// `Endpoint::owning_process` field: the real identity-relevant fields
    /// are `process_id: Option<ProcessId>` (never join/identity-driving) and
    /// `process_path: Option<ProcessPath>`. This builds two `Endpoint`s via
    /// `Endpoint::new` that differ only in `process_id` and asserts the join
    /// key and `ProcessChanged` classification both ignore it.
    #[test]
    fn pid_change_alone_is_not_drift() {
        let baseline = fixtures::sample_snapshot();
        let mut current = baseline.clone();
        current.endpoints[0] = fixtures::same_endpoint_different_pid(&baseline.endpoints[0]);
        let report = diff(&baseline, &current);
        assert!(report.entries.is_empty());
        assert_eq!(report.suppressed_ephemeral, 0);
    }

    #[test]
    fn ephemeral_port_churn_is_suppressed_not_dropped_silently() {
        let baseline = fixtures::snapshot_without_ephemeral_port(52_000);
        let current = fixtures::snapshot_with_ephemeral_port(52_000);
        let report = diff(&baseline, &current);
        assert_eq!(report.suppressed_ephemeral, 1);
        assert!(report.entries.is_empty());
    }

    #[test]
    fn severity_ordering_across_kind_and_exposure_matrix() {
        for case in fixtures::severity_matrix() {
            assert_eq!(
                severity_for(&case.kind, case.exposure),
                case.expected,
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn a_non_ephemeral_appeared_endpoint_is_reported() {
        let baseline = fixtures::snapshot_without_ephemeral_port(0);
        let current = build_snapshot(
            vec![
                endpoint_at(Protocol::Tcp, "0.0.0.0", 443),
                endpoint_at(Protocol::Tcp, "0.0.0.0", 80),
            ],
            vec![],
        );
        let report = diff(&baseline, &current);
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].kind, DriftKind::EndpointAppeared);
        assert_eq!(report.entries[0].severity, Severity::Critical);
    }

    #[test]
    fn reachability_changed_is_detected_when_a_new_allow_rule_appears() {
        let baseline = build_snapshot(vec![endpoint_at(Protocol::Tcp, "0.0.0.0", 443)], vec![]);
        let current = build_snapshot(
            vec![endpoint_at(Protocol::Tcp, "0.0.0.0", 443)],
            vec![allow_rule_for(443)],
        );
        let report = diff(&baseline, &current);
        // Adding a rule is itself a RuleSetChanged signal, alongside the
        // per-endpoint reachability effect of that rule — both are real.
        assert_eq!(report.entries.len(), 2);
        let reachability_entry = report
            .entries
            .iter()
            .find(|entry| matches!(entry.kind, DriftKind::ReachabilityChanged { .. }))
            .expect("a ReachabilityChanged entry");
        match &reachability_entry.kind {
            DriftKind::ReachabilityChanged { before, after } => {
                assert_eq!(*before, Reachability::DefaultAction);
                assert_eq!(*after, Reachability::Allowed);
            }
            other => panic!("expected ReachabilityChanged, got {other:?}"),
        }
        assert_eq!(reachability_entry.severity, Severity::Critical);
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.kind == DriftKind::RuleSetChanged)
        );
    }

    #[test]
    fn reachability_unchanged_when_firewall_rules_are_identical_is_not_reported() {
        let endpoints = vec![endpoint_at(Protocol::Tcp, "0.0.0.0", 443)];
        let rules = vec![allow_rule_for(443)];
        let baseline = build_snapshot(endpoints.clone(), rules.clone());
        let current = build_snapshot(endpoints, rules);
        let report = diff(&baseline, &current);
        assert!(
            report
                .entries
                .iter()
                .all(|entry| !matches!(entry.kind, DriftKind::ReachabilityChanged { .. }))
        );
    }

    #[test]
    fn signature_changed_is_detected_for_the_same_endpoint_key() {
        let baseline_endpoint = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").unwrap(),
            Port::try_from(443u16).unwrap(),
            None,
            None,
            vec![],
            SignatureStatus::Unknown,
            None,
        );
        let current_endpoint = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").unwrap(),
            Port::try_from(443u16).unwrap(),
            None,
            None,
            vec![],
            SignatureStatus::Signed(PublisherName::try_from("Contoso".to_owned()).unwrap()),
            None,
        );
        let baseline = build_snapshot(vec![baseline_endpoint], vec![]);
        let current = build_snapshot(vec![current_endpoint], vec![]);
        let report = diff(&baseline, &current);
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].kind, DriftKind::SignatureChanged);
    }

    #[test]
    fn identical_signature_status_is_not_reported() {
        let snap = fixtures::sample_snapshot();
        let report = diff(&snap, &snap);
        assert!(
            report
                .entries
                .iter()
                .all(|entry| entry.kind != DriftKind::SignatureChanged)
        );
    }

    #[test]
    fn process_changed_is_detected_when_process_path_differs() {
        let baseline_endpoint = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").unwrap(),
            Port::try_from(443u16).unwrap(),
            Some(ProcessId::try_from(100u32).unwrap()),
            Some(ProcessPath::from_str("C:\\svc\\old.exe").unwrap()),
            vec![],
            SignatureStatus::Unknown,
            None,
        );
        let current_endpoint = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").unwrap(),
            Port::try_from(443u16).unwrap(),
            Some(ProcessId::try_from(200u32).unwrap()),
            Some(ProcessPath::from_str("C:\\svc\\new.exe").unwrap()),
            vec![],
            SignatureStatus::Unknown,
            None,
        );
        let baseline = build_snapshot(vec![baseline_endpoint], vec![]);
        let current = build_snapshot(vec![current_endpoint], vec![]);
        let report = diff(&baseline, &current);
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].kind, DriftKind::ProcessChanged);
    }

    #[test]
    fn rule_set_changed_is_detected_independent_of_reachability() {
        let baseline = fixtures::snapshot_without_rules();
        let current = fixtures::snapshot_with_rule_on_port(22);
        let report = diff(&baseline, &current);
        // Loopback reachability is constant regardless of rules, so the
        // only entry this can produce is the snapshot-level signal.
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].kind, DriftKind::RuleSetChanged);
        assert_eq!(report.entries[0].endpoint_key, None);
    }

    #[test]
    fn identical_rule_sets_do_not_report_rule_set_changed() {
        let snap = fixtures::snapshot_with_rule_on_port(22);
        let report = diff(&snap, &snap);
        assert!(
            report
                .entries
                .iter()
                .all(|entry| entry.kind != DriftKind::RuleSetChanged)
        );
    }
}
