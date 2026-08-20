//! [`ReportModel`]: the serializable view model every report format renders from.
//!
//! Assembled once, from one or more [`ScanSnapshot`]s plus an optional
//! [`DriftReport`], with redaction already applied. No format-rendering
//! code (T21 JSON/CSV/SARIF, T23-T26 HTML) ever reaches back into
//! `ScanSnapshot`/`Endpoint` directly — this module owns the only path from
//! raw collected data to what a report can display, and every text field
//! that could carry a secret is redacted before it lands here. There is no
//! `ReportModel` accessor that hands back a raw `Endpoint` or its
//! unredacted `command_line`, so a future renderer cannot bypass this
//! boundary even by accident.
//!
//! # Known gap: `assignment_mismatches` and `certificate_findings`
//!
//! [`Rollup`] names both fields, per this task's own goal, but both are
//! always `0` today. Computing either genuinely requires data that no
//! current pipeline threads into [`ScanSnapshot`]: a mismatch needs an
//! evidence-backed *observed* [`crate::domain::ServiceIdentity`] per
//! endpoint (T08's `detect_mismatch` compares that against the registry
//! assignment), and a certificate finding needs T10's TLS inspection
//! output. Both live only in the probe/fingerprint/reconciliation pipeline
//! (`adapters::prober`, `adapters::tls_probe`, `domain::fingerprint`,
//! `domain::reconciliation`), which has no call site that folds its output
//! into a `ScanSnapshot`. Fabricating either count from data that isn't
//! actually evidence-backed would be worse than an honest zero. TODO(T31
//! integration-wiring): thread observed identities and certificate
//! findings into `ScanSnapshot` so these can be computed for real.

use crate::domain::bind_address::BindAddress;
use crate::domain::drift::{DriftEntry, DriftKind, DriftReport, EndpointKey, Severity};
use crate::domain::endpoint::Endpoint;
use crate::domain::exposure::Exposure;
use crate::domain::ids::{HostId, ScanId};
use crate::domain::port::Port;
use crate::domain::process::ProcessPath;
use crate::domain::protocol::Protocol;
use crate::domain::publisher::SignatureStatus;
use crate::domain::reachability::{Reachability, evaluate};
use crate::domain::redaction::{Redacted, redact};
use crate::domain::service::ServiceName;
use crate::domain::snapshot::ScanSnapshot;
use crate::domain::target_strategy::TargetStrategy;

/// Failure building a [`ReportModel`].
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// `no_redact_confirmed` was `false`.
    ///
    /// This task does not wire the real CLI `--no-redact` flow (that is a
    /// future CLI task's job), so `build` cannot distinguish "the caller
    /// never asked to disable redaction" from "the caller asked but never
    /// confirmed it" — a single `bool` cannot carry both states safely.
    /// Rather than guess, this contract is fail-closed: every caller,
    /// including the eventual default path with no `--no-redact` flag at
    /// all, must pass `true` explicitly. Redaction itself is always
    /// applied regardless of this flag's value once `build` proceeds —
    /// there is no code path in this task that can produce a
    /// `ReportModel` with unredacted text, since no downstream consumer
    /// exists yet that could safely be trusted with one.
    #[error(
        "redaction confirmation required: pass no_redact_confirmed = true, or wait for the \
         CLI task that wires --no-redact to a real second confirmation flag"
    )]
    RedactionConfirmationRequired,
}

/// Which collection tier a [`HostSection`] represents, in report-reader terms.
///
/// Derived from [`TargetStrategy`]: `Execute` and `LocalOnly` both ran a
/// collector directly and are authoritative; `Probe` never ran code on the
/// target and is inferred. See [`TargetStrategy`] for why `LocalOnly` counts
/// as authoritative rather than a third tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Fidelity {
    /// A collector ran on the target (or the target is the scanning host
    /// itself); PID, path, service, and firewall policy are ground truth.
    Authoritative,
    /// Observed from outside; every claim here is an inference, never a
    /// confirmed fact.
    Inferred,
}

impl Fidelity {
    const fn from_strategy(strategy: TargetStrategy) -> Self {
        match strategy {
            TargetStrategy::Execute | TargetStrategy::LocalOnly => Self::Authoritative,
            TargetStrategy::Probe => Self::Inferred,
        }
    }
}

/// Serializable mirror of [`Reachability`] for the view-model boundary.
///
/// `Reachability` itself deliberately carries no `serde` derive — it is a
/// pure-domain evaluation result, not a wire type — so this task adds a
/// report-local view rather than widen that type's surface for a single
/// downstream consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ReachabilityView {
    /// Bound to loopback only; never reachable off-host.
    LocalOnly,
    /// A firewall rule blocks the traffic.
    Blocked,
    /// A firewall rule allows the traffic.
    Allowed,
    /// No rule applies; governed by the profile's default action.
    DefaultAction,
    /// A dynamic port keyword made the verdict unresolvable statically.
    Indeterminate,
}

impl From<Reachability> for ReachabilityView {
    fn from(value: Reachability) -> Self {
        match value {
            Reachability::LocalOnly => Self::LocalOnly,
            Reachability::Blocked => Self::Blocked,
            Reachability::Allowed => Self::Allowed,
            Reachability::DefaultAction => Self::DefaultAction,
            Reachability::Indeterminate => Self::Indeterminate,
        }
    }
}

/// One listening endpoint as a report reader sees it: reachability already
/// resolved against its host's firewall policy, command line already
/// redacted.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EndpointView {
    /// Transport protocol the socket is bound with.
    pub protocol: Protocol,
    /// Address the socket is bound to.
    pub bind_address: BindAddress,
    /// Port the socket is bound to.
    pub port: Port,
    /// Owning process executable path, if resolved.
    pub process_path: Option<ProcessPath>,
    /// Services hosted behind this endpoint.
    pub hosted_services: Vec<ServiceName>,
    /// Code-signing status of the owning binary.
    pub signature_status: SignatureStatus,
    /// Reachability exposure, derived from `bind_address`.
    pub exposure: Exposure,
    /// Reachability against the host's own firewall rules and profiles.
    pub reachability: ReachabilityView,
    /// The owning process's command line, with every matched secret shape
    /// replaced by a `[REDACTED:...]` marker. `None` if the collector
    /// reported none.
    pub command_line: Option<String>,
    /// What was redacted from `command_line`, if anything — present so a
    /// reader can tell "no command line" apart from "command line present,
    /// nothing secret-shaped in it" apart from "secrets were found and
    /// removed."
    pub command_line_redactions: Vec<Redacted<String>>,
}

/// One host's section of the report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostSection {
    /// The host this section describes.
    pub host_id: HostId,
    /// The scan run that produced this section.
    pub scan_id: ScanId,
    /// When the collector gathered this data.
    pub collected_at: time::OffsetDateTime,
    /// Version string of the collector that produced this snapshot.
    pub collector_version: String,
    /// Which collection tier produced this section.
    pub strategy: TargetStrategy,
    /// Whether this section is authoritative or inferred — must render
    /// visually and textually distinct downstream; see [`Fidelity`].
    pub fidelity: Fidelity,
    /// Observed endpoints, in the snapshot's own stable order.
    pub endpoints: Vec<EndpointView>,
}

/// Serializable mirror of [`Severity`] for the view-model boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum SeverityView {
    /// Informational; no action expected.
    Low,
    /// Worth a look, not urgent.
    Medium,
    /// Should be reviewed promptly.
    High,
    /// Top of the list — review first.
    Critical,
}

impl From<Severity> for SeverityView {
    fn from(value: Severity) -> Self {
        match value {
            Severity::Low => Self::Low,
            Severity::Medium => Self::Medium,
            Severity::High => Self::High,
            Severity::Critical => Self::Critical,
        }
    }
}

/// Serializable mirror of [`EndpointKey`] for the view-model boundary.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EndpointKeyView {
    /// Transport protocol the socket is bound with.
    pub protocol: Protocol,
    /// Address the socket is bound to.
    pub bind_address: BindAddress,
    /// Port the socket is bound to.
    pub port: Port,
}

impl From<&EndpointKey> for EndpointKeyView {
    fn from(key: &EndpointKey) -> Self {
        Self {
            protocol: key.protocol,
            bind_address: key.bind_address,
            port: key.port,
        }
    }
}

/// Serializable mirror of [`DriftKind`] for the view-model boundary.
#[derive(Debug, Clone, serde::Serialize)]
pub enum DriftKindView {
    /// An endpoint present in the current scan was absent from the baseline.
    EndpointAppeared,
    /// An endpoint present in the baseline is absent from the current scan.
    EndpointDisappeared,
    /// The same endpoint's reachability verdict differs between the two scans.
    ReachabilityChanged {
        /// Reachability under the baseline's own firewall policy.
        before: ReachabilityView,
        /// Reachability under the current scan's firewall policy.
        after: ReachabilityView,
    },
    /// The same endpoint's owning process identity changed.
    ProcessChanged,
    /// The same endpoint's binary signature status changed.
    SignatureChanged,
    /// The firewall rule set itself changed between the two snapshots.
    RuleSetChanged,
}

impl From<&DriftKind> for DriftKindView {
    fn from(kind: &DriftKind) -> Self {
        match kind {
            DriftKind::EndpointAppeared => Self::EndpointAppeared,
            DriftKind::EndpointDisappeared => Self::EndpointDisappeared,
            DriftKind::ReachabilityChanged { before, after } => Self::ReachabilityChanged {
                before: ReachabilityView::from(*before),
                after: ReachabilityView::from(*after),
            },
            DriftKind::ProcessChanged => Self::ProcessChanged,
            DriftKind::SignatureChanged => Self::SignatureChanged,
            DriftKind::RuleSetChanged => Self::RuleSetChanged,
        }
    }
}

/// One detected change between a baseline and a rescan, as a report reader sees it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DriftEntryView {
    /// What kind of change this is.
    pub kind: DriftKindView,
    /// The endpoint this entry concerns, or `None` for a snapshot-level signal.
    pub endpoint_key: Option<EndpointKeyView>,
    /// How urgently this entry warrants review.
    pub severity: SeverityView,
}

impl From<&DriftEntry> for DriftEntryView {
    fn from(entry: &DriftEntry) -> Self {
        Self {
            kind: DriftKindView::from(&entry.kind),
            endpoint_key: entry.endpoint_key.as_ref().map(EndpointKeyView::from),
            severity: SeverityView::from(entry.severity),
        }
    }
}

/// Endpoint counts grouped by [`Exposure`].
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct ExposureCounts {
    /// Endpoints bound to loopback only.
    pub loopback: usize,
    /// Endpoints bound to one specific, non-loopback interface.
    pub specific_interface: usize,
    /// Endpoints bound to every interface.
    pub all_interfaces: usize,
}

/// Endpoint counts grouped by [`Reachability`].
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct ReachabilityCounts {
    /// Never reachable off-host regardless of policy.
    pub local_only: usize,
    /// Blocked by at least one applicable firewall rule.
    pub blocked: usize,
    /// Allowed by at least one applicable firewall rule.
    pub allowed: usize,
    /// No rule applies; governed by the profile's default action.
    pub default_action: usize,
    /// A dynamic port keyword made the verdict unresolvable statically.
    pub indeterminate: usize,
}

/// Drift entry counts grouped by [`Severity`].
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct DriftSeverityCounts {
    /// Informational entries.
    pub low: usize,
    /// Entries worth a look.
    pub medium: usize,
    /// Entries that should be reviewed promptly.
    pub high: usize,
    /// Entries to review first.
    pub critical: usize,
}

/// Fleet-wide aggregates, built genuinely from the input snapshots and
/// drift report — never left as empty placeholders.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Rollup {
    /// Number of hosts represented in this report.
    pub hosts_scanned: usize,
    /// Every observed endpoint, grouped by [`Exposure`].
    pub endpoints_by_exposure: ExposureCounts,
    /// Every observed endpoint, grouped by [`Reachability`] against its own
    /// host's firewall policy.
    pub endpoints_by_reachability: ReachabilityCounts,
    /// Count of endpoints whose owning binary is [`SignatureStatus::Unsigned`].
    pub unsigned_binaries: usize,
    /// See the module-level "Known gap" section — always `0` today.
    pub assignment_mismatches: usize,
    /// See the module-level "Known gap" section — always `0` today.
    pub certificate_findings: usize,
    /// Every drift entry, grouped by [`Severity`].
    pub drift_by_severity: DriftSeverityCounts,
}

/// The serializable view model every report format renders from.
///
/// Built once, with redaction already applied — see the module docs for why
/// no downstream format can bypass that boundary.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReportModel {
    /// One section per host, sorted by `(host_id, scan_id)` for
    /// deterministic serialization regardless of the order `snapshots` was
    /// supplied in.
    pub hosts: Vec<HostSection>,
    /// Every drift entry from the supplied [`DriftReport`], if any, in its
    /// own stable order.
    pub drift: Vec<DriftEntryView>,
    /// Fleet-wide aggregates.
    pub rollup: Rollup,
    /// Whether redaction was applied to this model. Always `true` today —
    /// see [`ReportError::RedactionConfirmationRequired`] for why this task
    /// has no code path that produces `false`. A future renderer should
    /// still check this field (rather than assume it) and render a
    /// prominent banner when it is `false`, once a later task adds a real
    /// way to reach that state.
    pub redaction_enabled: bool,
}

impl ReportModel {
    /// Assembles a [`ReportModel`] from `snapshots` and an optional
    /// `drift` report, redacting every command line along the way.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::RedactionConfirmationRequired`] if
    /// `no_redact_confirmed` is `false`. See that variant's docs for why
    /// this contract is fail-closed rather than defaulting to success.
    pub fn build(
        snapshots: &[ScanSnapshot],
        drift: Option<&DriftReport>,
        no_redact_confirmed: bool,
    ) -> Result<Self, ReportError> {
        if !no_redact_confirmed {
            return Err(ReportError::RedactionConfirmationRequired);
        }

        let mut hosts: Vec<HostSection> = snapshots.iter().map(build_host_section).collect();
        hosts.sort_by_key(|host| (host.host_id, host.scan_id));

        let drift_entries = drift.map_or_else(Vec::new, |report| {
            report.entries.iter().map(DriftEntryView::from).collect()
        });

        Ok(Self {
            rollup: build_rollup(snapshots, drift),
            hosts,
            drift: drift_entries,
            redaction_enabled: true,
        })
    }
}

fn build_host_section(snapshot: &ScanSnapshot) -> HostSection {
    let endpoints = snapshot
        .endpoints
        .iter()
        .map(|endpoint| build_endpoint_view(endpoint, snapshot))
        .collect();
    HostSection {
        host_id: snapshot.host_id,
        scan_id: snapshot.scan_id,
        collected_at: snapshot.collected_at,
        collector_version: snapshot.collector_version.clone(),
        strategy: snapshot.strategy,
        fidelity: Fidelity::from_strategy(snapshot.strategy),
        endpoints,
    }
}

fn build_endpoint_view(endpoint: &Endpoint, snapshot: &ScanSnapshot) -> EndpointView {
    let reachability =
        evaluate(endpoint, &snapshot.firewall_rules, &snapshot.profiles).reachability;
    let (command_line, command_line_redactions) = endpoint.command_line.as_deref().map_or_else(
        || (None, Vec::new()),
        |raw| {
            let (redacted, markers) = redact(raw);
            (Some(redacted), markers)
        },
    );
    EndpointView {
        protocol: endpoint.protocol,
        bind_address: endpoint.bind_address,
        port: endpoint.port,
        process_path: endpoint.process_path.clone(),
        hosted_services: endpoint.hosted_services.clone(),
        signature_status: endpoint.signature_status.clone(),
        exposure: endpoint.exposure,
        reachability: ReachabilityView::from(reachability),
        command_line,
        command_line_redactions,
    }
}

fn build_rollup(snapshots: &[ScanSnapshot], drift: Option<&DriftReport>) -> Rollup {
    let mut endpoints_by_exposure = ExposureCounts::default();
    let mut endpoints_by_reachability = ReachabilityCounts::default();
    let mut unsigned_binaries = 0usize;

    for snapshot in snapshots {
        for endpoint in &snapshot.endpoints {
            match endpoint.exposure {
                Exposure::Loopback => endpoints_by_exposure.loopback += 1,
                Exposure::SpecificInterface => endpoints_by_exposure.specific_interface += 1,
                Exposure::AllInterfaces => endpoints_by_exposure.all_interfaces += 1,
            }
            match evaluate(endpoint, &snapshot.firewall_rules, &snapshot.profiles).reachability {
                Reachability::LocalOnly => endpoints_by_reachability.local_only += 1,
                Reachability::Blocked => endpoints_by_reachability.blocked += 1,
                Reachability::Allowed => endpoints_by_reachability.allowed += 1,
                Reachability::DefaultAction => endpoints_by_reachability.default_action += 1,
                Reachability::Indeterminate => endpoints_by_reachability.indeterminate += 1,
            }
            if endpoint.signature_status == SignatureStatus::Unsigned {
                unsigned_binaries += 1;
            }
        }
    }

    let mut drift_by_severity = DriftSeverityCounts::default();
    if let Some(report) = drift {
        for entry in &report.entries {
            match entry.severity {
                Severity::Low => drift_by_severity.low += 1,
                Severity::Medium => drift_by_severity.medium += 1,
                Severity::High => drift_by_severity.high += 1,
                Severity::Critical => drift_by_severity.critical += 1,
            }
        }
    }

    Rollup {
        hosts_scanned: snapshots.len(),
        endpoints_by_exposure,
        endpoints_by_reachability,
        unsigned_binaries,
        assignment_mismatches: 0,
        certificate_findings: 0,
        drift_by_severity,
    }
}

#[cfg(test)]
mod tests {
    use super::{Fidelity, ReportModel};
    use crate::domain::drift::diff;
    use crate::domain::ids::{HostId, ScanId};
    use crate::domain::snapshot::ScanSnapshot;
    use crate::domain::target_strategy::TargetStrategy;

    mod fixtures {
        use core::str::FromStr as _;

        use crate::domain::bind_address::BindAddress;
        use crate::domain::endpoint::Endpoint;
        use crate::domain::ids::{HostId, ScanId};
        use crate::domain::port::Port;
        use crate::domain::process::ProcessPath;
        use crate::domain::protocol::Protocol;
        use crate::domain::publisher::SignatureStatus;
        use crate::domain::service::ServiceName;
        use crate::domain::snapshot::ScanSnapshot;
        use crate::domain::target_strategy::TargetStrategy;

        pub(super) fn snapshots() -> Vec<ScanSnapshot> {
            vec![authoritative_host(), probe_host()]
        }

        fn authoritative_host() -> ScanSnapshot {
            let endpoint = Endpoint::new(
                Protocol::Tcp,
                BindAddress::from_str("0.0.0.0").expect("valid ip"),
                Port::try_from(443u16).expect("nonzero port"),
                None,
                Some(ProcessPath::from_str("C:\\svc\\installer.exe").expect("non-empty path")),
                vec![ServiceName::try_from("MyService".to_owned()).expect("non-empty name")],
                SignatureStatus::Unsigned,
                Some(r"installer.exe /user:admin password=hunter2".to_owned()),
            );
            ScanSnapshot::new(
                HostId::generate(),
                ScanId::generate(),
                time::OffsetDateTime::UNIX_EPOCH,
                "1.0.0".to_owned(),
                vec![endpoint],
                vec![],
                vec![],
                TargetStrategy::Execute,
            )
        }

        fn probe_host() -> ScanSnapshot {
            let endpoint = Endpoint::new(
                Protocol::Tcp,
                BindAddress::from_str("127.0.0.1").expect("valid ip"),
                Port::try_from(22u16).expect("nonzero port"),
                None,
                None,
                vec![],
                SignatureStatus::Unknown,
                None,
            );
            ScanSnapshot::new(
                HostId::generate(),
                ScanId::generate(),
                time::OffsetDateTime::UNIX_EPOCH,
                "1.0.0".to_owned(),
                vec![endpoint],
                vec![],
                vec![],
                TargetStrategy::Probe,
            )
        }
    }

    #[test]
    fn no_redact_without_confirmation_is_rejected() {
        let err = ReportModel::build(&fixtures::snapshots(), None, false).unwrap_err();
        let _ = err; // this call path represents `--no-redact` without the second flag
    }

    #[test]
    fn view_model_rendering_is_deterministic() {
        let snapshots = fixtures::snapshots();
        let model_a = ReportModel::build(&snapshots, None, true).unwrap();
        let model_b = ReportModel::build(&snapshots, None, true).unwrap();
        assert_eq!(
            serde_json::to_vec(&model_a).unwrap(),
            serde_json::to_vec(&model_b).unwrap()
        );
    }

    #[test]
    fn command_line_secrets_never_reach_the_serialized_view_model() {
        let snapshots = fixtures::snapshots();
        let model = ReportModel::build(&snapshots, None, true).unwrap();

        let json = serde_json::to_string(&model).expect("model serializes");
        assert!(!json.contains("hunter2"));

        let authoritative_host = model
            .hosts
            .iter()
            .find(|host| host.fidelity == Fidelity::Authoritative)
            .expect("one authoritative host in fixtures");
        let endpoint = authoritative_host
            .endpoints
            .first()
            .expect("one endpoint in fixtures");
        assert!(!endpoint.command_line_redactions.is_empty());
        assert!(
            endpoint
                .command_line
                .as_deref()
                .is_some_and(|line| !line.contains("hunter2"))
        );
    }

    #[test]
    fn fidelity_is_derived_from_target_strategy_per_host() {
        let snapshots = fixtures::snapshots();
        let model = ReportModel::build(&snapshots, None, true).unwrap();
        let fidelities: Vec<Fidelity> = model.hosts.iter().map(|host| host.fidelity).collect();
        assert!(fidelities.contains(&Fidelity::Authoritative));
        assert!(fidelities.contains(&Fidelity::Inferred));
    }

    #[test]
    fn rollup_counts_are_built_from_the_real_input_not_left_empty() {
        let snapshots = fixtures::snapshots();
        let model = ReportModel::build(&snapshots, None, true).unwrap();
        assert_eq!(model.rollup.hosts_scanned, 2);
        assert_eq!(model.rollup.unsigned_binaries, 1);
        assert_eq!(model.rollup.endpoints_by_exposure.all_interfaces, 1);
        assert_eq!(model.rollup.endpoints_by_exposure.loopback, 1);
    }

    #[test]
    fn drift_by_severity_rollup_reflects_a_real_drift_report() {
        let host_id = HostId::generate();
        let baseline = ScanSnapshot::new(
            host_id,
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "1.0.0".to_owned(),
            vec![],
            vec![],
            vec![],
            TargetStrategy::Execute,
        );
        let current = fixtures::snapshots();
        let current_host = current.first().expect("fixture host present").clone();
        let report = diff(&baseline, &current_host);
        assert!(!report.entries.is_empty(), "fixture must produce real drift");

        let model = ReportModel::build(&[current_host], Some(&report), true).unwrap();
        let total = model.rollup.drift_by_severity.low
            + model.rollup.drift_by_severity.medium
            + model.rollup.drift_by_severity.high
            + model.rollup.drift_by_severity.critical;
        assert_eq!(total, report.entries.len());
        assert_eq!(model.drift.len(), report.entries.len());
    }
}
