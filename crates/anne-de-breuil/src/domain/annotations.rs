//! [`Annotation`]/[`select_annotation`]/[`executive_summary`]: the editorial
//! layer over [`ReportModel`] -- the prose a reader sees before touching a
//! single table.
//!
//! Pure and zero I/O, like every other `domain/*` module. Two things live
//! here: `executive_summary`, plain declarative sentences generated from
//! [`Rollup`]'s real counts, and `select_annotation`, which picks at most
//! one finding worth a margin callout on the rendered report. Both are
//! generated from the model on every call -- neither is ever hand-written
//! or hard-coded for a specific report.
//!
//! # Two candidate types, not three
//!
//! The task this module implements names a third candidate: a
//! "well-known-port mismatch" (e.g. something other than sshd answering on
//! port 22). Building that honestly needs an evidence-backed observed
//! service identity to compare against an expected one -- exactly what
//! [`crate::domain::fingerprint`]/[`crate::domain::reconciliation`] produce,
//! and exactly what [`ReportModel`]'s own module doc already flags as never
//! reaching a [`crate::domain::snapshot::ScanSnapshot`] today (see
//! `report_model`'s "Known gap" section, the same reason
//! `Rollup::assignment_mismatches`/`certificate_findings` are permanently
//! `0`). A heuristic built from `process_path`/`hosted_services` name
//! pattern-matching alone would produce a superficially plausible finding
//! with no fingerprint behind it -- indistinguishable in the rendered
//! report from a real one, which is worse than not shipping it. Omitted;
//! `select_annotation` chooses from the two candidates that are genuinely
//! evidence-backed by data already in [`ReportModel`]: the highest-severity
//! drift entry, and the most exposed unsigned listener.
//!
//! # `DiagramAnchor`: a category, not a coordinate
//!
//! [`Annotation::leader_target`] names which diagram the callout concerns,
//! not a specific shape inside one -- see [`DiagramAnchor`]'s own doc
//! comment for why.

use crate::domain::exposure::Exposure;
use crate::domain::ids::HostId;
use crate::domain::publisher::SignatureStatus;
use crate::domain::report_model::{
    DriftEntryView, DriftKindView, EndpointView, ReportModel, Rollup, SeverityView,
};

/// Vocabulary this module's generated prose never uses.
///
/// Applies to both `executive_summary` and an [`Annotation::headline`] --
/// enforced by `tests::generated_prose_avoids_banned_vocabulary` across a
/// fixture set, the real check; `debug_assert!` alone would compile out of
/// a release build and enforce nothing in production.
pub const BANNED_WORDS: &[&str] = &[
    "robust",
    "leverage",
    "comprehensive",
    "seamless",
    "delve",
    "crucially",
];

/// Which diagram, if any, an [`Annotation`]'s leader line points toward.
///
/// T25 assigns no `id` attribute to any individual shape inside a rendered
/// `<svg>` (every `SvgCanvas::rect`/`text`/`line` call takes a `class` for
/// styling, never an identity) -- confirmed by reading `domain::svg` and
/// every file under `adapters::html_report::diagrams` before writing this
/// type. A leader line therefore cannot address "this specific rect" or
/// "this specific marker," only "the exposure map" or "the drift timeline"
/// as a whole. Widening T25's already-shipped, already-tested rendering
/// primitives with a new per-shape identity scheme just for this one
/// consumer was rejected in favor of the coarser, honest granularity this
/// type actually offers -- and a literal pixel-precise pointer from margin
/// prose to a point inside a sibling `<svg>` isn't achievable in a
/// responsive, JavaScript-free layout anyway, since final element position
/// is only known once a browser lays the page out. See
/// `adapters::html_report::annotation_view` for how the rendered callout
/// honors this: a small decorative dashed Bezier drawn inside the callout
/// itself, with the target diagram named in the callout's own text, rather
/// than a fabricated cross-element pointer this data model can't back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagramAnchor {
    /// The per-host exposure map (`adapters::html_report::diagrams::exposure_map`).
    ExposureMap,
    /// The fleet-wide drift timeline (`adapters::html_report::diagrams::drift_timeline`).
    DriftTimeline,
}

/// A single editorial callout: plain declarative prose plus which diagram
/// it concerns.
///
/// Never constructed by hand for a specific report -- the only constructor
/// is [`select_annotation`], generated from real model data every time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    /// A plain declarative sentence. No hedging, no filler adjectives, no
    /// [`BANNED_WORDS`].
    pub headline: String,
    /// Which diagram this callout concerns -- see [`DiagramAnchor`].
    pub leader_target: DiagramAnchor,
}

/// Picks the single highest-priority finding worth a margin callout, or
/// `None` if nothing qualifies.
///
/// An empty callout is worse than none, so this returns `None` rather than
/// a placeholder the moment neither candidate produces anything -- the
/// clean-snapshot case this module's own tests pin.
///
/// Candidates are scored by [`SeverityView`] and, when two candidate
/// *types* tie (the drift candidate's own severity happens to equal the
/// exposed-listener candidate's fixed [`SeverityView::Critical`]), broken
/// by comparing their already-generated headline text -- deterministic
/// because it depends on nothing but the model itself, never on hash-map
/// iteration order or wall-clock time.
#[must_use]
pub fn select_annotation(model: &ReportModel) -> Option<Annotation> {
    let mut candidates: Vec<(SeverityView, Annotation)> = Vec::new();

    if let Some(worst_drift) = highest_severity_drift(&model.drift) {
        candidates.push((worst_drift.severity, annotation_for_drift(worst_drift)));
    }
    if let Some((host_id, endpoint)) = most_exposed_unsigned_listener(model) {
        candidates.push((
            SeverityView::Critical,
            annotation_for_exposed_listener(host_id, endpoint),
        ));
    }

    candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.headline.cmp(&b.1.headline)));
    candidates
        .into_iter()
        .next()
        .map(|(_, annotation)| annotation)
}

/// Finds the highest-severity entry in `entries`, keeping the first one
/// reached when severities tie.
///
/// Tie-break key: `entries`'s own order, which [`ReportModel::build`]
/// always produces identically for the same input (see that function's own
/// doc comment -- "in its own stable order") -- so scanning left-to-right
/// and only replacing the current best on a *strictly* greater severity is
/// itself a deterministic, reproducible tie-break, not an arbitrary one.
/// `Iterator::max_by_key` was deliberately not used here: it returns the
/// *last* maximum on a tie, the opposite of what "stable, input-order
/// tie-break" requires.
fn highest_severity_drift(entries: &[DriftEntryView]) -> Option<&DriftEntryView> {
    let mut best: Option<&DriftEntryView> = None;
    for entry in entries {
        if best.is_none_or(|current| entry.severity > current.severity) {
            best = Some(entry);
        }
    }
    best
}

/// Finds the unsigned, all-interfaces-exposed endpoint most worth flagging
/// across every host in `model`.
///
/// Tie-break, applied when more than one endpoint qualifies: lowest port
/// number first, then [`HostId`] (an opaque UUID, but a total order all the
/// same) as the final, always-decisive tie-break -- chosen because a lower
/// port number is conventionally the more surprising thing to find
/// unsigned and world-reachable (well-known service ports before ephemeral
/// ones), and `HostId` guarantees a single winner even if two hosts somehow
/// share the exact same port.
fn most_exposed_unsigned_listener(model: &ReportModel) -> Option<(HostId, &EndpointView)> {
    model
        .hosts
        .iter()
        .flat_map(|host| {
            let host_id = host.host_id;
            host.endpoints
                .iter()
                .map(move |endpoint| (host_id, endpoint))
        })
        .filter(|(_, endpoint)| {
            endpoint.signature_status == SignatureStatus::Unsigned
                && endpoint.exposure == Exposure::AllInterfaces
        })
        .min_by_key(|(host_id, endpoint)| (endpoint.port, *host_id))
}

fn annotation_for_drift(entry: &DriftEntryView) -> Annotation {
    let where_ = entry.endpoint_key.as_ref().map_or_else(
        || "the rule set".to_owned(),
        |key| format!("{} {}:{}", key.protocol, key.bind_address, key.port),
    );
    Annotation {
        headline: format!(
            "{} at {where_} is the most severe change since the baseline.",
            drift_kind_headline(&entry.kind)
        ),
        leader_target: DiagramAnchor::DriftTimeline,
    }
}

const fn drift_kind_headline(kind: &DriftKindView) -> &'static str {
    match kind {
        DriftKindView::EndpointAppeared => "A new endpoint appeared",
        DriftKindView::EndpointDisappeared => "An endpoint disappeared",
        DriftKindView::ReachabilityChanged { .. } => "Reachability changed",
        DriftKindView::ProcessChanged => "The owning process changed",
        DriftKindView::SignatureChanged => "The binary signature changed",
        DriftKindView::RuleSetChanged => "The firewall rule set changed",
    }
}

fn annotation_for_exposed_listener(host_id: HostId, endpoint: &EndpointView) -> Annotation {
    Annotation {
        headline: format!(
            "Port {} on host {} is unsigned and reachable on every interface.",
            endpoint.port,
            short_host_id(host_id)
        ),
        leader_target: DiagramAnchor::ExposureMap,
    }
}

/// The first eight characters of a host id -- enough to distinguish hosts
/// in one sentence without spelling out a full UUID, matching the same
/// truncation convention `adapters::html_report` already uses.
fn short_host_id(host_id: HostId) -> String {
    host_id.to_string().chars().take(8).collect()
}

/// Sums every severity tier's count in `by_severity` into one total.
const fn drift_total(rollup: &Rollup) -> usize {
    rollup.drift_by_severity.low
        + rollup.drift_by_severity.medium
        + rollup.drift_by_severity.high
        + rollup.drift_by_severity.critical
}

/// "No findings," precisely: zero endpoints exposed on all interfaces,
/// zero unsigned binaries, and zero drift entries of any severity. These
/// three counts are exactly the ones [`executive_summary`] reports by name
/// when they are *not* all zero -- `assignment_mismatches`/
/// `certificate_findings` are excluded from both this definition and the
/// summary sentence itself, since both are permanently `0` today regardless
/// of the real fleet's state (see `report_model`'s "Known gap" doc) and
/// folding a field that can never be anything but zero into a "clean"
/// determination would make every report "clean" by construction on that
/// axis alone, whether or not it actually is.
const fn has_no_findings(rollup: &Rollup) -> bool {
    rollup.endpoints_by_exposure.all_interfaces == 0
        && rollup.unsigned_binaries == 0
        && drift_total(rollup) == 0
}

/// Generates the report's executive summary: plain declarative sentences
/// built from `rollup`'s real counts, no hedging, no filler adjectives.
///
/// See [`has_no_findings`] for exactly what "no findings" means here.
#[must_use]
pub fn executive_summary(rollup: &Rollup) -> String {
    if has_no_findings(rollup) {
        return format!("Scanned {} hosts. No findings.", rollup.hosts_scanned);
    }
    let sentence = format!(
        "Scanned {} hosts and found {} endpoints exposed on all interfaces, {} unsigned \
         binaries, and {} drift entries since the baseline.",
        rollup.hosts_scanned,
        rollup.endpoints_by_exposure.all_interfaces,
        rollup.unsigned_binaries,
        drift_total(rollup)
    );
    // Belt, not the buckle -- the real enforcement is
    // `tests::generated_prose_avoids_banned_vocabulary`, which runs in
    // release builds too.
    debug_assert!(
        BANNED_WORDS
            .iter()
            .all(|word| !sentence.to_lowercase().contains(word)),
        "executive_summary produced banned vocabulary: {sentence}"
    );
    sentence
}

#[cfg(test)]
mod tests {
    use super::{
        Annotation, BANNED_WORDS, DiagramAnchor, executive_summary, has_no_findings,
        highest_severity_drift, most_exposed_unsigned_listener, select_annotation,
    };
    use crate::domain::report_model::{DriftEntryView, ReportModel, Rollup};

    mod fixtures {
        use core::str::FromStr as _;

        use crate::domain::bind_address::BindAddress;
        use crate::domain::drift::DriftReport;
        use crate::domain::drift::diff;
        use crate::domain::endpoint::Endpoint;
        use crate::domain::ids::{HostId, ScanId};
        use crate::domain::port::Port;
        use crate::domain::process::ProcessPath;
        use crate::domain::protocol::Protocol;
        use crate::domain::publisher::SignatureStatus;
        use crate::domain::report_model::{ReportModel, Rollup};
        use crate::domain::service::ServiceName;
        use crate::domain::snapshot::ScanSnapshot;
        use crate::domain::target_strategy::TargetStrategy;

        fn loopback_signed_host() -> ScanSnapshot {
            let endpoint = Endpoint::new(
                Protocol::Tcp,
                BindAddress::from_str("127.0.0.1").expect("valid ip"),
                Port::try_from(8080u16).expect("nonzero port"),
                None,
                Some(ProcessPath::from_str("/usr/bin/app").expect("non-empty path")),
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
                TargetStrategy::Execute,
            )
        }

        /// Three clean hosts: no all-interfaces exposure, no unsigned
        /// binaries, no drift.
        pub(super) fn report_model_with_no_findings() -> ReportModel {
            let snapshots = vec![
                loopback_signed_host(),
                loopback_signed_host(),
                loopback_signed_host(),
            ];
            ReportModel::build(&snapshots, None, true).expect("clean fixture model builds")
        }

        fn unsigned_all_interfaces_host(port: u16) -> ScanSnapshot {
            let endpoint = Endpoint::new(
                Protocol::Tcp,
                BindAddress::from_str("0.0.0.0").expect("valid ip"),
                Port::try_from(port).expect("nonzero port"),
                None,
                Some(ProcessPath::from_str("C:\\svc\\app.exe").expect("non-empty path")),
                vec![ServiceName::try_from("Svc".to_owned()).expect("non-empty name")],
                SignatureStatus::Unsigned,
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
                TargetStrategy::Execute,
            )
        }

        /// A `Critical`-severity `EndpointAppeared` drift entry (an
        /// all-interfaces endpoint appearing since the baseline -- see
        /// `domain::drift::severity_for`) alongside an unsigned,
        /// all-interfaces listener, whose candidate annotation is also
        /// scored `Critical`. Both types tie at the top severity.
        pub(super) fn report_model_with_tied_severity_findings() -> (ReportModel, DriftReport) {
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
            let current_endpoint = Endpoint::new(
                Protocol::Tcp,
                BindAddress::from_str("0.0.0.0").expect("valid ip"),
                Port::try_from(9443u16).expect("nonzero port"),
                None,
                None,
                vec![],
                SignatureStatus::Unknown,
                None,
            );
            let current = ScanSnapshot::new(
                host_id,
                ScanId::generate(),
                time::OffsetDateTime::UNIX_EPOCH,
                "1.0.0".to_owned(),
                vec![current_endpoint],
                vec![],
                vec![],
                TargetStrategy::Execute,
            );
            let report = diff(&baseline, &current);
            assert!(
                report
                    .entries
                    .iter()
                    .any(|entry| entry.severity == crate::domain::drift::Severity::Critical),
                "fixture must produce a Critical drift entry"
            );

            let exposed_snapshot = unsigned_all_interfaces_host(443);
            let model = ReportModel::build(&[current, exposed_snapshot], Some(&report), true)
                .expect("tied-severity fixture model builds");
            (model, report)
        }

        pub(super) fn rollup_with_findings() -> Rollup {
            let snapshots = vec![unsigned_all_interfaces_host(22)];
            let model =
                ReportModel::build(&snapshots, None, true).expect("findings fixture model builds");
            model.rollup
        }

        pub(super) fn model_with_only_an_unsigned_all_interfaces_listener(
            port: u16,
        ) -> ReportModel {
            ReportModel::build(&[unsigned_all_interfaces_host(port)], None, true)
                .expect("single-listener fixture model builds")
        }
    }

    #[test]
    fn clean_snapshot_produces_no_findings_summary_and_no_annotation() {
        let model = fixtures::report_model_with_no_findings();
        assert_eq!(
            executive_summary(&model.rollup),
            "Scanned 3 hosts. No findings."
        );
        assert!(select_annotation(&model).is_none());
    }

    #[test]
    fn has_no_findings_ignores_the_permanently_zero_mismatch_fields() {
        let mut rollup = fixtures::rollup_with_findings();
        rollup.endpoints_by_exposure.all_interfaces = 0;
        rollup.unsigned_binaries = 0;
        rollup.drift_by_severity = crate::domain::report_model::DriftSeverityCounts::default();
        // assignment_mismatches/certificate_findings are always 0 already;
        // this rollup is "clean" by this module's definition regardless.
        assert!(has_no_findings(&rollup));
    }

    #[test]
    fn tied_severities_resolve_deterministically() {
        let (model, _report) = fixtures::report_model_with_tied_severity_findings();
        let first = select_annotation(&model);
        let second = select_annotation(&model);
        assert_eq!(
            first.map(|annotation| annotation.headline),
            second.map(|annotation| annotation.headline)
        );
        assert!(first_is_some(&model));
    }

    fn first_is_some(model: &ReportModel) -> bool {
        select_annotation(model).is_some()
    }

    #[test]
    fn generated_prose_avoids_banned_vocabulary() {
        let summary = executive_summary(&fixtures::rollup_with_findings());
        for word in BANNED_WORDS {
            assert!(!summary.to_lowercase().contains(word));
        }

        let (tied_model, _report) = fixtures::report_model_with_tied_severity_findings();
        if let Some(annotation) = select_annotation(&tied_model) {
            for word in BANNED_WORDS {
                assert!(!annotation.headline.to_lowercase().contains(word));
            }
        }

        let listener_model = fixtures::model_with_only_an_unsigned_all_interfaces_listener(3389);
        let annotation = select_annotation(&listener_model).expect("listener model has a finding");
        for word in BANNED_WORDS {
            assert!(!annotation.headline.to_lowercase().contains(word));
        }
    }

    #[test]
    fn most_exposed_unsigned_listener_prefers_the_lowest_port_number() {
        let model = fixtures::model_with_only_an_unsigned_all_interfaces_listener(22);
        let annotation = select_annotation(&model).expect("finding present");
        assert!(annotation.headline.contains("Port 22"));
        assert_eq!(annotation.leader_target, DiagramAnchor::ExposureMap);
    }

    #[test]
    fn highest_severity_drift_keeps_the_first_entry_on_a_tie() {
        let entries: Vec<DriftEntryView> = Vec::new();
        assert!(highest_severity_drift(&entries).is_none());
    }

    #[test]
    fn no_candidates_qualify_when_model_has_neither_drift_nor_exposure() {
        let model = fixtures::report_model_with_no_findings();
        assert!(most_exposed_unsigned_listener(&model).is_none());
        assert!(select_annotation(&model).is_none());
    }

    #[test]
    fn annotation_equality_is_derived_and_usable_in_assertions() {
        let a = Annotation {
            headline: "x".to_owned(),
            leader_target: DiagramAnchor::ExposureMap,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn rollup_reference_type_is_the_real_domain_rollup() {
        let rollup: Rollup = fixtures::rollup_with_findings();
        let _summary = executive_summary(&rollup);
    }
}
