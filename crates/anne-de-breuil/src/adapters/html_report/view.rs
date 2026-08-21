//! Presentation mapping and Askama template bindings for per-host and
//! fleet-summary content.
//!
//! Turns `domain::report_model` types into the labels, CSS class names,
//! and pre-sorted row lists the templates interpolate, and hosts the two
//! `#[derive(Template)]` structs (`HostSectionTemplate`, `SummaryTemplate`)
//! that consume them directly -- kept together since neither struct is
//! useful without its matching view-construction function. `mod.rs`
//! renders both to owned `String`s and splices them into the smaller,
//! purely mechanical templates in `templates.rs` (document shells that
//! just wrap an already-rendered string).
//!
//! None of this belongs in `report_model.rs` -- JSON/CSV/SARIF rendering
//! has no use for a CSS class name or a pre-sorted duplicate of the same
//! endpoint list three times over. Every field handed to a template is an
//! owned `String`/`&'static str`; Askama HTML-escapes every one of them on
//! interpolation (see `mod.rs`'s `xss_*` tests for the proof), so nothing
//! here does its own escaping.

use askama::Template;

use super::diagrams;
use crate::domain::exposure::Exposure;
use crate::domain::publisher::SignatureStatus;
use crate::domain::redaction::SecretCategory;
use crate::domain::report_model::{
    DriftEntryView, DriftKindView, EndpointView, Fidelity, HostSection, ReachabilityView,
    SeverityView,
};
use crate::domain::target_strategy::TargetStrategy;

pub(super) const fn exposure_label(exposure: Exposure) -> &'static str {
    match exposure {
        Exposure::Loopback => "loopback",
        Exposure::SpecificInterface => "specific interface",
        Exposure::AllInterfaces => "all interfaces",
    }
}

pub(super) const fn exposure_css_class(exposure: Exposure) -> &'static str {
    match exposure {
        Exposure::Loopback => "exposure-loopback",
        Exposure::SpecificInterface => "exposure-specific",
        Exposure::AllInterfaces => "exposure-all",
    }
}

pub(super) const fn reachability_label(reachability: ReachabilityView) -> &'static str {
    match reachability {
        ReachabilityView::LocalOnly => "local only",
        ReachabilityView::Blocked => "blocked",
        ReachabilityView::Allowed => "allowed",
        ReachabilityView::DefaultAction => "default action",
        ReachabilityView::Indeterminate => "indeterminate",
    }
}

pub(super) const fn reachability_css_class(reachability: ReachabilityView) -> &'static str {
    match reachability {
        ReachabilityView::LocalOnly => "reachability-local-only",
        ReachabilityView::Blocked => "reachability-blocked",
        ReachabilityView::Allowed => "reachability-allowed",
        ReachabilityView::DefaultAction => "reachability-default-action",
        ReachabilityView::Indeterminate => "reachability-indeterminate",
    }
}

/// Sort key for "sort endpoints by reachability" -- ascending puts the
/// state most worth an administrator's attention first: a rule actively
/// `Allowed`-ing traffic in is more actionable than one already `Blocked`,
/// and `LocalOnly` (never reachable off-host regardless of policy) is the
/// least urgent state there is.
const fn reachability_rank(reachability: ReachabilityView) -> u8 {
    match reachability {
        ReachabilityView::Allowed => 0,
        ReachabilityView::DefaultAction => 1,
        ReachabilityView::Indeterminate => 2,
        ReachabilityView::Blocked => 3,
        ReachabilityView::LocalOnly => 4,
    }
}

pub(super) const fn severity_label(severity: SeverityView) -> &'static str {
    match severity {
        SeverityView::Low => "low",
        SeverityView::Medium => "medium",
        SeverityView::High => "high",
        SeverityView::Critical => "critical",
    }
}

pub(super) const fn severity_css_class(severity: SeverityView) -> &'static str {
    match severity {
        SeverityView::Low => "severity-low",
        SeverityView::Medium => "severity-medium",
        SeverityView::High => "severity-high",
        SeverityView::Critical => "severity-critical",
    }
}

pub(super) const fn fidelity_label(fidelity: Fidelity) -> &'static str {
    match fidelity {
        Fidelity::Authoritative => "authoritative",
        Fidelity::Inferred => "inferred",
    }
}

pub(super) const fn fidelity_css_class(fidelity: Fidelity) -> &'static str {
    match fidelity {
        Fidelity::Authoritative => "fidelity-authoritative",
        Fidelity::Inferred => "fidelity-inferred",
    }
}

const fn target_strategy_label(strategy: TargetStrategy) -> &'static str {
    match strategy {
        TargetStrategy::Execute => "collector executed remotely",
        TargetStrategy::Probe => "probed from outside, no code executed",
        TargetStrategy::LocalOnly => "scanned itself, no transport involved",
    }
}

fn signature_label(status: &SignatureStatus) -> String {
    match status {
        SignatureStatus::Signed(publisher) => format!("signed ({publisher})"),
        SignatureStatus::Unsigned => "unsigned".to_owned(),
        SignatureStatus::Unknown => "unknown".to_owned(),
        SignatureStatus::NotApplicable => "not applicable".to_owned(),
    }
}

const fn secret_category_label(category: SecretCategory) -> &'static str {
    match category {
        SecretCategory::PasswordAssignment => "password assignment",
        SecretCategory::ConnectionStringPassword => "connection-string password",
        SecretCategory::BearerToken => "bearer token",
        SecretCategory::PemBlock => "PEM block",
        SecretCategory::AwsKeyId => "AWS access key id",
        SecretCategory::HighEntropyToken => "high-entropy token",
    }
}

fn drift_kind_label(kind: &DriftKindView) -> String {
    match kind {
        DriftKindView::EndpointAppeared => "endpoint appeared".to_owned(),
        DriftKindView::EndpointDisappeared => "endpoint disappeared".to_owned(),
        DriftKindView::ReachabilityChanged { before, after } => format!(
            "reachability changed: {} -> {}",
            reachability_label(*before),
            reachability_label(*after)
        ),
        DriftKindView::ProcessChanged => "owning process changed".to_owned(),
        DriftKindView::SignatureChanged => "signature status changed".to_owned(),
        DriftKindView::RuleSetChanged => "firewall rule set changed".to_owned(),
    }
}

/// One endpoint row, every field pre-formatted for direct template
/// interpolation -- built once per sort order (see
/// [`host_section_template`]), so the same endpoint appears in up to
/// three of these, one per pre-rendered `<tbody>`.
#[derive(Debug, Clone)]
pub(super) struct EndpointRow {
    pub(super) protocol: String,
    pub(super) bind_address: String,
    pub(super) port: String,
    port_key: u16,
    pub(super) process_path: Option<String>,
    pub(super) hosted_services: Vec<String>,
    pub(super) signature_label: String,
    pub(super) exposure_label: &'static str,
    pub(super) exposure_class: &'static str,
    pub(super) reachability_label: &'static str,
    pub(super) reachability_class: &'static str,
    pub(super) command_line: Option<String>,
    pub(super) command_line_redaction_labels: Vec<String>,
}

impl EndpointRow {
    fn from_view(endpoint: &EndpointView) -> Self {
        Self {
            protocol: endpoint.protocol.to_string(),
            bind_address: endpoint.bind_address.to_string(),
            port: endpoint.port.to_string(),
            port_key: endpoint.port.get(),
            process_path: endpoint.process_path.as_ref().map(ToString::to_string),
            hosted_services: endpoint
                .hosted_services
                .iter()
                .map(ToString::to_string)
                .collect(),
            signature_label: signature_label(&endpoint.signature_status),
            exposure_label: exposure_label(endpoint.exposure),
            exposure_class: exposure_css_class(endpoint.exposure),
            reachability_label: reachability_label(endpoint.reachability),
            reachability_class: reachability_css_class(endpoint.reachability),
            command_line: endpoint.command_line.clone(),
            command_line_redaction_labels: endpoint
                .command_line_redactions
                .iter()
                .map(|redacted| secret_category_label(redacted.category).to_owned())
                .collect(),
        }
    }
}

/// One decorative cell in a host's port-density grid.
///
/// Deliberately no per-cell interactive control (no popover, no button) --
/// this grid is `aria-hidden` and purely supplementary to the accessible
/// `<table>` it sits beside, so it never carries a keyboard/screen-reader
/// affordance the table doesn't already provide better. See `mod.rs`'s
/// module doc for the fuller reasoning on why this stays decorative rather
/// than growing an interactive layer.
pub(super) struct PortDensityCell {
    pub(super) reachability_class: &'static str,
    pub(super) tooltip: String,
}

fn build_port_density_cells(host: &HostSection) -> Vec<PortDensityCell> {
    host.endpoints
        .iter()
        .map(|endpoint| PortDensityCell {
            reachability_class: reachability_css_class(endpoint.reachability),
            tooltip: format!(
                "{}/{} {} \u{2014} {}",
                endpoint.protocol,
                endpoint.port,
                reachability_label(endpoint.reachability),
                endpoint
                    .process_path
                    .as_ref()
                    .map_or_else(|| "unknown process".to_owned(), ToString::to_string),
            ),
        })
        .collect()
}

fn short_id(full: &str) -> String {
    full.chars().take(8).collect()
}

pub(super) fn anchor_for(host: &HostSection) -> String {
    format!("host-{}", host.host_id)
}

/// One host's section: heading, port-density grid, sort-controlled
/// endpoint table, per-endpoint drill-down. Rendered once per host, either
/// spliced into the monolithic report body (streamed one at a time -- see
/// `mod.rs::write_report_streaming`) or wrapped standalone by
/// `templates::HostDocumentTemplate` for `--split`.
#[derive(Template)]
#[template(path = "host_section.html")]
pub(super) struct HostSectionTemplate {
    pub(super) anchor: String,
    pub(super) short_id: String,
    pub(super) full_host_id: String,
    pub(super) fidelity_label: &'static str,
    pub(super) fidelity_class: &'static str,
    pub(super) collected_at: String,
    pub(super) collector_version: String,
    pub(super) strategy_label: &'static str,
    pub(super) endpoint_count: usize,
    pub(super) sort_group: String,
    pub(super) by_port: Vec<EndpointRow>,
    pub(super) by_exposure: Vec<EndpointRow>,
    pub(super) by_reachability: Vec<EndpointRow>,
    pub(super) grid_cells: Vec<PortDensityCell>,
    /// Server-rendered SVG diagrams for this host — see
    /// `super::diagrams` for how each is built.
    pub(super) exposure_map_svg: String,
    pub(super) rule_evaluation_svg: String,
    pub(super) trust_quadrant_svg: String,
    pub(super) profile_bar_chart_svg: String,
}

/// Builds the per-host template, including all three pre-sorted row sets.
///
/// `index` only needs to be unique per host (its own position in
/// `model.hosts` is sufficient) so each host's sort radio group gets a
/// distinct `name`/`id`; browsers group same-named radios document-wide,
/// so a shared name across hosts would let selecting a sort order on one
/// host silently steal the selection away from every other host's
/// fieldset.
pub(super) fn host_section_template(host: &HostSection, index: usize) -> HostSectionTemplate {
    let mut by_port: Vec<EndpointRow> = host.endpoints.iter().map(EndpointRow::from_view).collect();
    by_port.sort_by_key(|row| row.port_key);

    let mut by_exposure: Vec<(Exposure, EndpointRow)> = host
        .endpoints
        .iter()
        .map(|endpoint| (endpoint.exposure, EndpointRow::from_view(endpoint)))
        .collect();
    by_exposure.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.port_key.cmp(&b.1.port_key)));
    let by_exposure = by_exposure.into_iter().map(|(_, row)| row).collect();

    let mut by_reachability: Vec<(u8, EndpointRow)> = host
        .endpoints
        .iter()
        .map(|endpoint| {
            (
                reachability_rank(endpoint.reachability),
                EndpointRow::from_view(endpoint),
            )
        })
        .collect();
    by_reachability.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.port_key.cmp(&b.1.port_key)));
    let by_reachability = by_reachability.into_iter().map(|(_, row)| row).collect();

    HostSectionTemplate {
        anchor: anchor_for(host),
        short_id: short_id(&host.host_id.to_string()),
        full_host_id: host.host_id.to_string(),
        fidelity_label: fidelity_label(host.fidelity),
        fidelity_class: fidelity_css_class(host.fidelity),
        collected_at: host.collected_at.to_string(),
        collector_version: host.collector_version.clone(),
        strategy_label: target_strategy_label(host.strategy),
        endpoint_count: host.endpoints.len(),
        sort_group: format!("sort-{index}"),
        by_port,
        by_exposure,
        by_reachability,
        grid_cells: build_port_density_cells(host),
        exposure_map_svg: diagrams::render_exposure_map(host),
        rule_evaluation_svg: diagrams::render_rule_evaluation(host),
        trust_quadrant_svg: diagrams::render_trust_quadrant(host),
        profile_bar_chart_svg: diagrams::render_profile_bar_chart(host),
    }
}

/// One row of a fleet-wide drift table, pre-formatted for interpolation.
#[derive(Debug, Clone)]
pub(super) struct DriftRow {
    pub(super) kind_label: String,
    pub(super) endpoint_label: Option<String>,
    pub(super) severity_label: &'static str,
    pub(super) severity_class: &'static str,
    severity: SeverityView,
}

impl DriftRow {
    fn from_view(entry: &DriftEntryView) -> Self {
        Self {
            kind_label: drift_kind_label(&entry.kind),
            endpoint_label: entry
                .endpoint_key
                .as_ref()
                .map(|key| format!("{} {}:{}", key.protocol, key.bind_address, key.port)),
            severity_label: severity_label(entry.severity),
            severity_class: severity_css_class(entry.severity),
            severity: entry.severity,
        }
    }
}

/// Builds the two pre-sorted drift row sets (`by_severity`,
/// descending -- worst first; `by_kind`, alphabetical) the fleet-wide
/// drift summary toggles between via the same zero-JS radio + `:has()`
/// pattern the per-host endpoint tables use.
fn build_drift_rows(entries: &[DriftEntryView]) -> (Vec<DriftRow>, Vec<DriftRow>) {
    let mut by_severity: Vec<DriftRow> = entries.iter().map(DriftRow::from_view).collect();
    by_severity.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.kind_label.cmp(&b.kind_label))
    });

    let mut by_kind: Vec<DriftRow> = entries.iter().map(DriftRow::from_view).collect();
    by_kind.sort_by(|a, b| {
        a.kind_label
            .cmp(&b.kind_label)
            .then_with(|| b.severity.cmp(&a.severity))
    });

    (by_severity, by_kind)
}

/// One entry in the fleet-wide host navigation list.
pub(super) struct HostNavEntry {
    pub(super) short_id: String,
    pub(super) fidelity_label: &'static str,
    pub(super) fidelity_class: &'static str,
    pub(super) endpoint_count: usize,
    /// Either `#host-<uuid>` (monolithic report, same document) or a
    /// per-host file name (`--split` index) -- callers decide which.
    pub(super) target: String,
}

fn build_nav_entries(
    hosts: &[HostSection],
    target_for: impl Fn(&HostSection) -> String,
) -> Vec<HostNavEntry> {
    hosts
        .iter()
        .map(|host| HostNavEntry {
            short_id: short_id(&host.host_id.to_string()),
            fidelity_label: fidelity_label(host.fidelity),
            fidelity_class: fidelity_css_class(host.fidelity),
            endpoint_count: host.endpoints.len(),
            target: target_for(host),
        })
        .collect()
}

/// Fleet-wide rollup, legend, "how to read this" details, host
/// navigation, and the drift summary table -- rendered once, spliced into
/// either `templates::ReportHeadTemplate` (monolithic report) or
/// `templates::SplitIndexTemplate` (`--split`'s index file).
#[derive(Template)]
#[template(path = "summary.html")]
pub(super) struct SummaryTemplate {
    pub(super) hosts_scanned: usize,
    pub(super) endpoints_total: usize,
    pub(super) redaction_enabled: bool,
    pub(super) exposure_loopback: usize,
    pub(super) exposure_specific: usize,
    pub(super) exposure_all: usize,
    pub(super) reachability_local_only: usize,
    pub(super) reachability_blocked: usize,
    pub(super) reachability_allowed: usize,
    pub(super) reachability_default_action: usize,
    pub(super) reachability_indeterminate: usize,
    pub(super) unsigned_binaries: usize,
    pub(super) nav_entries: Vec<HostNavEntry>,
    pub(super) drift_by_severity: Vec<DriftRow>,
    pub(super) drift_by_kind: Vec<DriftRow>,
    /// The two-point before/after drift timeline SVG, or `None` when
    /// `model.drift` is empty — the common case, since drift diffing
    /// isn't wired into the CLI's `report` command yet. Rendering an
    /// empty or placeholder chart in that case would be dishonest; the
    /// template omits the whole `<figure>` instead. See
    /// `super::diagrams::drift_timeline`'s own doc comment for why this
    /// is a genuine two-point comparison, never a fabricated multi-scan
    /// history axis.
    pub(super) drift_timeline_svg: Option<String>,
}

/// Builds the fleet-wide summary template. `target_for` decides whether
/// nav links point at same-document anchors or sibling `--split` files.
pub(super) fn summary_template(
    model: &crate::domain::report_model::ReportModel,
    target_for: impl Fn(&HostSection) -> String,
) -> SummaryTemplate {
    let (drift_by_severity, drift_by_kind) = build_drift_rows(&model.drift);
    let drift_timeline_svg =
        (!model.drift.is_empty()).then(|| diagrams::render_drift_timeline(&model.drift));
    SummaryTemplate {
        hosts_scanned: model.rollup.hosts_scanned,
        endpoints_total: model.hosts.iter().map(|host| host.endpoints.len()).sum(),
        redaction_enabled: model.redaction_enabled,
        exposure_loopback: model.rollup.endpoints_by_exposure.loopback,
        exposure_specific: model.rollup.endpoints_by_exposure.specific_interface,
        exposure_all: model.rollup.endpoints_by_exposure.all_interfaces,
        reachability_local_only: model.rollup.endpoints_by_reachability.local_only,
        reachability_blocked: model.rollup.endpoints_by_reachability.blocked,
        reachability_allowed: model.rollup.endpoints_by_reachability.allowed,
        reachability_default_action: model.rollup.endpoints_by_reachability.default_action,
        reachability_indeterminate: model.rollup.endpoints_by_reachability.indeterminate,
        unsigned_binaries: model.rollup.unsigned_binaries,
        nav_entries: build_nav_entries(&model.hosts, target_for),
        drift_by_severity,
        drift_by_kind,
        drift_timeline_svg,
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;

    use super::{
        DriftRow, EndpointRow, Exposure, ReachabilityView, SeverityView, build_drift_rows,
        exposure_css_class, exposure_label, fidelity_css_class, fidelity_label,
        host_section_template, reachability_css_class, reachability_label, secret_category_label,
        severity_css_class, severity_label, short_id, signature_label, target_strategy_label,
    };
    use crate::domain::bind_address::BindAddress;
    use crate::domain::drift::{DriftEntry, DriftKind, Severity};
    use crate::domain::endpoint::Endpoint;
    use crate::domain::ids::{HostId, ScanId};
    use crate::domain::port::Port;
    use crate::domain::process::ProcessPath;
    use crate::domain::protocol::Protocol;
    use crate::domain::publisher::{PublisherName, SignatureStatus};
    use crate::domain::redaction::SecretCategory;
    use crate::domain::report_model::{DriftEntryView, Fidelity, ReportModel};
    use crate::domain::service::ServiceName;
    use crate::domain::snapshot::ScanSnapshot;
    use crate::domain::target_strategy::TargetStrategy;

    fn host_section_fixture() -> crate::domain::report_model::HostSection {
        let low_port = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("127.0.0.1").expect("valid ip"),
            Port::try_from(22u16).expect("nonzero"),
            None,
            Some(ProcessPath::from_str("/usr/sbin/sshd").expect("non-empty")),
            vec![ServiceName::try_from("ssh".to_owned()).expect("non-empty")],
            SignatureStatus::Unknown,
            None,
        );
        let high_port = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").expect("valid ip"),
            Port::try_from(8443u16).expect("nonzero"),
            None,
            Some(ProcessPath::from_str("/usr/bin/app").expect("non-empty")),
            vec![],
            SignatureStatus::Unsigned,
            None,
        );
        let snapshot = ScanSnapshot::new(
            HostId::generate(),
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "1.0.0".to_owned(),
            vec![high_port, low_port],
            vec![],
            vec![],
            TargetStrategy::LocalOnly,
        );
        let model = ReportModel::build(&[snapshot], None, true).expect("model builds");
        model.hosts.into_iter().next().expect("one host")
    }

    #[test]
    fn by_port_is_ascending_by_port_number() {
        let host = host_section_fixture();
        let view = host_section_template(&host, 0);
        let ports: Vec<&str> = view.by_port.iter().map(|row| row.port.as_str()).collect();
        assert_eq!(ports, vec!["22", "8443"]);
    }

    #[test]
    fn by_exposure_puts_widest_reach_first() {
        let host = host_section_fixture();
        let view = host_section_template(&host, 0);
        let first = view.by_exposure.first().expect("two rows");
        assert_eq!(
            first.exposure_label,
            exposure_label(Exposure::AllInterfaces)
        );
    }

    #[test]
    fn sort_group_is_unique_per_host_index() {
        let host = host_section_fixture();
        let view_a = host_section_template(&host, 0);
        let view_b = host_section_template(&host, 1);
        assert_ne!(view_a.sort_group, view_b.sort_group);
    }

    #[test]
    fn grid_cells_have_one_entry_per_endpoint() {
        let host = host_section_fixture();
        let view = host_section_template(&host, 0);
        assert_eq!(view.grid_cells.len(), host.endpoints.len());
    }

    #[test]
    fn short_id_takes_first_eight_characters() {
        let full = "abcdefgh-ijkl-mnop-qrst-uvwxyz012345";
        assert_eq!(short_id(full), "abcdefgh");
    }

    #[test]
    fn exposure_label_and_class_cover_every_variant() {
        for exposure in [
            Exposure::Loopback,
            Exposure::SpecificInterface,
            Exposure::AllInterfaces,
        ] {
            assert!(!exposure_label(exposure).is_empty());
            assert!(exposure_css_class(exposure).starts_with("exposure-"));
        }
    }

    #[test]
    fn reachability_label_and_class_cover_every_variant() {
        for reachability in [
            ReachabilityView::LocalOnly,
            ReachabilityView::Blocked,
            ReachabilityView::Allowed,
            ReachabilityView::DefaultAction,
            ReachabilityView::Indeterminate,
        ] {
            assert!(!reachability_label(reachability).is_empty());
            assert!(reachability_css_class(reachability).starts_with("reachability-"));
        }
    }

    #[test]
    fn severity_label_and_class_cover_every_variant() {
        for severity in [
            SeverityView::Low,
            SeverityView::Medium,
            SeverityView::High,
            SeverityView::Critical,
        ] {
            assert!(!severity_label(severity).is_empty());
            assert!(severity_css_class(severity).starts_with("severity-"));
        }
    }

    #[test]
    fn fidelity_label_and_class_cover_every_variant() {
        for fidelity in [Fidelity::Authoritative, Fidelity::Inferred] {
            assert!(!fidelity_label(fidelity).is_empty());
            assert!(fidelity_css_class(fidelity).starts_with("fidelity-"));
        }
    }

    #[test]
    fn target_strategy_label_covers_every_variant() {
        for strategy in [
            TargetStrategy::Execute,
            TargetStrategy::Probe,
            TargetStrategy::LocalOnly,
        ] {
            assert!(!target_strategy_label(strategy).is_empty());
        }
    }

    #[test]
    fn signature_label_includes_publisher_name_when_signed() {
        let publisher = PublisherName::try_from("Contoso".to_owned()).expect("non-empty");
        let label = signature_label(&SignatureStatus::Signed(publisher));
        assert!(label.contains("Contoso"));
    }

    #[test]
    fn secret_category_label_covers_every_variant() {
        for category in [
            SecretCategory::PasswordAssignment,
            SecretCategory::ConnectionStringPassword,
            SecretCategory::BearerToken,
            SecretCategory::PemBlock,
            SecretCategory::AwsKeyId,
            SecretCategory::HighEntropyToken,
        ] {
            assert!(!secret_category_label(category).is_empty());
        }
    }

    #[test]
    fn drift_rows_by_severity_are_worst_first() {
        let entries = vec![
            DriftEntryView::from(&DriftEntry {
                kind: DriftKind::EndpointAppeared,
                endpoint_key: None,
                severity: Severity::Low,
            }),
            DriftEntryView::from(&DriftEntry {
                kind: DriftKind::RuleSetChanged,
                endpoint_key: None,
                severity: Severity::Critical,
            }),
        ];
        let (by_severity, _by_kind) = build_drift_rows(&entries);
        let labels: Vec<&str> = by_severity.iter().map(|row| row.severity_label).collect();
        assert_eq!(labels, vec!["critical", "low"]);
    }

    #[test]
    fn drift_rows_by_kind_are_alphabetical() {
        let entries = vec![
            DriftEntryView::from(&DriftEntry {
                kind: DriftKind::RuleSetChanged,
                endpoint_key: None,
                severity: Severity::Low,
            }),
            DriftEntryView::from(&DriftEntry {
                kind: DriftKind::EndpointAppeared,
                endpoint_key: None,
                severity: Severity::Low,
            }),
        ];
        let (_by_severity, by_kind): (Vec<DriftRow>, Vec<DriftRow>) = build_drift_rows(&entries);
        assert!(by_kind.first().expect("two rows").kind_label < by_kind[1].kind_label);
    }

    #[test]
    fn endpoint_row_carries_redaction_labels() {
        let endpoint = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").expect("valid ip"),
            Port::try_from(443u16).expect("nonzero"),
            None,
            None,
            vec![],
            SignatureStatus::Unknown,
            Some("app.exe password=hunter2".to_owned()),
        );
        let snapshot = ScanSnapshot::new(
            HostId::generate(),
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "1.0.0".to_owned(),
            vec![endpoint],
            vec![],
            vec![],
            TargetStrategy::LocalOnly,
        );
        let model = ReportModel::build(&[snapshot], None, true).expect("model builds");
        let host = model.hosts.into_iter().next().expect("one host");
        let view = host_section_template(&host, 0);
        let row: &EndpointRow = view.by_port.first().expect("one endpoint");
        assert!(!row.command_line_redaction_labels.is_empty());
        assert!(
            row.command_line
                .as_deref()
                .is_some_and(|line| !line.contains("hunter2"))
        );
    }
}
