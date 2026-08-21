//! Askama templates and view structs for the two page shapes this task
//! adds that `html_report` has no equivalent for: the fleet index and the
//! drift view.
//!
//! Host detail is a navigation hub over a host's recorded scans (this
//! module's [`HostFragmentTemplate`]/[`HostPageTemplate`]) -- a shape
//! `html_report` never had a reason to build, since the CLI's `anne
//! report` always renders one already-chosen snapshot, never "list what's
//! available." Scan detail is the opposite case: exactly what `anne
//! report --format html` already renders for one snapshot, so
//! `router::scan_detail` calls straight into
//! [`crate::adapters::html_report::render`] instead of a third template
//! system living here.
//!
//! The mapping functions in this file (`reachability_label`,
//! `drift_kind_label`, `severity_label`/`severity_css_class`) duplicate a
//! handful of one-line match arms that already exist, `pub(super)`-scoped,
//! in `adapters::html_report::view`. That module's functions operate on
//! the `report_model`-specific `*View` mirror types
//! (`ReachabilityView`/`DriftKindView`/`SeverityView`), built by running a
//! snapshot through `ReportModel::build` first; this module works
//! directly off `domain::drift::diff`'s own output
//! (`DriftEntry`/`DriftKind`/`Severity`) without going through
//! `ReportModel` at all, since a drift-only page has no use for the rest
//! of what `ReportModel::build` computes (rollups, per-host endpoint
//! tables, annotations). Piping through `ReportModel` just to reach
//! `view`'s private helpers would pull in far more machinery than four
//! match statements justify; the CSS class names
//! (`severity-{low,medium,high,critical}`) and label text are kept
//! byte-for-byte identical to `view`'s so the two pages stay visually
//! consistent using the exact same `tokens.css` rules, not new ones.

use askama::Template;

use crate::domain::drift::{DriftEntry, DriftKind, Severity};
use crate::domain::reachability::Reachability;
use crate::domain::target_strategy::TargetStrategy;
use crate::domain::{HostId, ScanId};

/// The fleet index: every host the caller's token is scoped to, no
/// repository call needed -- `ctx.host_scopes` is already the
/// authoritative answer to "what can this token see," see
/// `router::fleet_index`'s doc comment.
#[derive(Template)]
#[template(path = "portal_index.html")]
pub(super) struct FleetIndexTemplate<'a> {
    pub(super) tokens_css: String,
    pub(super) asset_version: &'a str,
    pub(super) hosts: Vec<HostId>,
}

/// One row of a host's scan history table.
pub(super) struct ScanRow {
    pub(super) scan_id: ScanId,
    pub(super) collected_at: String,
    pub(super) strategy_label: &'static str,
    pub(super) endpoint_count: usize,
}

/// The host detail fragment on its own -- what an `htmx` swap from the
/// fleet index receives, and what [`HostPageTemplate`] wraps for a direct
/// (non-`htmx`) navigation.
#[derive(Template)]
#[template(path = "portal_host_fragment.html")]
pub(super) struct HostFragmentTemplate {
    pub(super) host_id: HostId,
    pub(super) scans: Vec<ScanRow>,
}

/// Host detail as a standalone document -- the fragment above, wrapped in
/// the same document shell every other portal page uses. Composition by
/// splicing an already-rendered `String` (`{{ fragment_html|safe }}`),
/// the same pattern `html_report::templates` already established, kept
/// consistent rather than introducing Askama's `{% include %}` here.
#[derive(Template)]
#[template(path = "portal_host_page.html")]
pub(super) struct HostPageTemplate {
    pub(super) tokens_css: String,
    pub(super) host_id: HostId,
    pub(super) fragment_html: String,
}

/// One row of the drift table.
pub(super) struct DriftRow {
    pub(super) kind_label: String,
    pub(super) endpoint_label: Option<String>,
    pub(super) severity_label: &'static str,
    pub(super) severity_class: &'static str,
    severity: Severity,
}

impl From<&DriftEntry> for DriftRow {
    fn from(entry: &DriftEntry) -> Self {
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

/// Sorts `entries` worst-severity-first, then alphabetically by kind label
/// as a deterministic tie-break -- the same ordering
/// `html_report::view::build_drift_rows`'s `by_severity` set uses.
pub(super) fn drift_rows(entries: &[DriftEntry]) -> Vec<DriftRow> {
    let mut rows: Vec<DriftRow> = entries.iter().map(DriftRow::from).collect();
    rows.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.kind_label.cmp(&b.kind_label))
    });
    rows
}

/// The drift view: the two most recent scans for one host, diffed. Renders
/// an explanatory empty state (never a `500`) when fewer than two scans
/// are on file yet.
#[derive(Template)]
#[template(path = "portal_drift.html")]
pub(super) struct DriftTemplate {
    pub(super) tokens_css: String,
    pub(super) host_id: HostId,
    pub(super) insufficient_history: bool,
    pub(super) scan_count: usize,
    pub(super) suppressed_ephemeral: usize,
    pub(super) entries: Vec<DriftRow>,
}

pub(super) const fn strategy_label(strategy: TargetStrategy) -> &'static str {
    match strategy {
        TargetStrategy::Execute => "execute (authoritative)",
        TargetStrategy::Probe => "probe (inferred)",
        TargetStrategy::LocalOnly => "local-only (authoritative)",
    }
}

const fn reachability_label(reachability: Reachability) -> &'static str {
    match reachability {
        Reachability::LocalOnly => "local only",
        Reachability::Blocked => "blocked",
        Reachability::Allowed => "allowed",
        Reachability::DefaultAction => "default action",
        Reachability::Indeterminate => "indeterminate",
    }
}

fn drift_kind_label(kind: &DriftKind) -> String {
    match kind {
        DriftKind::EndpointAppeared => "endpoint appeared".to_owned(),
        DriftKind::EndpointDisappeared => "endpoint disappeared".to_owned(),
        DriftKind::ReachabilityChanged { before, after } => format!(
            "reachability changed: {} -> {}",
            reachability_label(*before),
            reachability_label(*after)
        ),
        DriftKind::ProcessChanged => "owning process changed".to_owned(),
        DriftKind::SignatureChanged => "signature status changed".to_owned(),
        DriftKind::RuleSetChanged => "firewall rule set changed".to_owned(),
    }
}

const fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

const fn severity_css_class(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "severity-low",
        Severity::Medium => "severity-medium",
        Severity::High => "severity-high",
        Severity::Critical => "severity-critical",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DriftKind, Reachability, Severity, drift_kind_label, drift_rows, reachability_label,
        severity_css_class, severity_label, strategy_label,
    };
    use crate::domain::drift::DriftEntry;
    use crate::domain::target_strategy::TargetStrategy;

    #[test]
    fn every_severity_has_a_non_empty_label_and_class_prefix() {
        for severity in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert!(!severity_label(severity).is_empty());
            assert!(severity_css_class(severity).starts_with("severity-"));
        }
    }

    #[test]
    fn every_strategy_has_a_non_empty_label() {
        for strategy in [
            TargetStrategy::Execute,
            TargetStrategy::Probe,
            TargetStrategy::LocalOnly,
        ] {
            assert!(!strategy_label(strategy).is_empty());
        }
    }

    #[test]
    fn every_reachability_has_a_non_empty_label() {
        for reachability in [
            Reachability::LocalOnly,
            Reachability::Blocked,
            Reachability::Allowed,
            Reachability::DefaultAction,
            Reachability::Indeterminate,
        ] {
            assert!(!reachability_label(reachability).is_empty());
        }
    }

    #[test]
    fn reachability_changed_kind_names_both_states() {
        let label = drift_kind_label(&DriftKind::ReachabilityChanged {
            before: Reachability::Blocked,
            after: Reachability::Allowed,
        });
        assert!(label.contains("blocked"));
        assert!(label.contains("allowed"));
    }

    #[test]
    fn drift_rows_sort_worst_severity_first() {
        let entries = vec![
            DriftEntry {
                kind: DriftKind::SignatureChanged,
                endpoint_key: None,
                severity: Severity::Low,
            },
            DriftEntry {
                kind: DriftKind::RuleSetChanged,
                endpoint_key: None,
                severity: Severity::Critical,
            },
        ];
        let rows = drift_rows(&entries);
        assert_eq!(rows.first().expect("two rows").severity_label, "critical");
        assert_eq!(rows.get(1).expect("two rows").severity_label, "low");
    }
}
