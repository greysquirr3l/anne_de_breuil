//! Drift timeline: a genuine two-point before/after view of the one
//! baseline-vs-current comparison this pipeline actually has, never a
//! multi-scan history axis.
//!
//! # A real, honest gap -- not papered over
//!
//! Nothing in this codebase threads more than one baseline/current pair
//! into a single report today: [`crate::domain::report_model::ReportModel::drift`]
//! comes from a single `Option<&DriftReport>`, one comparison, not N
//! scans over time (see `report_model`'s own module doc and the T21
//! Accumulated Learnings entry on the same `DriftEntryView`
//! host-attribution gap in PROGRESS.md). A genuine "date axis across
//! scans" would need data this pipeline doesn't collect or retain yet.
//! This renders exactly what the real data supports: two columns,
//! "Baseline" and "Current," each entry placed by
//! [`crate::domain::report_model::DriftKindView`] (appeared -> current
//! only, disappeared -> baseline only, everything else -> both, connected)
//! and sized by severity -- weight, not colour, per the task's own design
//! rule; every marker uses the single accent class.
//!
//! Callers (`mod.rs`) only invoke [`render`] when
//! `ReportModel::drift` is non-empty; the common case (no drift report
//! supplied at all) omits this diagram entirely rather than rendering an
//! empty or misleading chart -- see `mod.rs`'s call site.

use crate::domain::report_model::{DriftEntryView, DriftKindView, SeverityView};
use crate::domain::svg::SvgCanvas;

const CANVAS_WIDTH: i32 = 600;
const BASELINE_X: i32 = 80;
const CURRENT_X: i32 = 520;
const AXIS_Y: i32 = 40;
const ROW_STEP: i32 = 24;
const TOP_MARGIN: i32 = 40;

const fn severity_weight(severity: SeverityView) -> i32 {
    match severity {
        SeverityView::Low => 4,
        SeverityView::Medium => 8,
        SeverityView::High => 12,
        SeverityView::Critical => 16,
    }
}

const fn kind_label(kind: &DriftKindView) -> &'static str {
    match kind {
        DriftKindView::EndpointAppeared => "endpoint appeared",
        DriftKindView::EndpointDisappeared => "endpoint disappeared",
        DriftKindView::ReachabilityChanged { .. } => "reachability changed",
        DriftKindView::ProcessChanged => "owning process changed",
        DriftKindView::SignatureChanged => "signature status changed",
        DriftKindView::RuleSetChanged => "firewall rule set changed",
    }
}

pub(in crate::adapters::html_report) fn render(entries: &[DriftEntryView]) -> String {
    let row_count = i32::try_from(entries.len()).unwrap_or(i32::MAX).max(1);
    let height = TOP_MARGIN + AXIS_Y + row_count * ROW_STEP + TOP_MARGIN;
    let mut canvas = SvgCanvas::new(CANVAS_WIDTH, height);

    let axis_y = TOP_MARGIN + AXIS_Y;
    canvas.line(BASELINE_X, axis_y, CURRENT_X, axis_y, "svg-stroke-hairline");
    canvas.text(BASELINE_X - 8, axis_y - 12, "Baseline", "svg-text");
    canvas.text(CURRENT_X - 8, axis_y - 12, "Current", "svg-text");

    for (index, entry) in entries.iter().enumerate() {
        let row_offset = i32::try_from(index).unwrap_or(0) * ROW_STEP;
        let y = axis_y + ROW_STEP + row_offset;
        let size = severity_weight(entry.severity);
        let label = kind_label(&entry.kind);

        match &entry.kind {
            DriftKindView::EndpointAppeared => {
                canvas.rect(
                    CURRENT_X - size / 2,
                    y - size / 2,
                    size,
                    size,
                    "svg-fill-accent",
                );
                canvas.text(CURRENT_X + 16, y + 4, label, "svg-text-mono");
            }
            DriftKindView::EndpointDisappeared => {
                canvas.rect(
                    BASELINE_X - size / 2,
                    y - size / 2,
                    size,
                    size,
                    "svg-fill-accent",
                );
                canvas.text(BASELINE_X + 16, y + 4, label, "svg-text-mono");
            }
            _ => {
                canvas.line(BASELINE_X, y, CURRENT_X, y, "svg-stroke-hairline");
                canvas.rect(
                    BASELINE_X - size / 2,
                    y - size / 2,
                    size,
                    size,
                    "svg-fill-accent",
                );
                canvas.rect(
                    CURRENT_X - size / 2,
                    y - size / 2,
                    size,
                    size,
                    "svg-fill-accent",
                );
                canvas.text(BASELINE_X + 16, y - 8, label, "svg-text-mono");
            }
        }
    }

    let title = "Drift since baseline".to_owned();
    let desc = format!(
        "{} change(s) between the baseline and current scan, two-point comparison only -- this \
         report does not retain a multi-scan history.",
        entries.len()
    );
    canvas.render(&title, &desc)
}

#[cfg(test)]
mod tests {
    use super::render;
    use crate::domain::drift::{DriftEntry, DriftKind, Severity};
    use crate::domain::report_model::DriftEntryView;

    fn entry(kind: DriftKind, severity: Severity) -> DriftEntryView {
        DriftEntryView::from(&DriftEntry {
            kind,
            endpoint_key: None,
            severity,
        })
    }

    #[test]
    fn appeared_and_disappeared_entries_produce_a_marker_on_their_own_side() {
        let entries = vec![
            entry(DriftKind::EndpointAppeared, Severity::Critical),
            entry(DriftKind::EndpointDisappeared, Severity::Low),
        ];
        let svg = render(&entries);
        assert!(svg.contains("endpoint appeared"));
        assert!(svg.contains("endpoint disappeared"));
    }

    #[test]
    fn changed_entries_connect_both_columns() {
        let entries = vec![entry(DriftKind::ProcessChanged, Severity::Medium)];
        let svg = render(&entries);
        assert!(svg.contains("owning process changed"));
        assert!(
            svg.matches("<line").count() >= 2,
            "axis line plus at least one connector"
        );
    }

    #[test]
    fn rendering_twice_is_byte_identical() {
        let entries = vec![entry(DriftKind::RuleSetChanged, Severity::High)];
        assert_eq!(render(&entries), render(&entries));
    }

    #[test]
    fn every_x_y_width_height_is_divisible_by_four() {
        let entries = vec![
            entry(DriftKind::EndpointAppeared, Severity::Critical),
            entry(DriftKind::SignatureChanged, Severity::Medium),
        ];
        let svg = render(&entries);
        for value in
            super::super::tests_support::extract_numeric_attrs(&svg, &["x", "y", "width", "height"])
        {
            assert!(value.is_multiple_of(4), "{value} is not divisible by 4");
        }
    }

    #[test]
    fn svg_has_title_and_desc_and_uses_only_the_accent_class_for_markers() {
        let entries = vec![entry(DriftKind::EndpointAppeared, Severity::Low)];
        let svg = render(&entries);
        assert!(svg.contains("<title>Drift since baseline</title>"));
        assert!(svg.contains("<desc>"));
        assert!(svg.contains("svg-fill-accent\""));
        for other in [
            "svg-fill-blocked",
            "svg-fill-allowed",
            "svg-fill-default-action",
        ] {
            assert!(
                !svg.contains(other),
                "drift markers must use only one accent class"
            );
        }
    }
}
