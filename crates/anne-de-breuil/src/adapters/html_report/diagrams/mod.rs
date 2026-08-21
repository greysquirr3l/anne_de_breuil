//! Server-rendered SVG diagram builders for the HTML report — one file per
//! diagram type, sharing the pure geometry primitives in
//! [`crate::domain::svg`] and the density-degradation / colour-class
//! helpers declared in this file.
//!
//! Each diagram is built once per host (exposure map, rule evaluation,
//! trust quadrant — [`crate::domain::report_model::HostSection`] carries
//! its own firewall rules/profiles, so there is no fleet-wide equivalent
//! to chart) or once for the whole fleet (profile bar chart is also
//! per-host for the same reason; drift timeline is fleet-wide because
//! [`crate::domain::report_model::ReportModel::drift`] itself is a single
//! shared list with no per-host attribution — see `drift_timeline`'s own
//! doc comment) directly from [`crate::domain::report_model`] view types,
//! never from [`crate::domain::snapshot::ScanSnapshot`] or any other raw
//! domain aggregate — same view-model boundary `report_model` itself
//! documents. `view.rs` calls the `render_*` functions re-exported below
//! and splices the resulting `String`s into
//! `HostSectionTemplate`/`SummaryTemplate` fields, the same composition
//! pattern already used for `tokens_css` and the two document templates.

mod drift_timeline;
mod exposure_map;
mod profile_bar_chart;
mod rule_evaluation;
mod trust_quadrant;

pub(in crate::adapters::html_report) use drift_timeline::render as render_drift_timeline;
pub(in crate::adapters::html_report) use exposure_map::render as render_exposure_map;
pub(in crate::adapters::html_report) use profile_bar_chart::render as render_profile_bar_chart;
pub(in crate::adapters::html_report) use rule_evaluation::render as render_rule_evaluation;
pub(in crate::adapters::html_report) use trust_quadrant::render as render_trust_quadrant;

use crate::domain::report_model::{HostSection, ReachabilityView};

/// Above this many endpoints, the exposure map degrades to a one-line
/// summary rather than one row per endpoint — see
/// `exposure_map::render`'s doc comment.
pub(super) const NODE_DENSITY_THRESHOLD: usize = 60;

/// Maps a resolved reachability verdict to the `fill`/`stroke` CSS class
/// diagrams use for it — distinct from `view::reachability_css_class`
/// (which sets `color` for ordinary HTML text) because SVG shapes need
/// `fill`, and `color` does not cascade into `fill` without an explicit
/// `fill: currentColor` rule this project doesn't define. Both class sets
/// point at the same `tokens.css` custom properties, just through
/// different CSS properties.
pub(super) const fn reachability_fill_class(reachability: ReachabilityView) -> &'static str {
    match reachability {
        ReachabilityView::LocalOnly => "svg-fill-local-only",
        ReachabilityView::Blocked => "svg-fill-blocked",
        ReachabilityView::Allowed => "svg-fill-allowed",
        ReachabilityView::DefaultAction => "svg-fill-default-action",
        ReachabilityView::Indeterminate => "svg-fill-indeterminate",
    }
}

/// Sort key for "most urgent reachability first" — shared with
/// `adapters::html_report::view`'s own (module-private) ranking, but
/// duplicated here rather than imported: that ranking is private to
/// `view.rs` and this module tree's own diagrams have no dependency on
/// the HTML endpoint table's internals beyond the shared view-model types.
pub(super) const fn reachability_rank(reachability: ReachabilityView) -> u8 {
    match reachability {
        ReachabilityView::Allowed => 0,
        ReachabilityView::DefaultAction => 1,
        ReachabilityView::Indeterminate => 2,
        ReachabilityView::Blocked => 3,
        ReachabilityView::LocalOnly => 4,
    }
}

/// The first eight characters of a host id — enough to distinguish hosts
/// in a diagram title without spelling out a full UUID, matching
/// `view::short_id`'s own convention.
pub(super) fn short_host_id(host: &HostSection) -> String {
    host.host_id.to_string().chars().take(8).collect()
}

/// Converts a length/count to `i32` for diagram geometry, saturating
/// rather than panicking or wrapping on the (never realistically hit,
/// but never assumed impossible) case of a value too large for `i32`.
/// Avoids an `as` cast, which would silently truncate instead of
/// saturating and trips this project's pedantic lint profile besides.
pub(super) fn geometry_i32(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

/// Shared by every diagram submodule's own test module — extracts every
/// value of the named attributes from real rendered SVG output, for the
/// grid-compliance test each diagram type carries. Lives here rather than
/// duplicated per file, since the parsing logic itself is not what any
/// individual diagram test is meant to exercise.
#[cfg(test)]
pub mod tests_support {
    /// Finds every `name="value"` occurrence for each of `names` in `svg`
    /// and parses `value` as an unsigned integer -- every coordinate this
    /// module's diagrams emit is non-negative by construction, and `u32`
    /// (unlike `i32`/`i64`) has a stable `is_multiple_of`, matching this
    /// project's own "prefer `.is_multiple_of(n)` over `% n == 0`"
    /// convention in the grid-compliance test each diagram carries. A
    /// real regex rather than a hand-rolled scanner here -- `regex` is
    /// already a real dependency of this crate
    /// (`domain::redaction`/`domain::fingerprint`), and attribute
    /// extraction is exactly what it's for.
    pub fn extract_numeric_attrs(svg: &str, names: &[&str]) -> Vec<u32> {
        let mut values = Vec::new();
        for name in names {
            // A leading `\s` requires the attribute name to start right
            // after whitespace -- without it, asking for `x` would also
            // match the `x` inside `rx="10"` (the border-radius
            // attribute, deliberately fixed and never grid-checked).
            let pattern = format!(r#"\s{name}="(\d+)""#);
            let Ok(re) = regex::Regex::new(&pattern) else {
                continue;
            };
            for capture in re.captures_iter(svg) {
                if let Some(value) = capture
                    .get(1)
                    .and_then(|matched| matched.as_str().parse::<u32>().ok())
                {
                    values.push(value);
                }
            }
        }
        values
    }
}

#[cfg(test)]
mod tests {
    use super::{geometry_i32, reachability_fill_class, reachability_rank};
    use crate::domain::report_model::ReachabilityView;

    #[test]
    fn reachability_fill_class_covers_every_variant_with_a_distinct_class() {
        let variants = [
            ReachabilityView::LocalOnly,
            ReachabilityView::Blocked,
            ReachabilityView::Allowed,
            ReachabilityView::DefaultAction,
            ReachabilityView::Indeterminate,
        ];
        let classes: Vec<&str> = variants
            .iter()
            .map(|v| reachability_fill_class(*v))
            .collect();
        for class in &classes {
            assert!(class.starts_with("svg-fill-"));
        }
        let mut unique = classes.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            classes.len(),
            "every variant needs its own class"
        );
    }

    #[test]
    fn reachability_rank_puts_allowed_first_and_local_only_last() {
        assert!(
            reachability_rank(ReachabilityView::Allowed)
                < reachability_rank(ReachabilityView::Blocked)
        );
        assert!(
            reachability_rank(ReachabilityView::Blocked)
                < reachability_rank(ReachabilityView::LocalOnly)
        );
    }

    #[test]
    fn geometry_i32_converts_ordinary_values_exactly() {
        assert_eq!(geometry_i32(0), 0);
        assert_eq!(geometry_i32(42), 42);
    }

    #[test]
    fn geometry_i32_saturates_rather_than_panicking_on_overflow() {
        assert_eq!(geometry_i32(usize::MAX), i32::MAX);
    }
}
