//! Self-contained HTML5 report rendering via Askama.
//!
//! T23 shipped the shell: the CSS custom-property token system, the two
//! font-embedding modes, the CSP meta tag, and the zero-JavaScript theme
//! override. This task (T24) builds the report body on top of it: one
//! section per host with a sort-controlled endpoint table and a
//! per-endpoint drill-down, a fleet-wide summary with a drift table, a
//! streaming writer bounded by one host's rendered fragment rather than
//! the whole document, and `--split` output (see
//! [`write_report_split`]).
//!
//! T25 (this module's second author) adds the report's five server-rendered
//! SVG diagrams on top of that shell.
//!
//! # Module layout
//!
//! - [`view`] builds the per-host and fleet-summary template structs
//!   directly from [`ReportModel`] data (labels, CSS classes, three
//!   pre-sorted endpoint row sets per host, and — as of T25 — the
//!   rendered diagram `String`s for that host/the fleet).
//! - [`diagrams`] builds the five SVG diagrams themselves, over the pure
//!   geometry primitives in [`crate::domain::svg`] — one file per diagram
//!   type; see that module's own doc comment for the full list and why
//!   each is scoped per-host or fleet-wide.
//! - [`templates`] holds the smaller document-shell templates that only
//!   ever splice in already-rendered `String`s.
//! - This file wires the three together: `render`/`write_report_streaming`/
//!   `write_report_split`, plus `HtmlRenderError`.
//!
//! # No per-endpoint severity; `matched_rules` arrived later, via T25
//!
//! The task this module (T24) implements sketches a sortable "severity"
//! column and a `matched_rules` list per endpoint (rule-provenance cards
//! via `popover`). At the time this module was written, neither existed
//! on the real view model: [`EndpointView`] carried a single resolved
//! [`crate::domain::report_model::ReachabilityView`] verdict, never the
//! underlying [`crate::domain::FirewallRule`] list that produced it
//! (T21's Accumulated Learnings entry on this same gap, in `render_csv`,
//! made the identical call). T25 later extended [`EndpointView`] with a
//! real `matched_rules: Vec<FirewallRuleView>` field (threaded through
//! from [`crate::domain::reachability::ReachabilityVerdict`], which
//! carried it all along) to feed its rule-evaluation diagram -- see
//! `diagrams::rule_evaluation`. This module's own endpoint table still
//! sorts by the three keys chosen when `matched_rules` didn't exist --
//! port, exposure, reachability -- since adding a fourth sort key here is
//! outside T25's scope and the existing three remain the genuinely useful
//! ones for a tabular view. "Severity" exists only on
//! [`crate::domain::report_model::DriftEntryView`], which is drift-specific;
//! the fleet-wide drift summary (see [`view::SummaryTemplate`]) sorts by
//! it. Nothing here fabricates a per-endpoint severity value.
//!
//! # No `popover`, no `<dialog>`
//!
//! The task allows `popover`/`<dialog>` "where a modal genuinely helps."
//! The sketch's own intended use -- rule-provenance cards -- needs the
//! `matched_rules` data above, which doesn't exist. Every other candidate
//! use is already covered natively: per-endpoint detail by
//! `<details>/<summary>`, and the port-density grid is deliberately
//! `aria-hidden` and decorative (supplementary to the accessible
//! `<table>` beside it, not a replacement) -- giving *that* an
//! interactive popover trigger would add a keyboard-focusable control
//! inside a region assistive tech is told to skip, which is a real
//! accessibility bug, not a feature. No genuine case remained, so neither
//! element is used.
//!
//! # The port-density grid stays pure CSS; real `<svg>` lives in `diagrams`
//!
//! The port-density grid (`view::PortDensityCell`, `templates/host_section.html`)
//! is pure CSS: `<span>` cells with `clip-path` for the hex shape and
//! `:nth-child` + `transform: translateY()` for the honeycomb column
//! offset, exactly the T24 task sketch's own description ("CSS grid +
//! translateY column offsets, no script"). That was a deliberate choice
//! to leave dedicated, server-rendered SVG diagrams to T25 as their own
//! system rather than building an ad hoc inline-SVG visualization here —
//! [`diagrams`] is that system, added later by this same module. The
//! port-density grid itself is unchanged: still pure CSS, no `<svg>`.
//! `tests::xss_svg_context_payload_is_neutralized` predates `diagrams` and
//! is kept verifying ordinary HTML-context escaping (there was no
//! `<svg><text>` node in this module's own templates when it was
//! written); [`diagrams`]'s own test modules carry the equivalent
//! SVG-context escaping checks against the real `<svg>` output T25 adds.

mod diagrams;
mod templates;
mod view;

use askama::Template as _;

use crate::adapters::config::FontsMode;
use crate::adapters::fonts;
use crate::adapters::report_writer;
use crate::domain::report_model::{HostSection, ReportModel};

/// Failure rendering or writing an HTML report.
#[derive(Debug, thiserror::Error)]
pub enum HtmlRenderError {
    /// Askama failed to render a template — in practice this only happens
    /// if a template file itself is malformed, which `cargo build` would
    /// already have caught at compile time; kept as a real `Result` rather
    /// than unwrapped so a future template change that somehow still
    /// compiles but fails at render time surfaces as an error, not a panic.
    #[error("rendering HTML report template: {0}")]
    Template(#[from] askama::Error),
    /// The destination writer (a file, stdout, a `--split` output
    /// directory) failed.
    #[error("writing HTML report: {0}")]
    Io(#[from] std::io::Error),
    /// Every byte this module writes originates from `String`s built out
    /// of Rust's own UTF-8 string types, so this should never actually
    /// trigger -- kept as a real error rather than an `.expect()` per this
    /// crate's own "never panic outside tests" rule, in case a future
    /// change threads raw bytes through somewhere.
    #[error("rendered HTML report was not valid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// Renders `model` as a single self-contained HTML document.
///
/// A thin wrapper over [`write_report_streaming`] -- kept for callers that
/// genuinely want one in-memory `String` (this module's own test suite,
/// and any future caller that needs to post-process the result before
/// writing it). CLI callers writing straight to a file or stdout should
/// prefer `write_report_streaming` directly, which never holds the whole
/// document as a single Askama-rendered `String` the way this function's
/// predecessor did before this task.
///
/// # Errors
///
/// Returns [`HtmlRenderError`] if template rendering fails.
pub fn render(model: &ReportModel, fonts_mode: FontsMode) -> Result<String, HtmlRenderError> {
    let mut buf = Vec::new();
    write_report_streaming(model, fonts_mode, &mut buf)?;
    Ok(String::from_utf8(buf)?)
}

/// Streams a single self-contained HTML document to `out`: the head and
/// fleet summary once, then one host section at a time.
///
/// Peak memory during rendering is bounded by the largest single host's
/// rendered fragment (plus the fleet summary, itself `O(hosts)` but far
/// smaller than a full per-host table), not by the whole document --
/// unlike building one [`askama::Template`] over the entire
/// [`ReportModel`] in a single `.render()` call, which is what this
/// function replaces. See `tests::synthetic_200_host_fleet_stays_under_10mb`.
///
/// # Errors
///
/// Returns [`HtmlRenderError`] if template rendering or the write to
/// `out` fails.
pub fn write_report_streaming(
    model: &ReportModel,
    fonts_mode: FontsMode,
    out: &mut dyn std::io::Write,
) -> Result<(), HtmlRenderError> {
    let tokens_css = render_tokens_css(fonts_mode)?;
    let summary_html =
        view::summary_template(model, |host| format!("#{}", view::anchor_for(host))).render()?;
    let head = templates::ReportHeadTemplate {
        tokens_css,
        summary_html,
    }
    .render()?;
    out.write_all(head.as_bytes())?;

    for (index, host) in model.hosts.iter().enumerate() {
        let section = view::host_section_template(host, index).render()?;
        out.write_all(section.as_bytes())?;
    }

    out.write_all(TAIL.as_bytes())?;
    Ok(())
}

/// Closing tags for the monolithic document. Fixed and constant -- never
/// templated, since it interpolates nothing and must be identical
/// regardless of how many host sections preceded it.
const TAIL: &str = "</main>\n</body>\n</html>\n";

/// Writes one self-contained HTML document per host into `dir`, plus a
/// lightweight `index.html` linking to each, instead of a single
/// monolithic document.
///
/// `dir` is created (including parents) if it doesn't already exist. Each
/// per-host file embeds `tokens_css` (and, under [`FontsMode::Embed`],
/// the full base64 font payload) in full, rather than referencing one
/// shared stylesheet file — this project's self-contained/offline
/// constraint is about any single artifact never depending on a network
/// fetch, but a `--split` file is also meant to be copyable on its own
/// (e.g. emailing one host's report to its owner without the rest of the
/// fleet), so "self-contained" is read here as "this one file, alone,
/// renders correctly," at the cost of duplicating the token/font bytes
/// across every file in the set. `--fonts system` avoids that
/// duplication entirely for size-conscious `--split` runs, but isn't
/// forced as the default here since embedding is still this module's
/// documented default everywhere else.
///
/// # Errors
///
/// Returns [`HtmlRenderError`] if `dir` can't be created, template
/// rendering fails, or any file write fails.
pub fn write_report_split(
    model: &ReportModel,
    fonts_mode: FontsMode,
    dir: &std::path::Path,
) -> Result<(), HtmlRenderError> {
    std::fs::create_dir_all(dir)?;
    let tokens_css = render_tokens_css(fonts_mode)?;

    for (index, host) in model.hosts.iter().enumerate() {
        let host_section_html = view::host_section_template(host, index).render()?;
        let doc = templates::HostDocumentTemplate {
            tokens_css: tokens_css.clone(),
            host_section_html,
        }
        .render()?;
        let path = dir.join(split_file_name(host));
        report_writer::write_atomically(&path, doc.as_bytes())?;
    }

    let summary_html = view::summary_template(model, split_file_name).render()?;
    let index_doc = templates::SplitIndexTemplate {
        tokens_css,
        summary_html,
    }
    .render()?;
    report_writer::write_atomically(&dir.join("index.html"), index_doc.as_bytes())?;

    Ok(())
}

fn split_file_name(host: &HostSection) -> String {
    format!("host-{}.html", host.host_id)
}

fn render_tokens_css(fonts_mode: FontsMode) -> Result<String, HtmlRenderError> {
    let (serif, sans_400, sans_500, mono) = match fonts_mode {
        FontsMode::Embed => (
            fonts::INSTRUMENT_SERIF_400_DATA_URI.as_str(),
            fonts::GEIST_400_DATA_URI.as_str(),
            fonts::GEIST_500_DATA_URI.as_str(),
            fonts::GEIST_MONO_400_DATA_URI.as_str(),
        ),
        // Never read when `fonts_mode` is `System` -- `tokens.css`'s
        // `{% match %}` only emits the `@font-face` block (and these
        // interpolations) in the `Embed` arm.
        FontsMode::System => ("", "", "", ""),
    };
    let template = templates::TokensCssTemplate {
        fonts_mode,
        instrument_serif_400_uri: serif,
        geist_400_uri: sans_400,
        geist_500_uri: sans_500,
        geist_mono_400_uri: mono,
    };
    Ok(template.render()?)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::str::FromStr as _;

    use super::{FontsMode, HtmlRenderError, render, write_report_split, write_report_streaming};
    use crate::domain::bind_address::BindAddress;
    use crate::domain::endpoint::Endpoint;
    use crate::domain::ids::{HostId, ScanId};
    use crate::domain::port::Port;
    use crate::domain::process::ProcessPath;
    use crate::domain::protocol::Protocol;
    use crate::domain::publisher::SignatureStatus;
    use crate::domain::report_model::ReportModel;
    use crate::domain::service::ServiceName;
    use crate::domain::snapshot::ScanSnapshot;
    use crate::domain::target_strategy::TargetStrategy;

    fn endpoint_with_process_name(process_name: &str) -> Endpoint {
        Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").expect("valid ip"),
            Port::try_from(8443u16).expect("nonzero port"),
            None,
            Some(ProcessPath::from_str(process_name).expect("non-empty path")),
            vec![
                ServiceName::try_from(process_name.to_owned()).unwrap_or_else(|_| {
                    ServiceName::try_from("svc".to_owned()).expect("fallback name is non-empty")
                }),
            ],
            SignatureStatus::Unknown,
            Some(process_name.to_owned()),
        )
    }

    fn sample_model() -> ReportModel {
        let endpoint = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").expect("valid ip"),
            Port::try_from(8443u16).expect("nonzero port"),
            None,
            Some(ProcessPath::from_str("/usr/sbin/sshd").expect("non-empty path")),
            vec![ServiceName::try_from("ssh".to_owned()).expect("non-empty name")],
            SignatureStatus::Unknown,
            None,
        );
        model_from_endpoints(vec![endpoint])
    }

    fn model_from_endpoints(endpoints: Vec<Endpoint>) -> ReportModel {
        let snapshot = ScanSnapshot::new(
            HostId::generate(),
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "test-fixture".to_owned(),
            endpoints,
            vec![],
            vec![],
            TargetStrategy::LocalOnly,
        );
        ReportModel::build(&[snapshot], None, true).expect("fixture model builds")
    }

    /// A synthetic multi-host fleet: `host_count` hosts, `endpoints_per_host`
    /// endpoints each, non-degenerate values in both fields (real
    /// process paths, real service names, real command lines) so the
    /// size measured against it reflects genuine per-endpoint template
    /// cost, not an artificially compressible fixture.
    fn synthetic_fleet_model(host_count: usize, endpoints_per_host: usize) -> ReportModel {
        let mut snapshots = Vec::with_capacity(host_count);
        for host_index in 0..host_count {
            let mut endpoints = Vec::with_capacity(endpoints_per_host);
            for endpoint_index in 0..endpoints_per_host {
                let port = 1024 + u16::try_from(endpoint_index).unwrap_or(0) * 7 + 1;
                let bind = if endpoint_index.is_multiple_of(3) {
                    "127.0.0.1"
                } else {
                    "0.0.0.0"
                };
                let endpoint = Endpoint::new(
                    Protocol::Tcp,
                    BindAddress::from_str(bind).expect("valid ip"),
                    Port::try_from(port).expect("nonzero port"),
                    None,
                    Some(
                        ProcessPath::from_str(&format!(
                            "C:\\Program Files\\vendor{host_index}\\service{endpoint_index}.exe"
                        ))
                        .expect("non-empty path"),
                    ),
                    vec![
                        ServiceName::try_from(format!("Service{host_index}_{endpoint_index}"))
                            .expect("non-empty name"),
                    ],
                    SignatureStatus::Unsigned,
                    Some(format!(
                        "service{endpoint_index}.exe --config C:\\ProgramData\\cfg{endpoint_index}.toml --verbose"
                    )),
                );
                endpoints.push(endpoint);
            }
            snapshots.push(ScanSnapshot::new(
                HostId::generate(),
                ScanId::generate(),
                time::OffsetDateTime::UNIX_EPOCH,
                "1.4.2".to_owned(),
                endpoints,
                vec![],
                vec![],
                TargetStrategy::Execute,
            ));
        }
        ReportModel::build(&snapshots, None, true).expect("synthetic fleet model builds")
    }

    fn extract_style_block(html: &str) -> &str {
        let open = html.find("<style>").expect("template emits a <style> tag") + "<style>".len();
        let close = html[open..]
            .find("</style>")
            .expect("template closes its <style> tag");
        html.get(open..open + close).expect("valid slice bounds")
    }

    /// Removes every `:root { ... }` / `:root:has(...) { ... }` /
    /// `@media (prefers-color-scheme: dark) { ... }` rule from `css` --
    /// together these are the token system's *only* definition surface
    /// (default palette, OS-dark override, manual-checkbox override), so
    /// stripping all three and checking what's left is the honest way to
    /// enforce "no hex literal outside the token block" against three
    /// separate rules that jointly define one token system.
    ///
    /// Callers must pass comment-free CSS (see [`strip_block_comments`]) --
    /// this scans for literal `{`/`}` to find rule boundaries, and the
    /// explanatory comment above the `:has()` override rule itself quotes
    /// a brace-containing CSS selector, which would otherwise desync the
    /// brace count.
    fn strip_token_blocks(css: &str) -> String {
        let mut result = String::new();
        let mut cursor = 0usize;
        while cursor < css.len() {
            let Some(rest) = css.get(cursor..) else {
                break;
            };
            let Some(rel_open) = rest.find('{') else {
                result.push_str(rest);
                break;
            };
            let open = cursor + rel_open;
            let selector = css.get(cursor..open).unwrap_or_default().trim();
            let is_token_selector = selector.starts_with(":root")
                || selector.starts_with("@media (prefers-color-scheme: dark)");

            let mut depth = 0i32;
            let mut close = open;
            for (offset, ch) in css.get(open..).unwrap_or_default().char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            close = open + offset;
                            break;
                        }
                    }
                    _ => {}
                }
            }

            if !is_token_selector {
                result.push_str(css.get(cursor..=close).unwrap_or_default());
            }
            cursor = close + 1;
        }
        result
    }

    fn strip_block_comments(text: &str) -> String {
        let mut result = String::new();
        let mut rest = text;
        while let Some(start) = rest.find("/*") {
            result.push_str(rest.get(..start).unwrap_or_default());
            if let Some(end_rel) = rest.get(start..).and_then(|tail| tail.find("*/")) {
                rest = rest.get(start + end_rel + 2..).unwrap_or_default();
            } else {
                rest = "";
                break;
            }
        }
        result.push_str(rest);
        result
    }

    fn contains_hex_colour_literal(css: &str) -> bool {
        css.char_indices().any(|(idx, ch)| {
            if ch != '#' {
                return false;
            }
            let hex_len = css
                .get(idx + 1..)
                .unwrap_or_default()
                .chars()
                .take_while(char::is_ascii_hexdigit)
                .count();
            hex_len == 3 || hex_len == 6
        })
    }

    /// Finds every top-level CSS rule (by selector text) whose declaration
    /// block mentions `animation-timeline`, and every top-level
    /// `@media (prefers-reduced-motion: no-preference) { ... }` block's
    /// byte range, on the real rendered stylesheet -- not the template
    /// source, per this task's own exit criterion.
    fn animation_timeline_rules_outside_reduced_motion_query(css: &str) -> Vec<String> {
        let no_comments = strip_block_comments(css);
        let mut reduced_motion_ranges: Vec<(usize, usize)> = Vec::new();
        let mut offenders = Vec::new();

        let mut cursor = 0usize;
        while let Some(at_rel) = no_comments.get(cursor..).and_then(|rest| rest.find('@')) {
            let at = cursor + at_rel;
            let Some(rest) = no_comments.get(at..) else {
                break;
            };
            if rest.starts_with("@media (prefers-reduced-motion: no-preference)")
                && let Some(open_rel) = rest.find('{')
            {
                let open = at + open_rel;
                if let Some(close) = matching_brace(&no_comments, open) {
                    reduced_motion_ranges.push((open, close));
                    cursor = close + 1;
                    continue;
                }
            }
            cursor = at + 1;
        }

        let mut scan_cursor = 0usize;
        while let Some(open_rel) = no_comments
            .get(scan_cursor..)
            .and_then(|rest| rest.find('{'))
        {
            let open = scan_cursor + open_rel;
            let Some(close) = matching_brace(&no_comments, open) else {
                break;
            };
            let selector = no_comments.get(scan_cursor..open).unwrap_or_default();
            let body = no_comments.get(open..=close).unwrap_or_default();
            let is_media_wrapper = selector.trim_start().starts_with('@');
            if !is_media_wrapper && body.contains("animation-timeline") {
                let inside_reduced_motion = reduced_motion_ranges
                    .iter()
                    .any(|&(start, end)| open >= start && close <= end);
                if !inside_reduced_motion {
                    offenders.push(selector.trim().to_owned());
                }
            }
            scan_cursor = close + 1;
        }

        offenders
    }

    fn matching_brace(text: &str, open: usize) -> Option<usize> {
        let mut depth = 0i32;
        for (offset, ch) in text.get(open..)?.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(open + offset);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Removes every `<script ...>...</script>` element from `html` --
    /// used to prove the report stays navigable even with script fully
    /// stripped, per this task's mandated (not merely commented) test.
    fn strip_script_tags(html: &str) -> String {
        let mut result = String::new();
        let mut rest = html;
        while let Some(start) = rest.find("<script") {
            result.push_str(rest.get(..start).unwrap_or_default());
            if let Some(end_rel) = rest.get(start..).and_then(|tail| tail.find("</script>")) {
                rest = rest
                    .get(start + end_rel + "</script>".len()..)
                    .unwrap_or_default();
            } else {
                rest = "";
                break;
            }
        }
        result.push_str(rest);
        result
    }

    #[test]
    fn rendered_artifact_has_zero_external_resource_references() {
        let html = render(&sample_model(), FontsMode::Embed).expect("renders");
        for pattern in ["src=\"http", "href=\"http", "url(http"] {
            assert!(
                !html.contains(pattern),
                "found external reference matching {pattern}"
            );
        }
    }

    #[test]
    fn csp_meta_tag_is_present_verbatim() {
        let html = render(&sample_model(), FontsMode::Embed).expect("renders");
        assert!(html.contains(
            r#"<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">"#
        ));
    }

    #[test]
    fn token_root_block_is_present() {
        let html = render(&sample_model(), FontsMode::Embed).expect("renders");
        let css = extract_style_block(&html);
        assert!(css.contains("--paper: #f5f5f4"));
        assert!(css.contains("--ink: #111111"));
    }

    #[test]
    fn no_hex_colour_literal_outside_token_block() {
        let html = render(&sample_model(), FontsMode::Embed).expect("renders");
        let css = extract_style_block(&html);
        let css_no_comments = strip_block_comments(css);
        let stripped = strip_token_blocks(&css_no_comments);
        assert!(
            !contains_hex_colour_literal(&stripped),
            "found a hex colour literal outside the token block:\n{stripped}"
        );
    }

    #[test]
    fn fonts_embed_emits_font_face_block_and_base64_payload() {
        // Positive control for `fonts_system_flag_emits_no_base64_or_
        // font_face_block` below -- proves that test isn't vacuously
        // passing because the template never emits either marker at all.
        let html = render(&sample_model(), FontsMode::Embed).expect("renders");
        assert!(html.contains("base64,"));
        assert!(html.contains("@font-face"));
    }

    #[test]
    fn fonts_system_flag_emits_no_base64_or_font_face_block() {
        let html = render(&sample_model(), FontsMode::System).expect("renders");
        assert!(!html.contains("base64,"));
        assert!(!html.contains("@font-face"));
    }

    #[test]
    fn fonts_system_still_names_the_three_type_roles() {
        let html = render(&sample_model(), FontsMode::System).expect("renders");
        let css = extract_style_block(&html);
        assert!(css.contains("--font-serif: ui-serif"));
        assert!(css.contains("--font-sans: ui-sans-serif"));
        assert!(css.contains("--font-mono: ui-monospace"));
    }

    #[test]
    fn html_render_error_wraps_askama_error() {
        // `HtmlRenderError` exists to keep this module's public surface
        // from leaking `askama::Error` directly; this just pins that the
        // `From` conversion used by `render`'s `?` actually compiles and
        // round-trips a real `askama::Error` variant, so the enum can't
        // silently rot into an unused/dead conversion.
        let err: HtmlRenderError = askama::Error::Fmt.into();
        assert!(matches!(err, HtmlRenderError::Template(_)));
    }

    #[test]
    fn html_render_error_wraps_io_error() {
        let io_err = std::io::Error::other("disk full");
        let err: HtmlRenderError = io_err.into();
        assert!(matches!(err, HtmlRenderError::Io(_)));
    }

    #[test]
    fn real_endpoint_data_renders_inside_the_endpoint_table() {
        let html = render(&sample_model(), FontsMode::Embed).expect("renders");
        assert!(html.contains("8443"));
        assert!(html.contains("sshd"));
        assert!(html.contains("class=\"host-section\""));
    }

    #[test]
    fn sort_controls_are_present_per_host() {
        let html = render(&sample_model(), FontsMode::Embed).expect("renders");
        assert!(html.contains("sort-controls"));
        assert!(html.contains("value=\"port\""));
        assert!(html.contains("value=\"exposure\""));
        assert!(html.contains("value=\"reachability\""));
    }

    #[test]
    fn drift_summary_renders_when_drift_is_present() {
        use crate::domain::drift::diff;

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
        let current = ScanSnapshot::new(
            host_id,
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "1.0.0".to_owned(),
            vec![endpoint_with_process_name("newsvc.exe")],
            vec![],
            vec![],
            TargetStrategy::Execute,
        );
        let report = diff(&baseline, &current);
        assert!(!report.entries.is_empty(), "fixture must produce drift");

        let model = ReportModel::build(&[current], Some(&report), true).expect("model builds");
        let mut buf = Vec::new();
        write_report_streaming(&model, FontsMode::Embed, &mut buf).expect("streams");
        let html = String::from_utf8(buf).expect("utf8");
        assert!(html.contains("drift-summary"));
        assert!(html.contains("endpoint appeared"));
    }

    #[test]
    fn xss_payloads_never_appear_unescaped() {
        let payloads = [
            "<script>alert(1)</script>",
            "\" onerror=\"alert(1)",
            "</script><script>alert(2)</script>",
        ];
        for payload in payloads {
            let model = model_from_endpoints(vec![endpoint_with_process_name(payload)]);
            let html = render(&model, FontsMode::Embed).expect("renders despite hostile input");
            assert!(
                !html.contains("<script>alert"),
                "payload {payload:?} produced an executable <script> context"
            );
            assert!(
                !html.contains("onerror=\"alert"),
                "payload {payload:?} produced a live onerror attribute"
            );
            assert!(
                !html.contains("</script><script>"),
                "payload {payload:?} broke out of an existing script context"
            );
        }
    }

    /// The SVG-context payload from the task's own test spec
    /// (`<text/onload=alert(3)>`), verified against real rendered report
    /// output.
    ///
    /// This module's module doc explains why no `<svg>` element exists
    /// anywhere in this report's output (the port-density grid is pure
    /// CSS, not SVG) -- so there is no literal `<text>` node this payload
    /// could land inside today. The check that remains meaningful, and is
    /// exactly what this test performs: Askama's HTML-context escaping
    /// (verified here against real output, not assumed) neutralizes the
    /// payload's `<`/`>` characters unconditionally, regardless of which
    /// element happens to surround the interpolated text. That is the
    /// actual security property this task cares about -- if a future
    /// change ever does add inline SVG that reuses these same `EndpointRow`
    /// fields, this same escaping already makes the payload inert there
    /// too, since SVG embedded in an HTML document is tokenized by the
    /// HTML parser, which applies the same entity-escaping rules to text
    /// content regardless of the surrounding element's namespace.
    #[test]
    fn xss_svg_context_payload_is_neutralized() {
        let payload = "<text/onload=alert(3)>";
        let model = model_from_endpoints(vec![endpoint_with_process_name(payload)]);
        let html = render(&model, FontsMode::Embed).expect("renders despite hostile input");
        assert!(
            !html.contains("<text/onload=alert(3)>"),
            "SVG-context payload appeared unescaped in rendered output"
        );
        assert!(
            !html.contains("<text/onload"),
            "payload's opening angle bracket was not escaped -- would open a live tag"
        );
        // Askama's HTML escaper emits numeric character references
        // (`&#60;`/`&#62;`), not named entities (`&lt;`/`&gt;`) -- either
        // is a valid, inert escape for a literal `<`/`>` in HTML text or
        // attribute-value context, so this checks for the form Askama
        // actually produces (confirmed against real rendered output, per
        // this task's own instruction not to assume the escaping claim).
        assert!(
            html.contains("&#60;text/onload=alert(3)&#62;"),
            "expected the payload to be entity-escaped end to end, angle brackets included"
        );
    }

    #[test]
    fn report_navigable_with_script_elements_stripped() {
        // This module adds no JavaScript at all (see the module doc) --
        // the report's navigation (host list, per-host sort controls,
        // drill-down) is native HTML5/CSS, so stripping every `<script>`
        // element (there are none) must be a no-op and the report must
        // stay fully usable. Asserted as a real test rather than a
        // comment, per this task's own exit criterion.
        let html = render(&sample_model(), FontsMode::Embed).expect("renders");
        assert!(
            !html.contains("<script"),
            "this module adds no JavaScript; a <script> tag appearing here is a regression"
        );
        let stripped = strip_script_tags(&html);
        assert_eq!(stripped, html, "stripping <script> tags must be a no-op");
        assert!(
            stripped.contains("sort-controls"),
            "sort controls still present"
        );
        assert!(stripped.contains("<nav"), "host navigation still present");
        assert!(
            stripped.contains("class=\"host-section\""),
            "host section still present"
        );
    }

    #[test]
    fn synthetic_200_host_fleet_stays_under_10mb() {
        let model = synthetic_fleet_model(200, 8);
        let mut buf = Vec::new();
        write_report_streaming(&model, FontsMode::Embed, &mut buf).expect("streams");
        assert!(
            buf.len() < 10 * 1024 * 1024,
            "rendered {} bytes, over the 10 MB budget",
            buf.len()
        );
    }

    #[test]
    fn every_scroll_driven_animation_wrapped_in_reduced_motion_query() {
        let html = render(&sample_model(), FontsMode::Embed).expect("renders");
        let css = extract_style_block(&html);
        let offenders = animation_timeline_rules_outside_reduced_motion_query(css);
        assert!(
            offenders.is_empty(),
            "rules using animation-timeline outside the reduced-motion query: {offenders:?}"
        );
    }

    #[test]
    fn stylesheet_genuinely_uses_animation_timeline_at_least_once() {
        // Positive control for the test above -- without this, an empty
        // `offenders` list could just mean the stylesheet never uses
        // `animation-timeline` at all, not that every use is correctly
        // scoped.
        let html = render(&sample_model(), FontsMode::Embed).expect("renders");
        let css = extract_style_block(&html);
        assert!(css.contains("animation-timeline"));
    }

    #[test]
    fn print_media_rules_are_present() {
        let html = render(&sample_model(), FontsMode::Embed).expect("renders");
        let css = extract_style_block(&html);
        assert!(css.contains("@media print"));
        assert!(css.contains("break-inside: avoid"));
    }

    #[test]
    fn write_report_split_emits_one_file_per_host_plus_an_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let model = synthetic_fleet_model(3, 2);
        write_report_split(&model, FontsMode::System, dir.path()).expect("split writes");

        let index = std::fs::read_to_string(dir.path().join("index.html")).expect("index exists");
        assert!(index.starts_with("<!doctype html>"));
        assert!(index.contains("Content-Security-Policy"));

        let mut host_files = 0usize;
        for host in &model.hosts {
            let path = dir.path().join(format!("host-{}.html", host.host_id));
            let doc = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("split file for {} exists", host.host_id));
            assert!(doc.starts_with("<!doctype html>"));
            assert!(doc.contains("Content-Security-Policy"));
            assert!(doc.contains("class=\"host-section\""));
            host_files += 1;
        }
        assert_eq!(host_files, model.hosts.len());
    }

    #[test]
    fn split_files_are_each_independently_self_contained() {
        // Every `--split` file must render correctly on its own -- see
        // `write_report_split`'s doc comment for why each file duplicates
        // the token/font payload rather than sharing one external
        // stylesheet.
        let dir = tempfile::tempdir().expect("tempdir");
        let model = synthetic_fleet_model(1, 1);
        write_report_split(&model, FontsMode::Embed, dir.path()).expect("split writes");

        let host = model.hosts.first().expect("one host");
        let path = dir.path().join(format!("host-{}.html", host.host_id));
        let doc = std::fs::read_to_string(&path).expect("split file exists");
        for pattern in ["src=\"http", "href=\"http", "url(http"] {
            assert!(!doc.contains(pattern), "found external reference {pattern}");
        }
        assert!(
            doc.contains("base64,"),
            "embed mode duplicates the font payload per file"
        );
    }

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate manifest dir has a workspace root two levels up")
            .to_path_buf()
    }

    fn find_rlib_artifact(cargo_stdout: &[u8]) -> Option<PathBuf> {
        for line in String::from_utf8_lossy(cargo_stdout).lines() {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if value.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact")
            {
                continue;
            }
            let Some(filenames) = value.get("filenames").and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            for name in filenames {
                if let Some(path) = name.as_str()
                    && Path::new(path)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("rlib"))
                {
                    return Some(PathBuf::from(path));
                }
            }
        }
        None
    }

    fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    /// Same shape as `adapters::fonts`'s `collector_only_build_contains_
    /// zero_font_bytes` -- a real nested `cargo build` without
    /// `report-html`, grepped for template/CSS text that can only be
    /// present if Askama actually compiled `templates/*` into the
    /// binary, not asserted in prose.
    #[test]
    fn collector_only_build_contains_zero_html_report_payload() {
        let workspace_root = workspace_root();
        let target_dir =
            std::env::temp_dir().join(format!("anne-html-report-audit-{}", std::process::id()));

        let output = Command::new(env!("CARGO"))
            .current_dir(&workspace_root)
            .arg("build")
            .arg("--locked")
            .arg("-p")
            .arg("anne-de-breuil")
            .arg("--lib")
            .arg("--no-default-features")
            .arg("--features")
            .arg("windows-collector,linux-collector")
            .arg("--message-format=json-render-diagnostics")
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .expect("spawning nested cargo build");
        assert!(
            output.status.success(),
            "nested cargo build (no report-html) failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let rlib_path = find_rlib_artifact(&output.stdout)
            .expect("cargo build output must report a compiler-artifact .rlib");
        let compiled = std::fs::read(&rlib_path).expect("reading compiled rlib");

        for needle in [
            b"exposure-loopback".as_slice(),
            b"Content-Security-Policy",
            b"theme-toggle",
        ] {
            assert!(
                !contains_subsequence(&compiled, needle),
                "collector-only build embeds HTML report template text ({})",
                String::from_utf8_lossy(needle)
            );
        }

        std::fs::remove_dir_all(&target_dir).ok();
    }
}
