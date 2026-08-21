//! Askama `#[derive(Template)]` structs that just wrap already-rendered
//! sub-documents into a complete shell.
//!
//! `view.rs` owns the two templates whose fields are built from
//! `ReportModel` data directly (`HostSectionTemplate`, `SummaryTemplate`);
//! this file owns the ones that only ever receive pre-rendered `String`s
//! (`{{ field|safe }}`), the same composition pattern `mod.rs` already
//! used for `tokens_css` before this task -- kept consistent rather than
//! mixing in Askama's `{% include %}`, which requires the includer and
//! includee to share one context struct and would force `SummaryTemplate`'s
//! many fields onto every document shell that embeds it.

use askama::Template;

use crate::adapters::config::FontsMode;

#[derive(Template)]
#[template(path = "tokens.css", escape = "none")]
pub(super) struct TokensCssTemplate<'a> {
    pub(super) fonts_mode: FontsMode,
    pub(super) instrument_serif_400_uri: &'a str,
    pub(super) geist_400_uri: &'a str,
    pub(super) geist_500_uri: &'a str,
    pub(super) geist_mono_400_uri: &'a str,
}

/// The document shell up through `<main>`'s opening tag -- host sections
/// are streamed in after this and the document is closed with the fixed
/// `super::TAIL` string, never assembled through one more-encompassing
/// template.
#[derive(Template)]
#[template(path = "report.html")]
pub(super) struct ReportHeadTemplate {
    pub(super) tokens_css: String,
    pub(super) summary_html: String,
}

/// A standalone, fully self-contained document for one host -- what
/// `--split` writes per host. Duplicates `tokens_css` in full rather than
/// referencing a shared stylesheet file, so a single split file copied off
/// the fleet report on its own still renders with zero external
/// dependencies; see `mod.rs::write_report_split`'s doc comment for the
/// size/self-containment trade-off this represents.
#[derive(Template)]
#[template(path = "host_document.html")]
pub(super) struct HostDocumentTemplate {
    pub(super) tokens_css: String,
    pub(super) host_section_html: String,
}

/// The `--split` index file: the same fleet-wide summary as
/// [`ReportHeadTemplate`], but as a complete standalone document whose
/// navigation links point at sibling per-host files instead of same-page
/// anchors.
#[derive(Template)]
#[template(path = "split_index.html")]
pub(super) struct SplitIndexTemplate {
    pub(super) tokens_css: String,
    pub(super) summary_html: String,
}
