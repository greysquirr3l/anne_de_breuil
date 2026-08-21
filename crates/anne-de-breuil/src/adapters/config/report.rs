//! `[report]` section: output formats, destination, and theming.

use std::path::PathBuf;

/// A machine- or human-readable report output target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ReportFormat {
    /// Structured JSON, one document per scan.
    Json,
    /// Flat CSV, one row per endpoint.
    Csv,
    /// SARIF for ingestion by code-scanning tooling.
    Sarif,
    /// Self-contained HTML5 report with embedded assets.
    Html,
}

/// Colour scheme for the HTML report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Theme {
    /// Always light.
    Light,
    /// Always dark.
    Dark,
    /// Follow the viewer's OS/browser preference.
    Auto,
}

/// Where the HTML report's fonts come from.
///
/// A peer setting to [`Theme`], not a CLI-only flag — it's exactly the
/// same shape of decision (how the HTML report renders) and belongs on
/// the same config surface an operator already uses to pin the theme, so
/// the CLI's `--fonts` flag maps onto this field the same way `--format`
/// already maps onto [`ReportFormat`] rather than introducing a second,
/// structurally different mechanism for a conceptually identical setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FontsMode {
    /// Vendored WOFF2 subsets, embedded as base64 `data:` URIs — fully
    /// self-contained, larger output.
    Embed,
    /// System font stack (`ui-serif`/`ui-sans-serif`/`ui-monospace`) — no
    /// embedded font bytes, no `@font-face` block at all.
    System,
}

/// Report generation settings.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportConfig {
    /// Which output formats to emit for each scan.
    pub formats: Vec<ReportFormat>,
    /// Directory reports are written to.
    pub output_dir: PathBuf,
    /// HTML report colour scheme.
    pub theme: Theme,
    /// Where the HTML report's fonts come from.
    pub fonts: FontsMode,
    /// Whether secret-shaped values (tokens, connection strings) are
    /// redacted from report output.
    pub redaction: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            formats: vec![ReportFormat::Json, ReportFormat::Html],
            output_dir: PathBuf::from("./anne-reports"),
            theme: Theme::Auto,
            fonts: FontsMode::Embed,
            redaction: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_redact_by_default() {
        assert!(ReportConfig::default().redaction);
    }

    #[test]
    fn defaults_emit_json_and_html() {
        let formats = ReportConfig::default().formats;
        assert_eq!(formats, vec![ReportFormat::Json, ReportFormat::Html]);
    }

    #[test]
    fn defaults_embed_fonts() {
        assert_eq!(ReportConfig::default().fonts, FontsMode::Embed);
    }
}
