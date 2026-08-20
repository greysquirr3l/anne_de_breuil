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
}
