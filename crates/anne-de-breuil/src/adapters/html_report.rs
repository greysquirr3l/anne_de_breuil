//! Self-contained HTML5 report rendering via Askama.
//!
//! T23 scope only: this proves the CSS custom-property token system, the
//! two font-embedding modes, the CSP meta tag, and the zero-JavaScript
//! theme override all render correctly end to end. `templates/report.html`
//! is deliberately thin — a page shell plus a rollup line and one example
//! endpoint, not host tables or drift views. Real report content is
//! `T24`'s job; building it out here would just have to be thrown away
//! and rebuilt against whatever `T24` actually needs.
//!
//! `templates/tokens.css` is a separate template (not inlined by hand into
//! `report.html`'s `<style>` block) so the `@font-face` swap between
//! [`FontsMode::Embed`] and [`FontsMode::System`] is expressed as a real
//! Askama `{% match %}`, not string concatenation in Rust — see that
//! file for the token palette and the `:has()`-based manual dark-mode
//! override.

use askama::Template;

use crate::adapters::config::FontsMode;
use crate::adapters::fonts;
use crate::domain::report_model::ReportModel;

/// Failure rendering the HTML report template.
#[derive(Debug, thiserror::Error)]
pub enum HtmlRenderError {
    /// Askama failed to render a template — in practice this only happens
    /// if a template file itself is malformed, which `cargo build` would
    /// already have caught at compile time; kept as a real `Result` rather
    /// than unwrapped so a future template change that somehow still
    /// compiles but fails at render time surfaces as an error, not a panic.
    #[error("rendering HTML report template: {0}")]
    Template(#[from] askama::Error),
}

#[derive(Template)]
#[template(path = "tokens.css", escape = "none")]
struct TokensCssTemplate<'a> {
    fonts_mode: FontsMode,
    instrument_serif_400_uri: &'a str,
    geist_400_uri: &'a str,
    geist_500_uri: &'a str,
    geist_mono_400_uri: &'a str,
}

#[derive(Template)]
#[template(path = "report.html")]
struct ReportTemplate {
    tokens_css: String,
    hosts_scanned: usize,
    endpoints_total: usize,
    redaction_enabled: bool,
    example_endpoint: Option<String>,
}

/// Renders `model` as a self-contained HTML report.
///
/// `fonts_mode` selects between the vendored WOFF2 faces embedded as
/// base64 `data:` URIs ([`FontsMode::Embed`]) and a system font stack
/// with no embedded bytes at all ([`FontsMode::System`]).
///
/// # Errors
///
/// Returns [`HtmlRenderError`] if template rendering fails — see that
/// type's doc comment for why this is not expected to happen in practice.
pub fn render(model: &ReportModel, fonts_mode: FontsMode) -> Result<String, HtmlRenderError> {
    let tokens_css = render_tokens_css(fonts_mode)?;
    let endpoints_total: usize = model.hosts.iter().map(|host| host.endpoints.len()).sum();
    let example_endpoint = model
        .hosts
        .first()
        .and_then(|host| host.endpoints.first())
        .map(|endpoint| format!("{}:{}", endpoint.bind_address, endpoint.port));

    let template = ReportTemplate {
        tokens_css,
        hosts_scanned: model.rollup.hosts_scanned,
        endpoints_total,
        redaction_enabled: model.redaction_enabled,
        example_endpoint,
    };
    Ok(template.render()?)
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
    let template = TokensCssTemplate {
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

    use super::{FontsMode, HtmlRenderError, render};
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
        let snapshot = ScanSnapshot::new(
            HostId::generate(),
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "test-fixture".to_owned(),
            vec![endpoint],
            vec![],
            vec![],
            TargetStrategy::LocalOnly,
        );
        ReportModel::build(&[snapshot], None, true).expect("fixture model builds")
    }

    fn extract_style_block(html: &str) -> &str {
        let open = html.find("<style>").expect("template emits a <style> tag") + "<style>".len();
        let close = html[open..]
            .find("</style>")
            .expect("template closes its <style> tag");
        html.get(open..open + close).expect("valid slice bounds")
    }

    /// Removes every `:root { ... }` / `:root:has(...) { ... }` /
    /// `@media (prefers-color-scheme: dark) { ... }` rule from `css` —
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

    /// Resolves `adapters::fonts`'s `// TODO(T23)` marker: once
    /// `--fonts=system` exists as a real flag, add a test asserting the
    /// rendered artifact carries neither a base64 font payload nor an
    /// `@font-face` block. This is that test.
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
    fn example_endpoint_address_renders_inside_a_mono_code_element() {
        let html = render(&sample_model(), FontsMode::Embed).expect("renders");
        assert!(html.contains("<code>0.0.0.0:8443</code>"));
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
