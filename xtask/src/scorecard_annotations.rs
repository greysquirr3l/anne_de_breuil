//! `cargo run -p xtask -- verify-scorecard-annotations`
//!
//! Validates `.github/scorecard.yml`, the Scorecard maintainer annotations
//! for this repository.
//!
//! Scorecard reads that file to decide which checks are not applicable to
//! the project, and it does so *silently*: if any check name or reason in
//! the file is invalid, Scorecard logs the parse failure at Info level,
//! discards the entire file, and every annotated check goes straight back
//! to raising a code-scanning alert. Nothing in the Scorecard workflow
//! fails when that happens, so the file needs a gate of its own -- the
//! tests in this module validate it on every `cargo test --workspace` run,
//! which CI performs on every pull request, and the
//! `verify-scorecard-annotations` task runs the same check on demand.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

/// The check names Scorecard accepts in an annotation.
///
/// Mirrors `internal/checknames.AllValidChecks` in the Scorecard source.
/// Scorecard matches these case-insensitively, so this list does too.
const VALID_CHECKS: &[&str] = &[
    "Binary-Artifacts",
    "Branch-Protection",
    "CII-Best-Practices",
    "CI-Tests",
    "Code-Review",
    "Contributors",
    "Dangerous-Workflow",
    "Dependency-Update-Tool",
    "Fuzzing",
    "License",
    "Maintained",
    "Packaging",
    "Pinned-Dependencies",
    "SAST",
    "SBOM",
    "Security-Policy",
    "Signed-Releases",
    "Token-Permissions",
    "Vulnerabilities",
    "Webhooks",
];

/// The annotation reasons Scorecard accepts.
///
/// Mirrors `config.Reason` in the Scorecard source. Anything outside this
/// set makes Scorecard discard the whole file.
const VALID_REASONS: &[&str] = &[
    "test-data",
    "remediated",
    "not-applicable",
    "not-supported",
    "not-detected",
];

/// One `annotations:` entry: the checks it covers and the reasons given.
#[derive(Debug, Default, PartialEq, Eq)]
struct Annotation {
    /// Check names this entry applies to.
    checks: Vec<String>,
    /// Reasons given for those checks.
    reasons: Vec<String>,
}

/// Which key of an annotation the following sequence items belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    /// The `checks:` list.
    Checks,
    /// The `reasons:` list.
    Reasons,
}

/// Strips a trailing `#` comment from a line.
///
/// The annotations file never needs a literal `#` in a value, so anything
/// from the first ` #` onwards is a comment.
fn strip_comment(line: &str) -> &str {
    line.find(" #").map_or(line, |idx| &line[..idx])
}

/// Parses the subset of YAML that Scorecard's annotations file uses.
///
/// Deliberately not a general YAML parser. The file has exactly one shape,
/// and a strict reader over that shape catches the mistakes that actually
/// break Scorecard -- a mistyped check name, a mistyped reason, a key in
/// the wrong place -- without pulling a YAML parser into a tool that does
/// not otherwise read YAML.
///
/// The accepted shape is:
///
/// ```yaml
/// annotations:
///   - checks:
///       - <Check-Name>
///     reasons:
///       - reason: <reason>
/// ```
///
/// # Errors
///
/// Returns an error if any line does not fit that shape.
fn parse_annotations(source: &str) -> Result<Vec<Annotation>> {
    let mut annotations: Vec<Annotation> = Vec::new();
    // Which key of the current entry the following sequence items belong to.
    let mut current_key: Option<Section> = None;
    let mut seen_annotations_key = false;

    for (index, raw) in source.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let line = strip_comment(raw);
        let indent = line.len() - line.trim_start().len();
        let content = line.trim_start();

        match (indent, content) {
            (0, "annotations:") => {
                ensure!(
                    !seen_annotations_key,
                    "line {line_number}: duplicate `annotations:` key"
                );
                seen_annotations_key = true;
            }
            (0, other) => bail!("line {line_number}: unexpected top-level key `{other}`"),
            (2, "- checks:") => {
                ensure!(
                    seen_annotations_key,
                    "line {line_number}: `annotations:` must come first"
                );
                annotations.push(Annotation::default());
                current_key = Some(Section::Checks);
            }
            (2, other) => bail!(
                "line {line_number}: expected `- checks:` at this indent, found `{other}`"
            ),
            (4, "reasons:") => {
                ensure!(
                    !annotations.is_empty(),
                    "line {line_number}: `reasons:` outside an annotation"
                );
                current_key = Some(Section::Reasons);
            }
            (4, other) => bail!("line {line_number}: unexpected key `{other}`"),
            (6, item) if item.starts_with("- ") => {
                let value = item.trim_start_matches("- ").trim();
                ensure!(!value.is_empty(), "line {line_number}: empty sequence item");
                let entry = annotations
                    .last_mut()
                    .context("sequence item outside an annotation")?;
                match current_key {
                    Some(Section::Checks) => entry.checks.push(value.to_owned()),
                    Some(Section::Reasons) => {
                        let reason = value.strip_prefix("reason: ").with_context(|| {
                            format!(
                                "line {line_number}: expected `reason: <reason>`, found `{value}`"
                            )
                        })?;
                        entry.reasons.push(reason.trim().to_owned());
                    }
                    None => bail!("line {line_number}: sequence item outside an annotation"),
                }
            }
            (6, other) => bail!("line {line_number}: unexpected sequence item `{other}`"),
            (other_indent, other) => bail!(
                "line {line_number}: unexpected indentation ({other_indent}) in `{other}`"
            ),
        }
    }

    ensure!(seen_annotations_key, "no `annotations:` key found");
    Ok(annotations)
}

/// Checks the parsed annotations against the names and reasons Scorecard
/// accepts.
///
/// # Errors
///
/// Returns an error naming the first invalid check name or reason.
fn validate_annotations(annotations: &[Annotation]) -> Result<()> {
    for (index, annotation) in annotations.iter().enumerate() {
        ensure!(
            !annotation.checks.is_empty(),
            "annotation {index} lists no checks"
        );
        ensure!(
            !annotation.reasons.is_empty(),
            "annotation {index} lists no reasons"
        );
        for check in &annotation.checks {
            ensure!(
                VALID_CHECKS.iter().any(|name| name.eq_ignore_ascii_case(check)),
                "annotation {index}: `{check}` is not a Scorecard check name"
            );
        }
        for reason in &annotation.reasons {
            ensure!(
                VALID_REASONS.contains(&reason.as_str()),
                "annotation {index}: `{reason}` is not a Scorecard annotation reason"
            );
        }
    }
    Ok(())
}

/// The repository-relative path of the annotations file.
fn annotations_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(".github")
        .join("scorecard.yml")
}

/// Validates the repository's Scorecard annotations file.
///
/// # Errors
///
/// Returns an error if the file is missing, unreadable, malformed, or
/// names a check or reason Scorecard would reject.
pub fn run() -> Result<()> {
    let path = annotations_path();
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    let annotations = parse_annotations(&source)?;
    validate_annotations(&annotations)?;

    let check_count: usize = annotations.iter().map(|a| a.checks.len()).sum();
    println!(
        "scorecard annotations: {check_count} check(s) across {} annotation(s) -- OK",
        annotations.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Annotation, VALID_CHECKS, VALID_REASONS, parse_annotations, validate_annotations,
    };

    const VALID_FILE: &str = "\
annotations:
  - checks:
      - CII-Best-Practices
    reasons:
      - reason: not-applicable
";

    #[test]
    fn a_valid_annotations_file_parses() {
        let parsed = parse_annotations(VALID_FILE).expect("valid file");
        assert_eq!(
            parsed,
            vec![Annotation {
                checks: vec!["CII-Best-Practices".to_owned()],
                reasons: vec!["not-applicable".to_owned()],
            }]
        );
        validate_annotations(&parsed).expect("valid annotations");
    }

    #[test]
    fn the_repositorys_own_annotations_file_is_valid() {
        let path = super::annotations_path();
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let parsed = parse_annotations(&source)
            .unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()));
        validate_annotations(&parsed)
            .unwrap_or_else(|e| panic!("validating {}: {e}", path.display()));
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let parsed = parse_annotations(
            "\
# a leading comment

annotations:
  # which checks this covers
  - checks:
      - Maintained   # and why
    reasons:
      - reason: not-applicable
",
        )
        .expect("valid file");
        assert_eq!(
            parsed,
            vec![Annotation {
                checks: vec!["Maintained".to_owned()],
                reasons: vec!["not-applicable".to_owned()],
            }]
        );
    }

    #[test]
    fn an_unknown_check_name_is_rejected() {
        let parsed = parse_annotations(
            "\
annotations:
  - checks:
      - Not-A-Check
    reasons:
      - reason: not-applicable
",
        )
        .expect("parses");
        let error = validate_annotations(&parsed).expect_err("unknown check must be rejected");
        assert!(error.to_string().contains("Not-A-Check"), "{error}");
    }

    #[test]
    fn an_unknown_reason_is_rejected() {
        let parsed = parse_annotations(
            "\
annotations:
  - checks:
      - Maintained
    reasons:
      - reason: because-i-said-so
",
        )
        .expect("parses");
        let error = validate_annotations(&parsed).expect_err("unknown reason must be rejected");
        assert!(error.to_string().contains("because-i-said-so"), "{error}");
    }

    #[test]
    fn a_mistyped_reason_key_is_rejected() {
        let error = parse_annotations(
            "\
annotations:
  - checks:
      - Maintained
    reasons:
      - reasons: not-applicable
",
        )
        .expect_err("a `reasons:` key must name a reason");
        assert!(error.to_string().contains("reason:"), "{error}");
    }

    #[test]
    fn an_unknown_top_level_key_is_rejected() {
        let error = parse_annotations("policy:\n  score: 10\n").expect_err("unknown top-level key");
        assert!(error.to_string().contains("top-level"), "{error}");
    }

    #[test]
    fn wrongly_indented_content_is_rejected() {
        let error = parse_annotations(
            "\
annotations:
  - checks:
     - Maintained
",
        )
        .expect_err("misindented sequence item");
        assert!(error.to_string().contains("indentation"), "{error}");
    }

    #[test]
    fn a_sequence_item_in_the_wrong_place_is_rejected() {
        let error = parse_annotations(
            "\
annotations:
  - checks:
    - Maintained
",
        )
        .expect_err("sequence item where a key belongs");
        assert!(error.to_string().contains("unexpected key"), "{error}");
    }

    #[test]
    fn an_annotation_without_a_reason_is_rejected() {
        let parsed = parse_annotations(
            "\
annotations:
  - checks:
      - Maintained
",
        )
        .expect("parses");
        let error = validate_annotations(&parsed).expect_err("missing reason");
        assert!(error.to_string().contains("no reasons"), "{error}");
    }

    #[test]
    fn the_valid_name_and_reason_lists_match_scorecard() {
        // Both lists are transcribed from the Scorecard source; if Scorecard
        // adds a check or a reason, this list needs the same change.
        assert_eq!(VALID_CHECKS.len(), 20);
        assert_eq!(VALID_REASONS.len(), 5);
        assert!(VALID_CHECKS.contains(&"CII-Best-Practices"));
        assert!(VALID_REASONS.contains(&"not-applicable"));
    }
}