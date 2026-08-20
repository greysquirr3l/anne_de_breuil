//! [`redact`]: strips secret-shaped substrings out of raw text once, at the
//! view-model boundary, before any report format can see them.
//!
//! `Win32_Process` `CommandLine` routinely carries service-account passwords,
//! connection strings, and bearer tokens. A recon report that faithfully
//! reproduces that text is a credential-harvesting artifact, so this module
//! exists to make reproducing it structurally impossible: [`redact`] never
//! returns the matched substring, only a [`Redacted`] marker that records
//! what kind of secret was found and where — never the secret itself.
//!
//! # Multiple matches, not just the first
//!
//! Every pattern is applied with `find_iter`, not `find` — a single command
//! line can legitimately carry two distinct secrets of the same shape (two
//! `password=` assignments in one `net use` chain, for instance), and
//! redacting only the first occurrence per category would leave the second
//! to leak straight through.
//!
//! # Overlap resolution is priority-ordered, not position-ordered
//!
//! [`SECRET_PATTERNS`] is declared most-specific first. A connection-string
//! password (`Password=hunter2;`) also satisfies the generic
//! `password=`/`pwd:` shape; the specific pattern claims that span first, so
//! the marker records [`SecretCategory::ConnectionStringPassword`] rather
//! than the less informative [`SecretCategory::PasswordAssignment`]. Once a
//! span is claimed, no lower-priority pattern may claim any overlapping
//! span.

use std::fmt::Write as _;
use std::sync::LazyLock;

use regex::Regex;

/// The class of secret shape a [`Redacted`] marker stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum SecretCategory {
    /// A bare `password=`/`pwd:` assignment.
    PasswordAssignment,
    /// A `Key=Value;`-style connection-string password field.
    ConnectionStringPassword,
    /// An HTTP `Authorization: Bearer <token>` value.
    BearerToken,
    /// A PEM-encoded key or certificate block header.
    PemBlock,
    /// An AWS-style access key id (`AKIA...`).
    AwsKeyId,
    /// A long, high-entropy base64-shaped token with no more specific match.
    HighEntropyToken,
}

/// A marker recording that a secret was found and removed.
///
/// `inner` is never `Some` outside this module: [`redact`] is the only
/// constructor, it always sets `inner: None`, and the field is private, so
/// there is no way for a caller anywhere else in the crate to construct a
/// `Redacted` that still carries the raw value. The type itself, not
/// convention, is what guarantees the secret never survives.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Redacted<T> {
    inner: Option<T>,
    /// What kind of secret this marker stands for.
    pub category: SecretCategory,
    /// The byte offset into the original input where the match started.
    pub offset: usize,
}

/// Compile-time-fixed secret-shape patterns, most-specific first.
///
/// A pattern that fails to compile is dropped rather than panicking this
/// crate never panics outside `#[cfg(test)]`; a dropped pattern is caught
/// immediately by
/// [`tests::every_declared_pattern_compiles`].
const RAW_PATTERNS: &[(&str, SecretCategory)] = &[
    (r"-----BEGIN [A-Z ]+-----", SecretCategory::PemBlock),
    (r"AKIA[0-9A-Z]{16}", SecretCategory::AwsKeyId),
    (
        r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",
        SecretCategory::BearerToken,
    ),
    (
        r"(?i)password\s*=\s*[^;\s]+;",
        SecretCategory::ConnectionStringPassword,
    ),
    (
        r"(?i)\bpassword\s*=\s*\S+",
        SecretCategory::PasswordAssignment,
    ),
    (
        r"(?i)\bpwd\s*[:=]\s*\S+",
        SecretCategory::PasswordAssignment,
    ),
    (
        r"[A-Za-z0-9+/]{40,}={0,2}",
        SecretCategory::HighEntropyToken,
    ),
];

static SECRET_PATTERNS: LazyLock<Vec<(Regex, SecretCategory)>> = LazyLock::new(|| {
    RAW_PATTERNS
        .iter()
        .filter_map(|(pattern, category)| Regex::new(pattern).ok().map(|regex| (regex, *category)))
        .collect()
});

/// Applied once at the view-model boundary — no report format ever sees the
/// unredacted value.
///
/// Returns the input with every matched span replaced by
/// `[REDACTED:<category>]`, alongside one [`Redacted`] marker per
/// replacement, sorted by ascending offset. Pure: no I/O, no shared mutable
/// state beyond the one-time pattern compilation.
#[must_use]
pub fn redact(input: &str) -> (String, Vec<Redacted<String>>) {
    let mut claimed: Vec<(usize, usize, SecretCategory)> = Vec::new();

    for (pattern, category) in SECRET_PATTERNS.iter() {
        for candidate in pattern.find_iter(input) {
            let (start, end) = (candidate.start(), candidate.end());
            let overlaps_claimed = claimed.iter().any(|&(claimed_start, claimed_end, _)| {
                ranges_overlap(start, end, claimed_start, claimed_end)
            });
            if overlaps_claimed {
                continue;
            }
            claimed.push((start, end, *category));
        }
    }
    claimed.sort_by_key(|&(start, _, _)| start);

    let mut output = String::with_capacity(input.len());
    let mut markers = Vec::with_capacity(claimed.len());
    let mut cursor = 0usize;
    for (start, end, category) in claimed {
        output.push_str(slice(input, cursor, start));
        markers.push(Redacted {
            inner: None,
            category,
            offset: start,
        });
        // Writing into a `String` via `fmt::Write` cannot fail; discard the
        // `Result` explicitly rather than `.expect()` it away.
        let _: core::fmt::Result = write!(output, "[REDACTED:{category:?}]");
        cursor = end;
    }
    output.push_str(slice(input, cursor, input.len()));

    (output, markers)
}

const fn ranges_overlap(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start < b_end && b_start < a_end
}

/// Never-panicking byte-range slice: `start`/`end` are always derived from
/// regex match boundaries or prior slice endpoints, so this always
/// succeeds, but the crate's no-panicking-index rule still applies.
fn slice(input: &str, start: usize, end: usize) -> &str {
    input.get(start..end).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{Redacted, SecretCategory, redact};

    #[test]
    fn every_declared_pattern_compiles() {
        assert_eq!(
            super::SECRET_PATTERNS.len(),
            super::RAW_PATTERNS.len(),
            "a declared pattern failed to compile and was silently dropped"
        );
    }

    #[test]
    fn redacts_six_distinct_secret_shapes() {
        let cases = [
            (
                r"net use \\svc /user:admin password=hunter2",
                SecretCategory::PasswordAssignment,
            ),
            (
                "Server=db;User Id=sa;Password=hunter2;",
                SecretCategory::ConnectionStringPassword,
            ),
            (
                "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc",
                SecretCategory::BearerToken,
            ),
            (
                "-----BEGIN PRIVATE KEY-----\nMIIExy...",
                SecretCategory::PemBlock,
            ),
            ("AKIAABCDEFGHIJKLMNOP", SecretCategory::AwsKeyId),
            (&"x".repeat(48), SecretCategory::HighEntropyToken),
        ];
        for (input, expected_category) in cases {
            let (redacted, markers) = redact(input);
            assert!(
                !redacted.contains("hunter2")
                    || expected_category != SecretCategory::PasswordAssignment
            );
            assert!(
                !redacted.contains("hunter2")
                    || expected_category != SecretCategory::ConnectionStringPassword
            );
            assert_eq!(
                markers.first().map(|marker| marker.category),
                Some(expected_category)
            );
        }
    }

    #[test]
    fn all_matches_of_all_patterns_are_redacted_not_just_the_first() {
        let input = "password=first;; password=second";
        let (redacted, markers) = redact(input);
        assert!(!redacted.contains("first"));
        assert!(!redacted.contains("second"));
        assert_eq!(markers.len(), 2);
    }

    #[test]
    fn more_specific_pattern_wins_over_a_generic_overlapping_one() {
        let (_, markers) = redact("Password=hunter2;");
        assert_eq!(
            markers.first().map(|marker| marker.category),
            Some(SecretCategory::ConnectionStringPassword)
        );
        assert_eq!(markers.len(), 1);
    }

    #[test]
    fn raw_value_never_survives_in_the_marker_or_its_debug_output() {
        let (_, markers) = redact("password=hunter2");
        let debug_output = format!("{markers:?}");
        assert!(!debug_output.contains("hunter2"));
    }

    #[test]
    fn text_with_no_secret_shape_is_returned_unchanged() {
        let (redacted, markers) = redact("nothing to see here");
        assert_eq!(redacted, "nothing to see here");
        assert!(markers.is_empty());
    }

    #[test]
    fn redacted_marker_offset_points_at_the_match_in_the_original_input() {
        let input = "prefix password=hunter2";
        let (_, markers) = redact(input);
        let marker: &Redacted<String> = markers.first().expect("one match");
        assert_eq!(
            marker.offset,
            input.find("password").expect("literal present")
        );
    }
}
