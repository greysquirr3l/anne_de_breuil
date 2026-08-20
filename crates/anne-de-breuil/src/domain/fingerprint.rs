//! [`fingerprint`]: turns collected [`Evidence`] into named [`ServiceIdentity`] values.
//!
//! Pure function, no I/O. The only thing resembling I/O anywhere in this
//! module is [`CATALOGUE`]'s one-time [`LazyLock`] initialisation, which
//! parses a compile-time-embedded (`include_str!`) TOML asset — not a
//! runtime read.
//!
//! # The catalogue is data
//!
//! `assets/fingerprints.toml` is DATA, not code. Adding a fingerprint —
//! including naming a specific Prometheus exporter from its metric
//! namespace prefix and extracting its version from a `..._build_info{...}`
//! line — is a matter of adding a `[[fingerprint]]` table, never a Rust
//! change. See that file's own header comment for the schema.
//!
//! This is a deliberate departure from a hardcoded `PREFIXES` lookup table:
//! `body_prefix` (a literal per-line prefix test) plus `version_capture` (a
//! regex capture applied only to the evidence that already matched) are
//! generic enough to express the "resolve namespace prefix to specific
//! exporter, extract version from `build_info`" worked example entirely as
//! catalogue entries — see `node_exporter`/`windows_exporter`/etc. in the
//! TOML. A new exporter family needs a new table, not a new Rust match arm.
//!
//! # Regex safety
//!
//! Every pattern is compiled once, via [`LazyLock`], using the `regex`
//! crate — a finite-automaton engine with no backtracking, so a pattern
//! applied against a hostile 64 KiB response body cannot exhibit
//! catastrophic-backtracking behaviour, structurally, regardless of how the
//! pattern is written. [`check_complexity`] does not add `DoS` protection the
//! engine doesn't already provide; it enforces authoring hygiene — a length
//! bound and a check against the "nested unbounded quantifier" shape
//! (`(x*)+`) that is the classic *backtracking* engine's catastrophic case
//! — so a catalogue contributor gets fast, load-time feedback that a
//! pattern looks suspicious, not a false sense that this check is the
//! reason the scanner is safe from an adversarial body.
//!
//! A catalogue entry that fails to compile or fails the complexity check is
//! dropped from the compiled catalogue rather than panicking the process —
//! this crate never panics outside `#[cfg(test)]`. In this crate's own CI,
//! [`tests::every_catalogue_pattern_compiles_and_passes_complexity_check`]
//! independently parses the raw TOML and asserts the compiled catalogue's
//! length matches, so a silently dropped entry fails a test loudly instead.

use std::sync::LazyLock;

use regex::Regex;

use crate::domain::confidence::Confidence;
use crate::domain::evidence::Evidence;
use crate::domain::service_category::ServiceCategory;
use crate::domain::service_identity::ServiceIdentity;

const RAW_CATALOGUE: &str = include_str!("../../assets/fingerprints.toml");

/// A pattern longer than this is rejected at load — bounds regex
/// compilation cost and keeps every catalogue entry legible for review.
const MAX_PATTERN_LEN: usize = 256;

#[derive(serde::Deserialize)]
struct FingerprintCatalogueRaw {
    fingerprint: Vec<FingerprintEntryRaw>,
}

#[derive(serde::Deserialize)]
struct FingerprintEntryRaw {
    name: String,
    category: ServiceCategory,
    confidence: Confidence,
    matchers: MatchersRaw,
}

#[derive(serde::Deserialize)]
struct MatchersRaw {
    http_header: Option<HeaderMatcherRaw>,
    body_prefix: Option<String>,
    body_pattern: Option<String>,
    tls_subject_pattern: Option<String>,
    banner_pattern: Option<String>,
    alpn: Option<Vec<String>>,
    version_capture: Option<String>,
}

#[derive(serde::Deserialize)]
struct HeaderMatcherRaw {
    name: String,
    pattern: String,
}

/// Failure compiling one catalogue entry. Never surfaced to a caller of
/// [`fingerprint`] — an entry that fails to compile is dropped from
/// [`CATALOGUE`], not propagated as a runtime error.
#[derive(Debug, thiserror::Error)]
enum CatalogueError {
    #[error("pattern exceeds {MAX_PATTERN_LEN} bytes ({len} bytes): {pattern:?}")]
    PatternTooLong { pattern: String, len: usize },
    #[error("pattern contains a nested unbounded quantifier: {pattern:?}")]
    NestedUnboundedQuantifier { pattern: String },
    #[error("invalid regex pattern {pattern:?}: {source}")]
    InvalidRegex {
        pattern: String,
        #[source]
        source: regex::Error,
    },
    #[error("fingerprint entry {name:?} defines no matcher")]
    NoMatchers { name: String },
}

/// Authoring-hygiene check, not a defense the `regex` crate doesn't already
/// provide structurally — see this module's own doc comment.
fn check_complexity(pattern: &str) -> Result<(), CatalogueError> {
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(CatalogueError::PatternTooLong {
            pattern: pattern.to_owned(),
            len: pattern.len(),
        });
    }
    if has_nested_unbounded_quantifier(pattern) {
        return Err(CatalogueError::NestedUnboundedQuantifier {
            pattern: pattern.to_owned(),
        });
    }
    Ok(())
}

/// `true` if `pattern` contains a group that itself carries a quantifier
/// (`*`, `+`, `?`, or `{...}`) and is followed immediately by another
/// quantifier — the `(x*)+` shape that is the canonical catastrophic case
/// for a *backtracking* regex engine.
///
/// A character-level heuristic, not a real parse: it does not understand
/// character classes (`[...]`), so a pattern with a literal quantifier
/// character inside `[...]` could in principle be misread. None of this
/// catalogue's patterns do that; see the module doc comment for what this
/// check is actually for.
fn has_nested_unbounded_quantifier(pattern: &str) -> bool {
    let mut group_has_quantifier: Vec<bool> = Vec::new();
    let mut chars = pattern.chars().peekable();
    let mut just_opened_group = false;

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            chars.next();
            just_opened_group = false;
            continue;
        }
        let was_just_opened = just_opened_group;
        just_opened_group = false;

        match ch {
            '(' => {
                group_has_quantifier.push(false);
                just_opened_group = true;
            }
            ')' => {
                let had_quantifier = group_has_quantifier.pop().unwrap_or(false);
                let next_is_quantifier = chars
                    .peek()
                    .is_some_and(|next| matches!(next, '*' | '+' | '?' | '{'));
                if had_quantifier && next_is_quantifier {
                    return true;
                }
            }
            '*' | '+' | '{' => mark_quantifier(&mut group_has_quantifier),
            // `(?:`, `(?i)`, `(?P<name>...)` etc. — a group-modifier prefix
            // immediately after `(`, not a quantifier on prior content.
            '?' if !was_just_opened => mark_quantifier(&mut group_has_quantifier),
            _ => {}
        }
    }
    false
}

const fn mark_quantifier(stack: &mut [bool]) {
    if let Some(top) = stack.last_mut() {
        *top = true;
    }
}

fn compile_pattern(pattern: &str) -> Result<Regex, CatalogueError> {
    check_complexity(pattern)?;
    Regex::new(pattern).map_err(|source| CatalogueError::InvalidRegex {
        pattern: pattern.to_owned(),
        source,
    })
}

#[derive(Debug)]
struct CompiledFingerprint {
    name: String,
    category: ServiceCategory,
    confidence: Confidence,
    http_header: Option<(String, Regex)>,
    body_prefix: Option<String>,
    body_pattern: Option<Regex>,
    tls_subject_pattern: Option<Regex>,
    banner_pattern: Option<Regex>,
    alpn: Option<Vec<String>>,
    version_capture: Option<Regex>,
}

impl CompiledFingerprint {
    fn compile(entry: FingerprintEntryRaw) -> Result<Self, CatalogueError> {
        let FingerprintEntryRaw {
            name,
            category,
            confidence,
            matchers,
        } = entry;

        let http_header = matchers
            .http_header
            .map(|header| -> Result<(String, Regex), CatalogueError> {
                Ok((header.name.to_ascii_lowercase(), compile_pattern(&header.pattern)?))
            })
            .transpose()?;
        let body_pattern = matchers.body_pattern.as_deref().map(compile_pattern).transpose()?;
        let tls_subject_pattern = matchers
            .tls_subject_pattern
            .as_deref()
            .map(compile_pattern)
            .transpose()?;
        let banner_pattern = matchers.banner_pattern.as_deref().map(compile_pattern).transpose()?;
        let version_capture = matchers.version_capture.as_deref().map(compile_pattern).transpose()?;
        let body_prefix = matchers.body_prefix;
        let alpn = matchers.alpn;

        if http_header.is_none()
            && body_prefix.is_none()
            && body_pattern.is_none()
            && tls_subject_pattern.is_none()
            && banner_pattern.is_none()
            && alpn.is_none()
        {
            return Err(CatalogueError::NoMatchers { name });
        }

        Ok(Self {
            name,
            category,
            confidence,
            http_header,
            body_prefix,
            body_pattern,
            tls_subject_pattern,
            banner_pattern,
            alpn,
            version_capture,
        })
    }

    /// Tries to match this entry against `evidence`, returning a
    /// [`ServiceIdentity`] backed by whichever entries matched.
    ///
    /// Matchers are independent, corroborating signals: any one of the
    /// matchers this entry defines finding a hit is sufficient — they are
    /// not a required-all checklist. [`Self::version_capture`], when
    /// present, is searched only within the evidence that already matched
    /// this entry, never across the full unrelated evidence set, so it
    /// cannot pick up a version-shaped substring from an unrelated header.
    fn try_match(&self, evidence: &[Evidence]) -> Option<ServiceIdentity> {
        let mut matched: Vec<Evidence> = Vec::new();

        if let Some((header_name, pattern)) = &self.http_header {
            for item in evidence {
                if let Evidence::HttpHeader { name, value } = item
                    && name.eq_ignore_ascii_case(header_name)
                    && pattern.is_match(value)
                {
                    push_unique(&mut matched, item.clone());
                }
            }
        }

        if let Some(prefix) = &self.body_prefix {
            for item in evidence {
                if let Evidence::HttpBodyPattern { snippet } = item
                    && body_has_prefixed_line(snippet, prefix)
                {
                    push_unique(&mut matched, item.clone());
                }
            }
        }

        if let Some(pattern) = &self.body_pattern {
            for item in evidence {
                if let Evidence::HttpBodyPattern { snippet } = item
                    && pattern.is_match(snippet)
                {
                    push_unique(&mut matched, item.clone());
                }
            }
        }

        if let Some(pattern) = &self.tls_subject_pattern {
            for item in evidence {
                if let Evidence::TlsCertificateSubject { subject } = item
                    && pattern.is_match(subject)
                {
                    push_unique(&mut matched, item.clone());
                }
            }
        }

        if let Some(pattern) = &self.banner_pattern {
            for item in evidence {
                if let Evidence::BannerMatch { pattern: banner } = item
                    && pattern.is_match(banner)
                {
                    push_unique(&mut matched, item.clone());
                }
            }
        }

        if let Some(protocols) = &self.alpn {
            for item in evidence {
                if let Evidence::AlpnProtocol { protocol } = item
                    && protocols.iter().any(|candidate| candidate.eq_ignore_ascii_case(protocol))
                {
                    push_unique(&mut matched, item.clone());
                }
            }
        }

        if matched.is_empty() {
            return None;
        }

        let version = self
            .version_capture
            .as_ref()
            .and_then(|pattern| extract_version(pattern, &matched));

        let identity = ServiceIdentity::new(self.name.clone(), self.category, self.confidence, matched).ok()?;
        Some(match version {
            Some(v) => identity.with_version(v),
            None => identity,
        })
    }
}

fn push_unique(matched: &mut Vec<Evidence>, item: Evidence) {
    if !matched.contains(&item) {
        matched.push(item);
    }
}

/// `true` if any line of `body` starts with `prefix` — used for
/// [`MatchersRaw::body_prefix`], deliberately a literal substring test
/// rather than a regex, so it is unbounded-cost by construction.
fn body_has_prefixed_line(body: &str, prefix: &str) -> bool {
    body.lines().any(|line| line.starts_with(prefix))
}

/// Runs `pattern` against every text-bearing entry in `evidence`, returning
/// the first capture-group match found.
fn extract_version(pattern: &Regex, evidence: &[Evidence]) -> Option<String> {
    for item in evidence {
        let text: &str = match item {
            Evidence::HttpHeader { value, .. } => value,
            Evidence::HttpBodyPattern { snippet } => snippet,
            Evidence::BannerMatch { pattern: banner } => banner,
            Evidence::TlsCertificateSubject { subject } => subject,
            Evidence::AlpnProtocol { .. } | Evidence::PortAssignment { .. } | Evidence::ProcessName { .. } => {
                continue;
            }
        };
        if let Some(captures) = pattern.captures(text)
            && let Some(group) = captures.get(1)
        {
            return Some(group.as_str().to_owned());
        }
    }
    None
}

static CATALOGUE: LazyLock<Vec<CompiledFingerprint>> = LazyLock::new(build_catalogue);

/// Parses [`RAW_CATALOGUE`] and compiles every entry, dropping — never
/// panicking on — an entry that fails to parse, compile, or pass the
/// complexity check. A malformed shipped catalogue degrades to fingerprint
/// coverage gaps, not a crashed scanner; see this module's doc comment for
/// how CI still catches a dropped entry loudly.
fn build_catalogue() -> Vec<CompiledFingerprint> {
    let parsed: FingerprintCatalogueRaw =
        toml::from_str(RAW_CATALOGUE).unwrap_or_else(|_err| FingerprintCatalogueRaw { fingerprint: Vec::new() });
    parsed
        .fingerprint
        .into_iter()
        .filter_map(|entry| CompiledFingerprint::compile(entry).ok())
        .collect()
}

/// Identifies services from collected evidence via the compiled-in
/// catalogue.
///
/// Pure: no I/O, fully testable from fixtures. See this module's doc
/// comment for how the catalogue is loaded and why that doesn't count as
/// I/O inside this function.
#[must_use]
pub fn fingerprint(evidence: &[Evidence]) -> Vec<ServiceIdentity> {
    CATALOGUE.iter().filter_map(|entry| entry.try_match(evidence)).collect()
}

#[cfg(test)]
mod tests {
    use super::{CatalogueError, FingerprintCatalogueRaw, RAW_CATALOGUE, fingerprint, has_nested_unbounded_quantifier};
    use crate::domain::Evidence;

    mod fixtures {
        use crate::domain::Evidence;

        pub(super) fn node_exporter_body() -> &'static str {
            include_str!("../../fixtures/metrics/node_exporter.txt")
        }

        pub(super) fn windows_exporter_body() -> &'static str {
            include_str!("../../fixtures/metrics/windows_exporter.txt")
        }

        pub(super) fn bare_prometheus_healthy_body() -> &'static str {
            include_str!("../../fixtures/metrics/bare_prometheus_healthy.txt")
        }

        pub(super) fn grafana_body() -> &'static str {
            r"<!DOCTYPE html><html><head><title>Grafana</title></head><body>
            <script>window.grafanaBootData = {};</script></body></html>"
        }

        pub(super) fn evidence_from_body(body: &str) -> Vec<Evidence> {
            vec![Evidence::HttpBodyPattern { snippet: body.to_owned() }]
        }

        /// `_port` is accepted, not used: [`Evidence`] carries no port
        /// field at all, so fingerprinting from evidence is port-oblivious
        /// by construction — this helper's whole purpose is to prove that,
        /// not to vary behaviour by port.
        pub(super) fn evidence_from_body_on_port(body: &str, _port: u16) -> Vec<Evidence> {
            evidence_from_body(body)
        }

        pub(super) fn evidence_with_healthy_endpoint() -> Vec<Evidence> {
            evidence_from_body(bare_prometheus_healthy_body())
        }
    }

    #[test]
    fn node_exporter_body_names_the_specific_exporter() {
        let evidence = fixtures::evidence_from_body(fixtures::node_exporter_body());

        let identities = fingerprint(&evidence);

        let node = identities
            .iter()
            .find(|identity| identity.name() == "node_exporter")
            .expect("node_exporter fixture body must be identified as node_exporter specifically");
        assert_eq!(node.version(), Some("1.8.2"));
    }

    #[test]
    fn windows_exporter_body_names_the_specific_exporter_and_not_node_exporter() {
        let evidence = fixtures::evidence_from_body(fixtures::windows_exporter_body());

        let identities = fingerprint(&evidence);

        let windows = identities
            .iter()
            .find(|identity| identity.name() == "windows_exporter")
            .expect("windows_exporter fixture body must be identified as windows_exporter specifically");
        assert_eq!(windows.version(), Some("0.25.1"));
        assert!(!identities.iter().any(|identity| identity.name() == "node_exporter"));
    }

    #[test]
    fn bare_prometheus_server_distinguished_via_healthy_endpoint() {
        let evidence = fixtures::evidence_with_healthy_endpoint();

        let identities = fingerprint(&evidence);

        assert!(identities.iter().any(|identity| identity.name() == "prometheus"));
        assert!(!identities.iter().any(|identity| identity.name() == "node_exporter"));
    }

    #[test]
    fn exporter_on_nonstandard_port_identified_same_as_9100() {
        let evidence_9100 = fixtures::evidence_from_body_on_port(fixtures::node_exporter_body(), 9100);
        let evidence_41337 = fixtures::evidence_from_body_on_port(fixtures::node_exporter_body(), 41_337);

        let identities_9100 = fingerprint(&evidence_9100);
        let identities_41337 = fingerprint(&evidence_41337);

        assert_eq!(identities_9100[0].name(), "node_exporter");
        assert_eq!(identities_9100[0].name(), identities_41337[0].name());
    }

    #[test]
    fn every_catalogue_pattern_compiles_and_passes_complexity_check() {
        // Forces `CATALOGUE`'s `LazyLock` to evaluate.
        assert!(!super::CATALOGUE.is_empty());

        // A dropped entry (parse/compile/complexity failure) never panics
        // in production — see `build_catalogue`'s doc comment — so this
        // independently parses the raw TOML and asserts nothing was
        // silently dropped, which is how this test earns its name.
        let raw: FingerprintCatalogueRaw =
            toml::from_str(RAW_CATALOGUE).expect("shipped catalogue TOML must parse");
        assert_eq!(
            super::CATALOGUE.len(),
            raw.fingerprint.len(),
            "a catalogue entry failed to compile or failed the complexity check and was silently dropped"
        );
    }

    #[test]
    fn conflicting_local_and_remote_identities_both_retained() {
        use crate::domain::attribution::Attribution;
        use crate::domain::ids::ProcessId;
        use crate::domain::process::ProcessPath;
        use crate::domain::publisher::SignatureStatus;
        use crate::domain::reconciliation::reconcile;

        let local = Attribution::authoritative(
            ProcessId::try_from(1234).expect("nonzero pid"),
            ProcessPath::try_from("nginx.exe".to_owned()).expect("non-empty path"),
            None,
            SignatureStatus::Unknown,
        );
        let remote = fingerprint(&fixtures::evidence_from_body(fixtures::grafana_body()));

        let report = reconcile(local, remote);

        assert!(report.local_identity.is_some());
        assert!(report.remote_identity.is_some());
    }

    #[test]
    fn nested_unbounded_quantifier_is_rejected_by_the_complexity_heuristic() {
        assert!(has_nested_unbounded_quantifier("(a*)+"));
        assert!(has_nested_unbounded_quantifier("(a+)*"));
        assert!(!has_nested_unbounded_quantifier("(?:Yes|No)"));
        assert!(!has_nested_unbounded_quantifier("node_exporter_build_info\\{[^}]*version=\"([0-9.]+)\""));
    }

    #[test]
    fn overlong_pattern_is_rejected() {
        let overlong = "a".repeat(super::MAX_PATTERN_LEN + 1);
        let err = super::compile_pattern(&overlong).expect_err("overlong pattern must be rejected");
        assert!(matches!(err, CatalogueError::PatternTooLong { .. }));
    }

    #[test]
    fn entry_with_no_matchers_is_rejected() {
        let raw = r#"
            [[fingerprint]]
            name = "nothing"
            category = "Other"
            confidence = "Heuristic"
            [fingerprint.matchers]
        "#;
        let parsed: FingerprintCatalogueRaw = toml::from_str(raw).expect("valid TOML shape");
        let entry = parsed.fingerprint.into_iter().next().expect("one entry");
        let err = super::CompiledFingerprint::compile(entry).expect_err("matcher-less entry must be rejected");
        assert!(matches!(err, CatalogueError::NoMatchers { .. }));
    }

    #[test]
    fn version_capture_never_reads_evidence_outside_the_match() {
        // A header carrying a version-shaped value must not leak into an
        // entry whose own matcher never fired against it.
        let evidence = vec![
            Evidence::HttpHeader { name: "content-length".to_owned(), value: "1234".to_owned() },
            Evidence::HttpBodyPattern { snippet: "Prometheus Server is Healthy.\n".to_owned() },
        ];

        let identities = fingerprint(&evidence);

        let prometheus = identities
            .iter()
            .find(|identity| identity.name() == "prometheus")
            .expect("healthy body must match prometheus");
        assert_eq!(prometheus.version(), None);
    }
}
