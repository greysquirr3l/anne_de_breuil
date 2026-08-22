//! JSON payload shape written by `assets/collect.ps1` (schema v2), and
//! the pure, platform-independent parse from bytes into T04's `Raw*`
//! DTOs.
//!
//! Nothing here spawns a process or touches the filesystem — every
//! function operates on an in-memory byte slice, so it runs (and is
//! tested) identically on any host, including this one.
//!
//! ## Schema versioning
//!
//! The script emits `schema_name = "windows-listening-surface"` and
//! `schema_version = 2`. Unknown versions are rejected outright at the
//! parse boundary so a future v3 payload can never silently coerce
//! through a v2 parser (a real risk: any new mandatory field the v3
//! script adds would deserialize as zero/empty without the v2 parser
//! noticing, then propagate as a misleading "clean" collection).

use std::collections::BTreeMap;

use crate::application::collect::{
    CollectError, RawEndpoint, RawProcess, RawProfile, RawRule, RawService,
};

/// The only schema version this parser understands. Bumping it is a
/// deliberate, coordinated change — the parser and the script both move
/// together.
const SUPPORTED_SCHEMA_VERSION: u32 = 2;

/// The canonical schema name. The parser rejects any other name with
/// `CollectError::Parse`, not a silent coercion.
const SUPPORTED_SCHEMA_NAME: &str = "windows-listening-surface";

/// Fidelity the helper script could actually collect at, recorded from
/// `$ExecutionContext.SessionState.LanguageMode`.
///
/// A locked-down host (WDAC/AppLocker) runs the script in
/// [`Self::Constrained`] — cmdlets still work, but modules the policy
/// hasn't allowlisted (commonly `NetSecurity`) can silently return nothing
/// rather than erroring, which is why a caller needs this recorded
/// alongside the data rather than inferring it from empty collections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
pub enum LanguageMode {
    /// No restrictions: every cmdlet and filter the script uses ran.
    #[serde(rename = "FullLanguage")]
    #[default]
    Full,
    /// WDAC/AppLocker-restricted: type accelerators, `New-Object`, and
    /// static .NET method calls are blocked (this script never uses any
    /// of them), but an unallowlisted module can still make a whole
    /// section come back empty.
    #[serde(rename = "ConstrainedLanguage")]
    Constrained,
    /// Only a small allowlist of cmdlets can run at all.
    #[serde(rename = "RestrictedLanguage")]
    Restricted,
    /// No script code permitted; effectively unreachable for a script
    /// that ran far enough to emit a payload, kept for completeness.
    #[serde(rename = "NoLanguage")]
    NoLanguage,
}

/// One service the helper script observed, still paired with the pid
/// `Win32_Service.ProcessId` reported for it.
///
/// [`crate::domain`]'s [`RawService`] carries no process id — grouping by
/// owning process is the collector's job, not the DTO's — so this pairing
/// lives only inside the adapter, stripped away once
/// [`super::PowerShellCollector::hosted_services`] has used it to filter.
#[derive(Debug, Clone)]
pub(super) struct HostedService {
    pub(super) process_id: u32,
    pub(super) service: RawService,
}

/// One fully parsed collection payload, already mapped into T04's `Raw*`
/// DTOs (or the adapter-local [`HostedService`] pairing, for services).
///
/// The richer v2 envelope (`Metadata`, `CollectionStatus`, `Diagnostics`,
/// `ListeningSurface`) is read and validated by the parser but its fields
/// are not propagated here — they're diagnostic/audit data, not inputs to
/// the four T04 ports the adapter implements. A future report-assembly
/// task is the right home for that data.
#[derive(Debug, Clone)]
pub(super) struct PowerShellPayload {
    pub(super) language_mode: LanguageMode,
    pub(super) tcp_endpoints: Vec<RawEndpoint>,
    pub(super) udp_endpoints: Vec<RawEndpoint>,
    pub(super) processes: Vec<RawProcess>,
    pub(super) services: Vec<HostedService>,
    pub(super) firewall_rules: Vec<RawRule>,
    pub(super) firewall_profiles: Vec<RawProfile>,
}

/// Top-level v2 envelope. Every section is `#[serde(default)]` so a
/// partial payload (e.g. CLM where the firewall section came back empty)
/// parses without per-field optionals — a real, common outcome on
/// hardened hosts.
#[derive(Debug, Clone, serde::Deserialize)]
struct PsPayload {
    #[serde(rename = "schema_name")]
    schema_name: String,
    #[serde(rename = "schema_version")]
    schema_version: u32,
    #[serde(default, rename = "metadata")]
    metadata: Option<PsMetadata>,
    #[serde(default, rename = "collection_status")]
    #[expect(
        dead_code,
        reason = "parsed for schema completeness; no report format (JSON, CSV, SARIF, or HTML) \
                  currently surfaces per-section collection diagnostics — a standing gap, not a \
                  scheduled follow-up"
    )]
    collection_status: BTreeMap<String, PsSectionStatus>,
    #[serde(default, rename = "diagnostics")]
    #[expect(
        dead_code,
        reason = "parsed for schema completeness; no report format (JSON, CSV, SARIF, or HTML) \
                  currently surfaces per-section collection diagnostics — a standing gap, not a \
                  scheduled follow-up"
    )]
    diagnostics: Vec<PsDiagnostic>,
    #[serde(default, rename = "listening_surface")]
    #[expect(
        dead_code,
        reason = "script's pre-join is ignored; the adapter reconstructs the same join from raw sections"
    )]
    listening_surface: Vec<PsListeningSurfaceEntry>,
    #[serde(default, rename = "tcp_endpoints")]
    tcp_endpoints: Vec<PsSocketEndpoint>,
    #[serde(default, rename = "udp_endpoints")]
    udp_endpoints: Vec<PsSocketEndpoint>,
    #[serde(default, rename = "processes")]
    processes: Vec<PsProcess>,
    #[serde(default, rename = "services")]
    services: Vec<PsService>,
    #[serde(default, rename = "firewall_rules")]
    firewall_rules: Vec<PsFirewallRule>,
    #[serde(default, rename = "firewall_profiles")]
    firewall_profiles: Vec<RawProfile>,
}

/// Host-level metadata the script records once at the top of every
/// payload — language mode, OS, host name, and the redaction-audit
/// booleans (`command_lines_included`, `executable_paths_included`,
/// `service_paths_included`, `disabled_firewall_rules_included`) that
/// prove which opt-in switches were set.
#[derive(Debug, Clone, serde::Deserialize, Default)]
struct PsMetadata {
    #[serde(default, rename = "language_mode")]
    language_mode: LanguageMode,
    #[serde(default, rename = "power_shell_version")]
    #[expect(dead_code, reason = "recorded by the script; no consumer needs it yet")]
    power_shell_version: String,
}

/// One per-section status entry: `success` (with a non-zero count) or
/// `failed` (count = 0, error captured separately in [`PsDiagnostic`]).
#[derive(Debug, Clone, serde::Deserialize)]
struct PsSectionStatus {
    #[serde(rename = "status")]
    #[expect(
        dead_code,
        reason = "parsed for schema completeness; no report format currently surfaces \
                  per-section collection status — a standing gap, not a scheduled follow-up"
    )]
    status: String,
    #[serde(rename = "count")]
    #[expect(
        dead_code,
        reason = "status string is the load-bearing field; count kept for future audit UI"
    )]
    count: u64,
}

/// One structured diagnostic — the same shape the script writes for
/// per-section failures and the final-catch fatal error.
#[derive(Debug, Clone, serde::Deserialize)]
#[expect(
    dead_code,
    reason = "parsed for schema completeness; no report format currently surfaces per-section \
              collection diagnostics — a standing gap, not a scheduled follow-up"
)]
struct PsDiagnostic {
    #[serde(rename = "section")]
    section: String,
    #[serde(rename = "severity")]
    severity: String,
    #[serde(rename = "message")]
    message: String,
}

/// One pre-joined listening-surface entry the script emits as a
/// convenience for downstream readers that don't want to redo the
/// endpoint→process→service join. The adapter ignores it (it builds
/// its own join from the raw sections); this deserializer exists purely
/// so a v2 payload can be deserialized without extra-fields being a
/// problem.
#[derive(Debug, Clone, serde::Deserialize)]
#[expect(
    dead_code,
    reason = "script's pre-join is ignored; the adapter reconstructs the same join from raw sections"
)]
struct PsListeningSurfaceEntry {
    #[serde(rename = "transport")]
    transport: String,
    #[serde(rename = "local_address")]
    local_address: String,
    #[serde(rename = "local_port")]
    local_port: u16,
    #[serde(rename = "owning_process")]
    owning_process: Option<u32>,
    #[serde(rename = "process_name")]
    process_name: Option<String>,
    #[serde(rename = "hosted_services")]
    hosted_services: Vec<String>,
    #[serde(rename = "owner_resolved")]
    owner_resolved: bool,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct PsSocketEndpoint {
    #[serde(rename = "local_address")]
    local_address: String,
    #[serde(rename = "local_port")]
    local_port: u16,
    #[serde(rename = "owning_process")]
    owning_process: Option<u32>,
}

impl PsSocketEndpoint {
    fn into_raw_endpoint(self, protocol: &str) -> RawEndpoint {
        RawEndpoint {
            protocol: protocol.to_owned(),
            local_address: self.local_address,
            local_port: self.local_port,
            owning_pid: self.owning_process,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct PsProcess {
    #[serde(rename = "process_id")]
    process_id: u32,
    #[serde(rename = "executable_path")]
    executable_path: Option<String>,
    #[serde(rename = "command_line")]
    command_line: Option<String>,
}

impl PsProcess {
    fn into_raw_process(self) -> RawProcess {
        RawProcess {
            pid: self.process_id,
            path: self.executable_path,
            command_line: self.command_line,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct PsService {
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "display_name")]
    display_name: String,
    #[serde(rename = "process_id")]
    process_id: Option<u32>,
    #[serde(default, rename = "path_name")]
    #[expect(
        dead_code,
        reason = "script emits path_name only when -IncludeServicePath is set, but RawService \
                  (this crate's own port DTO) has no path field to carry it into the domain \
                  model, and no CLI/config surface sets include_service_path today either -- \
                  parsed for schema completeness only, never reaches a consumer"
    )]
    path_name: Option<String>,
}

impl PsService {
    fn into_hosted(self) -> HostedService {
        HostedService {
            // `0` is `Win32_Service`'s own "not currently running" value;
            // treating a missing property the same way is the safe
            // default (nothing to attribute this service to) rather than
            // guessing.
            process_id: self.process_id.unwrap_or(0),
            service: RawService {
                name: self.name,
                display_name: self.display_name,
            },
        }
    }
}

/// One firewall rule as the script actually emits it.
///
/// `RawRule` (T04) was written before this script existed, with a
/// speculative shape: a single `local_port_spec: Option<String>` and a
/// required flat `policy_store: String`. The real script -- confirmed
/// against `assets/collect.ps1`'s own rule-object literal -- emits
/// `local_ports` as a JSON array (`Get-NetFirewallPortFilter`'s
/// `LocalPort` property, wrapped in PowerShell's `@()`), and has no flat
/// `policy_store` field at all, only `policy_store_source`/
/// `policy_store_source_type`. Deserializing `RawRule` directly against
/// real script output would fail on the first rule with a missing-field
/// error; `fixtures/powershell/server2019_full_lm.json`'s firewall-rule
/// entries never caught this because that fixture was hand-written to
/// match `RawRule`'s own shape, not the script's -- it never actually
/// came from a real host despite its name. This struct and
/// [`into_raw_rule`](Self::into_raw_rule) are the missing translation
/// step every other section already has (`PsSocketEndpoint`, `PsProcess`,
/// `PsService`).
#[derive(Debug, Clone, serde::Deserialize)]
struct PsFirewallRule {
    #[serde(rename = "rule_id")]
    rule_id: String,
    #[serde(rename = "display_name")]
    display_name: String,
    #[serde(rename = "direction")]
    direction: String,
    #[serde(rename = "action")]
    action: String,
    #[serde(default, rename = "protocol")]
    protocol: Option<String>,
    #[serde(default, rename = "local_ports")]
    local_ports: Vec<String>,
    #[serde(default, rename = "program_filter")]
    program_filter: Option<String>,
    #[serde(default, rename = "service_filter")]
    service_filter: Option<String>,
    #[serde(rename = "enabled")]
    enabled: bool,
    #[serde(default, rename = "policy_store_source_type")]
    policy_store_source_type: Option<String>,
    #[serde(default, rename = "policy_store_source")]
    policy_store_source: Option<String>,
}

impl PsFirewallRule {
    /// Joins `local_ports` into the single spec string `RawRule` carries
    /// (`domain::PortSpec`'s grammar accepts a comma-separated list, so
    /// `["443", "8443"]` becomes `"443,8443"`). `Get-NetFirewallPortFilter`
    /// reports `"Any"` for a rule with no port restriction -- that means
    /// the same thing `RawRule::local_port_spec`'s own doc comment already
    /// defines `None` as ("applies to every port"), so `"Any"` collapses
    /// to `None` rather than becoming a literal, unparseable port spec.
    fn local_port_spec(&self) -> Option<String> {
        let ports: Vec<&str> = self
            .local_ports
            .iter()
            .map(String::as_str)
            .filter(|port| !port.eq_ignore_ascii_case("any") && !port.is_empty())
            .collect();
        (!ports.is_empty()).then(|| ports.join(","))
    }

    /// `policy_store_source_type` (Windows' own enum text, e.g. `"Local"`,
    /// `"Gpo"`, `"Dynamic"`) is what `domain::PolicyStore::from_str`
    /// actually expects and is present on every rule PowerShell's own API
    /// returns; `policy_store_source` (a free-text description) is the
    /// fallback for the rare case a rule reports one but not the other.
    /// `"Local"` if neither is present -- the least surprising default for
    /// a rule this API returned at all.
    fn into_raw_rule(self) -> RawRule {
        let local_port_spec = self.local_port_spec();
        let policy_store = self
            .policy_store_source_type
            .or(self.policy_store_source)
            .unwrap_or_else(|| "Local".to_owned());
        RawRule {
            rule_id: self.rule_id,
            display_name: self.display_name,
            direction: self.direction,
            action: self.action,
            protocol: self.protocol,
            local_port_spec,
            program_filter: self.program_filter,
            service_filter: self.service_filter,
            enabled: self.enabled,
            policy_store,
        }
    }
}

/// Markers `ConvertTo-Json` leaves behind when its `-Depth` ran out before
/// it could fully recurse into a nested value: it falls back to that
/// value's `.ToString()`, and for the collection/hashtable types this
/// script's own objects are built from, that renders as one of these
/// literal strings sitting where structured data belongs. The script
/// always passes `-Depth 10`, so seeing one of these means something
/// upstream went wrong — a payload carrying one is rejected outright
/// rather than accepted with silently missing fields.
const DEPTH_TRUNCATION_MARKERS: [&str; 4] = [
    "System.Object[]",
    "System.Collections.Hashtable",
    "Microsoft.Management.Infrastructure.CimInstance",
    "System.Management.Automation.PSCustomObject",
];

/// Nearest valid `str` char boundary at or after `index` — a truncation
/// marker's surrounding bytes can land mid-codepoint if a nearby field
/// happens to carry non-ASCII text, and slicing on a non-boundary panics.
const fn char_boundary_at_or_after(text: &str, mut index: usize) -> usize {
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

/// How much raw JSON to show on each side of an error location — enough
/// to name the field responsible without dumping the whole payload.
const ERROR_CONTEXT_RADIUS: usize = 200;

/// A window of `text` around byte offset `index`, `ERROR_CONTEXT_RADIUS`
/// bytes to each side, clamped to valid char boundaries.
fn context_window(text: &str, index: usize) -> &str {
    let start = char_boundary_at_or_after(text, index.saturating_sub(ERROR_CONTEXT_RADIUS));
    let end = char_boundary_at_or_after(text, (index + ERROR_CONTEXT_RADIUS).min(text.len()));
    &text[start..end]
}

fn reject_if_depth_truncated(text: &str) -> Result<(), CollectError> {
    let Some(marker) = DEPTH_TRUNCATION_MARKERS
        .iter()
        .find(|marker| text.contains(**marker))
    else {
        return Ok(());
    };
    // A snippet of surrounding JSON, not just the marker itself: this is
    // the only way a real CI failure (no live Windows box to reproduce
    // against) reveals *which* field the helper script left unconverted,
    // rather than only that depth truncation happened somewhere in a
    // multi-kilobyte payload.
    let marker_index = text.find(marker).unwrap_or(0);
    let context = context_window(text, marker_index);
    Err(CollectError::Parse(format!(
        "payload looks truncated by insufficient -Depth (found {marker:?} where structured \
         data was expected); context: {context:?}"
    )))
}

/// Wraps a `serde_json` deserialization failure with a slice of the raw
/// payload around it. `collect.ps1` always writes `-Compress`d (single
/// line) JSON, so `source.column()` (1-indexed) doubles as a byte offset
/// into `text` -- the same "show real context instead of guessing which
/// field broke" approach `reject_if_depth_truncated` already uses, now
/// covering type-mismatch failures too (a `null` where a required
/// non-optional field expected a string, for example).
fn describe_json_error(text: &str, source: &serde_json::Error) -> CollectError {
    let byte_index = source.column().saturating_sub(1);
    let context = context_window(text, byte_index);
    CollectError::Parse(format!("{source} near: {context:?}"))
}

/// Strips a leading UTF-8 byte-order mark, if present.
///
/// `Out-File -Encoding utf8` on PowerShell 5.1 Desktop always writes one;
/// `serde_json` treats it as invalid input rather than ignoring it.
pub(super) fn strip_bom(mut bytes: Vec<u8>) -> Vec<u8> {
    const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
    if bytes.starts_with(&BOM) {
        bytes.drain(0..3);
    }
    bytes
}

/// Decodes payload bytes to text, tolerating a non-UTF-8 host.
///
/// PowerShell 5.1 Desktop writes stdout in the OEM code page by default,
/// and while this script always requests `-Encoding utf8` for the file
/// write, a misconfigured `Out-File -Encoding utf8` can still drop
/// non-ASCII bytes. `from_utf8_lossy` never panics and never produces
/// invalid UTF-8 — it substitutes `U+FFFD` for any byte sequence that
/// isn't valid UTF-8 — so a downstream JSON parse can still recover
/// every recoverable field.
fn decode_payload_text(bytes: &[u8]) -> String {
    match core::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_source) => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Parses one collection payload from the helper script's output bytes.
///
/// Strips a UTF-8 BOM, decodes with an OEM-codepage-tolerant fallback
/// (see [`decode_payload_text`]), rejects payloads bearing evidence of
/// insufficient `-Depth` truncation, then validates the v2 envelope's
/// `schema_name`/`schema_version` before deserializing into T04's `Raw*`
/// DTOs — no `serde_json::Value` is ever handed back to a caller.
pub(super) fn parse_payload(bytes: &[u8]) -> Result<PowerShellPayload, CollectError> {
    let stripped = strip_bom(bytes.to_vec());
    let text = decode_payload_text(&stripped);
    reject_if_depth_truncated(&text)?;
    let envelope: PsPayload =
        serde_json::from_str(&text).map_err(|source| describe_json_error(&text, &source))?;
    if envelope.schema_name != SUPPORTED_SCHEMA_NAME {
        return Err(CollectError::Parse(format!(
            "unsupported schema_name {:?} (expected {:?})",
            envelope.schema_name, SUPPORTED_SCHEMA_NAME
        )));
    }
    if envelope.schema_version != SUPPORTED_SCHEMA_VERSION {
        return Err(CollectError::Parse(format!(
            "unsupported schema_version {} (this parser supports only version {SUPPORTED_SCHEMA_VERSION})",
            envelope.schema_version
        )));
    }
    Ok(PowerShellPayload {
        language_mode: envelope
            .metadata
            .as_ref()
            .map_or(LanguageMode::Full, |m| m.language_mode),
        tcp_endpoints: envelope
            .tcp_endpoints
            .into_iter()
            .map(|endpoint| endpoint.into_raw_endpoint("tcp"))
            .collect(),
        udp_endpoints: envelope
            .udp_endpoints
            .into_iter()
            .map(|endpoint| endpoint.into_raw_endpoint("udp"))
            .collect(),
        processes: envelope
            .processes
            .into_iter()
            .map(PsProcess::into_raw_process)
            .collect(),
        services: envelope
            .services
            .into_iter()
            .map(PsService::into_hosted)
            .collect(),
        firewall_rules: envelope
            .firewall_rules
            .into_iter()
            .map(PsFirewallRule::into_raw_rule)
            .collect(),
        firewall_profiles: envelope.firewall_profiles,
    })
}

#[cfg(test)]
mod tests {
    use super::{LanguageMode, PsFirewallRule, parse_payload, strip_bom};

    #[test]
    fn strips_utf8_bom() {
        let with_bom = [0xEF, 0xBB, 0xBF, b'{', b'}'].to_vec();
        assert_eq!(strip_bom(with_bom), b"{}".to_vec());
    }

    #[test]
    fn parses_fixture_payload_from_real_host() {
        let raw = include_bytes!("../../../fixtures/powershell/server2019_full_lm.json");
        let parsed = parse_payload(raw).unwrap();
        assert!(!parsed.tcp_endpoints.is_empty());
        assert_eq!(parsed.language_mode, LanguageMode::Full);
        // Regression coverage for the local_ports-array/policy_store_source_type
        // shape the real script emits (see PsFirewallRule's own doc comment) --
        // this only proves something if the fixture rules actually round-trip
        // into real RawRule values, not just that parsing didn't error.
        assert_eq!(parsed.firewall_rules.len(), 3);
        let https_rule = parsed
            .firewall_rules
            .iter()
            .find(|rule| rule.display_name.contains("HTTPS"))
            .unwrap();
        assert_eq!(https_rule.local_port_spec.as_deref(), Some("443"));
        assert_eq!(https_rule.policy_store, "Local");
        let rdp_rule = parsed
            .firewall_rules
            .iter()
            .find(|rule| rule.display_name.contains("Remote Desktop"))
            .unwrap();
        assert_eq!(rdp_rule.policy_store, "Gpo");
    }

    /// Deserializes a rule object shaped exactly like `assets/collect.ps1`'s
    /// real per-rule literal (`local_ports` as an array, no flat
    /// `policy_store` field) -- the shape that broke before
    /// `PsFirewallRule` existed, independent of the fixture file.
    fn parse_one_rule(json: &str) -> PsFirewallRule {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn multiple_local_ports_join_with_a_comma() {
        let rule = parse_one_rule(
            r#"{"rule_id":"r1","display_name":"d","direction":"Inbound","action":"Allow",
                "enabled":true,"local_ports":["443","8443"]}"#,
        );
        assert_eq!(
            rule.into_raw_rule().local_port_spec.as_deref(),
            Some("443,8443")
        );
    }

    #[test]
    fn any_local_port_collapses_to_no_filter() {
        let rule = parse_one_rule(
            r#"{"rule_id":"r1","display_name":"d","direction":"Inbound","action":"Allow",
                "enabled":true,"local_ports":["Any"]}"#,
        );
        assert_eq!(rule.into_raw_rule().local_port_spec, None);
    }

    #[test]
    fn empty_local_ports_is_no_filter() {
        let rule = parse_one_rule(
            r#"{"rule_id":"r1","display_name":"d","direction":"Inbound","action":"Allow",
                "enabled":true,"local_ports":[]}"#,
        );
        assert_eq!(rule.into_raw_rule().local_port_spec, None);
    }

    #[test]
    fn policy_store_falls_back_to_source_then_to_local() {
        let type_only = parse_one_rule(
            r#"{"rule_id":"r1","display_name":"d","direction":"Inbound","action":"Allow",
                "enabled":true,"policy_store_source_type":"Dynamic"}"#,
        );
        assert_eq!(type_only.into_raw_rule().policy_store, "Dynamic");

        let source_only = parse_one_rule(
            r#"{"rule_id":"r1","display_name":"d","direction":"Inbound","action":"Allow",
                "enabled":true,"policy_store_source":"MyDomain\\Firewall Policy"}"#,
        );
        assert_eq!(
            source_only.into_raw_rule().policy_store,
            "MyDomain\\Firewall Policy"
        );

        let neither = parse_one_rule(
            r#"{"rule_id":"r1","display_name":"d","direction":"Inbound","action":"Allow",
                "enabled":true}"#,
        );
        assert_eq!(neither.into_raw_rule().policy_store, "Local");
    }

    #[test]
    fn rejects_unknown_schema_name() {
        let payload = br#"{"schema_name":"not-our-schema","schema_version":2}"#;
        let err = parse_payload(payload).unwrap_err();
        assert!(matches!(err, super::CollectError::Parse(_)));
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let payload = br#"{"schema_name":"windows-listening-surface","schema_version":99}"#;
        let err = parse_payload(payload).unwrap_err();
        assert!(matches!(err, super::CollectError::Parse(_)));
    }

    #[test]
    fn truncated_depth_payload_is_rejected() {
        let raw = include_bytes!("../../../fixtures/powershell/truncated_depth2.json");
        let err = parse_payload(raw).unwrap_err();
        assert!(matches!(err, super::CollectError::Parse(_)));
    }

    #[test]
    fn clm_payload_yields_reduced_fidelity_not_failure() {
        let raw = include_bytes!("../../../fixtures/powershell/constrained_language_mode.json");
        let parsed = parse_payload(raw).unwrap();
        assert_eq!(parsed.language_mode, LanguageMode::Constrained);
        assert!(!parsed.tcp_endpoints.is_empty());
        assert!(
            parsed.firewall_rules.is_empty(),
            "the NetSecurity module is a common WDAC-unallowlisted casualty; the fixture models it coming back empty, not the whole payload failing"
        );
    }

    #[test]
    fn non_utf8_bytes_fall_back_to_lossy_decode_instead_of_panicking() {
        // Splice an invalid UTF-8 byte into a position that keeps the
        // surrounding JSON syntactically valid once lossily decoded to
        // U+FFFD -- this is not a plausible real payload, only proof the
        // decoder never panics on bad bytes and still returns a `Result`.
        let mut bytes = br#"{"schema_name":"windows-listening-surface","schema_version":2,"metadata":{"language_mode":"FullLanguage","power_shell_version":"5.1"}}"#.to_vec();
        let splice_at = bytes.iter().position(|&b| b == b'5').unwrap();
        bytes[splice_at] = 0xFF;
        let parsed = parse_payload(&bytes).unwrap();
        assert_eq!(parsed.language_mode, LanguageMode::Full);
    }
}
