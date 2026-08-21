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
    firewall_rules: Vec<RawRule>,
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

fn reject_if_depth_truncated(text: &str) -> Result<(), CollectError> {
    if let Some(marker) = DEPTH_TRUNCATION_MARKERS
        .iter()
        .find(|marker| text.contains(**marker))
    {
        return Err(CollectError::Parse(format!(
            "payload looks truncated by insufficient -Depth (found {marker:?} where structured data was expected)"
        )));
    }
    Ok(())
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
        serde_json::from_str(&text).map_err(|source| CollectError::Parse(source.to_string()))?;
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
        firewall_rules: envelope.firewall_rules,
        firewall_profiles: envelope.firewall_profiles,
    })
}

#[cfg(test)]
mod tests {
    use super::{LanguageMode, parse_payload, strip_bom};

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
