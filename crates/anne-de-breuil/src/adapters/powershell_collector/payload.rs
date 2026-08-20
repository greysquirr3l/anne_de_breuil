//! JSON payload shape written by `assets/collect.ps1`, and the pure,
//! platform-independent parse from bytes into T04's `Raw*` DTOs.
//!
//! Nothing here spawns a process or touches the filesystem — every
//! function operates on an in-memory byte slice, so it runs (and is
//! tested) identically on any host, including this one.

use crate::application::collect::{
    CollectError, RawEndpoint, RawProcess, RawProfile, RawRule, RawService,
};

/// Fidelity the helper script could actually collect at, recorded from
/// `$ExecutionContext.SessionState.LanguageMode`.
///
/// A locked-down host (WDAC/AppLocker) runs the script in
/// [`Self::Constrained`] — cmdlets still work, but modules the policy
/// hasn't allowlisted (commonly `NetSecurity`) can silently return nothing
/// rather than erroring, which is why a caller needs this recorded
/// alongside the data rather than inferring it from empty collections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum LanguageMode {
    /// No restrictions: every cmdlet and filter the script uses ran.
    #[serde(rename = "FullLanguage")]
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

#[derive(Debug, Clone, serde::Deserialize)]
struct PsSocketEndpoint {
    #[serde(rename = "LocalAddress")]
    local_address: String,
    #[serde(rename = "LocalPort")]
    local_port: u16,
    #[serde(rename = "OwningProcess")]
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
    #[serde(rename = "ProcessId")]
    process_id: u32,
    #[serde(rename = "ExecutablePath")]
    executable_path: Option<String>,
    #[serde(rename = "CommandLine")]
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
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "DisplayName")]
    display_name: String,
    #[serde(rename = "ProcessId")]
    process_id: Option<u32>,
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

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawPsPayload {
    language_mode: LanguageMode,
    #[expect(dead_code, reason = "recorded by the script; no consumer needs it yet")]
    power_shell_version: String,
    tcp_endpoints: Vec<PsSocketEndpoint>,
    udp_endpoints: Vec<PsSocketEndpoint>,
    processes: Vec<PsProcess>,
    services: Vec<PsService>,
    firewall_rules: Vec<RawRule>,
    firewall_profiles: Vec<RawProfile>,
}

impl From<RawPsPayload> for PowerShellPayload {
    fn from(raw: RawPsPayload) -> Self {
        Self {
            language_mode: raw.language_mode,
            tcp_endpoints: raw
                .tcp_endpoints
                .into_iter()
                .map(|endpoint| endpoint.into_raw_endpoint("tcp"))
                .collect(),
            udp_endpoints: raw
                .udp_endpoints
                .into_iter()
                .map(|endpoint| endpoint.into_raw_endpoint("udp"))
                .collect(),
            processes: raw
                .processes
                .into_iter()
                .map(PsProcess::into_raw_process)
                .collect(),
            services: raw
                .services
                .into_iter()
                .map(PsService::into_hosted)
                .collect(),
            firewall_rules: raw.firewall_rules,
            firewall_profiles: raw.firewall_profiles,
        }
    }
}

/// Markers `ConvertTo-Json` leaves behind when its `-Depth` ran out before
/// it could fully recurse into a nested value: it falls back to that
/// value's `.ToString()`, and for the collection/hashtable types this
/// script's own objects are built from, that renders as one of these
/// literal strings sitting where structured data belongs. The script
/// always passes `-Depth 6`, so seeing one of these means something
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
/// and while this script always requests `-Encoding utf8` for the file it
/// writes, a string property sourced from a legacy OEM-codepage API can
/// still carry non-UTF-8 bytes inside an otherwise-UTF-8 file. This crate
/// has no OEM code-page conversion table (adding one is a real dependency
/// for a rare edge case), so the fallback here is deliberately
/// approximate: bytes that are already valid UTF-8 decode losslessly;
/// anything else is decoded with `String::from_utf8_lossy`, replacing
/// invalid sequences with U+FFFD rather than panicking or discarding the
/// whole payload over a handful of unreadable characters in one field. If
/// the lossy result still isn't valid JSON, [`parse_payload`] reports
/// `CollectError::Parse`, same as any other malformed payload.
fn decode_payload_text(bytes: &[u8]) -> String {
    match core::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_source) => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Parses one collection payload from the helper script's output bytes.
///
/// Strips a UTF-8 BOM, decodes with an OEM-codepage-tolerant fallback (see
/// [`decode_payload_text`]), rejects payloads bearing evidence of
/// insufficient `-Depth` truncation, then deserializes directly into T04's
/// `Raw*` DTOs — no `serde_json::Value` is ever handed back to a caller.
pub(super) fn parse_payload(bytes: &[u8]) -> Result<PowerShellPayload, CollectError> {
    let stripped = strip_bom(bytes.to_vec());
    let text = decode_payload_text(&stripped);
    reject_if_depth_truncated(&text)?;
    let raw: RawPsPayload =
        serde_json::from_str(&text).map_err(|source| CollectError::Parse(source.to_string()))?;
    Ok(PowerShellPayload::from(raw))
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
        let mut bytes = br#"{"LanguageMode":"FullLanguage","PowerShellVersion":"5.1","TcpEndpoints":[],"UdpEndpoints":[],"Processes":[],"Services":[],"FirewallRules":[],"FirewallProfiles":[]}"#.to_vec();
        // Splice an invalid UTF-8 byte into a position that keeps the
        // surrounding JSON syntactically valid once lossily decoded to
        // U+FFFD -- this is not a plausible real payload, only proof the
        // decoder never panics on bad bytes and still returns a `Result`.
        let splice_at = bytes.iter().position(|&b| b == b'5').unwrap();
        bytes[splice_at] = 0xFF;
        let parsed = parse_payload(&bytes).unwrap();
        assert_eq!(parsed.language_mode, LanguageMode::Full);
    }
}
