//! Renders a [`ReportModel`] to the three machine-consumable formats: JSON,
//! CSV, and SARIF 2.1.0.
//!
//! Every function here is a pure transform — `&ReportModel` in, bytes (or a
//! [`serde_json::Value`] for SARIF, since that's what a caller hands to
//! GitHub code scanning or a SIEM ingester without a round trip through
//! `String`) out. No file touches disk in this module; that's
//! [`crate::adapters::report_writer::write_atomically`]'s job.
//!
//! ## Why CSV and SARIF return `Result`
//!
//! Neither can genuinely fail against a real [`ReportModel`] — its own
//! field types are closed enums and validated newtypes, never a float that
//! could be non-finite, and the CSV sink is an in-memory `Vec<u8>` that
//! never hits a real I/O error. `Result` says that honestly through
//! `?`-propagation rather than reaching for `.unwrap()`/`.expect()`, which
//! this project's lint profile forbids outside tests.

use crate::domain::exposure::Exposure;
use crate::domain::ids::HostId;
use crate::domain::publisher::SignatureStatus;
use crate::domain::report_model::{
    DriftEntryView, DriftKindView, EndpointKeyView, EndpointView, ReachabilityView, ReportModel,
    SeverityView,
};
use crate::domain::service::ServiceName;

/// Failure serializing a [`ReportModel`] to a machine format.
#[derive(Debug, thiserror::Error)]
pub enum ReportRenderError {
    /// JSON serialization failed.
    #[error("serializing report to JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// CSV serialization failed.
    #[error("serializing report to CSV: {0}")]
    Csv(#[from] csv::Error),
}

/// Renders `model` as JSON: the view model's own serialization, verbatim.
///
/// `pretty` selects indented output (a file an operator might open
/// directly) over compact output (piped to another tool); both are UTF-8
/// with no BOM, since [`serde_json`] never emits one.
///
/// # Errors
///
/// Returns [`ReportRenderError::Json`] if serialization fails — see the
/// module docs for why that never happens against a real `ReportModel`.
pub fn render_json(model: &ReportModel, pretty: bool) -> Result<Vec<u8>, ReportRenderError> {
    Ok(if pretty {
        serde_json::to_vec_pretty(model)?
    } else {
        serde_json::to_vec(model)?
    })
}

/// [`EndpointRow`]'s header row, in the same order as its fields.
///
/// Written explicitly rather than left to `csv::Writer`'s automatic
/// header inference: that inference only fires before the *first*
/// serialized row, so a model with zero endpoints across every host
/// (a real case — a quiet host, or a scan against nothing listening)
/// would otherwise produce a completely empty CSV, no header at all,
/// which breaks any downstream tool expecting a stable column set
/// regardless of row count. Keep this in sync with [`EndpointRow`]'s
/// field order by hand — the `csv_has_no_bom_and_stable_column_order`
/// test pins the exact header string, so a drift between the two is a
/// test failure, not a silent misalignment.
const CSV_HEADERS: [&str; 9] = [
    "host_id",
    "protocol",
    "bind_address",
    "port",
    "process_path",
    "hosted_services",
    "signature_status",
    "exposure",
    "reachability",
];

/// One flattened `(host, endpoint)` row of the CSV table.
///
/// Column order is this struct's declared field order, matching
/// [`CSV_HEADERS`]. `matched_rules` from the task sketch has no
/// equivalent on [`EndpointView`] (there is no per-endpoint firewall-rule
/// list in the view model, only a resolved [`ReachabilityView`] verdict);
/// the closest honest substitute is `hosted_services`, sorted and joined
/// the same way the sketch's own `matched_rules` comment describes
/// ("sorted, joined — identical scans produce identical rows").
#[derive(Debug, serde::Serialize)]
struct EndpointRow {
    host_id: String,
    protocol: String,
    bind_address: String,
    port: u16,
    process_path: String,
    hosted_services: String,
    signature_status: String,
    exposure: String,
    reachability: String,
}

impl EndpointRow {
    fn from_view(host_id: HostId, endpoint: &EndpointView) -> Self {
        let mut services: Vec<&str> = endpoint
            .hosted_services
            .iter()
            .map(ServiceName::as_str)
            .collect();
        services.sort_unstable();

        Self {
            host_id: host_id.to_string(),
            protocol: endpoint.protocol.to_string(),
            bind_address: endpoint.bind_address.to_string(),
            port: endpoint.port.get(),
            process_path: endpoint
                .process_path
                .as_ref()
                .map_or_else(String::new, |path| path.as_str().to_owned()),
            hosted_services: services.join(";"),
            signature_status: signature_status_text(&endpoint.signature_status),
            exposure: exposure_text(endpoint.exposure).to_owned(),
            reachability: reachability_text(endpoint.reachability).to_owned(),
        }
    }
}

fn signature_status_text(status: &SignatureStatus) -> String {
    match status {
        SignatureStatus::Signed(publisher) => format!("Signed({publisher})"),
        SignatureStatus::Unsigned => "Unsigned".to_owned(),
        SignatureStatus::Unknown => "Unknown".to_owned(),
        SignatureStatus::NotApplicable => "NotApplicable".to_owned(),
    }
}

const fn exposure_text(exposure: Exposure) -> &'static str {
    match exposure {
        Exposure::Loopback => "Loopback",
        Exposure::SpecificInterface => "SpecificInterface",
        Exposure::AllInterfaces => "AllInterfaces",
    }
}

const fn reachability_text(reachability: ReachabilityView) -> &'static str {
    match reachability {
        ReachabilityView::LocalOnly => "LocalOnly",
        ReachabilityView::Blocked => "Blocked",
        ReachabilityView::Allowed => "Allowed",
        ReachabilityView::DefaultAction => "DefaultAction",
        ReachabilityView::Indeterminate => "Indeterminate",
    }
}

/// Renders `model` as the flattened endpoint CSV table, one row per
/// `(host, endpoint)` pair in the model's own stable order.
///
/// The header row is always present, even when `model` has zero
/// endpoints across every host — see [`CSV_HEADERS`] for why that can't
/// be left to `csv::Writer`'s automatic header inference.
///
/// # Errors
///
/// Returns [`ReportRenderError::Csv`] if serialization fails — see the
/// module docs for why that never happens against a real `ReportModel`.
pub fn render_csv(model: &ReportModel) -> Result<Vec<u8>, ReportRenderError> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(Vec::new());
    writer.write_record(CSV_HEADERS)?;
    for host in &model.hosts {
        for endpoint in &host.endpoints {
            writer.serialize(EndpointRow::from_view(host.host_id, endpoint))?;
        }
    }
    writer
        .into_inner()
        .map_err(|err| ReportRenderError::Csv(err.into_error().into()))
}

/// The canonical SARIF 2.1.0 schema identifier — also this crate's
/// vendored fixture's own `$id` (see `fixtures/sarif-schema-2.1.0.json`).
const SARIF_SCHEMA_URI: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

/// The six [`DriftKindView`] variants as SARIF `reportingDescriptor`
/// entries: `(ruleId, name, shortDescription)`. Kept in sync with
/// [`drift_rule_id`]'s match arms by hand — six short strings, not worth a
/// shared lookup table.
const DRIFT_RULES: [(&str, &str, &str); 6] = [
    (
        "endpoint-appeared",
        "EndpointAppeared",
        "A listening endpoint present in the current scan was absent from the baseline.",
    ),
    (
        "endpoint-disappeared",
        "EndpointDisappeared",
        "A listening endpoint present in the baseline is absent from the current scan.",
    ),
    (
        "reachability-changed",
        "ReachabilityChanged",
        "The same endpoint's reachability verdict differs between the baseline and current scan.",
    ),
    (
        "process-changed",
        "ProcessChanged",
        "The same endpoint's owning process identity changed between scans.",
    ),
    (
        "signature-changed",
        "SignatureChanged",
        "The same endpoint's binary signature status changed between scans.",
    ),
    (
        "rule-set-changed",
        "RuleSetChanged",
        "The host's firewall rule set itself changed between scans.",
    ),
];

const fn drift_rule_id(kind: &DriftKindView) -> &'static str {
    match kind {
        DriftKindView::EndpointAppeared => "endpoint-appeared",
        DriftKindView::EndpointDisappeared => "endpoint-disappeared",
        DriftKindView::ReachabilityChanged { .. } => "reachability-changed",
        DriftKindView::ProcessChanged => "process-changed",
        DriftKindView::SignatureChanged => "signature-changed",
        DriftKindView::RuleSetChanged => "rule-set-changed",
    }
}

const fn sarif_level(severity: SeverityView) -> &'static str {
    match severity {
        SeverityView::Low => "note",
        SeverityView::Medium => "warning",
        SeverityView::High | SeverityView::Critical => "error",
    }
}

/// Renders `model`'s drift entries as a SARIF 2.1.0 log.
///
/// Each [`DriftEntryView`] becomes one `result` — that's this model's own
/// notion of a "finding," unlike the task sketch's `sarif_results_for_host`
/// signature, which assumed findings nested under each host section.
/// `level` comes from [`SeverityView`]; the `ruleId` from
/// [`drift_rule_id`].
///
/// ## Location and the missing host id
///
/// [`DriftEntryView`] carries an `endpoint_key` but no `host_id` — `diff`
/// (`domain::drift`) compares exactly one baseline/current snapshot pair
/// for one host, and [`ReportModel::build`] accepts only one shared
/// `Option<&DriftReport>` for the whole model, so a drift entry has no way
/// to name which host it came from once the model spans more than one.
/// Rather than fabricate an attribution, this function only names a host
/// in the SARIF `location` when the model is unambiguous — exactly one
/// host section — which is also the only shape `report`'s CLI wiring
/// produces today. A multi-host report with a drift section would need
/// [`DriftEntryView`] itself to carry a `host_id`, which is outside this
/// task's scope to add to T20's shipped view model; see the module doc on
/// `report_model.rs` for the precedent of documenting a real gap instead
/// of papering over it.
///
/// When a host is resolvable, `location` names it plus the endpoint (if
/// any); when the model is ambiguous, `location` names the endpoint alone;
/// when there is neither (a snapshot-level signal, e.g.
/// [`DriftKindView::RuleSetChanged`], in an ambiguous or hostless model)
/// the result carries no `locations` field at all — SARIF's own schema
/// makes it optional.
#[must_use]
pub fn render_sarif(model: &ReportModel) -> serde_json::Value {
    let host_id = single_host_id(model);
    let results: Vec<serde_json::Value> = model
        .drift
        .iter()
        .map(|entry| sarif_result_for_drift_entry(entry, host_id))
        .collect();
    let rules: Vec<serde_json::Value> = DRIFT_RULES
        .iter()
        .map(|(id, name, description)| {
            serde_json::json!({
                "id": id,
                "name": name,
                "shortDescription": { "text": description },
            })
        })
        .collect();

    serde_json::json!({
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "anne-de-breuil",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules,
                }
            },
            "results": results,
        }],
    })
}

/// Returns the model's single host id, or `None` if the model has zero or
/// more than one host section — see [`render_sarif`]'s doc comment for why
/// only the unambiguous case gets a host-attributed location.
fn single_host_id(model: &ReportModel) -> Option<HostId> {
    match model.hosts.as_slice() {
        [only] => Some(only.host_id),
        _ => None,
    }
}

fn sarif_result_for_drift_entry(
    entry: &DriftEntryView,
    host_id: Option<HostId>,
) -> serde_json::Value {
    let mut result = serde_json::Map::new();
    result.insert(
        "ruleId".to_owned(),
        serde_json::Value::String(drift_rule_id(&entry.kind).to_owned()),
    );
    result.insert(
        "level".to_owned(),
        serde_json::Value::String(sarif_level(entry.severity).to_owned()),
    );
    result.insert(
        "message".to_owned(),
        serde_json::json!({ "text": drift_message(entry, host_id) }),
    );
    let locations = sarif_locations(host_id, entry.endpoint_key.as_ref());
    if !locations.is_empty() {
        result.insert("locations".to_owned(), serde_json::Value::Array(locations));
    }
    serde_json::Value::Object(result)
}

fn endpoint_label(key: &EndpointKeyView) -> String {
    format!("{}:{}:{}", key.protocol, key.bind_address, key.port)
}

fn drift_message(entry: &DriftEntryView, host_id: Option<HostId>) -> String {
    let host_clause = host_id.map_or_else(String::new, |id| format!(" on host {id}"));
    let subject = entry.endpoint_key.as_ref().map_or_else(
        || "the host".to_owned(),
        |key| format!("endpoint {}", endpoint_label(key)),
    );

    match &entry.kind {
        DriftKindView::EndpointAppeared => {
            format!("{subject}{host_clause} appeared; not present in the baseline scan.")
        }
        DriftKindView::EndpointDisappeared => {
            format!(
                "{subject}{host_clause} was present in the baseline scan and is no longer observed."
            )
        }
        DriftKindView::ReachabilityChanged { before, after } => {
            format!("Reachability for {subject}{host_clause} changed from {before:?} to {after:?}.")
        }
        DriftKindView::ProcessChanged => {
            format!("The owning process for {subject}{host_clause} changed between scans.")
        }
        DriftKindView::SignatureChanged => {
            format!("The binary signature status for {subject}{host_clause} changed between scans.")
        }
        DriftKindView::RuleSetChanged => {
            format!("The firewall rule set{host_clause} changed between scans.")
        }
    }
}

fn sarif_locations(
    host_id: Option<HostId>,
    endpoint_key: Option<&EndpointKeyView>,
) -> Vec<serde_json::Value> {
    let fully_qualified_name = match (host_id, endpoint_key) {
        (None, None) => return Vec::new(),
        (Some(host), None) => format!("host:{host}"),
        (None, Some(key)) => endpoint_label(key),
        (Some(host), Some(key)) => format!("host:{host}/{}", endpoint_label(key)),
    };

    vec![serde_json::json!({
        "logicalLocations": [{
            "fullyQualifiedName": fully_qualified_name,
            "kind": "resource",
        }],
    })]
}

#[cfg(test)]
mod tests {
    use super::{render_csv, render_json, render_sarif};

    /// The real, canonical SARIF 2.1.0 JSON Schema (draft-07), fetched
    /// once from `https://json.schemastore.org/sarif-2.1.0.json` on
    /// 2026-08-20 and vendored here so schema validation never makes a
    /// network call in a test. Its own `$id` is the same
    /// `raw.githubusercontent.com/oasis-tcs/...` URI this module's
    /// `SARIF_SCHEMA_URI` constant uses.
    const SARIF_SCHEMA: &str = include_str!("../../fixtures/sarif-schema-2.1.0.json");

    mod fixtures {
        use core::str::FromStr as _;

        use crate::domain::bind_address::BindAddress;
        use crate::domain::drift::diff;
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

        fn endpoint() -> Endpoint {
            Endpoint::new(
                Protocol::Tcp,
                BindAddress::from_str("0.0.0.0").unwrap(),
                Port::try_from(8443u16).unwrap(),
                None,
                Some(ProcessPath::from_str("/usr/bin/svc").unwrap()),
                vec![
                    ServiceName::try_from("zeta".to_owned()).unwrap(),
                    ServiceName::try_from("alpha".to_owned()).unwrap(),
                ],
                SignatureStatus::Unsigned,
                None,
            )
        }

        /// One host, one endpoint, no drift — the report model the CLI's
        /// default `anne report <path>` path (no `--diff` wiring yet)
        /// actually produces today.
        pub(super) fn sample_report_model() -> ReportModel {
            let snapshot = ScanSnapshot::new(
                HostId::generate(),
                ScanId::generate(),
                time::OffsetDateTime::UNIX_EPOCH,
                "1.0.0".to_owned(),
                vec![endpoint()],
                vec![],
                vec![],
                TargetStrategy::Execute,
            );
            ReportModel::build(&[snapshot], None, true).unwrap()
        }

        /// One host with a real drift report attached (an appeared
        /// endpoint), for exercising the SARIF host+endpoint location arm.
        pub(super) fn single_host_report_model_with_drift() -> ReportModel {
            let host_id = HostId::generate();
            let baseline = ScanSnapshot::new(
                host_id,
                ScanId::generate(),
                time::OffsetDateTime::UNIX_EPOCH,
                "1.0.0".to_owned(),
                vec![],
                vec![],
                vec![],
                TargetStrategy::Execute,
            );
            let current = ScanSnapshot::new(
                host_id,
                ScanId::generate(),
                time::OffsetDateTime::UNIX_EPOCH,
                "1.0.0".to_owned(),
                vec![endpoint()],
                vec![],
                vec![],
                TargetStrategy::Execute,
            );
            let report = diff(&baseline, &current);
            assert!(!report.entries.is_empty(), "fixture must produce drift");
            ReportModel::build(&[current], Some(&report), true).unwrap()
        }

        /// Two hosts sharing the same drift report — an ambiguous model
        /// (the drift entries can't honestly be attributed to either
        /// host), for exercising the SARIF endpoint-only location arm.
        pub(super) fn multi_host_report_model_with_drift() -> ReportModel {
            let host_a = HostId::generate();
            let host_b = HostId::generate();
            let baseline = ScanSnapshot::new(
                host_a,
                ScanId::generate(),
                time::OffsetDateTime::UNIX_EPOCH,
                "1.0.0".to_owned(),
                vec![],
                vec![],
                vec![],
                TargetStrategy::Execute,
            );
            let current_a = ScanSnapshot::new(
                host_a,
                ScanId::generate(),
                time::OffsetDateTime::UNIX_EPOCH,
                "1.0.0".to_owned(),
                vec![endpoint()],
                vec![],
                vec![],
                TargetStrategy::Execute,
            );
            let current_b = ScanSnapshot::new(
                host_b,
                ScanId::generate(),
                time::OffsetDateTime::UNIX_EPOCH,
                "1.0.0".to_owned(),
                vec![],
                vec![],
                vec![],
                TargetStrategy::Execute,
            );
            let report = diff(&baseline, &current_a);
            assert!(!report.entries.is_empty(), "fixture must produce drift");
            ReportModel::build(&[current_a, current_b], Some(&report), true).unwrap()
        }

        /// One host, zero endpoints — a quiet host, or a scan against
        /// nothing listening. A real, unremarkable case, not an edge case
        /// to special-case away.
        pub(super) fn report_model_with_no_endpoints() -> ReportModel {
            let snapshot = ScanSnapshot::new(
                HostId::generate(),
                ScanId::generate(),
                time::OffsetDateTime::UNIX_EPOCH,
                "1.0.0".to_owned(),
                vec![],
                vec![],
                vec![],
                TargetStrategy::Execute,
            );
            ReportModel::build(&[snapshot], None, true).unwrap()
        }
    }

    #[test]
    fn all_three_formats_are_deterministic_across_renders() {
        let model = fixtures::sample_report_model();
        assert_eq!(
            render_json(&model, false).unwrap(),
            render_json(&model, false).unwrap()
        );
        assert_eq!(render_csv(&model).unwrap(), render_csv(&model).unwrap());
        assert_eq!(
            render_sarif(&model).to_string(),
            render_sarif(&model).to_string()
        );
    }

    #[test]
    fn json_render_is_utf8_with_no_bom_and_round_trips() {
        let model = fixtures::sample_report_model();
        let bytes = render_json(&model, true).unwrap();
        assert!(!bytes.starts_with(&[0xEF, 0xBB, 0xBF]));
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value.get("hosts").is_some());
    }

    #[test]
    fn csv_has_no_bom_and_stable_column_order() {
        let csv_bytes = render_csv(&fixtures::sample_report_model()).unwrap();
        assert!(!csv_bytes.starts_with(&[0xEF, 0xBB, 0xBF]));
        let newline = csv_bytes.iter().position(|&b| b == b'\n').unwrap();
        let header = String::from_utf8_lossy(&csv_bytes[..newline]);
        assert_eq!(
            header,
            "host_id,protocol,bind_address,port,process_path,hosted_services,signature_status,exposure,reachability"
        );
    }

    #[test]
    fn csv_header_is_present_even_with_zero_endpoints() {
        // `csv::Writer`'s automatic header inference only fires before the
        // first serialized row — a model with no endpoints at all must
        // still produce a header, not an empty file, or a downstream tool
        // (spreadsheet import, SIEM ingester) sees an unparseable blank
        // where it expects a stable column set.
        let csv_bytes = render_csv(&fixtures::report_model_with_no_endpoints()).unwrap();
        let text = String::from_utf8(csv_bytes).unwrap();
        assert_eq!(
            text.trim_end(),
            "host_id,protocol,bind_address,port,process_path,hosted_services,signature_status,exposure,reachability"
        );
    }

    #[test]
    fn csv_joins_hosted_services_sorted() {
        let csv_bytes = render_csv(&fixtures::sample_report_model()).unwrap();
        let text = String::from_utf8(csv_bytes).unwrap();
        let data_row = text.lines().nth(1).unwrap();
        // Fixture endpoint carries services ["zeta", "alpha"]; the row must
        // show them sorted, not in insertion order.
        assert!(data_row.contains("alpha;zeta"));
    }

    #[test]
    fn sarif_output_validates_against_the_vendored_schema() {
        let schema: serde_json::Value = serde_json::from_str(SARIF_SCHEMA).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();

        for model in [
            fixtures::sample_report_model(),
            fixtures::single_host_report_model_with_drift(),
            fixtures::multi_host_report_model_with_drift(),
        ] {
            let sarif = render_sarif(&model);
            let errors: Vec<String> = validator
                .iter_errors(&sarif)
                .map(|err| err.to_string())
                .collect();
            assert!(errors.is_empty(), "SARIF validation errors: {errors:?}");
        }
    }

    #[test]
    fn sarif_result_names_host_and_endpoint_when_the_model_is_unambiguous() {
        let model = fixtures::single_host_report_model_with_drift();
        let sarif = render_sarif(&model);
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert!(!results.is_empty());

        let host_id = model.hosts.first().unwrap().host_id.to_string();
        let found_host_and_endpoint = results.iter().any(|result| {
            result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
                .as_str()
                .is_some_and(|name| name.starts_with(&format!("host:{host_id}/")))
        });
        assert!(
            found_host_and_endpoint,
            "expected at least one result naming both host and endpoint, got: {results:?}"
        );
    }

    #[test]
    fn sarif_result_names_endpoint_only_when_the_model_has_more_than_one_host() {
        let model = fixtures::multi_host_report_model_with_drift();
        let sarif = render_sarif(&model);
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert!(!results.is_empty());

        let never_names_a_host = results.iter().all(|result| {
            let name = result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
                .as_str()
                .unwrap_or_default();
            !name.starts_with("host:")
        });
        assert!(
            never_names_a_host,
            "an ambiguous multi-host model must never attribute drift to a specific host: {results:?}"
        );
    }

    #[test]
    fn sarif_result_omits_locations_when_neither_host_nor_endpoint_is_known() {
        // A `RuleSetChanged` entry (no `endpoint_key`) in an ambiguous
        // (multi-host) model has nothing honest to put in `locations` at
        // all — confirm the field is genuinely absent, not an empty array
        // masquerading as "no location".
        let entry = crate::domain::report_model::DriftEntryView {
            kind: crate::domain::report_model::DriftKindView::RuleSetChanged,
            endpoint_key: None,
            severity: crate::domain::report_model::SeverityView::Medium,
        };
        let result = super::sarif_result_for_drift_entry(&entry, None);
        assert!(result.get("locations").is_none());
    }

    #[test]
    fn severity_maps_to_the_documented_sarif_levels() {
        use crate::domain::report_model::SeverityView;
        assert_eq!(super::sarif_level(SeverityView::Low), "note");
        assert_eq!(super::sarif_level(SeverityView::Medium), "warning");
        assert_eq!(super::sarif_level(SeverityView::High), "error");
        assert_eq!(super::sarif_level(SeverityView::Critical), "error");
    }
}
