//! `anne diff` — compare two snapshots and emit drift.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::cli::{ExitCode, SeverityArg};
use anne_de_breuil::domain::ScanSnapshot;
use anne_de_breuil::domain::drift::diff;
use anne_de_breuil::domain::report_model::DriftEntryView;

/// Load both snapshots, compute drift, and decide an exit code.
///
/// Snapshot JSON files are the on-disk representation of `ScanSnapshot`;
/// deserialising them through `serde_json::from_reader` exercises the
/// `deny_unknown_fields` guarantee in `domain::snapshot.rs` (a corrupted
/// or tampered file fails fast rather than silently dropping fields).
pub fn run(baseline: &Path, current: &Path, fail_on_drift: SeverityArg) -> Result<ExitCode> {
    let baseline = load_snapshot(baseline)
        .with_context(|| format!("loading baseline {}", baseline.display()))?;
    let current =
        load_snapshot(current).with_context(|| format!("loading current {}", current.display()))?;

    let report = diff(&baseline, &current);

    let threshold: anne_de_breuil::domain::Severity = fail_on_drift.into();
    let drift_exits = report
        .entries
        .iter()
        .any(|entry| entry.severity >= threshold);

    let as_json = {
        // `DriftEntry` does not derive `Serialize` (the domain deliberately
        // keeps wire-format mirrors in `report_model::DriftEntryView`).
        // Map through the view before serialising so JSON output is stable
        // across domain changes.
        let views: Vec<DriftEntryView> = report.entries.iter().map(DriftEntryView::from).collect();
        serde_json::to_string_pretty(&views).context("serialize drift entries")?
    };
    println!("{as_json}");

    if drift_exits {
        Ok(ExitCode::DriftDetected)
    } else {
        Ok(ExitCode::Clean)
    }
}

fn load_snapshot(path: &Path) -> Result<ScanSnapshot> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let value: Value =
        serde_json::from_reader(std::io::BufReader::new(file)).context("parse JSON envelope")?;
    let snapshot: ScanSnapshot =
        serde_json::from_value(value).context("parse JSON into ScanSnapshot")?;
    Ok(snapshot)
}
