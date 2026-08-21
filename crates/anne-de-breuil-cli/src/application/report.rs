//! `anne report` — render a stored snapshot as JSON (T21 wires HTML/CSV/SARIF).

use std::str::FromStr;

use anyhow::{Context, Result, anyhow};

use crate::cli::ExitCode;
use anne_de_breuil::application::snapshot_store::SnapshotStore;
use anne_de_breuil::domain::ScanId;

/// Render `target` (a `scan-id` UUID, or a path to a `.json` file) as
/// a `ReportModel` JSON envelope to stdout.
///
/// `anne report <scan-id>` resolves the id against the default
/// `anne-snapshots/` store; `anne report <path>` loads the file directly.
/// The full multi-format rendering is T21's scope — this task wires the
/// JSON path because it's the one format the report model is guaranteed
/// to support today (see `domain::report_model::ReportModel`).
pub async fn run(target: String) -> Result<ExitCode> {
    let snapshot = if looks_like_uuid(&target) {
        load_from_store(&target).await?
    } else {
        load_from_path(std::path::Path::new(&target))?
    };

    let model = anne_de_breuil::domain::report_model::ReportModel::build(
        std::slice::from_ref(&snapshot),
        None,
        // `no_redact_confirmed` gates whether `build` proceeds at all, not
        // whether redaction happens — `build` always redacts every command
        // line regardless of this flag's value (see the doc comment on
        // `ReportError::RedactionConfirmationRequired`; there is no code
        // path yet that can produce an unredacted `ReportModel`). Passing
        // `true` unconditionally is therefore the correct default path
        // today, not a bypass: a real `--no-redact` flag has nothing to
        // attach to until a later report-format task adds one.
        true,
    )
    .map_err(|e| anyhow!("building report model: {e}"))?;

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer_pretty(&mut handle, &model).context("serialize ReportModel to stdout")?;
    Ok(ExitCode::Clean)
}

const fn looks_like_uuid(target: &str) -> bool {
    target.len() == 36 || target.len() == 32
}

async fn load_from_store(raw_id: &str) -> Result<anne_de_breuil::domain::ScanSnapshot> {
    let id = ScanId::from_str(raw_id).with_context(|| format!("parsing scan id {raw_id:?}"))?;
    let path = std::path::PathBuf::from("anne-snapshots");
    if !path.exists() {
        return Err(anyhow!(
            "snapshot store path {} does not exist; pass a file path instead",
            path.display()
        ));
    }
    let store = anne_de_breuil::adapters::snapshot_store::FsSnapshotStore::new(&path)?;
    store
        .get(id)
        .await?
        .ok_or_else(|| anyhow!("no snapshot with id {id} found in {}", path.display()))
}

fn load_from_path(path: &std::path::Path) -> Result<anne_de_breuil::domain::ScanSnapshot> {
    let path_display = path.display().to_string();
    let bytes =
        std::fs::read(path).with_context(|| format!("reading snapshot file {path_display}"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {path_display}"))
}
