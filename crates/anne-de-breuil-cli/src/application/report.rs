//! `anne report` — render a stored snapshot as JSON, CSV, or SARIF.

use std::io::Write as _;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result, anyhow};

use crate::cli::{ExitCode, FontsModeArg, ReportFormatArg};
use anne_de_breuil::adapters::config::{FontsMode, ReportFormat};
use anne_de_breuil::adapters::html_report;
use anne_de_breuil::adapters::report_writer;
use anne_de_breuil::application::snapshot_store::SnapshotStore;
use anne_de_breuil::domain::ScanId;
use anne_de_breuil::domain::report_render;

/// Render `target` (a `scan-id` UUID, or a path to a `.json` file) as
/// `format`, writing the result to `output` if given or stdout otherwise.
///
/// `anne report <scan-id>` resolves the id against the default
/// `anne-snapshots/` store; `anne report <path>` loads the file directly.
/// With no `--format`/`--output` at all, this is byte-for-byte the same
/// pretty-JSON-to-stdout behavior the CLI has shipped since T18 — nothing
/// about the default path changes here. `fonts` selects between embedded
/// vendored WOFF2 faces and a system font stack for `--format html`; every
/// other format ignores it.
///
/// # Errors
///
/// Returns an error if the snapshot can't be loaded, the report model
/// can't be built, rendering fails, or (for `--output`) the write fails.
pub async fn run(
    target: String,
    format: ReportFormatArg,
    output: Option<PathBuf>,
    fonts: FontsModeArg,
) -> Result<ExitCode> {
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

    let bytes = match ReportFormat::from(format) {
        ReportFormat::Json => report_render::render_json(&model, true).context("render JSON")?,
        ReportFormat::Csv => report_render::render_csv(&model).context("render CSV")?,
        ReportFormat::Sarif => {
            let sarif = report_render::render_sarif(&model);
            serde_json::to_vec_pretty(&sarif).context("serialize SARIF")?
        }
        ReportFormat::Html => html_report::render(&model, FontsMode::from(fonts))
            .context("render HTML")?
            .into_bytes(),
    };

    match output {
        Some(path) => report_writer::write_atomically(&path, &bytes)
            .with_context(|| format!("writing report to {}", path.display()))?,
        None => std::io::stdout()
            .write_all(&bytes)
            .context("writing report to stdout")?,
    }

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
