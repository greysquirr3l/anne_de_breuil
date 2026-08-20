//! `anne inventory` — validate an inventory TOML file without scanning.

use anyhow::{Context, Result, anyhow};

use crate::cli::ExitCode;

/// Parse the file and report any validation errors.
///
/// A clean parse returns `Ok(ExitCode::Clean)` and prints the parsed
/// host count to stderr (so stdout stays empty for shell pipelines).
pub fn run_validate(path: &std::path::Path) -> Result<ExitCode> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading inventory file {}", path.display()))?;
    let hosts = match anne_de_breuil::adapters::inventory::parse_inventory(&contents) {
        Ok(hosts) => hosts,
        Err(e) => {
            eprintln!("inventory validation failed: {e}");
            return Ok(ExitCode::ConfigOrArgError);
        }
    };

    if hosts.is_empty() {
        return Err(anyhow!(
            "inventory file {} parsed successfully but contains zero hosts",
            path.display()
        ));
    }

    eprintln!(
        "inventory {}: {} host(s) parsed",
        path.display(),
        hosts.len()
    );
    Ok(ExitCode::Clean)
}
