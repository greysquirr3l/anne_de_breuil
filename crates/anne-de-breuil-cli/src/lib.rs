//! Command dispatch, shared by the `anne` binary and this crate's own
//! integration test suite.
//!
//! `src/main.rs` only does argv parsing, tracing setup, and the tokio
//! runtime bootstrap — every subcommand's actual dispatch lives here in
//! [`run`], so it's compiled exactly once (into this library target) and
//! the binary links against it, rather than each getting its own copy of
//! every handler. The integration suite under `tests/` drives the same
//! [`run`] function directly with a pre-parsed `Cli`, without spawning a
//! child process, for tests that don't specifically need to observe
//! process-level behavior (exit codes, stdout purity).

pub mod adapters;
pub mod application;
pub mod cli;
pub mod domain;
pub mod observability;
pub mod ports;

use anyhow::Result;

pub use cli::{Cli, ExitCode, ScanArgs};

/// Drive a parsed `Cli` to completion. Callers own argv parsing and
/// tracing subscriber installation — this function assumes both already
/// happened.
pub async fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        cli::Command::Scan(args) => application::scan::run(args).await,
        cli::Command::Diff {
            baseline,
            current,
            fail_on_drift,
        } => application::diff::run(&baseline, &current, fail_on_drift),
        cli::Command::Report {
            target,
            format,
            output,
            fonts,
            split,
        } => application::report::run(target, format, output, fonts, split).await,
        cli::Command::Inventory { action } => match action {
            cli::InventoryAction::Validate { path } => application::inventory::run_validate(&path),
        },
        cli::Command::Version => Ok(application::version::run()),
    }
}
