//! Library re-exports for integration tests. The `main` binary uses
//! `Cli::parse()` + `application::*::run` directly; the integration
//! suite calls [`run`] with a pre-parsed `Cli` so tests can drive the
//! full handler chain without spawning a child process.

#![allow(dead_code)]

pub mod adapters;
pub mod application;
pub mod cli;
pub mod domain;
pub mod observability;
pub mod ports;

use anyhow::Result;

pub use cli::{Cli, ExitCode, ScanArgs};

/// Drive a parsed `Cli` to completion. Mirrors the binary's `main`
/// minus the argv parsing and tracing init (callers install whatever
/// subscriber they want first).
pub async fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        cli::Command::Scan(args) => application::scan::run(args).await,
        cli::Command::Diff {
            baseline,
            current,
            fail_on_drift,
        } => application::diff::run(&baseline, &current, fail_on_drift),
        cli::Command::Report { target } => application::report::run(target).await,
        cli::Command::Inventory { action } => match action {
            cli::InventoryAction::Validate { path } => application::inventory::run_validate(&path),
        },
        cli::Command::Version => Ok(application::version::run()),
    }
}
