//! Binary entry point.
//!
//! clap parses argv once into a [`Cli`], the `tracing` subscriber is
//! installed with stderr-only output (stdout is reserved for `--emit-json`
//! and report rendering), then `application::*::run` is awaited. Exit
//! codes are the documented contract: 0 clean, 1 operational error,
//! 2 config/arg error, 3 drift detected.

#![deny(dead_code_pub_in_binary)]

mod adapters;
mod application;
mod cli;
mod domain;
mod observability;
mod ports;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, ExitCode};

/// Wrapper around `Result<ExitCode, anyhow::Error>` to satisfy the
/// orphan rule (we can't `impl Termination for Result<…, _>` directly).
/// `Err(anyhow::Error)` collapses to `OperationalError` — a panic or
/// unhandled error in any subcommand is operationally a 1, never a 0
/// or 2 (config errors are caught at parse time, before `run` starts).
struct MainResult(Result<ExitCode, anyhow::Error>);

impl std::process::Termination for MainResult {
    fn report(self) -> std::process::ExitCode {
        match self.0 {
            Ok(code) => std::process::ExitCode::from(exit_code_byte(code)),
            Err(e) => {
                eprintln!("error: {e:?}");
                std::process::ExitCode::from(1u8)
            }
        }
    }
}

/// Map the documented [`ExitCode`] variants to their `u8` representation
/// expected by [`std::process::ExitCode::from`]. Pattern-match instead
/// of `as u8` so the cast is exhaustive and clippy-clean (`cast_possible_truncation`
/// + `cast_sign_loss` both object to `code.as_i32() as u8`).
const fn exit_code_byte(code: ExitCode) -> u8 {
    match code {
        ExitCode::Clean => 0,
        ExitCode::OperationalError => 1,
        ExitCode::ConfigOrArgError => 2,
        ExitCode::DriftDetected => 3,
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
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

fn main() -> MainResult {
    MainResult(run_main())
}

fn run_main() -> Result<ExitCode> {
    let cli = Cli::parse();
    let format = if std::env::var("ANNE_LOG_FORMAT").as_deref() == Ok("json") {
        observability::LoggingFormat::Json
    } else {
        observability::LoggingFormat::Pretty
    };
    observability::init(format);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("tokio runtime: {e}"))?;
    runtime.block_on(run(cli))
}
