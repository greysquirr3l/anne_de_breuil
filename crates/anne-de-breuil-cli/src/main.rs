//! Binary entry point.
//!
//! clap parses argv once into a [`Cli`], the `tracing` subscriber is
//! installed with stderr-only output (stdout is reserved for `--emit-json`
//! and report rendering), then [`anne_de_breuil_cli::run`] is awaited. Exit
//! codes are the documented contract: 0 clean, 1 operational error,
//! 2 config/arg error, 3 drift detected.
//!
//! The command-dispatch match itself lives in `lib.rs`, not here — this
//! binary just links against its own package's library target (Cargo does
//! that automatically for any package with both a `lib.rs` and a `[[bin]]`)
//! and calls straight into it. An earlier draft of this file declared its
//! own `mod application; mod cli; ...` tree pointing at the same source
//! files the library already compiles, which built two independent copies
//! of every handler into two different crates (`anne` and
//! `anne_de_breuil_cli`) — never actually calling the library's copy from
//! this binary at all. `#![deny(dead_code_pub_in_binary)]` only inspects
//! the binary crate root, so it had nothing to say about the duplication.
//!
//! `main` checks for a bare `anne --self-hash` invocation *before*
//! `Cli::parse()` — that mode has no subcommand at all (see
//! `application::self_hash`'s doc comment), which `Cli`'s required
//! `#[command(subcommand)]` field can never accept.
#![deny(dead_code_pub_in_binary)]

use anyhow::Result;
use clap::Parser;

use anne_de_breuil_cli::cli::{Cli, ExitCode};
use anne_de_breuil_cli::observability;

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

fn main() -> MainResult {
    let argv: Vec<String> = std::env::args().collect();
    if anne_de_breuil_cli::application::self_hash::is_self_hash_invocation(&argv) {
        return MainResult(
            anne_de_breuil_cli::application::self_hash::run()
                .map(|()| ExitCode::Clean)
                .map_err(|e| anyhow::anyhow!("computing --self-hash: {e}")),
        );
    }
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
    runtime.block_on(anne_de_breuil_cli::run(cli))
}
