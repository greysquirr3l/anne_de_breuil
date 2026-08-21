//! Embeds a cache-busting asset version into the binary at build time so
//! the `portal` feature can append `?v=...` to every CSS/JS URL it serves.
//!
//! Same shape as `anne-de-breuil-cli/build.rs`'s git-SHA embedding --
//! `cargo:rustc-env` is scoped to this crate's own rustc invocation, never
//! a process-wide environment variable, and `cargo:rerun-if-changed`
//! targets exactly the paths that can change the answer so a concurrent
//! `cargo build` and rust-analyzer `cargo check` converge on the same
//! cached value instead of racing to re-run `git`. Unlike the CLI's
//! script, this one also honours an explicit `ASSET_VERSION` override
//! (the task's own requirement -- a release pipeline that stamps a
//! specific version string shouldn't be forced through git) before
//! falling back to the short HEAD SHA.
//!
//! Runs unconditionally, even in builds where the `portal` feature is
//! off -- Cargo doesn't expose enough to build scripts to skip cheaply,
//! and a single `git rev-parse` is not worth the complexity of trying.
//! The `ASSET_VERSION` env var it emits is simply never read by
//! `env!("ASSET_VERSION")` unless `adapters::portal` (behind `portal`) is
//! actually compiled.

use std::process::Command;

const ENV_KEY: &str = "ASSET_VERSION";

fn main() {
    println!("cargo:rerun-if-env-changed={ENV_KEY}");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");

    let version = std::env::var(ENV_KEY)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(short_head_sha)
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env={ENV_KEY}={version}");
}

fn short_head_sha() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}
