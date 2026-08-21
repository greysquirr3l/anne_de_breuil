//! Embed the current `HEAD` short SHA into the binary at build time so
//! `anne version` prints the build provenance, matching the task's "version
//! prints semver plus the git SHA embedded by build.rs" requirement.
//!
//! `cargo:rustc-env` sets a real environment variable for `cargo
//! test`/`cargo run` invocations of this same package, not just a
//! compile-time constant for `env!()` — confirmed empirically (T31) by
//! dumping `std::env::vars()` from a running test binary, contradicting an
//! earlier version of this comment's claim that it "can never leak into
//! ... runtime environment." An earlier version of this script paired the
//! same key with a workspace `.cargo/config.toml [env]` entry (removed:
//! it didn't even feed this script, which always re-derives the SHA via
//! `git` rather than reading its own env var back) — that entry's only
//! real effect was making the same collision permanent across every
//! process on the machine, not just `cargo test`'s own child processes.
//! `ENV_KEY` is deliberately *not* `ANNE_`-prefixed for exactly this
//! reason: any name under that prefix collides with
//! `AnneConfig::load`'s `Env::prefixed("ANNE_")` config-override scan the
//! moment anything in this crate actually calls `load` — see
//! `application::version`'s own doc comment on `GIT_HASH` for where this
//! was actually caught. The cache-stability concern the removed `[env]`
//! entry was reaching for is handled correctly below, via
//! `cargo:rerun-if-changed` on the paths that can change the SHA.

use std::process::Command;

const ENV_KEY: &str = "CLI_GIT_HASH";

fn main() {
    // Re-run only when HEAD moves (new commit, checkout, rebase) or the
    // index changes (`git add`/`git commit`) — not on every build — so a
    // concurrent `cargo build` and rust-analyzer `cargo check` converge on
    // the same cached SHA instead of racing to re-run `git`.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");

    let sha = short_head_sha().unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env={ENV_KEY}={sha}");
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
