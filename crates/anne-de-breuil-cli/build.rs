//! Embed the current `HEAD` short SHA into the binary at build time so
//! `anne version` prints the build provenance, matching the task's "version
//! prints semver plus the git SHA embedded by build.rs" requirement.
//!
//! `cargo:rustc-env` is compile-time only — scoped to this crate's own
//! rustc invocation, never a process-wide environment variable — so unlike
//! an earlier version of this script (which paired it with a workspace
//! `.cargo/config.toml [env]` entry to try to keep it stable across
//! concurrent `cargo build`/rust-analyzer `cargo check` invocations), it
//! can never leak into an unrelated crate's runtime environment. That
//! `[env]` entry was removed: it didn't even feed this script (which always
//! re-derives the SHA via `git`, never reads its own env var back), and its
//! only real effect was setting a real `ANNE_CLI_GIT_HASH` process env var
//! that collided with `AnneConfig::load`'s `ANNE_`-prefixed config-override
//! scan in every test process cargo spawned. The actual cache-stability
//! concern the `[env]` entry was reaching for is handled correctly below,
//! via `cargo:rerun-if-changed` on the paths that can change the SHA.

use std::process::Command;

const ENV_KEY: &str = "ANNE_CLI_GIT_HASH";

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
