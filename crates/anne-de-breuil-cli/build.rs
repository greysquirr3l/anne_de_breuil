//! Embed the current `HEAD` short SHA into the binary at build time so
//! `anne version` prints the build provenance, matching the task's "version
//! prints semver plus the git SHA embedded by build.rs" requirement.

use std::process::Command;

const ENV_KEY: &str = "ANNE_CLI_GIT_HASH";

fn main() {
    let sha = short_head_sha().unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env:{ENV_KEY}={sha}");
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
