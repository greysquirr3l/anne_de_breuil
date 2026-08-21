//! `anne version` — print semver and the git SHA embedded at build time.

use crate::cli::ExitCode;

/// Git SHA at build time.
///
/// Set by `build.rs` as `cargo:rustc-env=ANNE_CLI_GIT_HASH=<sha>`. Falls
/// back to `"unknown"` so release builds work in source tarballs and CI
/// environments without `.git/` — `option_env!` returns `None` in that
/// case and we land on `"unknown"`, no panic.
const GIT_HASH: &str = match option_env!("ANNE_CLI_GIT_HASH") {
    Some(sha) if !sha.is_empty() => sha,
    _ => "unknown",
};

/// Print the build version and return `Clean`.
pub fn run() -> ExitCode {
    let version = env!("CARGO_PKG_VERSION");
    println!("anne {version} (git {GIT_HASH})");
    ExitCode::Clean
}
