//! `anne version` — print semver and the git SHA embedded at build time.

use crate::cli::ExitCode;

/// Git SHA at build time.
///
/// Set by `build.rs` as `cargo:rustc-env:ANNE_CLI_GIT_HASH=<sha>`.
/// Falls back to `"unknown"` so release builds work in source tarballs
/// and CI environments without `.git/`. When build-script propagation
/// fails (e.g. a race between `cargo build` and rust-analyzer's
/// concurrent `cargo check` against the same target dir, or
/// rust-analyzer populating the cache with an empty env var), the
/// compile-time `option_env!` returns `None` and we land on
/// `"unknown"` — same outcome as a tarball build, no panic.
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
