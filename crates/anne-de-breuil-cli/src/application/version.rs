//! `anne version` — print semver and the git SHA embedded at build time.

use crate::cli::ExitCode;

/// Git SHA at build time.
///
/// Set by `build.rs` as `cargo:rustc-env=CLI_GIT_HASH=<sha>`. Falls back to
/// `"unknown"` so release builds work in source tarballs and CI
/// environments without `.git/` — `option_env!` returns `None` in that
/// case and we land on `"unknown"`, no panic.
///
/// Deliberately *not* `ANNE_`-prefixed (T31 finding): `cargo:rustc-env`
/// output is a real process environment variable for any `cargo
/// test`/`cargo run` invocation of this package, not just a compile-time
/// constant — confirmed empirically by dumping `std::env::vars()` from a
/// running test binary, not assumed. An `ANNE_`-prefixed name here
/// collided with `AnneConfig::load`'s `Env::prefixed("ANNE_")` scan the
/// moment anything in this crate actually called `load` (T18's own
/// learning predicted this exact collision for "whoever wires `--config`
/// for real" — that was this task).
const GIT_HASH: &str = match option_env!("CLI_GIT_HASH") {
    Some(sha) if !sha.is_empty() => sha,
    _ => "unknown",
};

/// Print the build version and return `Clean`.
pub fn run() -> ExitCode {
    let version = env!("CARGO_PKG_VERSION");
    println!("anne {version} (git {GIT_HASH})");
    ExitCode::Clean
}
