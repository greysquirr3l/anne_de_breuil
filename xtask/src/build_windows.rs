//! `cargo run -p xtask -- build-windows`
//!
//! Cross-builds the release `anne.exe` for `x86_64-pc-windows-msvc` via
//! `cargo xwin` and verifies the result has no dynamic CRT import -- the
//! same two steps `release.yml` runs as separate CI steps
//! (`cargo xwin build --release --target x86_64-pc-windows-msvc -p
//! anne-de-breuil-cli`, then `verify-static`), wrapped into one local dev
//! command. Requires `cargo-xwin` and `llvm-objdump` already on `PATH` --
//! this task never installs anything, matching every other xtask task's
//! "operates only on what's already there" contract (see `main.rs`'s
//! module docs).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, ensure};

use crate::verify_static::assert_no_dynamic_crt_import;

const TARGET: &str = "x86_64-pc-windows-msvc";

/// Where `cargo xwin build --release --target x86_64-pc-windows-msvc -p
/// anne-de-breuil-cli` places the binary -- fixed by cargo's own
/// target-dir convention, not something this task chooses.
fn release_exe_path() -> PathBuf {
    Path::new("target")
        .join(TARGET)
        .join("release")
        .join("anne.exe")
}

/// # Errors
///
/// Returns an error if `cargo xwin` can't be spawned, the cross-build
/// exits non-zero, or the resulting binary imports a dynamic CRT DLL.
pub fn run() -> anyhow::Result<()> {
    let status = Command::new("cargo")
        .args([
            "xwin",
            "build",
            "--release",
            "--target",
            TARGET,
            "-p",
            "anne-de-breuil-cli",
        ])
        .status()
        .context(
            "spawning `cargo xwin` -- install it (`cargo install cargo-xwin`) and add the \
             target (`rustup target add x86_64-pc-windows-msvc`) first",
        )?;
    ensure!(status.success(), "cargo xwin build exited with {status}");

    let exe = release_exe_path();
    assert_no_dynamic_crt_import(&exe)?;
    println!("{}: built and verified statically linked", exe.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::release_exe_path;

    #[test]
    fn release_exe_path_matches_cargos_own_target_dir_convention() {
        assert_eq!(
            release_exe_path(),
            std::path::Path::new("target/x86_64-pc-windows-msvc/release/anne.exe")
        );
    }
}
