//! `cargo run -p xtask -- verify-static <path-to-exe>`
//!
//! Fails if a windows-msvc release binary imports a dynamic CRT DLL.
//! `.cargo/config.toml` sets `target-feature=+crt-static` for both `-msvc`
//! targets specifically because the collector gets pushed onto hosts
//! assumed to have neither Rust nor the Visual C++ Redistributable
//! installed -- a dynamically-linked CRT means it silently fails to start
//! with a missing-DLL error on exactly the bare hosts this tool exists to
//! run on. This is the automated check that the rustflag actually applied,
//! run from the release workflow right after each xwin cross-build.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, ensure};

/// True if an import table (as rendered by `llvm-objdump -p`, or anything
/// in the same `DLL Name: ...` line format) names a dynamic CRT DLL.
///
/// Split out from [`assert_no_dynamic_crt_import`] so the detection logic
/// itself is unit-testable against literal text -- neither a real exe nor
/// `llvm-objdump` needs to be present for `cargo test` to exercise it.
fn names_dynamic_crt_dll(import_table: &str) -> bool {
    let lower = import_table.to_lowercase();
    lower.contains("vcruntime") || lower.contains("msvcp")
}

/// Runs `llvm-objdump -p` against `exe_path` and fails if its import table
/// names `VCRUNTIME*.dll` or `MSVCP*.dll`.
///
/// # Errors
///
/// Returns an error if `llvm-objdump` can't be spawned (not installed, or
/// not on `PATH`), exits non-zero, or the binary imports a dynamic CRT DLL.
pub fn assert_no_dynamic_crt_import(exe_path: &Path) -> anyhow::Result<()> {
    let path_str = exe_path
        .to_str()
        .with_context(|| format!("{} is not valid UTF-8", exe_path.display()))?;

    let output = Command::new("llvm-objdump")
        .args(["-p", path_str])
        .output()
        .context(
            "spawning llvm-objdump -- install it (e.g. `apt-get install llvm` in CI, or via \
             the Xcode command line tools on macOS) and ensure it's on PATH",
        )?;
    ensure!(
        output.status.success(),
        "llvm-objdump exited with {} against {}",
        output.status,
        exe_path.display()
    );

    let text = String::from_utf8_lossy(&output.stdout);
    ensure!(
        !names_dynamic_crt_dll(&text),
        "dynamic CRT dependency found in {} -- rebuild with target-feature=+crt-static",
        exe_path.display()
    );
    Ok(())
}

pub fn run(mut args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    let path = args
        .next()
        .context("usage: cargo run -p xtask -- verify-static <path-to-exe>")?;
    assert_no_dynamic_crt_import(Path::new(&path))?;
    println!("{path}: no dynamic CRT dependency found");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::names_dynamic_crt_dll;

    // Trimmed from a real `llvm-objdump -p` run against this task's own
    // `cargo xwin build --release --target x86_64-pc-windows-msvc` output
    // (T29) -- crt-static linked, only OS-level DLLs in the import table.
    const STATIC_CRT_IMPORTS: &str = "\
Import Table:
  DLL Name: bcryptprimitives.dll
  DLL Name: kernel32.dll
  DLL Name: ntdll.dll
  DLL Name: api-ms-win-core-synch-l1-2-0.dll
";

    const DYNAMIC_CRT_IMPORTS: &str = "\
Import Table:
  DLL Name: KERNEL32.dll
  DLL Name: VCRUNTIME140.dll
  DLL Name: MSVCP140.dll
  DLL Name: api-ms-win-crt-runtime-l1-1-0.dll
";

    #[test]
    fn static_crt_import_table_has_no_dynamic_dll() {
        assert!(!names_dynamic_crt_dll(STATIC_CRT_IMPORTS));
    }

    #[test]
    fn dynamic_vcruntime_import_is_detected() {
        assert!(names_dynamic_crt_dll(DYNAMIC_CRT_IMPORTS));
    }

    #[test]
    fn dynamic_msvcp_import_is_detected_case_insensitively() {
        assert!(names_dynamic_crt_dll("DLL Name: msvcp140.dll\n"));
    }

    // Requires a real cross-built exe and `llvm-objdump` on PATH -- neither
    // is available in a default `cargo test` run, so this stays `#[ignore]`
    // rather than depending on committing a cross-compiled binary to the
    // repo. Run it directly after a real cross-build:
    //
    //   cargo xwin build --release --target x86_64-pc-windows-msvc
    //   ANNE_VERIFY_STATIC_FIXTURE_EXE=target/x86_64-pc-windows-msvc/release/anne.exe \
    //     cargo test -p xtask -- --ignored windows_msvc_binary_has_no_dynamic_crt_dependency
    //
    // Verified this way during T29 against a real cross-build on this
    // machine; the release workflow's `verify-static` step runs the same
    // code path in CI, right after the same `cargo xwin build` invocation.
    #[test]
    #[ignore = "requires ANNE_VERIFY_STATIC_FIXTURE_EXE (a real cross-built .exe) and llvm-objdump on PATH"]
    fn windows_msvc_binary_has_no_dynamic_crt_dependency() {
        let exe = std::env::var("ANNE_VERIFY_STATIC_FIXTURE_EXE")
            .expect("set ANNE_VERIFY_STATIC_FIXTURE_EXE to a cross-built windows-msvc .exe path");
        assert!(super::assert_no_dynamic_crt_import(std::path::Path::new(&exe)).is_ok());
    }
}
