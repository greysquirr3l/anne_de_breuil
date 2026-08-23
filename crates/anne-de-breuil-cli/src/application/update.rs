//! `anne update` -- check GitHub Releases for a newer `anne` build and,
//! with confirmation, download, checksum-verify, and atomically replace
//! the running executable.
//!
//! Never automatic: only runs on an explicit `anne update` invocation,
//! and even then prompts for confirmation unless `--yes` is given.
//! Checksum verification (against the release's own `SHA256SUMS.txt`,
//! reusing [`anne_de_breuil::adapters::binary_hash::hash_bytes`] -- the
//! same function `anne --self-hash` and the SSH push-side integrity
//! check already use) happens *before* anything on disk is touched.
//!
//! Windows binaries aren't code-signed today (see README.md's "Release
//! artifacts" section) -- checksum verification is the only integrity
//! check available there, equivalent trust to a manual download +
//! checksum, not weaker, but not stronger either.

use std::io::IsTerminal as _;
use std::path::Path;

use anyhow::Context as _;

use crate::adapters::github_release::{GITHUB_API_BASE, GitHubReleaseSource, owner_repo};
use crate::cli::{ExitCode, UpdateArgs};
use crate::ports::ReleaseSource;

pub async fn run(args: UpdateArgs) -> anyhow::Result<ExitCode> {
    let source = GitHubReleaseSource::new(GITHUB_API_BASE.to_owned(), owner_repo()?)?;
    let target_exe = std::env::current_exe().context("locating the running executable")?;
    run_with_source(
        &source,
        &args,
        &target_exe,
        std::env::consts::OS,
        std::env::consts::ARCH,
    )
    .await
}

async fn run_with_source(
    source: &dyn ReleaseSource,
    args: &UpdateArgs,
    target_exe: &Path,
    os: &str,
    arch: &str,
) -> anyhow::Result<ExitCode> {
    let requested_tag = args.version.as_deref().map(|v| {
        if v.starts_with('v') {
            v.to_owned()
        } else {
            format!("v{v}")
        }
    });
    let release = source
        .release(requested_tag.as_deref())
        .await
        .context("fetching release info")?;

    let current = current_version()?;
    let target = parse_release_version(&release.tag_name)?;

    if args.check {
        if target > current {
            println!("update available: {current} -> {target}");
        } else {
            println!("up to date ({current})");
        }
        return Ok(ExitCode::Clean);
    }

    if target <= current && args.version.is_none() {
        println!("already up to date ({current})");
        return Ok(ExitCode::Clean);
    }

    // Only checked once an install is actually about to happen -- `--check`
    // and the "already up to date" branch above both report real version
    // status on every platform, install-artifact availability or not.
    let asset_name = match target_asset_name(os, arch) {
        Ok(name) => name,
        Err(message) => {
            eprintln!("error: {message}");
            return Ok(ExitCode::OperationalError);
        }
    };

    println!("anne {current} -> {target}");

    let is_terminal = std::io::stdin().is_terminal();
    let confirmation = if args.yes {
        Confirmation::Proceed
    } else if !is_terminal {
        Confirmation::NonInteractiveWithoutYes
    } else {
        print!("Update? [y/N] ");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("reading confirmation")?;
        decide_confirmation(false, true, Some(&answer))
    };

    match confirmation {
        Confirmation::NonInteractiveWithoutYes => {
            eprintln!("error: stdin is not a terminal; pass --yes to update non-interactively");
            return Ok(ExitCode::ConfigOrArgError);
        }
        Confirmation::Aborted => {
            println!("aborted");
            return Ok(ExitCode::Clean);
        }
        Confirmation::Proceed => {}
    }

    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == asset_name)
        .with_context(|| format!("release {} has no {asset_name} asset", release.tag_name))?;
    let sums_asset = release
        .assets
        .iter()
        .find(|asset| asset.name == "SHA256SUMS.txt")
        .with_context(|| format!("release {} has no SHA256SUMS.txt asset", release.tag_name))?;

    let bytes = source
        .download_asset(&asset.download_url)
        .await
        .context("downloading update")?;
    let sums_bytes = source
        .download_asset(&sums_asset.download_url)
        .await
        .context("downloading SHA256SUMS.txt")?;
    let sums_text =
        String::from_utf8(sums_bytes).context("SHA256SUMS.txt is not valid UTF-8")?;

    let expected_digest = expected_digest_for(&sums_text, &asset_name)?;
    let actual_digest = anne_de_breuil::adapters::binary_hash::hash_bytes(&bytes);
    if actual_digest != expected_digest {
        eprintln!(
            "error: checksum mismatch for {asset_name}: expected {expected_digest}, got {actual_digest} -- aborting, nothing on disk was touched"
        );
        return Ok(ExitCode::OperationalError);
    }

    replace_running_executable(target_exe, &bytes)?;
    println!("updated to {target}");
    Ok(ExitCode::Clean)
}

/// The release asset filename this platform's `anne update` should
/// install, or a human-readable reason none exists.
///
/// Pure and parameterized on `(os, arch)` rather than reading
/// `std::env::consts` directly, so every platform combination is
/// unit-testable without cross-compiling.
fn target_asset_name(os: &str, arch: &str) -> Result<String, String> {
    match (os, arch) {
        ("windows", "x86_64") => Ok("anne-x86_64-pc-windows-msvc.exe".to_owned()),
        ("windows", "aarch64") => {
            eprintln!(
                "note: no native aarch64-pc-windows-msvc release is published (a real \
                 cargo-xwin/ring cross-compile bug, see release.yml) -- using the x86_64 \
                 build, which runs under Windows 11 ARM64's built-in x64 emulation"
            );
            Ok("anne-x86_64-pc-windows-msvc.exe".to_owned())
        }
        ("linux", "x86_64") => Ok("anne-x86_64-unknown-linux-musl".to_owned()),
        ("linux", "aarch64") => Ok("anne-aarch64-unknown-linux-musl".to_owned()),
        (os, arch) => Err(format!(
            "no release artifact is published for {os}/{arch}; build from source instead \
             (see README.md)"
        )),
    }
}

/// Finds `asset_name`'s expected digest in `SHA256SUMS.txt`'s contents
/// (`<hex digest>  <file name>` per line -- the exact format
/// `xtask/src/checksum.rs::checksum_line` writes).
fn expected_digest_for(sums_text: &str, asset_name: &str) -> anyhow::Result<String> {
    for line in sums_text.lines() {
        if let Some((digest, name)) = line.split_once("  ")
            && name == asset_name
        {
            return Ok(digest.to_owned());
        }
    }
    anyhow::bail!("SHA256SUMS.txt has no entry for {asset_name}")
}

fn parse_release_version(tag_name: &str) -> anyhow::Result<semver::Version> {
    let stripped = tag_name.strip_prefix('v').unwrap_or(tag_name);
    semver::Version::parse(stripped)
        .with_context(|| format!("parsing release tag {tag_name:?} as semver"))
}

fn current_version() -> anyhow::Result<semver::Version> {
    semver::Version::parse(env!("CARGO_PKG_VERSION")).context("parsing CARGO_PKG_VERSION as semver")
}

enum Confirmation {
    Proceed,
    Aborted,
    NonInteractiveWithoutYes,
}

/// Pure confirmation decision, independently testable without faking a
/// real terminal or real stdin: `yes` always short-circuits to
/// [`Confirmation::Proceed`]; otherwise a non-terminal stdin (`is_terminal
/// = false`) always yields [`Confirmation::NonInteractiveWithoutYes`]
/// regardless of `answer`; otherwise `answer` is checked case-insensitively
/// for `y`/`yes`.
fn decide_confirmation(yes: bool, is_terminal: bool, answer: Option<&str>) -> Confirmation {
    if yes {
        return Confirmation::Proceed;
    }
    if !is_terminal {
        return Confirmation::NonInteractiveWithoutYes;
    }
    match answer.map(str::trim).map(str::to_lowercase).as_deref() {
        Some("y" | "yes") => Confirmation::Proceed,
        _ => Confirmation::Aborted,
    }
}

/// Atomically replaces `target`'s file contents with `new_bytes`.
///
/// Takes `target` as a parameter rather than calling
/// `std::env::current_exe()` itself, so tests can point it at a scratch
/// tempdir file instead of ever touching the real running test binary.
#[cfg(unix)]
fn replace_running_executable(target: &Path, new_bytes: &[u8]) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    // Same directory as `target`, not a system temp dir -- `fs::rename`
    // is only atomic within one filesystem, and a bare `mv` across
    // filesystems silently falls back to copy+delete (a window where a
    // reader could see a partially-written file).
    let dir = target
        .parent()
        .context("current executable path has no parent directory")?;
    let tmp_path = dir.join(".anne.update.tmp");

    std::fs::write(&tmp_path, new_bytes)
        .with_context(|| format!("writing {}", tmp_path.display()))?;

    // OR in the executable bits regardless of what `target`'s prior mode
    // was (or `0o755` if it didn't exist yet) -- we always just wrote a
    // fresh executable, so the result must be runnable even if the old
    // file's permissions were somehow wrong.
    let mode =
        std::fs::metadata(target).map_or(0o755, |metadata| metadata.permissions().mode()) | 0o111;
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting permissions on {}", tmp_path.display()))?;

    // Safe even though `target` is the currently-executing image: Unix
    // lets a file be replaced while it's in use -- the running process
    // keeps its old inode mapped until it exits; only a *future*
    // invocation sees the new file.
    std::fs::rename(&tmp_path, target)
        .with_context(|| format!("replacing {}", target.display()))
}

/// Windows won't allow overwriting or deleting a running `.exe`'s file in
/// place, but does allow renaming it -- rename the current target out of
/// the way first, then write the new bytes to the original path. The
/// `.exe.old` backup is left for a best-effort cleanup on the *next*
/// `anne update` run (deleting it here would fail while the process that
/// just renamed it away from `target` is still that exact file).
#[cfg(windows)]
fn replace_running_executable(target: &Path, new_bytes: &[u8]) -> anyhow::Result<()> {
    let backup = target.with_extension("exe.old");
    let _ = std::fs::remove_file(&backup);
    std::fs::rename(target, &backup)
        .with_context(|| format!("renaming {} to {}", target.display(), backup.display()))?;
    std::fs::write(target, new_bytes).with_context(|| format!("writing {}", target.display()))
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::{Confirmation, decide_confirmation, expected_digest_for, run_with_source, target_asset_name};
    #[cfg(unix)]
    use super::replace_running_executable;
    use crate::cli::{ExitCode, UpdateArgs};
    use crate::ports::{ReleaseAsset, ReleaseInfo, ReleaseSource};

    #[test]
    fn target_asset_name_covers_every_supported_platform() {
        assert_eq!(
            target_asset_name("windows", "x86_64").unwrap(),
            "anne-x86_64-pc-windows-msvc.exe"
        );
        assert_eq!(
            target_asset_name("windows", "aarch64").unwrap(),
            "anne-x86_64-pc-windows-msvc.exe",
            "ARM64 Windows falls back to the x86_64 build (runs under emulation)"
        );
        assert_eq!(
            target_asset_name("linux", "x86_64").unwrap(),
            "anne-x86_64-unknown-linux-musl"
        );
        assert_eq!(
            target_asset_name("linux", "aarch64").unwrap(),
            "anne-aarch64-unknown-linux-musl"
        );
        assert!(target_asset_name("macos", "aarch64").is_err());
    }

    #[test]
    fn expected_digest_for_finds_the_matching_line() {
        let sums = "aaaa  anne-x86_64-unknown-linux-musl\nbbbb  SHA256SUMS.txt\n";
        assert_eq!(
            expected_digest_for(sums, "anne-x86_64-unknown-linux-musl").unwrap(),
            "aaaa"
        );
        assert!(expected_digest_for(sums, "anne-does-not-exist").is_err());
    }

    #[test]
    fn decide_confirmation_covers_every_branch() {
        assert!(matches!(
            decide_confirmation(true, false, None),
            Confirmation::Proceed
        ));
        assert!(matches!(
            decide_confirmation(false, false, None),
            Confirmation::NonInteractiveWithoutYes
        ));
        assert!(matches!(
            decide_confirmation(false, true, Some("y\n")),
            Confirmation::Proceed
        ));
        assert!(matches!(
            decide_confirmation(false, true, Some("Yes\n")),
            Confirmation::Proceed
        ));
        assert!(matches!(
            decide_confirmation(false, true, Some("\n")),
            Confirmation::Aborted
        ));
        assert!(matches!(
            decide_confirmation(false, true, Some("n\n")),
            Confirmation::Aborted
        ));
    }

    #[cfg(unix)]
    #[test]
    fn replace_running_executable_swaps_in_new_bytes() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("anne");
        std::fs::write(&target, b"old bytes").unwrap();

        replace_running_executable(&target, b"new bytes").unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"new bytes");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_ne!(mode & 0o111, 0, "replaced binary must stay executable");
    }

    /// In-memory [`ReleaseSource`] test double -- mirrors
    /// `powershell_collector`'s `Backend::Fixed` pattern for the same
    /// reason: proving the orchestration logic here is correct without
    /// any real network call.
    struct FakeReleaseSource {
        release: ReleaseInfo,
        assets: std::collections::HashMap<String, Vec<u8>>,
    }

    #[async_trait]
    impl ReleaseSource for FakeReleaseSource {
        async fn release(&self, _tag: Option<&str>) -> anyhow::Result<ReleaseInfo> {
            Ok(self.release.clone())
        }

        async fn download_asset(&self, url: &str) -> anyhow::Result<Vec<u8>> {
            self.assets
                .get(url)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no fixture bytes for {url}"))
        }
    }

    fn fixture_source(binary_bytes: &[u8], asset_name: &str, digest: &str) -> FakeReleaseSource {
        let mut assets = std::collections::HashMap::new();
        assets.insert("https://example.invalid/binary".to_owned(), binary_bytes.to_vec());
        assets.insert(
            "https://example.invalid/sums".to_owned(),
            format!("{digest}  {asset_name}\n").into_bytes(),
        );
        FakeReleaseSource {
            release: ReleaseInfo {
                tag_name: "v99.0.0".to_owned(),
                assets: vec![
                    ReleaseAsset {
                        name: asset_name.to_owned(),
                        download_url: "https://example.invalid/binary".to_owned(),
                    },
                    ReleaseAsset {
                        name: "SHA256SUMS.txt".to_owned(),
                        download_url: "https://example.invalid/sums".to_owned(),
                    },
                ],
            },
            assets,
        }
    }

    /// Fixed at `("linux", "x86_64")` rather than `std::env::consts::{OS,
    /// ARCH}` -- these tests must pass on every CI runner in the matrix,
    /// including macOS, which `target_asset_name` deliberately rejects
    /// (no macOS release is published; see its own test above), so
    /// `run_with_source`'s `os`/`arch` parameters exist specifically to
    /// let orchestration tests pin a supported platform independently of
    /// whatever host happens to be running the test suite.
    const TEST_OS: &str = "linux";
    const TEST_ARCH: &str = "x86_64";

    fn test_asset_name() -> String {
        target_asset_name(TEST_OS, TEST_ARCH).expect("linux/x86_64 is a supported platform")
    }

    #[tokio::test]
    async fn check_reports_an_available_update_without_touching_the_filesystem() {
        let asset_name = test_asset_name();
        let source = fixture_source(b"new bytes", &asset_name, "irrelevant-for-check");
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("anne");

        let args = UpdateArgs {
            yes: false,
            check: true,
            version: None,
        };
        let code = run_with_source(&source, &args, &target, TEST_OS, TEST_ARCH)
            .await
            .unwrap();

        assert!(matches!(code, ExitCode::Clean));
        assert!(!target.exists(), "--check must never write anything");
    }

    #[tokio::test]
    async fn yes_flag_with_a_correct_checksum_replaces_the_target_file() {
        let asset_name = test_asset_name();
        let binary_bytes = b"a totally real anne binary";
        let digest = anne_de_breuil::adapters::binary_hash::hash_bytes(binary_bytes);
        let source = fixture_source(binary_bytes, &asset_name, &digest);
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("anne");
        std::fs::write(&target, b"old bytes").unwrap();

        let args = UpdateArgs {
            yes: true,
            check: false,
            version: None,
        };
        let code = run_with_source(&source, &args, &target, TEST_OS, TEST_ARCH)
            .await
            .unwrap();

        assert!(matches!(code, ExitCode::Clean));
        assert_eq!(std::fs::read(&target).unwrap(), binary_bytes);
    }

    #[tokio::test]
    async fn checksum_mismatch_aborts_before_touching_the_filesystem() {
        let asset_name = test_asset_name();
        let binary_bytes = b"a totally real anne binary";
        let source = fixture_source(binary_bytes, &asset_name, "0000000000000000");
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("anne");
        std::fs::write(&target, b"old bytes").unwrap();

        let args = UpdateArgs {
            yes: true,
            check: false,
            version: None,
        };
        let code = run_with_source(&source, &args, &target, TEST_OS, TEST_ARCH)
            .await
            .unwrap();

        assert!(matches!(code, ExitCode::OperationalError));
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"old bytes",
            "a checksum mismatch must never touch the target file"
        );
    }
}
