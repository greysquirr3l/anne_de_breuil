//! `cargo run -p xtask -- checksum <write|verify> ...`
//!
//! The release workflow's own checksum mechanism, not just documentation
//! of one: `write` hashes each release artifact into a `sha256sum`-format
//! manifest published alongside the release; `verify` re-hashes every
//! artifact a manifest names and fails on the first mismatch, which is
//! exactly what a release dry run needs to prove the published checksums
//! match the bytes they ship next to. The SSH transport's own integrity
//! check (`adapters::ssh_transport`, T15) compares a pushed collector
//! against a hash the same way -- this is the release-time half of that
//! same "never trust a binary without checking its hash" posture.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use sha2::{Digest, Sha256};

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// One `sha256sum`-format line: `<hex digest>  <file name>`.
///
/// # Errors
///
/// Returns an error if `path` can't be read, or its file name isn't valid UTF-8.
pub fn checksum_line(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("{} has no valid UTF-8 file name", path.display()))?;
    Ok(format!("{}  {name}", sha256_hex(&bytes)))
}

/// Writes a manifest covering every artifact in `paths`, one line per file,
/// sorted by file name so the output is deterministic regardless of the
/// order a release's parallel build jobs happen to finish in.
///
/// # Errors
///
/// Returns an error if any artifact can't be hashed, or the manifest can't be written.
pub fn write_manifest(paths: &[PathBuf], manifest_path: &Path) -> anyhow::Result<()> {
    let mut lines = paths
        .iter()
        .map(|p| checksum_line(p))
        .collect::<anyhow::Result<Vec<_>>>()?;
    lines.sort();
    let mut contents = lines.join("\n");
    contents.push('\n');
    fs::write(manifest_path, contents)
        .with_context(|| format!("writing {}", manifest_path.display()))
}

/// Re-hashes every artifact `manifest_path` names (resolved under
/// `artifact_dir`) and fails on the first digest mismatch.
///
/// # Errors
///
/// Returns an error on a malformed manifest line, a missing artifact, or a checksum mismatch.
pub fn verify_manifest(manifest_path: &Path, artifact_dir: &Path) -> anyhow::Result<()> {
    let manifest = fs::read_to_string(manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    for line in manifest.lines() {
        let Some((expected_digest, name)) = line.split_once("  ") else {
            bail!("malformed checksum line: {line:?}");
        };
        let artifact_path = artifact_dir.join(name);
        let actual_line = checksum_line(&artifact_path)?;
        let Some((actual_digest, _)) = actual_line.split_once("  ") else {
            bail!("internal error re-hashing {}", artifact_path.display());
        };
        ensure!(
            actual_digest == expected_digest,
            "checksum mismatch for {name}: manifest says {expected_digest}, artifact hashes to {actual_digest}"
        );
    }
    Ok(())
}

pub fn run(mut args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    match args.next().as_deref() {
        Some("write") => {
            let manifest_path = PathBuf::from(args.next().context(
                "usage: cargo run -p xtask -- checksum write <manifest-path> <artifact>...",
            )?);
            let paths: Vec<PathBuf> = args.map(PathBuf::from).collect();
            ensure!(
                !paths.is_empty(),
                "checksum write needs at least one artifact path"
            );
            write_manifest(&paths, &manifest_path)?;
            println!("wrote {}", manifest_path.display());
            Ok(())
        }
        Some("verify") => {
            let manifest_path = PathBuf::from(args.next().context(
                "usage: cargo run -p xtask -- checksum verify <manifest-path> <artifact-dir>",
            )?);
            let artifact_dir = PathBuf::from(args.next().context(
                "usage: cargo run -p xtask -- checksum verify <manifest-path> <artifact-dir>",
            )?);
            verify_manifest(&manifest_path, &artifact_dir)?;
            println!("all checksums in {} verified", manifest_path.display());
            Ok(())
        }
        Some(other) => {
            anyhow::bail!("unknown checksum subcommand `{other}` -- known: write, verify")
        }
        None => anyhow::bail!("usage: cargo run -p xtask -- checksum <write|verify> ..."),
    }
}

#[cfg(test)]
mod tests {
    use super::{sha256_hex, verify_manifest, write_manifest};
    use std::fs;

    #[test]
    fn sha256_hex_matches_known_vector() {
        // sha256("") -- the canonical empty-input test vector.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Real dry run of the write-then-verify roundtrip against real files
    /// on disk (not a hardcoded digest asserted against itself) -- proves
    /// the mechanism a release dry run relies on: a manifest this crate
    /// writes is one it can also independently confirm against the same
    /// bytes.
    #[test]
    fn written_manifest_verifies_against_the_same_artifacts() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let artifact_a = dir.path().join("anne-x86_64-unknown-linux-musl");
        let artifact_b = dir.path().join("anne-aarch64-unknown-linux-musl");
        fs::write(&artifact_a, b"pretend-static-binary-x86_64").expect("write artifact a");
        fs::write(&artifact_b, b"pretend-static-binary-aarch64").expect("write artifact b");

        let manifest_path = dir.path().join("SHA256SUMS.txt");
        write_manifest(&[artifact_a, artifact_b], &manifest_path).expect("write manifest");

        verify_manifest(&manifest_path, dir.path()).expect("verify manifest");
    }

    /// The negative case matters as much as the happy path here: a
    /// checksum mechanism that can't detect a tampered artifact isn't
    /// actually verifying anything.
    #[test]
    fn verify_fails_when_an_artifact_is_tampered_with_after_the_manifest_is_written() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let artifact = dir.path().join("anne-x86_64-unknown-linux-musl");
        fs::write(&artifact, b"original bytes").expect("write artifact");

        let manifest_path = dir.path().join("SHA256SUMS.txt");
        write_manifest(std::slice::from_ref(&artifact), &manifest_path).expect("write manifest");

        fs::write(&artifact, b"tampered bytes").expect("tamper with artifact");

        let result = verify_manifest(&manifest_path, dir.path());
        assert!(
            result.is_err(),
            "verify_manifest must reject a mismatched artifact"
        );
    }
}
