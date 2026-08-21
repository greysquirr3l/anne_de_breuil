//! Hashes this process's own executable file.
//!
//! One small piece of logic, shared by two call sites that must never
//! disagree on how a hash is computed: `anne --self-hash` (the mode the
//! pushed collector runs remotely, on the target host) and
//! [`crate::adapters::remote_scanner`]'s `Execute` path (which computes the
//! hash locally, on the orchestrator's own machine, before push —
//! `SshTransport::push_exec_collect_remove`'s doc comment is explicit that
//! "the caller owns that" computation). Both sides hash the exact same
//! bytes for the exact same reason: the collector this crate pushes to a
//! remote host *is* this same binary, invoked there with `--self-hash`
//! instead of `--emit-json`.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Failure locating or reading the bytes to hash.
#[derive(Debug, thiserror::Error)]
pub enum BinaryHashError {
    /// The OS could not report the path of the running executable.
    #[error("locating the running executable failed: {0}")]
    LocateExe(#[source] std::io::Error),
    /// The executable file could not be read.
    #[error("reading executable file {path}: {source}")]
    ReadExe {
        /// The path that failed to read.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
}

/// Lowercase hex SHA-256 digest of `bytes`.
#[must_use]
pub fn hash_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Reads `path` and returns its lowercase hex SHA-256 digest.
///
/// # Errors
///
/// Returns [`BinaryHashError::ReadExe`] if `path` cannot be read.
pub fn hash_file(path: &Path) -> Result<String, BinaryHashError> {
    let bytes = std::fs::read(path).map_err(|source| BinaryHashError::ReadExe {
        path: path.to_owned(),
        source,
    })?;
    Ok(hash_bytes(&bytes))
}

/// Locates the currently running executable and hashes it.
///
/// # Errors
///
/// Returns [`BinaryHashError::LocateExe`] if the OS cannot report this
/// process's own executable path, or [`BinaryHashError::ReadExe`] if that
/// path cannot be read.
pub fn locate_and_hash_current_exe() -> Result<(PathBuf, String), BinaryHashError> {
    let exe = std::env::current_exe().map_err(BinaryHashError::LocateExe)?;
    let hash = hash_file(&exe)?;
    Ok((exe, hash))
}

#[cfg(test)]
mod tests {
    use super::{hash_bytes, hash_file, locate_and_hash_current_exe};

    #[test]
    fn hash_bytes_matches_a_known_sha256_vector() {
        // SHA-256("") — the standard empty-input test vector.
        assert_eq!(
            hash_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash_bytes_is_deterministic_and_sensitive_to_every_byte() {
        assert_eq!(hash_bytes(b"anne-de-breuil"), hash_bytes(b"anne-de-breuil"));
        assert_ne!(hash_bytes(b"anne-de-breuil"), hash_bytes(b"anne-de-breuiL"));
    }

    #[test]
    fn hash_file_matches_hash_bytes_for_the_same_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fixture.bin");
        std::fs::write(&path, b"some fixture content").expect("write fixture");

        assert_eq!(
            hash_file(&path).expect("hash_file succeeds"),
            hash_bytes(b"some fixture content")
        );
    }

    #[test]
    fn hash_file_reports_a_real_error_for_a_missing_path() {
        let path = std::env::temp_dir().join("anne-binary-hash-missing-fixture-does-not-exist");
        assert!(hash_file(&path).is_err());
    }

    #[test]
    fn locate_and_hash_current_exe_hashes_the_real_test_binary() {
        // The test harness binary is a real, already-built executable on
        // disk -- this proves current_exe()/read/hash all actually work
        // together against a real file, not just a fixture we wrote.
        let (path, hash) = locate_and_hash_current_exe().expect("locate and hash test binary");
        assert!(path.exists());
        assert_eq!(hash.len(), 64, "sha256 hex digest is 64 chars");
        assert!(
            hash.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}
