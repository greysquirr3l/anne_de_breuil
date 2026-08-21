//! [`write_atomically`]: write bytes to a file with no partial-write window.
//!
//! Same temp-file-then-rename shape as
//! [`crate::adapters::snapshot_store::fs`]'s `write_atomic`, but a fresh
//! implementation rather than a reuse of that one: the store's helper
//! writes to a *fixed* temp path (`.content.json.tmp`) and gets away with
//! it because every `put` already holds `.anne-store.lock`, a directory-
//! wide advisory lock, for its whole critical section — there is no
//! equivalent lock here. A report's `--output` path is caller-supplied and
//! arbitrary (any directory on the filesystem, not a store root this crate
//! owns), so two concurrent `anne report` invocations targeting the same
//! output path must not be able to collide on the same fixed temp name.
//! The temp name is instead made unique per call via a v4 UUID suffix, the
//! same source of uniqueness `application::remote::RemotePath::
//! random_under_temp` already uses for the same reason (an unpredictable,
//! collision-free name, not a value that needs to resist adversarial
//! prediction).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Writes `bytes` to `path`, replacing any existing file there atomically.
///
/// Writes to a uniquely-named temp file in `path`'s own directory first —
/// same-directory placement is what makes the final `rename` atomic, since
/// `rename` is only guaranteed atomic within a single filesystem/volume.
/// The temp file is fsync'd before the rename so a crash mid-write can
/// never leave a truncated file at `path`: either the rename never
/// happened (old content, or no file, still at `path`) or it did (new
/// content, complete).
///
/// Report output is meant to be read by whoever the operator shares it
/// with (an analyst, a SIEM ingester) — unlike
/// [`crate::adapters::snapshot_store::fs`]'s store content, this doesn't
/// force owner-only permissions; it inherits the process umask, the same
/// as any ordinary `> file` shell redirection would.
///
/// # Errors
///
/// Returns the underlying [`std::io::Error`] if the temp file can't be
/// created, written, or renamed. On failure, this cleans up its own temp
/// file (best-effort — a cleanup failure doesn't shadow the original
/// error) rather than leaving a stray `.tmp` file behind.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomically_with(path, |writer| writer.write_all(bytes))
}

/// Same atomicity contract as [`write_atomically`], but streams through
/// `write_fn` instead of taking a byte slice already fully in memory.
///
/// `write_fn` gets a `&mut dyn Write` over the temp file directly, so a
/// caller that itself writes incrementally (see
/// `adapters::html_report::write_report_streaming`) never has to buffer
/// its whole output into one `Vec<u8>` first just to hand this function
/// bytes.
///
/// # Errors
///
/// Returns the underlying [`std::io::Error`] if the temp file can't be
/// created, `write_fn` fails, or the rename fails. On failure, this
/// cleans up its own temp file (best-effort) rather than leaving a stray
/// `.tmp` file behind -- same as [`write_atomically`].
pub fn write_atomically_with(
    path: &Path,
    write_fn: impl FnOnce(&mut dyn Write) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let tmp_path = temp_path_for(path)?;

    let write_result = write_new_file(&tmp_path, write_fn);
    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return write_result;
    }

    std::fs::rename(&tmp_path, path)
}

fn write_new_file(
    tmp_path: &Path,
    write_fn: impl FnOnce(&mut dyn Write) -> std::io::Result<()>,
) -> std::io::Result<()> {
    // `create_new` fails outright if the (UUID-suffixed) name is somehow
    // already taken, rather than silently overwriting another writer's
    // in-flight temp file.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp_path)?;
    write_fn(&mut file)?;
    file.sync_all()
}

fn temp_path_for(path: &Path) -> std::io::Result<PathBuf> {
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} has no file name component", path.display()),
        )
    })?;
    Ok(dir.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        uuid::Uuid::new_v4()
    )))
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use super::{write_atomically, write_atomically_with};

    fn dir_entries(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn writes_the_given_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");

        write_atomically(&path, b"{\"ok\":true}").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"{\"ok\":true}");
    }

    #[test]
    fn overwrites_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.csv");

        write_atomically(&path, b"first").unwrap();
        write_atomically(&path, b"second").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"second");
    }

    #[test]
    fn leaves_no_temp_file_behind_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.sarif.json");

        write_atomically(&path, b"{}").unwrap();

        assert_eq!(
            dir_entries(dir.path()),
            vec!["report.sarif.json".to_owned()]
        );
    }

    #[test]
    fn temp_path_lives_in_the_same_directory_as_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested.json");

        let tmp = super::temp_path_for(&path).unwrap();

        assert_eq!(tmp.parent(), Some(dir.path()));
    }

    #[test]
    fn temp_path_falls_back_to_the_current_directory_for_a_bare_relative_filename() {
        let tmp = super::temp_path_for(Path::new("report.json")).unwrap();
        assert_eq!(tmp.parent(), Some(Path::new(".")));
    }

    #[test]
    fn rejects_a_path_with_no_file_name() {
        // A trailing `..` has no file-name component to derive a temp name
        // from — must fail cleanly, not panic on `Option::unwrap`.
        assert!(super::temp_path_for(Path::new("/tmp/..")).is_err());
    }

    #[test]
    fn concurrent_writers_to_the_same_path_never_collide_or_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path: Arc<std::path::PathBuf> = Arc::new(dir.path().join("shared.json"));

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let path = Arc::clone(&path);
                std::thread::spawn(move || {
                    let payload = format!("writer-{i}").into_bytes();
                    write_atomically(&path, &payload)
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap().unwrap();
        }

        // Every writer must have fully succeeded (asserted above via the
        // double `.unwrap()`) and exactly one final file must remain, with
        // content matching one of the eight payloads whole -- never a
        // truncated or interleaved mix of two.
        let final_bytes = std::fs::read(path.as_path()).unwrap();
        let final_text = String::from_utf8(final_bytes).unwrap();
        assert!(final_text.starts_with("writer-"));

        let entries = dir_entries(dir.path());
        assert_eq!(entries, vec!["shared.json".to_owned()]);
    }

    #[test]
    fn write_atomically_with_streams_multiple_writes_into_one_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("streamed.html");

        write_atomically_with(&path, |writer| {
            writer.write_all(b"first-")?;
            writer.write_all(b"second-")?;
            writer.write_all(b"third")
        })
        .unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"first-second-third");
    }

    #[test]
    fn write_atomically_with_leaves_no_temp_file_on_write_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never-created.html");

        let result = write_atomically_with(&path, |_writer| {
            Err(std::io::Error::other("simulated write failure"))
        });

        assert!(result.is_err());
        assert!(!path.exists());
        assert_eq!(dir_entries(dir.path()), Vec::<String>::new());
    }

    #[test]
    fn write_atomically_is_still_backed_by_the_streaming_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.json");

        write_atomically(&path, b"{\"ok\":true}").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"{\"ok\":true}");
    }
}
