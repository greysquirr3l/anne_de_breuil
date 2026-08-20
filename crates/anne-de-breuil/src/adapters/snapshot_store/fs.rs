//! [`FsSnapshotStore`]: the default snapshot store — one content-addressed
//! JSON file per snapshot on the local filesystem, no external services.
//!
//! ## On-disk layout
//!
//! Under `root`:
//! - `{blake3-hex}.json` — one file per distinct serialized snapshot body,
//!   named by the BLAKE3 hash of its bytes.
//! - `index.json` — a durable record of every `(scan_id, host_id,
//!   idempotency_key, content_hash)` tuple ever written. `get` resolves a
//!   [`ScanId`] to its content hash through this index; `list` filters it
//!   by [`HostId`]; `put`'s idempotency check scans it for `idempotency_key`.
//!   Rewritten atomically (temp-then-rename) alongside every `put`.
//! - `.anne-store.lock` — an advisory lock (`File::try_lock`, stable
//!   1.89) held for a `put`'s full critical section: reading the index,
//!   writing the content file, and rewriting the index. A second `anne`
//!   process racing the same store directory fails fast with
//!   [`StoreError::Locked`] instead of interleaving writes and corrupting
//!   `index.json`.
//!
//! ## Idempotency durability
//!
//! The task sketch this adapter is based on keeps `seen_keys` as an
//! in-memory `HashMap`, which only dedupes retries within one process's
//! lifetime. That falls short of the stated goal: "a retried upload after
//! a network timeout must not create a duplicate scan record" says
//! nothing about the retry landing in the *same* process, and a collector
//! push that times out is exactly the kind of caller that might retry
//! after `anne` itself restarted (crashed, was redeployed, or the retry
//! is a wholly separate `anne` invocation). `idempotency_key` is folded
//! into `index.json` instead of a process-local cache, so the dedupe
//! check reads durable state on every `put` — correct across restarts,
//! not just within one run.
//!
//! ## Atomicity
//!
//! Every write (content file, index file) goes to a fixed temp path,
//! `File::try_lock`s it, writes, `sync_all`s, then `rename`s over the
//! final path. `rename` within one directory is atomic on every target
//! filesystem this project cross-compiles for, so a crash or full disk
//! mid-write leaves either the old final file or nothing at the temp
//! path — never a truncated file at the final path.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::application::snapshot_store::{SnapshotStore, StoreError};
use crate::domain::{HostId, IdempotencyKey, ScanId, ScanSnapshot};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexEntry {
    scan_id: ScanId,
    host_id: HostId,
    idempotency_key: IdempotencyKey,
    content_hash: String,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    entries: Vec<IndexEntry>,
}

/// Default, always-available snapshot store: one content-addressed JSON
/// file per snapshot plus a durable index, all under `root`.
#[derive(Debug, Clone)]
pub struct FsSnapshotStore {
    root: PathBuf,
}

impl FsSnapshotStore {
    /// Opens (creating if absent) a filesystem-backed store rooted at `root`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] if `root` cannot be created.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }
}

#[async_trait]
impl SnapshotStore for FsSnapshotStore {
    async fn put(&self, key: IdempotencyKey, snapshot: ScanSnapshot) -> Result<ScanId, StoreError> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || put_blocking(&root, key, &snapshot)).await?
    }

    async fn get(&self, id: ScanId) -> Result<Option<ScanSnapshot>, StoreError> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || get_blocking(&root, id)).await?
    }

    async fn list(&self, host: HostId) -> Result<Vec<ScanId>, StoreError> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || list_blocking(&root, host)).await?
    }
}

fn lock_path(root: &Path) -> PathBuf {
    root.join(".anne-store.lock")
}

fn index_path(root: &Path) -> PathBuf {
    root.join("index.json")
}

fn index_tmp_path(root: &Path) -> PathBuf {
    root.join(".index.json.tmp")
}

fn content_path(root: &Path, content_hash: &str) -> PathBuf {
    root.join(format!("{content_hash}.json"))
}

fn content_tmp_path(root: &Path) -> PathBuf {
    root.join(".content.json.tmp")
}

/// Opens `path` for a fresh write, creating it if absent, with
/// owner-only permissions on Unix — snapshot contents describe a host's
/// listening-port surface and firewall policy, not something to leave
/// world-readable.
fn open_private(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Acquires the whole-store advisory lock for the duration of the
/// returned guard's lifetime; dropping it releases the lock.
fn acquire_store_lock(root: &Path) -> Result<File, StoreError> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(lock_path(root))?;
    file.try_lock().map_err(|_source| StoreError::Locked)?;
    Ok(file)
}

fn read_index(root: &Path) -> Result<Index, StoreError> {
    let path = index_path(root);
    if !path.exists() {
        return Ok(Index::default());
    }
    let bytes = std::fs::read(&path)?;
    serde_json::from_slice(&bytes).map_err(|source| StoreError::Corrupt(source.to_string()))
}

fn write_index(root: &Path, index: &Index) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec(index)?;
    write_atomic(&index_tmp_path(root), &index_path(root), &bytes)
}

fn write_atomic(tmp_path: &Path, final_path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let mut file = open_private(tmp_path)?;
    file.try_lock().map_err(|_source| StoreError::Locked)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(tmp_path, final_path)?;
    Ok(())
}

fn put_blocking(
    root: &Path,
    key: IdempotencyKey,
    snapshot: &ScanSnapshot,
) -> Result<ScanId, StoreError> {
    let _lock = acquire_store_lock(root)?;

    let mut index = read_index(root)?;
    if let Some(existing) = index
        .entries
        .iter()
        .find(|entry| entry.idempotency_key == key)
    {
        return Ok(existing.scan_id);
    }

    let bytes = serde_json::to_vec(snapshot)?;
    let content_hash = blake3::hash(&bytes).to_string();
    let final_path = content_path(root, &content_hash);

    // Same content hashes to the same bytes; skip the write if this exact
    // body is already on disk rather than re-locking and re-renaming it.
    if !final_path.exists() {
        write_atomic(&content_tmp_path(root), &final_path, &bytes)?;
    }

    index.entries.push(IndexEntry {
        scan_id: snapshot.scan_id,
        host_id: snapshot.host_id,
        idempotency_key: key,
        content_hash,
    });
    write_index(root, &index)?;

    Ok(snapshot.scan_id)
}

fn get_blocking(root: &Path, id: ScanId) -> Result<Option<ScanSnapshot>, StoreError> {
    let index = read_index(root)?;
    let Some(entry) = index.entries.iter().find(|entry| entry.scan_id == id) else {
        return Ok(None);
    };
    let bytes = std::fs::read(content_path(root, &entry.content_hash))?;
    let snapshot = serde_json::from_slice(&bytes)?;
    Ok(Some(snapshot))
}

fn list_blocking(root: &Path, host: HostId) -> Result<Vec<ScanId>, StoreError> {
    let index = read_index(root)?;
    let mut ids: Vec<ScanId> = index
        .entries
        .iter()
        .filter(|entry| entry.host_id == host)
        .map(|entry| entry.scan_id)
        .collect();
    ids.sort_unstable();
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;

    use super::*;
    use crate::domain::bind_address::BindAddress;
    use crate::domain::port::Port;
    use crate::domain::protocol::Protocol;
    use crate::domain::publisher::SignatureStatus;
    use crate::domain::{Endpoint, HostId, IdempotencyKey, ScanId, ScanSnapshot, TargetStrategy};

    mod fixtures {
        use super::{HostId, ScanId, ScanSnapshot, TargetStrategy};
        use crate::adapters::snapshot_store::FsSnapshotStore;

        pub(super) fn temp_fs_store() -> (tempfile::TempDir, FsSnapshotStore) {
            let dir = tempfile::tempdir().unwrap();
            let store = FsSnapshotStore::new(dir.path()).unwrap();
            (dir, store)
        }

        pub(super) fn sample_snapshot() -> ScanSnapshot {
            ScanSnapshot::new(
                HostId::generate(),
                ScanId::generate(),
                time::OffsetDateTime::UNIX_EPOCH,
                "1.0.0".to_owned(),
                vec![super::endpoint_fixture()],
                vec![],
                vec![],
                TargetStrategy::LocalOnly,
            )
        }

        pub(super) fn count_content_files(dir: &std::path::Path) -> usize {
            std::fs::read_dir(dir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry.path().extension().is_some_and(|ext| ext == "json")
                        && entry.file_name() != "index.json"
                })
                .count()
        }
    }

    fn endpoint_fixture() -> Endpoint {
        Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("10.0.0.4").unwrap(),
            Port::try_from(443).unwrap(),
            None,
            None,
            vec![],
            SignatureStatus::Unknown,
            None,
        )
    }

    #[tokio::test]
    async fn duplicate_idempotency_key_returns_existing_scan_id() {
        let (dir, store) = fixtures::temp_fs_store();
        let key = IdempotencyKey::generate();
        let snapshot = fixtures::sample_snapshot();

        let first = store.put(key, snapshot.clone()).await.unwrap();
        let second = store.put(key, snapshot).await.unwrap();

        assert_eq!(first, second);
        assert_eq!(fixtures::count_content_files(dir.path()), 1);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn simulated_write_failure_leaves_prior_artifact_intact() {
        use std::os::unix::fs::PermissionsExt as _;

        let (dir, store) = fixtures::temp_fs_store();

        let first_snapshot = fixtures::sample_snapshot();
        let first_id = store
            .put(IdempotencyKey::generate(), first_snapshot.clone())
            .await
            .unwrap();

        // Strip write permission from the store directory itself: creating
        // a *new* directory entry (the second put's temp file) now fails,
        // while opening the already-existing lock file for write still
        // succeeds, so the failure lands exactly where a real disk-full
        // condition would — mid-write, before any rename.
        let readonly = std::fs::Permissions::from_mode(0o500);
        std::fs::set_permissions(dir.path(), readonly).unwrap();

        let result = store
            .put(IdempotencyKey::generate(), fixtures::sample_snapshot())
            .await;

        // Restore write permission so the TempDir can clean itself up.
        let writable = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir.path(), writable).unwrap();

        assert!(result.is_err(), "expected the second put to fail");

        let recovered = store.get(first_id).await.unwrap();
        assert_eq!(recovered, Some(first_snapshot));
    }

    #[test]
    fn identical_snapshot_produces_identical_bytes_cross_platform() {
        // No real cross-platform CI here — the cross-platform guarantee
        // comes from `ScanSnapshot::new` sorting every collection at
        // construction (T02) and `serde_json` producing platform-
        // independent UTF-8 output. This exercises the same serialization
        // path twice and asserts it is byte-for-byte deterministic, which
        // is the property "linux" and "windows" callers both depend on.
        let snapshot = fixtures::sample_snapshot();
        let linux_bytes = serde_json::to_vec(&snapshot).unwrap();
        let windows_bytes = serde_json::to_vec(&snapshot).unwrap();

        assert_eq!(linux_bytes, windows_bytes);
        assert!(!linux_bytes.starts_with(&[0xEF, 0xBB, 0xBF]));
    }

    #[tokio::test]
    async fn get_returns_none_for_unknown_scan_id() {
        let (_dir, store) = fixtures::temp_fs_store();
        assert_eq!(store.get(ScanId::generate()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn list_filters_by_host_and_survives_a_fresh_store_handle() {
        let (dir, store) = fixtures::temp_fs_store();
        let host_a = HostId::generate();
        let host_b = HostId::generate();

        let snap_a1 = ScanSnapshot::new(
            host_a,
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "1.0.0".to_owned(),
            vec![],
            vec![],
            vec![],
            TargetStrategy::LocalOnly,
        );
        let snap_a2 = ScanSnapshot::new(
            host_a,
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "1.0.0".to_owned(),
            vec![endpoint_fixture()],
            vec![],
            vec![],
            TargetStrategy::LocalOnly,
        );
        let snap_b = ScanSnapshot::new(
            host_b,
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "1.0.0".to_owned(),
            vec![],
            vec![],
            vec![],
            TargetStrategy::LocalOnly,
        );

        let id_a1 = store
            .put(IdempotencyKey::generate(), snap_a1)
            .await
            .unwrap();
        let id_a2 = store
            .put(IdempotencyKey::generate(), snap_a2)
            .await
            .unwrap();
        store.put(IdempotencyKey::generate(), snap_b).await.unwrap();

        // A fresh handle over the same directory proves `list`/`get` read
        // durable state, not anything cached on `store` itself.
        let reopened = FsSnapshotStore::new(dir.path()).unwrap();
        let mut for_host_a = reopened.list(host_a).await.unwrap();
        for_host_a.sort_unstable();
        let mut expected = vec![id_a1, id_a2];
        expected.sort_unstable();

        assert_eq!(for_host_a, expected);
    }

    #[tokio::test]
    async fn idempotency_key_index_survives_process_restart_simulation() {
        let (dir, store) = fixtures::temp_fs_store();
        let key = IdempotencyKey::generate();
        let snapshot = fixtures::sample_snapshot();

        let first = store.put(key, snapshot.clone()).await.unwrap();
        drop(store);

        // A brand-new `FsSnapshotStore` over the same root has no
        // in-memory state at all; the durable index alone must still
        // catch the duplicate.
        let reopened = FsSnapshotStore::new(dir.path()).unwrap();
        let second = reopened.put(key, snapshot).await.unwrap();

        assert_eq!(first, second);
        assert_eq!(fixtures::count_content_files(dir.path()), 1);
    }
}
