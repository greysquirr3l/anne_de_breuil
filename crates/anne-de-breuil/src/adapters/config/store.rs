//! `[store]` section: where scan snapshots are persisted.

use std::path::PathBuf;

/// Snapshot persistence backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StoreBackend {
    /// One content-addressed file per snapshot on the local filesystem.
    FileSystem,
    /// `SQLite`-backed store (requires the `store-sqlite` build feature).
    Sqlite,
}

/// Snapshot persistence settings.
///
/// Deliberately has no [`Default`] impl: where scan data lands is a
/// decision every operator must make explicitly, so a config that omits
/// `[store]` (or omits `backend`) fails to load rather than silently
/// persisting snapshots somewhere unexpected.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    /// Which backend persists snapshots.
    pub backend: StoreBackend,
    /// Backend-specific location: a directory for `FileSystem`, a database
    /// file for `Sqlite`.
    pub path: PathBuf,
}
