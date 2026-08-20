//! [`SnapshotStore`]: the port for persisting and retrieving scan snapshots.
//!
//! Declared here, not in `domain`, because persistence is a capability a
//! use case *consumes* — a scan or drift use case depends on this trait,
//! never on a concrete adapter, so it stays testable with an in-memory
//! fake and swappable between the filesystem and `SQLite` backends.

use async_trait::async_trait;

use crate::domain::{HostId, IdempotencyKey, ScanId, ScanSnapshot};

/// Persists and retrieves content-addressed scan snapshots.
///
/// Exactly three operations, the ceiling per the task this port was
/// specified under: `put` is idempotent on `IdempotencyKey` — a retried
/// upload after a network timeout must return the same [`ScanId`] rather
/// than creating a duplicate record — `get` resolves one snapshot by id,
/// `list` enumerates every scan recorded for a host.
#[async_trait]
pub trait SnapshotStore: Send + Sync {
    /// Stores `snapshot` under `key`.
    ///
    /// If `key` has already been used in a prior successful `put` (on
    /// this store, surviving process restarts), returns the [`ScanId`]
    /// from that earlier call without writing anything new — the
    /// idempotency contract is enforced by the adapter, not left to the
    /// caller to deduplicate.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the snapshot cannot be durably persisted.
    async fn put(&self, key: IdempotencyKey, snapshot: ScanSnapshot) -> Result<ScanId, StoreError>;

    /// Fetches the snapshot recorded under `id`, or `None` if no such scan exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store cannot be read or a recorded
    /// artifact fails to parse.
    async fn get(&self, id: ScanId) -> Result<Option<ScanSnapshot>, StoreError>;

    /// Lists every [`ScanId`] recorded for `host`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store cannot be read.
    async fn list(&self, host: HostId) -> Result<Vec<ScanId>, StoreError>;
}

/// Failure persisting or retrieving a snapshot through a [`SnapshotStore`].
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The underlying filesystem operation failed.
    #[error("snapshot store I/O failure: {0}")]
    Io(#[from] std::io::Error),

    /// A snapshot or index entry failed to serialize or deserialize.
    #[error("snapshot store serialization failure: {0}")]
    Serde(#[from] serde_json::Error),

    /// A concurrent writer already holds the store's lock.
    #[error("snapshot store is locked by another writer")]
    Locked,

    /// A stored record (index entry, or a row's identifier column) failed
    /// to parse back into its expected domain type.
    #[error("snapshot store record is corrupt: {0}")]
    Corrupt(String),

    /// The blocking store task panicked or was cancelled.
    #[error("snapshot store background task failed: {0}")]
    Join(#[from] tokio::task::JoinError),

    /// The `SQLite` backend reported a failure.
    ///
    /// Boxed: `rusqlite::Error` carries a full `ffi::Error` plus an
    /// optional extended message and trips `clippy::result_large_err`
    /// left bare, same reasoning as `ConfigError` boxing `figment::Error`.
    #[cfg(feature = "store-sqlite")]
    #[error("sqlite snapshot store failure: {0}")]
    Sqlite(#[from] Box<rusqlite::Error>),
}
