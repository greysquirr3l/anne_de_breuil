//! [`SqliteSnapshotStore`]: a `SQLite`-backed snapshot store for fleet
//! volumes where a flat file per scan becomes unwieldy.
//!
//! Gated behind the `store-sqlite` feature — a collector-only build never
//! links `rusqlite` (and, via its `bundled` feature, a vendored `SQLite`
//! amalgamation).
//!
//! `rusqlite` is synchronous; every method wraps its work in
//! [`tokio::task::spawn_blocking`] and never lets `&rusqlite::Transaction`
//! or `&rusqlite::Connection` escape this module — application code only
//! ever sees the [`SnapshotStore`] trait.
//!
//! Idempotency is enforced with a real transactional guarantee rather
//! than the filesystem adapter's advisory lock: `idempotency_key` carries
//! a `UNIQUE` constraint, and `put` checks-then-inserts inside one
//! transaction. If two writers race between the check and the insert,
//! the constraint rejects the loser's `INSERT`; the loser then reads back
//! the winner's row and returns *that* `ScanId`, so both callers observe
//! the same idempotent result regardless of which one's transaction
//! physically landed first.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use core::str::FromStr as _;

use crate::application::snapshot_store::{SnapshotStore, StoreError};
use crate::domain::{HostId, IdempotencyKey, ScanId, ScanSnapshot};

/// `SQLite`-backed snapshot store, available behind the `store-sqlite`
/// feature.
///
/// Holds a single connection behind a `std::sync::Mutex`: every access
/// happens inside a `spawn_blocking` closure that already runs
/// synchronously end-to-end, so there is never a reason to hold the lock
/// across an `.await` — a plain blocking mutex is simpler and cheaper
/// than `tokio::sync::Mutex` here.
pub struct SqliteSnapshotStore {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl SqliteSnapshotStore {
    /// Opens (creating and migrating if absent) a `SQLite` database at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] if the database cannot be opened or
    /// the schema cannot be created.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = rusqlite::Connection::open(path).map_err(sqlite_err)?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Opens a private in-memory database — used by tests and by callers
    /// that want an ephemeral store with the same schema/behaviour as the
    /// file-backed one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] if the schema cannot be created.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = rusqlite::Connection::open_in_memory().map_err(sqlite_err)?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

#[async_trait]
impl SnapshotStore for SqliteSnapshotStore {
    async fn put(&self, key: IdempotencyKey, snapshot: ScanSnapshot) -> Result<ScanId, StoreError> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().unwrap_or_else(PoisonError::into_inner);
            put_tx(&mut guard, key, &snapshot)
        })
        .await?
    }

    async fn get(&self, id: ScanId) -> Result<Option<ScanSnapshot>, StoreError> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().unwrap_or_else(PoisonError::into_inner);
            get_by_scan_id(&guard, id)
        })
        .await?
    }

    async fn list(&self, host: HostId) -> Result<Vec<ScanId>, StoreError> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().unwrap_or_else(PoisonError::into_inner);
            list_by_host(&guard, host)
        })
        .await?
    }
}

fn sqlite_err(source: rusqlite::Error) -> StoreError {
    StoreError::Sqlite(Box::new(source))
}

fn init_schema(conn: &rusqlite::Connection) -> Result<(), StoreError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS snapshots (
            scan_id          TEXT    PRIMARY KEY,
            host_id          TEXT    NOT NULL,
            idempotency_key  TEXT    NOT NULL UNIQUE,
            created_at_unix  INTEGER NOT NULL,
            snapshot_json    TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_snapshots_host_id ON snapshots(host_id);",
    )
    .map_err(sqlite_err)
}

fn find_by_idempotency_key(
    conn: &rusqlite::Connection,
    key: IdempotencyKey,
) -> Result<Option<ScanId>, StoreError> {
    let mut stmt = conn
        .prepare("SELECT scan_id FROM snapshots WHERE idempotency_key = ?1")
        .map_err(sqlite_err)?;
    let mut rows = stmt.query([key.to_string()]).map_err(sqlite_err)?;
    let Some(row) = rows.next().map_err(sqlite_err)? else {
        return Ok(None);
    };
    let scan_id_text: String = row.get(0).map_err(sqlite_err)?;
    let scan_id = ScanId::from_str(&scan_id_text)
        .map_err(|source| StoreError::Corrupt(source.to_string()))?;
    Ok(Some(scan_id))
}

fn put_tx(
    conn: &mut rusqlite::Connection,
    key: IdempotencyKey,
    snapshot: &ScanSnapshot,
) -> Result<ScanId, StoreError> {
    let tx = conn.transaction().map_err(sqlite_err)?;

    if let Some(existing) = find_by_idempotency_key(&tx, key)? {
        return Ok(existing);
    }

    let json = serde_json::to_string(snapshot)?;
    let created_at_unix = time::OffsetDateTime::now_utc().unix_timestamp();

    let insert = tx.execute(
        "INSERT INTO snapshots (scan_id, host_id, idempotency_key, created_at_unix, snapshot_json) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            snapshot.scan_id.to_string(),
            snapshot.host_id.to_string(),
            key.to_string(),
            created_at_unix,
            json,
        ],
    );

    match insert {
        Ok(_) => {
            tx.commit().map_err(sqlite_err)?;
            Ok(snapshot.scan_id)
        }
        Err(rusqlite::Error::SqliteFailure(sqlite_error, _))
            if sqlite_error.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            // Another writer's transaction inserted the same
            // idempotency_key between our check above and this INSERT,
            // and its UNIQUE constraint caught ours. Drop this
            // transaction (an implicit rollback — our failed INSERT
            // never committed) and read back the winner's row.
            drop(tx);
            find_by_idempotency_key(conn, key)?.ok_or_else(|| {
                StoreError::Corrupt(
                    "idempotency_key uniqueness conflict left no winning row".to_owned(),
                )
            })
        }
        Err(other) => Err(sqlite_err(other)),
    }
}

fn get_by_scan_id(
    conn: &rusqlite::Connection,
    id: ScanId,
) -> Result<Option<ScanSnapshot>, StoreError> {
    let mut stmt = conn
        .prepare("SELECT snapshot_json FROM snapshots WHERE scan_id = ?1")
        .map_err(sqlite_err)?;
    let mut rows = stmt.query([id.to_string()]).map_err(sqlite_err)?;
    let Some(row) = rows.next().map_err(sqlite_err)? else {
        return Ok(None);
    };
    let json: String = row.get(0).map_err(sqlite_err)?;
    Ok(Some(serde_json::from_str(&json)?))
}

fn list_by_host(conn: &rusqlite::Connection, host: HostId) -> Result<Vec<ScanId>, StoreError> {
    let mut stmt = conn
        .prepare("SELECT scan_id FROM snapshots WHERE host_id = ?1 ORDER BY scan_id")
        .map_err(sqlite_err)?;
    let rows = stmt
        .query_map([host.to_string()], |row| row.get::<_, String>(0))
        .map_err(sqlite_err)?;

    let mut ids = Vec::new();
    for row in rows {
        let scan_id_text = row.map_err(sqlite_err)?;
        let scan_id = ScanId::from_str(&scan_id_text)
            .map_err(|source| StoreError::Corrupt(source.to_string()))?;
        ids.push(scan_id);
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;

    use super::*;
    use crate::domain::Endpoint;
    use crate::domain::bind_address::BindAddress;
    use crate::domain::port::Port;
    use crate::domain::protocol::Protocol;
    use crate::domain::publisher::SignatureStatus;

    fn sample_snapshot() -> ScanSnapshot {
        ScanSnapshot::new(
            HostId::generate(),
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "1.0.0".to_owned(),
            vec![Endpoint::new(
                Protocol::Tcp,
                BindAddress::from_str("10.0.0.4").unwrap(),
                Port::try_from(443).unwrap(),
                None,
                None,
                vec![],
                SignatureStatus::Unknown,
            )],
            vec![],
            vec![],
        )
    }

    #[tokio::test]
    async fn duplicate_idempotency_key_returns_existing_scan_id() {
        let store = SqliteSnapshotStore::open_in_memory().unwrap();
        let key = IdempotencyKey::generate();
        let snapshot = sample_snapshot();

        let first = store.put(key, snapshot.clone()).await.unwrap();
        let second = store.put(key, snapshot).await.unwrap();

        assert_eq!(first, second);

        let row_count: i64 = {
            let guard = store.conn.lock().unwrap();
            guard
                .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
                .unwrap()
        };
        assert_eq!(row_count, 1);
    }

    #[tokio::test]
    async fn put_then_get_round_trips_the_full_snapshot() {
        let store = SqliteSnapshotStore::open_in_memory().unwrap();
        let snapshot = sample_snapshot();

        let id = store
            .put(IdempotencyKey::generate(), snapshot.clone())
            .await
            .unwrap();
        let fetched = store.get(id).await.unwrap();

        assert_eq!(fetched, Some(snapshot));
    }

    #[tokio::test]
    async fn get_returns_none_for_unknown_scan_id() {
        let store = SqliteSnapshotStore::open_in_memory().unwrap();
        assert_eq!(store.get(ScanId::generate()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn list_filters_by_host() {
        let store = SqliteSnapshotStore::open_in_memory().unwrap();
        let host_a = HostId::generate();
        let host_b = HostId::generate();

        let mut snap_a1 = sample_snapshot();
        snap_a1.host_id = host_a;
        let mut snap_a2 = sample_snapshot();
        snap_a2.host_id = host_a;
        snap_a2.scan_id = ScanId::generate();
        let mut snap_b = sample_snapshot();
        snap_b.host_id = host_b;

        let id_a1 = store
            .put(IdempotencyKey::generate(), snap_a1)
            .await
            .unwrap();
        let id_a2 = store
            .put(IdempotencyKey::generate(), snap_a2)
            .await
            .unwrap();
        store.put(IdempotencyKey::generate(), snap_b).await.unwrap();

        let mut for_host_a = store.list(host_a).await.unwrap();
        for_host_a.sort_unstable();
        let mut expected = vec![id_a1, id_a2];
        expected.sort_unstable();

        assert_eq!(for_host_a, expected);
    }

    #[tokio::test]
    async fn a_failed_transaction_leaves_no_partial_row() {
        // Same idempotency_key inserted for two genuinely different
        // scan_ids: the second INSERT hits the UNIQUE constraint and its
        // transaction rolls back. Assert the store still reports exactly
        // the first, complete row — no half-written row from the
        // second attempt.
        let store = SqliteSnapshotStore::open_in_memory().unwrap();
        let key = IdempotencyKey::generate();

        let first_snapshot = sample_snapshot();
        let first_id = store.put(key, first_snapshot.clone()).await.unwrap();

        let mut second_snapshot = sample_snapshot();
        second_snapshot.scan_id = ScanId::generate();
        let second_id = store.put(key, second_snapshot).await.unwrap();

        assert_eq!(
            first_id, second_id,
            "put must be idempotent on key, not scan_id"
        );

        let row_count: i64 = {
            let guard = store.conn.lock().unwrap();
            guard
                .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
                .unwrap()
        };
        assert_eq!(row_count, 1);

        let fetched = store.get(first_id).await.unwrap();
        assert_eq!(fetched, Some(first_snapshot));
    }
}
