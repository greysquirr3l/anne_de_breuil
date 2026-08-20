//! [`SnapshotStore`](crate::application::SnapshotStore) implementations.
//!
//! [`fs`] is the default, always-available adapter: one content-addressed
//! JSON file per snapshot on the local filesystem. [`sqlite`] is gated
//! behind `store-sqlite` for fleet-scale deployments where thousands of
//! snapshots make a flat file layout unwieldy.

pub mod fs;

#[cfg(feature = "store-sqlite")]
pub mod sqlite;

pub use fs::FsSnapshotStore;

#[cfg(feature = "store-sqlite")]
pub use sqlite::SqliteSnapshotStore;
