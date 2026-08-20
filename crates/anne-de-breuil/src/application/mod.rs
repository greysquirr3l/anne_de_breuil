//! Use-case orchestration: wires domain logic to port traits.
//!
//! No direct I/O — application code depends on ports, never on adapters.
//! Use cases themselves are still empty until scan and drift land in later
//! phases; [`clock`] and [`snapshot_store`] hold port traits that exist
//! ahead of their first use-case consumer, per the hexagonal rule that a
//! port lives with the code that calls it, not with the domain types it
//! moves data between.

pub mod clock;
pub mod snapshot_store;

pub use clock::Clock;
pub use snapshot_store::{SnapshotStore, StoreError};
