//! Use-case orchestration: wires domain logic to port traits.
//!
//! No direct I/O — application code depends on ports, never on adapters.
//! Use cases themselves are still empty until scan, drift, and fan-out land
//! in later phases; the [`clock`] module holds the one port trait that
//! exists ahead of its first consumer, per the hexagonal rule that a port
//! lives with the code that calls it, not with the domain types it moves
//! data between.

pub mod clock;

pub use clock::Clock;
