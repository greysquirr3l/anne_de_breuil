//! [`Clock`]: the port that supplies wall-clock time to use cases.
//!
//! Declared here, not in `domain`, because it is a capability a use case
//! *consumes* — domain functions stay deterministic by taking a timestamp
//! as a parameter instead of reading the clock themselves.

/// Supplies the current wall-clock time.
///
/// Application code depends on this trait rather than calling
/// `OffsetDateTime::now_utc()` directly, so use cases stay testable with a
/// fixed clock.
pub trait Clock {
    /// Returns the current wall-clock time.
    fn now(&self) -> time::OffsetDateTime;
}
