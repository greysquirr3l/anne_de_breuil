//! Typed domain events for significant scan-lifecycle transitions.
//!
//! Events are recorded, never mutated or removed — [`EventLog`] only
//! exposes `record` and read access, never a way to edit or drop a past
//! entry, so the log stays a trustworthy audit trail.

use crate::domain::endpoint::Endpoint;
use crate::domain::ids::{HostId, ScanId};

/// A scan run began for a host.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanStarted {
    /// The scan that began.
    pub scan_id: ScanId,
    /// The host being scanned.
    pub host_id: HostId,
    /// When the scan began.
    pub started_at: time::OffsetDateTime,
}

/// One endpoint was observed during a scan.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointObserved {
    /// The scan that observed this endpoint.
    pub scan_id: ScanId,
    /// The endpoint that was observed.
    pub endpoint: Endpoint,
    /// When the observation was made.
    pub observed_at: time::OffsetDateTime,
}

/// A scan run finished.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanCompleted {
    /// The scan that completed.
    pub scan_id: ScanId,
    /// The host that was scanned.
    pub host_id: HostId,
    /// When the scan finished.
    pub completed_at: time::OffsetDateTime,
    /// Number of endpoints observed during the scan.
    pub endpoint_count: usize,
}

/// A rescan diverged from its baseline.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftDetected {
    /// The baseline scan being compared against.
    pub baseline_scan_id: ScanId,
    /// The scan that was compared to the baseline.
    pub scan_id: ScanId,
    /// The host both scans describe.
    pub host_id: HostId,
    /// When the comparison was made.
    pub detected_at: time::OffsetDateTime,
    /// Number of changes found. The typed change list itself belongs to the
    /// drift-diff domain function.
    pub change_count: usize,
}

/// A significant scan-lifecycle transition.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DomainEvent {
    /// See [`ScanStarted`].
    ScanStarted(ScanStarted),
    /// See [`EndpointObserved`].
    EndpointObserved(EndpointObserved),
    /// See [`ScanCompleted`].
    ScanCompleted(ScanCompleted),
    /// See [`DriftDetected`].
    DriftDetected(DriftDetected),
}

/// An append-only log of domain events.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EventLog(Vec<DomainEvent>);

impl EventLog {
    /// Creates an empty log.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Appends an event. There is no corresponding removal method — the log
    /// is append-only by construction.
    pub fn record(&mut self, event: DomainEvent) {
        self.0.push(event);
    }

    /// Returns the recorded events in the order they were appended.
    #[must_use]
    pub fn events(&self) -> &[DomainEvent] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_preserves_append_order() {
        let mut log = EventLog::new();
        let scan_id = ScanId::generate();
        let host_id = HostId::generate();

        log.record(DomainEvent::ScanStarted(ScanStarted {
            scan_id,
            host_id,
            started_at: time::OffsetDateTime::UNIX_EPOCH,
        }));
        log.record(DomainEvent::ScanCompleted(ScanCompleted {
            scan_id,
            host_id,
            completed_at: time::OffsetDateTime::UNIX_EPOCH,
            endpoint_count: 3,
        }));

        assert_eq!(log.events().len(), 2);
        assert!(matches!(log.events()[0], DomainEvent::ScanStarted(_)));
        assert!(matches!(log.events()[1], DomainEvent::ScanCompleted(_)));
    }
}
