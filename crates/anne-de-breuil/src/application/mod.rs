//! Use-case orchestration: wires domain logic to port traits.
//!
//! No direct I/O — application code depends on ports, never on adapters.
//! [`clock`] and [`snapshot_store`] hold port traits that exist ahead of
//! their first use-case consumer, per the hexagonal rule that a port lives
//! with the code that calls it, not with the domain types it moves data
//! between. [`collect`] is the first real use case: it declares the four
//! collector ports a platform adapter must satisfy, and the handler that
//! turns their raw output into [`crate::domain`] value objects. [`identify`]
//! declares the [`identify::Prober`] port: bounded, opt-in active probing
//! that produces [`crate::domain::Evidence`], never a verdict. [`remote`]
//! declares the [`remote::RemoteTransport`] port: push/exec/remove against
//! a remote host, optional to the design — a host with no working
//! implementation degrades to [`remote::TargetStrategy::Probe`], never a
//! hard failure. [`fanout`] is the orchestration layer above all of the
//! above: bounded-concurrency fan-out across an inventory of hosts, behind
//! the [`fanout::HostScanner`] port so the orchestration logic itself
//! stays testable against fakes, independent of which real collection
//! pipeline eventually backs it.

pub mod clock;
pub mod collect;
pub mod fanout;
pub mod identify;
pub mod remote;
pub mod snapshot_store;

pub use clock::Clock;
pub use collect::{
    CollectError, CollectedEndpoint, CollectorSet, EndpointSource, FirewallPolicySource,
    ProcessAttribution, ProcessResolver, RawEndpoint, RawProcess, RawProfile, RawRule, RawService,
    SignatureVerifier, collect_endpoints,
};
pub use fanout::{
    DEFAULT_CONCURRENCY, DEFAULT_PER_HOST_TIMEOUT, HostError, HostOutcome, HostResult, HostScanner,
    NullProgressReporter, ProgressReporter, run_fanout,
};
pub use identify::{ProbeConfig, ProbeError, ProbeExclusions, Prober};
pub use remote::{
    ExecOutput, RemoteCommand, RemotePath, RemoteTransport, TargetStrategy, TransportError,
};
pub use snapshot_store::{SnapshotStore, StoreError};
