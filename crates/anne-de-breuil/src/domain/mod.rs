//! Pure domain layer: value objects, aggregates, and deterministic functions.
//!
//! No I/O, no framework derives, no port traits. Every value object here is
//! constructed exclusively through `TryFrom`/`FromStr` — there is no public
//! way to build one from an unvalidated raw value, so untrusted host data is
//! parsed exactly once, at the boundary, into these types.

pub mod bind_address;
pub mod endpoint;
pub mod error;
pub mod events;
pub mod exposure;
pub mod firewall_rule;
pub mod ids;
pub mod policy_store;
pub mod port;
pub mod port_spec;
pub mod process;
pub mod profile;
pub mod protocol;
pub mod publisher;
pub mod reachability;
pub mod service;
pub mod snapshot;

pub use bind_address::BindAddress;
pub use endpoint::Endpoint;
pub use error::DomainError;
pub use events::{
    DomainEvent, DriftDetected, EndpointObserved, EventLog, ScanCompleted, ScanStarted,
};
pub use exposure::Exposure;
pub use firewall_rule::{Direction, FirewallRule, RuleAction};
pub use ids::{HostId, IdempotencyKey, ProcessId, RuleId, ScanId};
pub use policy_store::PolicyStore;
pub use port::Port;
pub use port_spec::{DynamicKeyword, PortRange, PortSpec};
pub use process::ProcessPath;
pub use profile::{FirewallProfileKind, ProfileState};
pub use protocol::Protocol;
pub use publisher::{PublisherName, SignatureStatus};
pub use reachability::{Reachability, ReachabilityVerdict, evaluate};
pub use service::ServiceName;
pub use snapshot::ScanSnapshot;
