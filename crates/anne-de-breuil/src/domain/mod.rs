//! Pure domain layer: value objects, aggregates, and deterministic functions.
//!
//! No I/O, no framework derives, no port traits. Every value object here is
//! constructed exclusively through `TryFrom`/`FromStr` — there is no public
//! way to build one from an unvalidated raw value, so untrusted host data is
//! parsed exactly once, at the boundary, into these types.

pub mod annotations;
pub mod attribution;
pub mod bind_address;
pub mod confidence;
pub mod contrast;
pub mod drift;
pub mod endpoint;
pub mod error;
pub mod events;
pub mod evidence;
pub mod exposure;
pub mod fingerprint;
pub mod firewall_rule;
pub mod host_address;
pub mod ids;
pub mod mismatch;
pub mod policy_store;
pub mod port;
pub mod port_registry;
pub mod port_spec;
pub mod process;
pub mod profile;
pub mod profile_ports;
pub mod protocol;
pub mod publisher;
pub mod reachability;
pub mod reconciliation;
pub mod redaction;
pub mod report_model;
pub mod report_render;
pub mod service;
pub mod service_category;
pub mod service_identity;
pub mod snapshot;
pub mod svg;
pub mod target_strategy;

pub use annotations::{
    Annotation, BANNED_WORDS, DiagramAnchor, executive_summary, select_annotation,
};
pub use attribution::Attribution;
pub use bind_address::BindAddress;
pub use confidence::Confidence;
pub use contrast::contrast_ratio;
pub use drift::{DriftEntry, DriftKind, DriftReport, EndpointKey, Severity, diff, severity_for};
pub use endpoint::Endpoint;
pub use error::DomainError;
pub use events::{
    DomainEvent, DriftDetected, EndpointObserved, EventLog, ScanCompleted, ScanStarted,
};
pub use evidence::Evidence;
pub use exposure::Exposure;
pub use fingerprint::fingerprint;
pub use firewall_rule::{Direction, FirewallRule, RuleAction};
pub use host_address::HostAddress;
pub use ids::{HostId, IdempotencyKey, ProcessId, RuleId, ScanId};
pub use mismatch::{MismatchedAssignment, detect_mismatch};
pub use policy_store::PolicyStore;
pub use port::Port;
pub use port_registry::identity_for_port;
pub use port_spec::{DynamicKeyword, PortRange, PortSpec};
pub use process::ProcessPath;
pub use profile::{FirewallProfileKind, ProfileState};
pub use profile_ports::{AllowedPortEntry, ProfilePortSummary, summarize_inbound_ports};
pub use protocol::Protocol;
pub use publisher::{PublisherName, SignatureStatus};
pub use reachability::{Reachability, ReachabilityVerdict, evaluate};
pub use reconciliation::{ReconciliationReport, reconcile};
pub use redaction::{Redacted, SecretCategory, redact};
pub use report_model::{Fidelity, HostSection, ReportError, ReportModel, Rollup};
pub use report_render::{ReportRenderError, render_csv, render_json, render_sarif};
pub use service::ServiceName;
pub use service_category::ServiceCategory;
pub use service_identity::ServiceIdentity;
pub use snapshot::ScanSnapshot;
pub use svg::{Grid4, SvgCanvas, escape_svg_text};
pub use target_strategy::TargetStrategy;
