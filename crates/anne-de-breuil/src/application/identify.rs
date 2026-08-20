//! Consumer-owned probing port: [`Prober`].
//!
//! Declared here, not in `adapters/`, per the hexagonal rule that a port
//! lives with the use case that consumes it. Probing is opt-in behaviour a
//! caller chooses to invoke (behind a future `--probe` CLI flag) — nothing
//! in this module runs on its own. [`crate::adapters::prober::HttpProber`]
//! is the first and, for now, only implementation.
//!
//! A probe produces [`Evidence`] and never a verdict — fingerprinting from
//! evidence is a separate, pure function over collected evidence (a later
//! task), so it stays testable without a network. Same `#[async_trait]`
//! pattern as [`crate::application::collect`]'s collector ports.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use ipnet::IpNet;

use crate::domain::{Endpoint, Evidence};

/// Ports and address ranges a probe run must never connect to.
///
/// Checked before any socket connects. Industrial, medical, and legacy
/// appliance endpoints can be destabilised by a bare TCP connect; the
/// operator needs a way to say so ahead of the run, not after.
#[derive(Debug, Clone, Default)]
pub struct ProbeExclusions {
    ports: HashSet<u16>,
    cidrs: Vec<IpNet>,
}

impl ProbeExclusions {
    /// Builds an exclusion set from explicit ports and CIDR ranges.
    #[must_use]
    pub fn new(ports: impl IntoIterator<Item = u16>, cidrs: Vec<IpNet>) -> Self {
        Self {
            ports: ports.into_iter().collect(),
            cidrs,
        }
    }

    /// `true` if `addr`/`port` must never be probed.
    #[must_use]
    pub fn excludes(&self, addr: IpAddr, port: u16) -> bool {
        self.ports.contains(&port) || self.cidrs.iter().any(|cidr| cidr.contains(&addr))
    }
}

/// Bounds every probe run must respect.
///
/// Every field is a default, not a suggestion — see
/// [`crate::adapters::prober::HttpProber`] for where each one is enforced.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// Maximum time to wait for a TCP/TLS connect to complete.
    pub connect_timeout: Duration,
    /// Maximum time for a single request to complete, connect through body.
    pub read_timeout: Duration,
    /// Maximum response body bytes read per request, ~64 KiB by default.
    pub max_response_bytes: usize,
    /// Maximum probes running concurrently against the same host.
    pub max_concurrent_per_host: usize,
    /// Maximum total calls to [`Prober::probe`] permitted against the same
    /// host for the lifetime of one prober instance.
    pub max_probes_per_host: usize,
    /// Minimum spacing enforced between any two outbound probe requests,
    /// across every host, regardless of `max_concurrent_per_host`.
    pub min_probe_interval: Duration,
    /// Ports and address ranges excluded from probing entirely.
    pub exclude: ProbeExclusions,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(10),
            max_response_bytes: 64 * 1024,
            max_concurrent_per_host: 1,
            max_probes_per_host: 50,
            min_probe_interval: Duration::from_millis(200),
            exclude: ProbeExclusions::default(),
        }
    }
}

/// Failure attempting to probe an endpoint.
///
/// Transport-level failures for an individual HTTP request (connection
/// refused, a stalled response, a failed TLS handshake) are deliberately
/// *not* modelled here — a closed port or an untrusted certificate is
/// itself a fact about the target, recorded as [`Evidence`], not a probe
/// failure. This enum only covers reasons the probe could not be attempted
/// at all.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// The target's port or address is in the operator's exclusion set.
    #[error("target is excluded from probing")]
    Excluded,
    /// The host has already received its configured maximum number of
    /// probe calls for the lifetime of this prober instance.
    #[error("host probe budget exhausted")]
    HostBudgetExhausted,
    /// Building the underlying HTTP client failed.
    #[error("building probe client failed: {0}")]
    ClientBuild(String),
}

/// Probes one endpoint for evidence of the service behind it.
///
/// One method. Implementations must never issue anything but a GET, must
/// never follow a redirect to a different host, must never send
/// credentials, and must respect every bound in [`ProbeConfig`].
///
/// # Examples
///
/// ```
/// use async_trait::async_trait;
/// use anne_de_breuil::application::identify::{Prober, ProbeError};
/// use anne_de_breuil::domain::{Endpoint, Evidence};
///
/// struct NeverProbes;
///
/// #[async_trait]
/// impl Prober for NeverProbes {
///     async fn probe(&self, _endpoint: &Endpoint) -> Result<Vec<Evidence>, ProbeError> {
///         Ok(vec![])
///     }
/// }
/// ```
#[async_trait]
pub trait Prober: Send + Sync {
    /// Probes `endpoint`, returning whatever evidence could be gathered.
    ///
    /// # Errors
    ///
    /// Returns [`ProbeError::Excluded`] if `endpoint` matches the prober's
    /// configured exclusions, or [`ProbeError::HostBudgetExhausted`] if the
    /// endpoint's host has already exhausted its probe budget.
    async fn probe(&self, endpoint: &Endpoint) -> Result<Vec<Evidence>, ProbeError>;
}
