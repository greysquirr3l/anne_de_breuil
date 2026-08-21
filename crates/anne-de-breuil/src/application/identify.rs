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

/// Cloud-provider instance-metadata endpoints. Reachable only from the
/// instance itself, and a standard SSRF pivot for stealing that instance's
/// IAM/managed-identity credentials once *any* outbound fetch on its behalf
/// can be aimed here — see T30's `docs/security-hardening-review.md`.
/// `169.254.169.254` is the AWS/Azure/GCP link-local metadata address;
/// `169.254.170.2` is AWS ECS's task metadata endpoint (a distinct address
/// from the EC2 instance one, reachable from inside a container even when
/// the host's own EC2 metadata endpoint is firewalled off).
const DEFAULT_EXCLUDED_CIDRS: &[&str] = &["169.254.169.254/32", "169.254.170.2/32"];

/// Ports and address ranges a probe run must never connect to.
///
/// Checked before any socket connects. Industrial, medical, and legacy
/// appliance endpoints can be destabilised by a bare TCP connect; the
/// operator needs a way to say so ahead of the run, not after.
///
/// The cloud-metadata CIDRs above are folded into every instance of this
/// type, including operator-supplied ones built via [`ProbeExclusions::new`]
/// — an operator naming their own `--probe-exclude` ranges still gets the
/// metadata exclusion for free, and there is no constructor that can build
/// a [`ProbeExclusions`] without it.
#[derive(Debug, Clone)]
pub struct ProbeExclusions {
    ports: HashSet<u16>,
    cidrs: Vec<IpNet>,
}

impl ProbeExclusions {
    /// Builds an exclusion set from explicit ports and CIDR ranges, always
    /// including the cloud-metadata default exclusions on top of whatever
    /// `cidrs` the caller supplies.
    #[must_use]
    pub fn new(ports: impl IntoIterator<Item = u16>, cidrs: Vec<IpNet>) -> Self {
        Self {
            ports: ports.into_iter().collect(),
            cidrs: default_excluded_cidrs().chain(cidrs).collect(),
        }
    }

    /// `true` if `addr`/`port` must never be probed.
    #[must_use]
    pub fn excludes(&self, addr: IpAddr, port: u16) -> bool {
        self.ports.contains(&port) || self.cidrs.iter().any(|cidr| cidr.contains(&addr))
    }
}

impl Default for ProbeExclusions {
    fn default() -> Self {
        Self::new(std::iter::empty(), Vec::new())
    }
}

/// Parses [`DEFAULT_EXCLUDED_CIDRS`]. `.ok()` rather than `.expect()` on
/// each entry — a malformed literal here should degrade to "one fewer
/// default exclusion," never panic a probe run over a typo in this
/// module's own constant.
fn default_excluded_cidrs() -> impl Iterator<Item = IpNet> {
    DEFAULT_EXCLUDED_CIDRS
        .iter()
        .filter_map(|raw| raw.parse().ok())
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
    /// The TLS handshake with the target could not be completed at all —
    /// a genuine connection or protocol-negotiation failure (unreachable
    /// host, connect timeout, no mutually supported protocol version).
    ///
    /// Never returned for a certificate the target presents but which
    /// fails ordinary validation (self-signed, expired, hostname
    /// mismatch) — those are captured as evidence, not treated as
    /// failures. See [`crate::adapters::tls_probe`].
    #[error("tls handshake failed: {0}")]
    Handshake(String),
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

#[cfg(test)]
mod tests {
    use super::ProbeExclusions;

    #[test]
    fn cloud_metadata_address_excluded_by_default() {
        let exclusions = ProbeExclusions::default();
        assert!(exclusions.excludes("169.254.169.254".parse().unwrap(), 80));
        assert!(exclusions.excludes("169.254.170.2".parse().unwrap(), 443));
    }

    #[test]
    fn cloud_metadata_exclusion_holds_even_with_operator_supplied_exclusions() {
        // An operator naming their own `--probe-exclude` ranges via `new`
        // must not lose the metadata default as a side effect — this is
        // the "always-on, no flags required" property the fix guarantees.
        let exclusions = ProbeExclusions::new([8080], vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(exclusions.excludes("169.254.169.254".parse().unwrap(), 80));
        assert!(exclusions.excludes("10.0.0.5".parse().unwrap(), 1));
        assert!(exclusions.excludes("1.2.3.4".parse().unwrap(), 8080));
    }

    #[test]
    fn an_ordinary_public_address_is_not_excluded() {
        let exclusions = ProbeExclusions::default();
        assert!(!exclusions.excludes("93.184.216.34".parse().unwrap(), 443));
    }
}
