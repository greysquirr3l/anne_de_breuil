//! [`SshHostScanner`]: the production [`HostScanner`] implementation.
//!
//! `resolve_strategy` attempts a short, bounded SSH connect to decide
//! whether a host is reachable via the `Execute` tier; `scan` then either
//! pushes this same running binary and runs it remotely
//! (`TargetStrategy::Execute`, via [`SshTransport::push_exec_collect_remove`])
//! or probes a small, bounded set of well-known ports from outside
//! (`TargetStrategy::Probe`, via [`probe`]). Neither path is ever a hard
//! failure at the `resolve_strategy` stage — a host with no reachable sshd
//! degrades to `Probe`, matching [`HostScanner`]'s own documented contract.
//!
//! # Known limitation: `InventoryHost::jump` is not honoured
//!
//! [`crate::adapters::inventory::InventoryHost::jump`] is parsed by the
//! inventory adapter, but [`SshTransport::connect`] has no bastion-hop
//! parameter — this scanner always connects directly to `host.address`.
//! A host that's only reachable through a jump host degrades to
//! `TargetStrategy::Probe` (the direct connect simply fails), same as any
//! other unreachable host. Documented as a real, deliberately deferred gap
//! in `docs/integration-wiring-audit.md`, not something this module
//! silently gets wrong.

mod probe;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::adapters::binary_hash;
use crate::adapters::inventory::InventoryHost;
use crate::adapters::prober::HttpProber;
use crate::adapters::ssh_transport::{KnownHosts, SshTransport};
use crate::adapters::tls_probe::TlsProber;
use crate::application::fanout::{HostError, HostScanner};
use crate::application::identify::{ProbeConfig, ProbeError};
use crate::application::remote::TransportError;
use crate::domain::{IdempotencyKey, ScanId, ScanSnapshot, TargetStrategy};

/// How long [`SshHostScanner::resolve_strategy`] waits for a connect
/// attempt before concluding the host isn't reachable via SSH.
///
/// Deliberately much shorter than a full per-host scan budget
/// (`RemoteConfig::timeout`, 2 minutes by default): `resolve_strategy` runs
/// unconditionally for *every* host in a fleet, including every host that
/// turns out to have no sshd at all. A probe-only fleet (the documented
/// common case in Windows-heavy environments — see `TargetStrategy`'s own
/// doc comment) would otherwise spend minutes per host just discovering
/// that before ever reaching the `Probe` tier. Matches
/// `ProbeConfig::default().connect_timeout` in magnitude, coincidentally —
/// the two aren't derived from each other, this is its own independent
/// constant for its own reason.
const STRATEGY_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Constructor arguments for [`SshHostScanner::new`].
pub struct SshHostScannerConfig {
    /// Host key verification book, shared across every host this scanner
    /// touches so an accepted-this-run key is remembered for retries.
    pub known_hosts: Arc<KnownHosts>,
    /// Whether an unrecognised host key is trusted on first connect.
    pub accept_new: bool,
    /// Cap on captured remote stdout/stderr per command.
    pub max_output_bytes: usize,
    /// Bounds for the `Probe` tier's `HttpProber`/`TlsProber` calls.
    pub probe_config: ProbeConfig,
}

/// Production [`HostScanner`]: SSH for `Execute`, bounded HTTP/TLS probing
/// for `Probe`.
pub struct SshHostScanner {
    known_hosts: Arc<KnownHosts>,
    accept_new: bool,
    max_output_bytes: usize,
    probe_config: ProbeConfig,
    http_prober: Arc<HttpProber>,
    tls_prober: Arc<TlsProber>,
}

impl SshHostScanner {
    /// Builds a scanner, constructing its own `HttpProber`/`TlsProber`
    /// instances from `config.probe_config`.
    ///
    /// # Errors
    ///
    /// Returns [`ProbeError::ClientBuild`] if the underlying HTTP client
    /// cannot be constructed.
    pub fn new(config: SshHostScannerConfig) -> Result<Self, ProbeError> {
        let http_prober = Arc::new(HttpProber::new(config.probe_config.clone())?);
        let tls_prober = Arc::new(TlsProber::new(config.probe_config.clone()));
        Ok(Self {
            known_hosts: config.known_hosts,
            accept_new: config.accept_new,
            max_output_bytes: config.max_output_bytes,
            probe_config: config.probe_config,
            http_prober,
            tls_prober,
        })
    }

    async fn connect(&self, host: &InventoryHost) -> Result<Arc<SshTransport>, TransportError> {
        SshTransport::connect(
            host.address.as_str(),
            host.port.get(),
            &host.user,
            &host.auth,
            Arc::clone(&self.known_hosts),
            self.accept_new,
            self.max_output_bytes,
        )
        .await
    }

    /// `Execute` tier: pushes this same running binary to `host` and runs
    /// it there. The remote invocation self-generates its own `HostId` (it
    /// has no way to know the orchestrator's inventory-assigned one — see
    /// [`crate::application::scan`]'s local `--emit-json` path, which
    /// always calls `HostId::generate()`), so the returned snapshot's
    /// `host_id` is stamped with `host.host_id` before being handed back,
    /// not trusted from the remote side.
    async fn scan_execute(&self, host: &InventoryHost) -> Result<ScanSnapshot, HostError> {
        let (exe_path, expected_hash) = binary_hash::locate_and_hash_current_exe()
            .map_err(|err| HostError::Fatal(format!("hashing this binary before push: {err}")))?;

        let transport = self
            .connect(host)
            .await
            .map_err(|err| map_transport_error(&err))?;
        let snapshot = transport
            .push_exec_collect_remove(&exe_path, &expected_hash)
            .await
            .map_err(|err| map_transport_error(&err))?;

        Ok(ScanSnapshot {
            host_id: host.host_id,
            ..snapshot
        })
    }

    /// `Probe` tier: bounded, outside-in reconnaissance — never a hard
    /// failure, matching `TargetStrategy::Probe`'s own "inferred, no
    /// process attribution" contract even when nothing responds at all.
    async fn scan_probe(&self, host: &InventoryHost) -> ScanSnapshot {
        let endpoints = probe::probe_host(
            host,
            &self.probe_config,
            self.http_prober.as_ref(),
            self.tls_prober.as_ref(),
        )
        .await;

        ScanSnapshot::new(
            host.host_id,
            ScanId::generate(),
            time::OffsetDateTime::now_utc(),
            env!("CARGO_PKG_VERSION").to_owned(),
            endpoints,
            Vec::new(),
            Vec::new(),
            TargetStrategy::Probe,
        )
    }
}

#[async_trait]
impl HostScanner for SshHostScanner {
    async fn resolve_strategy(&self, host: &InventoryHost) -> TargetStrategy {
        match tokio::time::timeout(STRATEGY_RESOLUTION_TIMEOUT, self.connect(host)).await {
            Ok(Ok(_transport)) => TargetStrategy::Execute,
            _ => TargetStrategy::Probe,
        }
    }

    async fn scan(
        &self,
        host: &InventoryHost,
        strategy: TargetStrategy,
        _idempotency_key: IdempotencyKey,
    ) -> Result<ScanSnapshot, HostError> {
        match strategy {
            TargetStrategy::Execute => self.scan_execute(host).await,
            TargetStrategy::Probe => Ok(self.scan_probe(host).await),
            TargetStrategy::LocalOnly => Err(HostError::Fatal(
                "SshHostScanner does not handle TargetStrategy::LocalOnly -- that tier is the \
                 local scan path's own responsibility, never fanned out over a transport"
                    .to_owned(),
            )),
        }
    }
}

/// Maps a transport-level failure onto the fan-out orchestrator's retry
/// policy.
///
/// `Connect`/`Transfer`/`Exec`/`Remove`/`Ssh`/`Sftp` are network-shaped
/// failures a flaky link or a momentarily busy host can plausibly recover
/// from on retry -- `Retryable`. `IntegrityMismatch` (a tampered or
/// truncated artifact), `UnknownHostKey`/`HostKeyChanged` (a security
/// decision that needs a human, never silently retried into acceptance),
/// `OutputCapExceeded` and `InvalidPath` (both configuration facts that
/// retrying with the same inputs reproduces identically) are `Fatal`.
/// `JsonDecode` is classified `Retryable`: a garbled read is at least as
/// plausible an explanation as a genuinely malformed collector, and
/// retrying is cheap.
fn map_transport_error(err: &TransportError) -> HostError {
    match err {
        TransportError::Timeout(_duration) => HostError::Timeout,
        TransportError::Connect(_)
        | TransportError::Transfer(_)
        | TransportError::Exec(_)
        | TransportError::Remove(_)
        | TransportError::JsonDecode(_)
        | TransportError::Ssh(_)
        | TransportError::Sftp(_) => HostError::Retryable(err.to_string()),
        TransportError::IntegrityMismatch
        | TransportError::UnknownHostKey { .. }
        | TransportError::HostKeyChanged
        | TransportError::OutputCapExceeded
        | TransportError::InvalidPath(_) => HostError::Fatal(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::map_transport_error;
    use crate::application::fanout::HostError;
    use crate::application::remote::TransportError;

    #[test]
    fn network_shaped_failures_are_retryable() {
        assert!(matches!(
            map_transport_error(&TransportError::Connect("refused".to_owned())),
            HostError::Retryable(_)
        ));
        assert!(matches!(
            map_transport_error(&TransportError::Transfer("sftp reset".to_owned())),
            HostError::Retryable(_)
        ));
        assert!(matches!(
            map_transport_error(&TransportError::Exec("channel error".to_owned())),
            HostError::Retryable(_)
        ));
        assert!(matches!(
            map_transport_error(&TransportError::Remove("busy".to_owned())),
            HostError::Retryable(_)
        ));
    }

    #[test]
    fn security_and_config_failures_are_fatal_not_retried() {
        assert!(matches!(
            map_transport_error(&TransportError::IntegrityMismatch),
            HostError::Fatal(_)
        ));
        assert!(matches!(
            map_transport_error(&TransportError::HostKeyChanged),
            HostError::Fatal(_)
        ));
        assert!(matches!(
            map_transport_error(&TransportError::UnknownHostKey {
                fingerprint: "SHA256:abc".to_owned()
            }),
            HostError::Fatal(_)
        ));
        assert!(matches!(
            map_transport_error(&TransportError::OutputCapExceeded),
            HostError::Fatal(_)
        ));
    }

    #[test]
    fn timeout_maps_to_the_dedicated_timeout_outcome() {
        assert!(matches!(
            map_transport_error(&TransportError::Timeout(std::time::Duration::from_secs(5))),
            HostError::Timeout
        ));
    }
}
