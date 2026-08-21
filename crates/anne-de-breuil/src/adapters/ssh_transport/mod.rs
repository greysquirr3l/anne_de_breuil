//! [`SshTransport`]: [`RemoteTransport`] implemented over SSH via
//! `russh`/`russh-sftp`, behind the `ssh` Cargo feature.
//!
//! SSH is opportunistic here, never assumed: a host with no reachable
//! sshd, or one whose host key can't be verified, is an expected outcome
//! for [`SshTransport::connect`] to return as a [`TransportError`] --
//! demoting that host to `TargetStrategy::Probe` is a decision for this
//! crate's future fan-out orchestrator (T16), not something this adapter
//! decides on its own.
//!
//! # Cleanup-guard soundness
//!
//! [`RemoteArtifactGuard`] is a last-resort safety net, not the primary
//! cleanup mechanism. `Drop::drop` cannot `.await`, so the *only* thing it
//! can do about an async remove is spawn a detached task and hope the
//! runtime gets around to polling it -- and if the process or the runtime
//! is already tearing down when that happens, the spawned task may never
//! run at all. That's a real, unavoidable limit of "fire-and-forget spawn
//! from `Drop`" in any async Rust codebase, not a defect specific to this
//! one.
//!
//! [`SshTransport::push_exec_collect_remove`] therefore does *not* lean on
//! that spawn for its own structured control flow. Every branch it can
//! reach through ordinary `match`ing -- integrity mismatch, a failed
//! `--emit-json` exec, a JSON decode failure, or plain success -- calls
//! [`RemoteArtifactGuard::remove_now`] and `.await`s it directly before
//! returning, so cleanup for all of those is a real, verified guarantee,
//! not a hope. The guard's `Drop` impl only matters for exits no
//! structured code gets to run for at all: a panic unwinding through one
//! of the `.await` points above, or the surrounding task being cancelled
//! (e.g. a `JoinHandle::abort()` or an enclosing `tokio::time::timeout`
//! firing). Those are exactly the cases where fire-and-forget is the best
//! *any* Drop guard can do -- and it is strictly better than nothing, since
//! a live multi-threaded Tokio runtime does keep polling spawned tasks
//! after the spawning task exits, right up until the runtime itself shuts
//! down.
//!
//! # Self-hash verification, exercised for real (T31)
//!
//! [`SshTransport::push_exec_collect_remove`] implements the *client* side
//! of self-hash verification in full: it pushes the collector binary, runs
//! it with `--self-hash`, and rejects the run if the echoed hash doesn't
//! match the hash the caller computed locally before push.
//! [`push_exec_collect_remove_round_trip`]'s test below stands a small
//! fixture script in for the real collector, proving the SSH-side plumbing
//! (push, hash-check, exec, JSON decode, cleanup) correct in isolation.
//! `crates/anne-de-breuil-cli/tests/remote_scan_end_to_end.rs` (T31) goes
//! further and runs this against the real `anne` binary end to end -- that
//! test is what actually caught `run_and_collect`'s `--emit-json` exec
//! invoking a bare `anne --emit-json`, which the real CLI has never
//! accepted (there is no top-level `--emit-json` flag, only
//! `ScanArgs::emit_json` under the `scan` subcommand); a fixture script
//! doesn't care about subcommand structure, so this went unnoticed until
//! something that does was actually pushed and run.

mod exec;
mod handler;
mod known_hosts;
mod sftp;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use russh::client::Handle;

use crate::adapters::inventory::AuthMethod;
use crate::application::remote::{
    ExecOutput, RemoteCommand, RemotePath, RemoteTransport, TransportError,
};
use crate::domain::ScanSnapshot;

pub use known_hosts::KnownHosts;

use handler::ClientHandler;

/// The default cap on captured `exec()` stdout/stderr.
///
/// Applied when a caller doesn't override it via [`SshTransport::connect`].
/// A JSON snapshot of a normal host's listening-port surface is well under
/// this; a host trying to exhaust the orchestrator's memory hits the cap
/// instead.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;

/// [`RemoteTransport`] implemented over an established SSH session.
pub struct SshTransport {
    handle: Handle<ClientHandler>,
    max_output_bytes: usize,
}

impl SshTransport {
    /// Establishes an SSH session to `host:port`, verifies its host key
    /// against `known_hosts`, and authenticates as `user` using exactly
    /// the method `auth` names.
    ///
    /// `accept_new` is the caller's explicit, per-invocation opt-in to
    /// trusting a host key this `known_hosts` book has never seen before --
    /// it is never on by default, and it never causes an already-recorded,
    /// *different* key to be accepted (see
    /// [`known_hosts::verify_host_key`]). Any acceptance it does grant is
    /// held only in `known_hosts`'s own in-memory state, not written back
    /// to any file.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Connect`] if the TCP/SSH handshake fails,
    /// [`TransportError::UnknownHostKey`]/[`TransportError::HostKeyChanged`]
    /// if host key verification fails closed, or [`TransportError::Connect`]
    /// if authentication is rejected.
    pub async fn connect(
        host: &str,
        port: u16,
        user: &str,
        auth: &AuthMethod,
        known_hosts: Arc<KnownHosts>,
        accept_new: bool,
        max_output_bytes: usize,
    ) -> Result<Arc<Self>, TransportError> {
        let config = Arc::new(russh::client::Config::default());
        let label = handler::host_label(host, port);
        let client_handler = ClientHandler::new(label, known_hosts, accept_new);
        let mut handle = russh::client::connect(config, (host, port), client_handler).await?;
        handler::authenticate(&mut handle, user, auth).await?;
        Ok(Arc::new(Self {
            handle,
            max_output_bytes,
        }))
    }

    /// Pushes `collector_binary`, verifies it against `expected_hash`, runs
    /// it with `--emit-json`, and removes it -- guaranteeing cleanup on
    /// every code path this function can structurally reach. See the
    /// module doc for exactly what that guarantee does and doesn't cover.
    ///
    /// `expected_hash` should be the hash of `collector_binary` computed by
    /// the caller before this call, in whatever digest format the real
    /// collector's (T18) `--self-hash` output will use. This adapter
    /// compares the two as opaque, already-normalised strings; it doesn't
    /// itself compute a hash over `collector_binary`; the caller owns that
    /// so the same hash can be logged/recorded regardless of whether the
    /// push succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::IntegrityMismatch`] if the remote's
    /// self-reported hash doesn't match `expected_hash`, or any
    /// [`TransportError`] the underlying push/exec calls produce. A
    /// `remove` failure that happens *after* a successful collect is
    /// swallowed (best-effort) rather than surfaced here -- a scan that
    /// already succeeded must not be discarded because the cleanup step
    /// that follows it failed; see [`RemoteArtifactGuard`]'s own doc
    /// comment for why an orphaned artifact is harmless.
    pub async fn push_exec_collect_remove(
        self: &Arc<Self>,
        collector_binary: &Path,
        expected_hash: &str,
    ) -> Result<ScanSnapshot, TransportError> {
        let remote_path = RemotePath::random_under_temp();
        self.push(collector_binary, &remote_path).await?;
        let guard = RemoteArtifactGuard::new(Arc::clone(self), remote_path.clone());

        match run_and_collect(self, &remote_path, expected_hash).await {
            Ok(snapshot) => {
                // A cleanup failure here must not discard a scan that
                // already succeeded -- the caller asked for a snapshot and
                // got a real one; losing it because the *following*
                // best-effort cleanup step failed would be strictly worse
                // than an orphaned remote artifact (the next scan of this
                // host pushes to a fresh, unrelated random path, so nothing
                // downstream ever reuses or collides with a leftover one).
                let _ = guard.remove_now().await;
                Ok(snapshot)
            }
            Err(err) => {
                // Best-effort in the sense that a remove failure here
                // doesn't overwrite the original, more informative error --
                // not best-effort in the sense of the Drop-spawned path:
                // this call is `.await`ed, so it genuinely runs before this
                // function returns.
                let _ = guard.remove_now().await;
                Err(err)
            }
        }
    }
}

async fn run_and_collect(
    transport: &SshTransport,
    remote_path: &RemotePath,
    expected_hash: &str,
) -> Result<ScanSnapshot, TransportError> {
    let hash_check = transport
        .exec(&RemoteCommand::new(remote_path.as_str(), ["--self-hash"]))
        .await?;
    if String::from_utf8_lossy(&hash_check.stdout).trim() != expected_hash {
        return Err(TransportError::IntegrityMismatch);
    }

    // `scan` is required here, unlike `--self-hash` above: the real `anne`
    // CLI has no top-level `--emit-json` flag, only `ScanArgs::emit_json`
    // under the `scan` subcommand (`cli::Command::Scan`) -- confirmed the
    // hard way (T31) by an end-to-end test against a real pushed `anne`
    // binary, which failed decoding empty stdout until this line named
    // the subcommand. `--self-hash` gets away with a bare invocation only
    // because `main` intercepts it *before* `Cli::parse()` ever runs.
    let output = transport
        .exec(&RemoteCommand::new(
            remote_path.as_str(),
            ["scan", "--emit-json"],
        ))
        .await?;
    serde_json::from_slice(&output.stdout).map_err(TransportError::from)
}

#[async_trait]
impl RemoteTransport for SshTransport {
    async fn push(&self, local: &Path, remote: &RemotePath) -> Result<(), TransportError> {
        sftp::push(&self.handle, local, remote).await
    }

    async fn exec(&self, cmd: &RemoteCommand) -> Result<ExecOutput, TransportError> {
        exec::exec(&self.handle, cmd, self.max_output_bytes).await
    }

    async fn remove(&self, remote: &RemotePath) -> Result<(), TransportError> {
        sftp::remove(&self.handle, remote).await
    }
}

/// Guarantees remote cleanup for [`SshTransport::push_exec_collect_remove`]
/// on exit paths its own code can't structurally reach. See the module doc
/// for the full reasoning; in short, call [`Self::remove_now`] and
/// `.await` it on every code-visible path -- `Drop` is the panic/
/// cancellation-only fallback, not the primary mechanism.
struct RemoteArtifactGuard {
    transport: Arc<SshTransport>,
    path: RemotePath,
    disarmed: AtomicBool,
}

impl RemoteArtifactGuard {
    const fn new(transport: Arc<SshTransport>, path: RemotePath) -> Self {
        Self {
            transport,
            path,
            disarmed: AtomicBool::new(false),
        }
    }

    /// Removes the artifact now, on the caller's own task, and marks the
    /// guard disarmed so `Drop` doesn't also spawn a redundant removal.
    async fn remove_now(&self) -> Result<(), TransportError> {
        self.disarmed.store(true, Ordering::Release);
        self.transport.remove(&self.path).await
    }
}

impl Drop for RemoteArtifactGuard {
    fn drop(&mut self) {
        if self.disarmed.load(Ordering::Acquire) {
            return;
        }
        let transport = Arc::clone(&self.transport);
        let path = self.path.clone();
        tokio::spawn(async move {
            let _ = transport.remove(&path).await;
        });
    }
}

#[cfg(test)]
mod tests;
