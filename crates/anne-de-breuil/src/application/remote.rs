//! [`RemoteTransport`]: the port for pushing, executing, and removing a
//! static collector on a remote host.
//!
//! Declared here, not in `adapters/`, because remote execution is a
//! capability a use case *consumes* — the concrete transport (SSH, via
//! `russh`) doesn't exist yet, and the fan-out orchestrator that will drive
//! this port is a later task too. This port is deliberately optional to the
//! design: a host with no working [`RemoteTransport`] implementation
//! available for it degrades to [`TargetStrategy::Probe`], never a hard
//! failure — a probe-only fleet scan is the expected default in most
//! Windows environments, not a degraded mode to apologise for.
//!
//! `push`/`exec`/`remove` all do real I/O over a network connection and
//! must stay object-safe so a fan-out orchestrator can hold many of them
//! behind `Arc<dyn RemoteTransport>` for concurrent hosts. Native `async
//! fn` in traits is not object-safe, so `#[async_trait]` is used here, the
//! same sanctioned pattern already established by
//! [`crate::application::collect`] and [`crate::application::SnapshotStore`].

use core::time::Duration;
use std::path::Path;

use async_trait::async_trait;

/// Which collection tier produced a snapshot.
///
/// Re-exported here from [`crate::domain::TargetStrategy`] rather than
/// defined in this module: it is recorded directly on
/// [`crate::domain::ScanSnapshot`], a pure domain aggregate, and the
/// project's hexagonal rule ("depend inward: adapters → ports ← domain")
/// means domain code can never import from `application`. The type has to
/// live in `domain` to be embeddable there; this re-export keeps it
/// reachable from `application::remote` too, next to the transport port
/// whose caller (the future fan-out orchestrator) decides which variant
/// applies per host.
pub use crate::domain::TargetStrategy;

/// Failure using a [`RemoteTransport`] against a remote host.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Establishing or maintaining the connection to the remote host failed.
    #[error("connecting to remote host failed: {0}")]
    Connect(String),
    /// Transferring a file to or from the remote host failed.
    #[error("transferring a file failed: {0}")]
    Transfer(String),
    /// Running a command on the remote host failed.
    #[error("executing a remote command failed: {0}")]
    Exec(String),
    /// Deleting a remote artifact failed.
    #[error("removing a remote artifact failed: {0}")]
    Remove(String),
    /// The operation did not complete within the allotted time.
    #[error("remote transport timed out after {0:?}")]
    Timeout(Duration),
    /// A candidate [`RemotePath`] was empty or otherwise not a usable path.
    #[error("invalid remote path: {0:?}")]
    InvalidPath(String),
    /// The remote collector's self-reported hash did not match the hash
    /// computed locally before push -- the pushed artifact may have been
    /// tampered with, truncated, or swapped in transit.
    #[error("remote artifact hash did not match the expected local hash")]
    IntegrityMismatch,
    /// The host presented a key with no matching entry in `known_hosts`,
    /// and the caller did not opt into accepting new keys for this
    /// invocation. Fails closed: connecting with a fresh, unverified key is
    /// exactly the trust-on-first-use gap a MITM would exploit.
    #[error(
        "host key is not in known_hosts (fingerprint {fingerprint}); \
         re-run with an explicit accept-new option after verifying it out of band"
    )]
    UnknownHostKey {
        /// The SHA256 fingerprint of the offered, unrecognised key.
        fingerprint: String,
    },
    /// The host's key does not match the one already recorded in
    /// `known_hosts`. Never auto-accepted, even when the caller opted into
    /// accepting *new* keys -- a changed key on a known host is exactly the
    /// signal `--accept-new` must not paper over.
    #[error("host key has changed since it was last recorded in known_hosts")]
    HostKeyChanged,
    /// Captured stdout reached the configured byte cap before the remote
    /// command finished producing output. The command's actual output is
    /// discarded rather than silently truncated and trusted.
    #[error("remote stdout exceeded the configured capture cap")]
    OutputCapExceeded,
    /// Decoding a JSON payload read back from a remote command failed.
    #[error("decoding remote JSON output failed: {0}")]
    JsonDecode(#[from] serde_json::Error),
    /// The underlying SSH protocol/session failed. Only constructible when
    /// the `ssh` feature is enabled, since `russh::Error` is only in the
    /// dependency graph behind that feature.
    #[cfg(feature = "ssh")]
    #[error("ssh session error: {0}")]
    Ssh(#[from] russh::Error),
    /// An SFTP operation (push/remove) failed at the protocol level. Only
    /// constructible when the `ssh` feature is enabled, for the same reason
    /// as [`TransportError::Ssh`].
    #[cfg(feature = "ssh")]
    #[error("sftp error: {0}")]
    Sftp(#[from] russh_sftp::client::error::Error),
}

/// Pushes, executes, and removes a static collector on a remote host.
///
/// Three methods, the ceiling. This port exists so an execute path (SSH
/// today, potentially another transport later) can be added without ever
/// touching the fan-out handler that consumes it.
///
/// # Examples
///
/// ```
/// use async_trait::async_trait;
/// use std::path::Path;
/// use std::time::Duration;
/// use anne_de_breuil::application::remote::{
///     ExecOutput, RemoteCommand, RemotePath, RemoteTransport, TransportError,
/// };
///
/// /// A transport that never leaves the process — useful for exercising
/// /// callers of `RemoteTransport` with no network access at all.
/// struct NoopTransport;
///
/// #[async_trait]
/// impl RemoteTransport for NoopTransport {
///     async fn push(&self, _local: &Path, _remote: &RemotePath) -> Result<(), TransportError> {
///         Ok(())
///     }
///
///     async fn exec(&self, _cmd: &RemoteCommand) -> Result<ExecOutput, TransportError> {
///         Ok(ExecOutput {
///             status: 0,
///             stdout: Vec::new(),
///             stderr: Vec::new(),
///             duration: Duration::from_secs(0),
///         })
///     }
///
///     async fn remove(&self, _remote: &RemotePath) -> Result<(), TransportError> {
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait RemoteTransport: Send + Sync {
    /// Copies the file at `local` to `remote` on the target host.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the connection or transfer fails.
    async fn push(&self, local: &Path, remote: &RemotePath) -> Result<(), TransportError>;

    /// Runs `cmd` on the target host and returns its captured output.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the connection or execution fails.
    async fn exec(&self, cmd: &RemoteCommand) -> Result<ExecOutput, TransportError>;

    /// Deletes the artifact at `remote` on the target host.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the connection or removal fails.
    async fn remove(&self, remote: &RemotePath) -> Result<(), TransportError>;
}

/// A command to run on a remote host, expressed as an argv vector.
///
/// There is deliberately no constructor from a shell string. Every argument
/// is a distinct, unescaped element — never concatenated, quoted, or
/// otherwise assembled into a single command line — so no value, however
/// untrusted, can ever be interpolated into shell syntax. This is a
/// compile-time guarantee, not a runtime check: [`RemoteCommand::new`] is
/// the only constructor this type has, and no `FromStr`/`from_shell`
/// (or any other string-parsing) impl exists anywhere in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCommand {
    argv: Vec<String>,
}

impl RemoteCommand {
    /// Builds a command from a program name and its arguments.
    ///
    /// `program` becomes `argv[0]`; every element of `arguments` becomes one
    /// further, unmodified argv entry.
    #[must_use]
    pub fn new(
        program: impl Into<String>,
        arguments: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let mut built = vec![program.into()];
        built.extend(arguments.into_iter().map(Into::into));
        Self { argv: built }
    }

    /// Returns the argv vector: index 0 is the program, the rest are its arguments.
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }
}

/// A validated remote filesystem path.
///
/// Parse-validated at construction: an empty or whitespace-only path is
/// rejected here, at the boundary, rather than trusted downstream through
/// [`RemoteTransport`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemotePath(String);

impl RemotePath {
    /// Returns the path as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Builds a fresh, unpredictable path under the remote temp directory.
    ///
    /// Every SSH-reachable target this crate scans is Unix-like (WinRM/PSRP
    /// are out of scope by design), so `/tmp` is a safe, always-present
    /// default rather than something that needs a round trip to discover.
    /// The random component is a v4 UUID: unguessable enough that a
    /// concurrent, unrelated process on the same host can't collide with
    /// or predict the artifact's path, which matters because the artifact
    /// briefly holds a copy of the collector binary this crate ships.
    #[must_use]
    pub fn random_under_temp() -> Self {
        // Constructed directly (bypassing `TryFrom`'s validation) rather
        // than via `.unwrap()`: the format string is always non-empty and
        // non-whitespace, so the validation could never fail here, and this
        // way there's no fallible path to justify at all.
        Self(format!("/tmp/anne-collector-{}", uuid::Uuid::new_v4()))
    }
}

impl TryFrom<String> for RemotePath {
    type Error = TransportError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(TransportError::InvalidPath(value));
        }
        Ok(Self(trimmed.to_owned()))
    }
}

impl core::str::FromStr for RemotePath {
    type Err = TransportError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl core::fmt::Display for RemotePath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The captured result of running a [`RemoteCommand`] through [`RemoteTransport::exec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// The process's exit status.
    pub status: i32,
    /// Captured standard output bytes.
    pub stdout: Vec<u8>,
    /// Captured standard error bytes.
    pub stderr: Vec<u8>,
    /// How long the command took to complete.
    pub duration: Duration,
}

#[cfg(test)]
mod tests {
    use super::{ExecOutput, RemoteCommand, RemotePath, TransportError};

    #[test]
    fn remote_command_argv_has_no_shell_interpolation_path() {
        let cmd = RemoteCommand::new("anne-collector", ["--emit-json"]);
        assert_eq!(
            cmd.argv,
            vec!["anne-collector".to_owned(), "--emit-json".to_owned()]
        );
        // No `RemoteCommand::from_str`/`from_shell` exists anywhere in this
        // crate — this is a compile-time guarantee, not a runtime one.
    }

    #[test]
    fn remote_command_argv_accessor_matches_construction_order() {
        let cmd = RemoteCommand::new("cmd", ["a", "b", "c"]);
        assert_eq!(cmd.argv(), ["cmd", "a", "b", "c"]);
    }

    #[test]
    fn remote_path_rejects_empty_and_whitespace() {
        assert!(RemotePath::try_from(String::new()).is_err());
        assert!(RemotePath::try_from("   ".to_owned()).is_err());
    }

    #[test]
    fn remote_path_accepts_a_real_path() {
        let path = RemotePath::try_from("/tmp/anne-collector-abc123".to_owned()).unwrap();
        assert_eq!(path.as_str(), "/tmp/anne-collector-abc123");
    }

    #[test]
    fn exec_output_carries_status_bytes_and_duration() {
        let output = ExecOutput {
            status: 0,
            stdout: b"hello".to_vec(),
            stderr: Vec::new(),
            duration: core::time::Duration::from_millis(5),
        };
        assert_eq!(output.status, 0);
        assert_eq!(output.stdout, b"hello");
        assert!(output.stderr.is_empty());
        assert_eq!(output.duration, core::time::Duration::from_millis(5));
    }

    #[test]
    fn transport_error_display_names_the_failure_kind() {
        let err = TransportError::Timeout(core::time::Duration::from_secs(30));
        assert!(err.to_string().contains("timed out"));
    }
}
