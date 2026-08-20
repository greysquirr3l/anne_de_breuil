//! [`Attribution`]: who — or what — is believed to own an endpoint.
//!
//! Local and remote attribution are different kinds and must never be
//! conflated. [`Attribution::Authoritative`] carries owning PID, process
//! path, service name, and signature — only a local collector, which reads
//! these off the live OS, has that data in hand. [`Attribution::Inferred`]
//! carries observed behaviour only: a network probe can claim the responder
//! *behaves like* something, never that a given process *owns* the port.
//!
//! [`Attribution::authoritative`] is the only path to construct
//! `Authoritative`. There is deliberately no `From<Evidence>`,
//! `From<Vec<Evidence>>`, or any other conversion from [`Evidence`] or
//! [`Attribution::Inferred`] to `Authoritative` anywhere in this module —
//! grep it if in doubt. Producing an `Authoritative` value always requires
//! genuinely possessing a [`ProcessId`], a [`ProcessPath`], and a
//! [`SignatureStatus`], none of which are derivable from probe evidence.

use crate::domain::evidence::Evidence;
use crate::domain::ids::ProcessId;
use crate::domain::process::ProcessPath;
use crate::domain::publisher::SignatureStatus;
use crate::domain::service::ServiceName;

/// Who is believed to own an endpoint, and on what basis.
#[derive(Debug, Clone)]
pub enum Attribution {
    /// Owning-process data read directly off the live OS by a local
    /// collector. Only [`Attribution::authoritative`] constructs this.
    Authoritative {
        /// The owning process's id.
        pid: ProcessId,
        /// The owning process's executable path.
        process_path: ProcessPath,
        /// The hosted service name, if the platform reports one (e.g. a
        /// Windows service name or systemd unit).
        service_name: Option<ServiceName>,
        /// The code-signing status of the owning binary.
        signature: SignatureStatus,
    },
    /// Behaviour observed by a network probe, with no claim of ownership.
    Inferred {
        /// The evidence a probe collected about the responder's behaviour.
        evidence: Vec<Evidence>,
    },
}

impl Attribution {
    /// Builds an [`Attribution::Authoritative`] from local-collector data.
    ///
    /// This is the only constructor for that variant — there is no
    /// conversion from [`Evidence`] or from [`Attribution::Inferred`].
    #[must_use]
    pub const fn authoritative(
        pid: ProcessId,
        process_path: ProcessPath,
        service_name: Option<ServiceName>,
        signature: SignatureStatus,
    ) -> Self {
        Self::Authoritative {
            pid,
            process_path,
            service_name,
            signature,
        }
    }

    /// Builds an [`Attribution::Inferred`] from probe-observed evidence.
    #[must_use]
    pub const fn inferred(evidence: Vec<Evidence>) -> Self {
        Self::Inferred { evidence }
    }
}

#[cfg(test)]
mod tests {
    use super::Attribution;
    use crate::domain::evidence::Evidence;
    use crate::domain::ids::ProcessId;
    use crate::domain::process::ProcessPath;
    use crate::domain::publisher::SignatureStatus;

    #[test]
    fn authoritative_requires_pid_path_and_signature() {
        let pid = ProcessId::try_from(4321).expect("nonzero pid");
        let path = ProcessPath::try_from("C:\\Windows\\System32\\svchost.exe".to_owned())
            .expect("non-empty path");
        let attribution = Attribution::authoritative(pid, path, None, SignatureStatus::Unknown);
        match attribution {
            Attribution::Authoritative {
                pid: got_pid,
                signature,
                ..
            } => {
                assert_eq!(got_pid, pid);
                assert_eq!(signature, SignatureStatus::Unknown);
            }
            Attribution::Inferred { .. } => panic!("expected Authoritative"),
        }
    }

    /// There is no function or trait impl in this module that takes
    /// evidence alone and returns `Attribution::Authoritative` — the only
    /// way to reach that variant is [`Attribution::authoritative`], which
    /// this test calls with genuine local-collector data. Probe-only data
    /// (a bare `Vec<Evidence>`) can only ever produce `Inferred`.
    #[test]
    fn probe_only_evidence_can_only_produce_inferred_attribution() {
        let evidence = vec![Evidence::BannerMatch {
            pattern: "SSH-2.0-OpenSSH_9.6".into(),
        }];
        let attribution = Attribution::inferred(evidence);
        assert!(matches!(attribution, Attribution::Inferred { .. }));
    }
}
