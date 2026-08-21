//! [`reconcile`]: compares local process attribution against remote
//! fingerprinting without ever letting one silently overwrite the other.
//!
//! A reverse proxy in front of something is the normal explanation when the
//! owning process is `nginx.exe` but the port answers as Grafana —
//! collapsing that to one answer destroys the evidence that made it
//! legible. [`ReconciliationReport`] always keeps both sides, each with its
//! own evidence, whether or not they agree.
//!
//! # Hard invariant: a fingerprint match never promotes `Inferred` to `Authoritative`
//!
//! [`reconcile`] takes ownership of the caller's [`Attribution`] and stores
//! it unchanged in [`ReconciliationReport::local`] — there is no branch in
//! this module that calls [`Attribution::authoritative`], and no branch
//! that constructs an `Attribution` at all. However confidently `remote`
//! identifies a service, it can never turn a probe-only [`Attribution::Inferred`]
//! into an [`Attribution::Authoritative`]; see
//! [`tests::reconcile_never_promotes_inferred_to_authoritative`] for the
//! enforcing test.

use crate::domain::attribution::Attribution;
use crate::domain::service_identity::ServiceIdentity;

/// The result of comparing local process attribution against remote
/// service fingerprinting for one endpoint.
#[derive(Debug, Clone)]
pub struct ReconciliationReport {
    /// The local attribution exactly as supplied — never mutated, never
    /// promoted.
    pub local: Attribution,
    /// A display label for `local`, when it carries one: the Windows
    /// service name or systemd unit if the platform reported one,
    /// otherwise the owning process's executable path. `None` for
    /// [`Attribution::Inferred`], which has no ownership claim to label.
    pub local_identity: Option<String>,
    /// Every service identity fingerprinting produced from remote
    /// evidence, each still carrying its own evidence and confidence.
    pub remote: Vec<ServiceIdentity>,
    /// The name of the strongest remote identity, if any were found.
    pub remote_identity: Option<String>,
    /// `true` if `local_identity` and `remote_identity` are both present
    /// and name different services.
    pub conflict: bool,
}

/// Compares `local` process attribution against `remote` fingerprinting
/// results, retaining both in full rather than letting either silently win.
#[must_use]
pub fn reconcile(local: Attribution, remote: Vec<ServiceIdentity>) -> ReconciliationReport {
    let local_identity = local_identity_label(&local);
    let remote_identity = remote.first().map(|identity| identity.name().to_owned());
    let conflict = match (&local_identity, &remote_identity) {
        (Some(local_name), Some(remote_name)) => !local_name.eq_ignore_ascii_case(remote_name),
        _ => false,
    };

    ReconciliationReport {
        local,
        local_identity,
        remote,
        remote_identity,
        conflict,
    }
}

fn local_identity_label(local: &Attribution) -> Option<String> {
    match local {
        Attribution::Authoritative {
            process_path,
            service_name,
            ..
        } => Some(service_name.as_ref().map_or_else(
            || process_path.as_str().to_owned(),
            |name| name.as_str().to_owned(),
        )),
        Attribution::Inferred { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::reconcile;
    use crate::domain::attribution::Attribution;
    use crate::domain::confidence::Confidence;
    use crate::domain::evidence::Evidence;
    use crate::domain::ids::ProcessId;
    use crate::domain::process::ProcessPath;
    use crate::domain::publisher::SignatureStatus;
    use crate::domain::service::ServiceName;
    use crate::domain::service_category::ServiceCategory;
    use crate::domain::service_identity::ServiceIdentity;

    fn nginx_identity() -> ServiceIdentity {
        ServiceIdentity::new(
            "grafana",
            ServiceCategory::Monitoring,
            Confidence::Probable,
            vec![Evidence::HttpBodyPattern {
                snippet: "<title>Grafana</title>".to_owned(),
            }],
        )
        .expect("body-pattern evidence justifies Probable confidence")
    }

    #[test]
    fn conflicting_local_and_remote_identities_are_both_retained() {
        let local = Attribution::authoritative(
            ProcessId::try_from(4321).expect("nonzero pid"),
            ProcessPath::try_from("nginx.exe".to_owned()).expect("non-empty path"),
            None,
            SignatureStatus::Unknown,
        );
        let remote = vec![nginx_identity()];

        let report = reconcile(local, remote);

        assert_eq!(report.local_identity.as_deref(), Some("nginx.exe"));
        assert_eq!(report.remote_identity.as_deref(), Some("grafana"));
        assert!(report.conflict);
        assert_eq!(
            report.remote.len(),
            1,
            "remote evidence must not be dropped on conflict"
        );
    }

    #[test]
    fn agreeing_local_and_remote_identities_report_no_conflict() {
        let local = Attribution::authoritative(
            ProcessId::try_from(1).expect("nonzero pid"),
            ProcessPath::try_from("/usr/sbin/grafana-server".to_owned()).expect("non-empty path"),
            Some(ServiceName::try_from("grafana".to_owned()).expect("non-empty name")),
            SignatureStatus::NotApplicable,
        );
        let remote = vec![nginx_identity()];

        let report = reconcile(local, remote);

        assert_eq!(report.local_identity.as_deref(), Some("grafana"));
        assert!(!report.conflict);
    }

    #[test]
    fn reconcile_never_promotes_inferred_to_authoritative() {
        let local = Attribution::inferred(vec![Evidence::BannerMatch {
            pattern: "SSH-2.0-OpenSSH_9.6".to_owned(),
        }]);

        let report = reconcile(local, vec![nginx_identity()]);

        assert!(matches!(report.local, Attribution::Inferred { .. }));
        assert!(report.local_identity.is_none());
        assert!(report.remote_identity.is_some());
    }
}
