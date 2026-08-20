//! [`MismatchedAssignment`] and [`detect_mismatch`]: a registry-assigned
//! port answering as something else.
//!
//! This is a first-class finding, not a warning — the single most valuable
//! output of this subsystem. A well-known service relocated to a high port
//! to avoid notice, or a high-value port (3389, 22, 3306, ...) quietly
//! repurposed, is exactly what an operator needs surfaced, not buried in a
//! log line.

use crate::domain::port::Port;
use crate::domain::service_identity::ServiceIdentity;

/// A registry-assigned service identity that contradicts what was actually observed.
#[derive(Debug, Clone)]
pub struct MismatchedAssignment {
    /// The port and protocol this finding is about.
    pub port: Port,
    /// What the registry says this port should be.
    pub assigned: ServiceIdentity,
    /// What actually answered.
    pub observed: ServiceIdentity,
}

/// Compares a registry-assigned identity against an observed one for `port`
/// and reports a [`MismatchedAssignment`] if their service names disagree.
///
/// Pure comparison, no I/O. The comparison is case-insensitive on `name()`
/// — `"HTTP"` and `"http"` are the same claim, but `"ms-wbt-server"` against
/// an OpenSSH banner is exactly the contradiction this function exists to
/// catch.
#[must_use]
pub fn detect_mismatch(
    port: Port,
    assigned: &ServiceIdentity,
    observed: &ServiceIdentity,
) -> Option<MismatchedAssignment> {
    if assigned.name().eq_ignore_ascii_case(observed.name()) {
        return None;
    }
    Some(MismatchedAssignment {
        port,
        assigned: assigned.clone(),
        observed: observed.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::detect_mismatch;
    use crate::domain::confidence::Confidence;
    use crate::domain::evidence::Evidence;
    use crate::domain::port::Port;
    use crate::domain::service_category::ServiceCategory;
    use crate::domain::service_identity::ServiceIdentity;

    fn identity_for_port(name: &str) -> ServiceIdentity {
        ServiceIdentity::new(
            name,
            ServiceCategory::RemoteAccess,
            Confidence::Assigned,
            vec![Evidence::PortAssignment {
                registry_name: name.to_owned(),
            }],
        )
        .expect("a bare port assignment at Assigned confidence must construct")
    }

    fn identity_from_banner(banner: &str) -> ServiceIdentity {
        ServiceIdentity::new(
            "ssh",
            ServiceCategory::RemoteAccess,
            Confidence::Probable,
            vec![Evidence::BannerMatch {
                pattern: banner.to_owned(),
            }],
        )
        .expect("a single banner-match entry justifies Probable confidence")
    }

    #[test]
    fn contradicting_observed_identity_produces_mismatch() {
        let port = Port::try_from(3389u16).expect("nonzero port");
        let assigned = identity_for_port("ms-wbt-server");
        let observed = identity_from_banner("SSH-2.0-OpenSSH_9.6");
        let mismatch =
            detect_mismatch(port, &assigned, &observed).expect("names disagree, must mismatch");
        assert_eq!(mismatch.assigned.name(), "ms-wbt-server");
        assert_eq!(mismatch.observed.name(), "ssh");
        assert_eq!(mismatch.port, port);
    }

    #[test]
    fn agreeing_identities_produce_no_mismatch() {
        let port = Port::try_from(22u16).expect("nonzero port");
        let assigned = identity_for_port("ssh");
        let observed = identity_from_banner("SSH-2.0-OpenSSH_9.6");
        assert!(detect_mismatch(port, &assigned, &observed).is_none());
    }
}
