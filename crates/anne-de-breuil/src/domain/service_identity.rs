//! [`ServiceIdentity`]: what is believed to be running on a port, backed by evidence.
//!
//! Modelled as an inference, never as an assertion derived from the port
//! number: the only constructor requires at least one [`Evidence`] entry,
//! and refuses to let a bare registry match claim more than the weakest
//! confidence tier.

use crate::domain::confidence::Confidence;
use crate::domain::error::DomainError;
use crate::domain::evidence::Evidence;
use crate::domain::service_category::ServiceCategory;

/// A believed service identity, always backed by non-empty evidence.
///
/// There is no public raw constructor and no `pub` field — [`Self::new`] is
/// the only way to build one, so an evidence-free or overconfident identity
/// is unrepresentable rather than merely discouraged.
#[derive(Debug, Clone)]
pub struct ServiceIdentity {
    name: String,
    category: ServiceCategory,
    version: Option<String>,
    confidence: Confidence,
    evidence: Vec<Evidence>,
}

impl ServiceIdentity {
    /// The only constructor — an evidence-free identity is unrepresentable.
    ///
    /// Rejects an empty `evidence` ([`DomainError::MissingEvidence`]) and
    /// rejects `confidence` above [`Confidence::Assigned`] when every entry
    /// in `evidence` is [`Evidence::PortAssignment`]
    /// ([`DomainError::OverconfidentFromPortAlone`]) — a registry number
    /// match alone can never justify more than the weakest tier.
    pub fn new(
        name: impl Into<String>,
        category: ServiceCategory,
        confidence: Confidence,
        evidence: Vec<Evidence>,
    ) -> Result<Self, DomainError> {
        if evidence.is_empty() {
            return Err(DomainError::MissingEvidence);
        }
        if confidence > Confidence::Assigned
            && evidence.iter().all(Evidence::is_port_assignment_only)
        {
            return Err(DomainError::OverconfidentFromPortAlone);
        }
        Ok(Self {
            name: name.into(),
            category,
            version: None,
            confidence,
            evidence,
        })
    }

    /// Attaches an observed version string. Not evidence in its own right —
    /// callers should already have justified `confidence` before adding one.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// The believed service name (e.g. `"nginx"`, `"ssh"`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The coarse category this service belongs to.
    #[must_use]
    pub const fn category(&self) -> ServiceCategory {
        self.category
    }

    /// The observed version string, if any evidence carried one.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// How strongly this identity is believed.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// The evidence backing this identity. Never empty.
    #[must_use]
    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }
}

#[cfg(test)]
mod tests {
    use super::ServiceIdentity;
    use crate::domain::confidence::Confidence;
    use crate::domain::error::DomainError;
    use crate::domain::evidence::Evidence;
    use crate::domain::service_category::ServiceCategory;

    #[test]
    fn empty_evidence_is_rejected() {
        let err = ServiceIdentity::new(
            "nginx",
            ServiceCategory::WebServer,
            Confidence::Confirmed,
            vec![],
        )
        .unwrap_err();
        assert!(matches!(err, DomainError::MissingEvidence));
    }

    #[test]
    fn port_assignment_alone_cannot_exceed_assigned_confidence() {
        let evidence = vec![Evidence::PortAssignment {
            registry_name: "https".into(),
        }];
        let err = ServiceIdentity::new(
            "https",
            ServiceCategory::WebServer,
            Confidence::Confirmed,
            evidence,
        )
        .unwrap_err();
        assert!(matches!(err, DomainError::OverconfidentFromPortAlone));
    }

    #[test]
    fn port_assignment_alone_permits_assigned_confidence() {
        let evidence = vec![Evidence::PortAssignment {
            registry_name: "https".into(),
        }];
        let identity = ServiceIdentity::new(
            "https",
            ServiceCategory::WebServer,
            Confidence::Assigned,
            evidence,
        )
        .expect("Assigned confidence from a bare port match must be permitted");
        assert_eq!(identity.confidence(), Confidence::Assigned);
        assert_eq!(identity.evidence().len(), 1);
    }

    #[test]
    fn mixed_evidence_permits_higher_confidence() {
        let evidence = vec![
            Evidence::PortAssignment {
                registry_name: "ssh".into(),
            },
            Evidence::BannerMatch {
                pattern: "SSH-2.0-OpenSSH".into(),
            },
        ];
        let identity = ServiceIdentity::new(
            "ssh",
            ServiceCategory::RemoteAccess,
            Confidence::Probable,
            evidence,
        )
        .expect("banner evidence alongside a port match may justify Probable");
        assert_eq!(identity.confidence(), Confidence::Probable);
    }
}
