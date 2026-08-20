//! [`Evidence`]: the typed, observable basis for a [`crate::domain::ServiceIdentity`].
//!
//! A verdict with no evidence must be unrepresentable — see
//! [`crate::domain::ServiceIdentity::new`], the only constructor, which
//! rejects an empty `Vec<Evidence>`.

/// One observed fact supporting a service identification.
///
/// Each variant names the class of observation it stands for; nothing here
/// carries a confidence value of its own — confidence is a judgement about
/// the evidence as a whole, made once, at [`crate::domain::ServiceIdentity`]
/// construction.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Evidence {
    /// The port number matches an IANA (or vendored-equivalent) registry entry.
    PortAssignment {
        /// The registry's service name for this port/protocol pair.
        registry_name: String,
    },
    /// A weak or generic response banner matched a known pattern.
    BannerMatch {
        /// The pattern that matched.
        pattern: String,
    },
    /// An HTTP response header matched an expected name/value pair.
    HttpHeader {
        /// The header name.
        name: String,
        /// The header value.
        value: String,
    },
    /// The HTTP response body contained a recognisable pattern.
    HttpBodyPattern {
        /// The matched snippet.
        snippet: String,
    },
    /// A TLS certificate's subject matched an expected pattern.
    TlsCertificateSubject {
        /// The certificate subject string.
        subject: String,
    },
    /// The owning process's name matched an expected value.
    ProcessName {
        /// The observed process name.
        name: String,
    },
}

impl Evidence {
    /// `true` iff this evidence is a bare registry port-number match.
    ///
    /// Used by [`crate::domain::ServiceIdentity::new`] to reject confidence
    /// above [`crate::domain::Confidence::Assigned`] when every piece of
    /// evidence is this variant — a registry match alone can never justify
    /// more.
    #[must_use]
    pub const fn is_port_assignment_only(&self) -> bool {
        matches!(self, Self::PortAssignment { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::Evidence;

    #[test]
    fn is_port_assignment_only_distinguishes_variants() {
        let assignment = Evidence::PortAssignment {
            registry_name: "https".to_owned(),
        };
        let banner = Evidence::BannerMatch {
            pattern: "SSH-2.0".to_owned(),
        };
        assert!(assignment.is_port_assignment_only());
        assert!(!banner.is_port_assignment_only());
    }
}
