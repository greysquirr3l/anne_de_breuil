//! The single error type for every value-object parse in the domain.

/// Failure parsing untrusted host data into a domain value object.
///
/// Every `TryFrom`/`FromStr` impl in [`crate::domain`] returns this type so
/// callers at the adapter boundary have one error surface to match on.
#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    /// A port number of zero was supplied; zero is "any port", not a bindable target.
    #[error("port must be nonzero (got {0})")]
    InvalidPort(u16),

    /// A process id of zero was supplied; no live process ever has pid 0.
    #[error("process id must be nonzero (got {0})")]
    InvalidProcessId(u32),

    /// The input did not match the `PortSpec` grammar (number, range, list, or keyword).
    #[error("malformed port spec: {0}")]
    MalformedPortSpec(String),

    /// The input did not parse as an IPv4 or IPv6 address.
    #[error("invalid bind address: {0}")]
    InvalidBindAddress(String),

    /// The input was not a recognised transport protocol name.
    #[error("invalid protocol: {0}")]
    InvalidProtocol(String),

    /// A string-backed value object received an empty or whitespace-only value.
    #[error("{field} must not be empty")]
    EmptyField {
        /// Name of the field that was empty, for diagnostic purposes.
        field: &'static str,
    },

    /// A UUID-backed identifier failed to parse from its string form.
    #[error("invalid uuid for {field}: {source}")]
    InvalidUuid {
        /// Name of the identifier type being parsed, for diagnostic purposes.
        field: &'static str,
        /// The underlying UUID parse failure.
        #[source]
        source: uuid::Error,
    },

    /// The input was not a recognised firewall policy store origin.
    #[error("unknown policy store: {0}")]
    UnknownPolicyStore(String),

    /// The input was not a recognised firewall rule direction.
    #[error("invalid firewall rule direction: {0}")]
    InvalidDirection(String),

    /// The input was not a recognised firewall rule action.
    #[error("invalid firewall rule action: {0}")]
    InvalidRuleAction(String),

    /// The input was not a recognised firewall profile kind.
    #[error("invalid firewall profile kind: {0}")]
    InvalidFirewallProfileKind(String),

    /// A `ServiceIdentity` was constructed with no supporting evidence.
    #[error("a ServiceIdentity requires at least one Evidence entry")]
    MissingEvidence,

    /// A `ServiceIdentity` claimed a confidence above `Confidence::Assigned`
    /// while backed only by `Evidence::PortAssignment` entries. A registry
    /// number match alone can never justify more than the weakest tier.
    #[error("a port-registry match alone cannot justify confidence above Assigned")]
    OverconfidentFromPortAlone,

    /// The input was neither a valid IP address nor a syntactically valid hostname.
    #[error("invalid host address: {0}")]
    InvalidHostAddress(String),
}
