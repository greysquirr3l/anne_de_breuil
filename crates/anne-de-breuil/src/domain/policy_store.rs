//! [`PolicyStore`]: where a firewall rule's definition originates.

use crate::domain::error::DomainError;

/// The origin store a firewall rule was defined in.
///
/// Distinguishing origin matters for the report: a rule pushed down by
/// Group Policy has a different owner and a different remediation path
/// than one an admin added locally.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum PolicyStore {
    /// Defined directly on the host. Also where a Linux nftables ruleset
    /// lands — this project's data model has no Group-Policy-style
    /// centrally-managed origin concept for nftables, so its one
    /// host-wide ruleset is always local by definition.
    Local,
    /// Pushed down by Group Policy (or an equivalent centrally-managed policy engine).
    GroupPolicy,
    /// Created transiently at runtime (e.g. by an application installer or a service).
    Dynamic,
    /// Part of the platform's built-in/persistent default rule set.
    Static,
}

impl core::str::FromStr for PolicyStore {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("local") || trimmed.eq_ignore_ascii_case("nftables") {
            Ok(Self::Local)
        } else if trimmed.eq_ignore_ascii_case("grouppolicy") || trimmed.eq_ignore_ascii_case("gpo")
        {
            Ok(Self::GroupPolicy)
        } else if trimmed.eq_ignore_ascii_case("dynamic") {
            Ok(Self::Dynamic)
        } else if trimmed.eq_ignore_ascii_case("static")
            || trimmed.eq_ignore_ascii_case("persistentstore")
        {
            Ok(Self::Static)
        } else {
            Err(DomainError::UnknownPolicyStore(s.to_owned()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_stores_case_insensitively() {
        assert_eq!("Local".parse::<PolicyStore>().unwrap(), PolicyStore::Local);
        assert_eq!(
            "gpo".parse::<PolicyStore>().unwrap(),
            PolicyStore::GroupPolicy
        );
        assert_eq!(
            "DYNAMIC".parse::<PolicyStore>().unwrap(),
            PolicyStore::Dynamic
        );
        assert_eq!(
            "PersistentStore".parse::<PolicyStore>().unwrap(),
            PolicyStore::Static
        );
    }

    #[test]
    fn rejects_unknown_store() {
        assert!("Cloud".parse::<PolicyStore>().is_err());
    }

    #[test]
    fn nftables_maps_to_local() {
        assert_eq!(
            "nftables".parse::<PolicyStore>().unwrap(),
            PolicyStore::Local
        );
    }
}
