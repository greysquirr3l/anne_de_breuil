//! [`ProfileState`]: a firewall profile's default action and enablement.

use crate::domain::error::DomainError;
use crate::domain::firewall_rule::RuleAction;

/// Which firewall profile a [`ProfileState`] describes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum FirewallProfileKind {
    /// Applies when the host is joined to and connected via a domain network.
    Domain,
    /// Applies to networks the user has marked private/trusted.
    Private,
    /// Applies to untrusted/public networks.
    Public,
}

impl core::str::FromStr for FirewallProfileKind {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("domain") {
            Ok(Self::Domain)
        } else if trimmed.eq_ignore_ascii_case("private") {
            Ok(Self::Private)
        } else if trimmed.eq_ignore_ascii_case("public") {
            Ok(Self::Public)
        } else {
            Err(DomainError::InvalidFirewallProfileKind(s.to_owned()))
        }
    }
}

/// The observed state of one firewall profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileState {
    /// Which profile this describes.
    pub profile: FirewallProfileKind,
    /// Whether the firewall is enabled for this profile.
    pub enabled: bool,
    /// The action applied to inbound traffic that no rule explicitly covers.
    pub default_inbound_action: RuleAction,
    /// The action applied to outbound traffic that no rule explicitly covers.
    pub default_outbound_action: RuleAction,
}

impl ProfileState {
    /// A stable sort key for deterministic snapshot serialization.
    #[must_use]
    pub const fn sort_key(&self) -> FirewallProfileKind {
        self.profile
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sort_key_is_the_profile_kind() {
        let state = ProfileState {
            profile: FirewallProfileKind::Public,
            enabled: true,
            default_inbound_action: RuleAction::Block,
            default_outbound_action: RuleAction::Allow,
        };
        assert_eq!(state.sort_key(), FirewallProfileKind::Public);
    }

    #[test]
    fn firewall_profile_kind_parses_case_insensitively() {
        use core::str::FromStr as _;

        assert_eq!(
            FirewallProfileKind::from_str("Domain").unwrap(),
            FirewallProfileKind::Domain
        );
        assert_eq!(
            FirewallProfileKind::from_str("PRIVATE").unwrap(),
            FirewallProfileKind::Private
        );
        assert_eq!(
            FirewallProfileKind::from_str("public").unwrap(),
            FirewallProfileKind::Public
        );
    }

    #[test]
    fn firewall_profile_kind_rejects_unknown_text() {
        use core::str::FromStr as _;

        assert!(FirewallProfileKind::from_str("Guest").is_err());
    }
}
