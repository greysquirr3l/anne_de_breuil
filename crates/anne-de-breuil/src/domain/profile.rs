//! [`ProfileState`]: a firewall profile's default action and enablement.

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
}
