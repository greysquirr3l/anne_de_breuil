//! [`summarize_inbound_ports`]: per-profile inbound allow-rule posture.
//!
//! Pure and zero I/O, same shape as [`crate::domain::reachability::evaluate`]
//! next to it: no clock, no environment, deterministic in the input rules
//! and profiles alone.
//!
//! # A real limitation in this domain model, not glossed over
//!
//! [`crate::domain::firewall_rule::FirewallRule`] carries no
//! profile-scoping field. Windows Firewall rules can in reality be scoped
//! to specific profiles (the `-Profile` parameter on
//! `New-NetFirewallRule`), but nothing in this collector's data model
//! captures that scoping — a `FirewallRule` observed on a host applies
//! however this evaluator treats it, uniformly, regardless of which
//! profile is active. So this function honestly applies the same enabled
//! inbound allow rules to every [`ProfileState`] it's given; the only
//! thing that genuinely differs per profile here is each profile's own
//! `enabled`/`default_inbound_action`. A caller that renders this data
//! (see `adapters::html_report::diagrams::profile_bar_chart`) must not
//! imply the rule sets themselves differ across profiles, because in this
//! data model they don't — there's nothing to differ them on.

use crate::domain::firewall_rule::{Direction, FirewallRule, RuleAction};
use crate::domain::profile::{FirewallProfileKind, ProfileState};

/// One inbound-allow rule as it applies to a profile, labeled honestly.
///
/// See [`crate::domain::port_spec::PortSpec::display_label`] for how a
/// wide range or list is summarized rather than exploded port by port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedPortEntry {
    /// The rule's own display name — never matched on, display only.
    pub rule_display_name: String,
    /// A short, human-readable label for the rule's port spec.
    pub port_label: String,
}

/// One profile's inbound posture: its own enabled/default-action state,
/// plus the inbound allow rules that apply to it.
///
/// See the module doc for why that rule list is identical across every
/// profile in this data model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePortSummary {
    /// Which profile this describes.
    pub profile: FirewallProfileKind,
    /// Whether the firewall enforces this profile's rules at all.
    pub enabled: bool,
    /// The action applied to inbound traffic no rule explicitly covers.
    pub default_inbound_action: RuleAction,
    /// Enabled inbound allow rules, in the input `rules` slice's own order.
    pub allowed: Vec<AllowedPortEntry>,
}

/// Builds one [`ProfilePortSummary`] per entry in `profiles`.
///
/// Only `enabled` `Direction::Inbound` `RuleAction::Allow` rules
/// contribute an [`AllowedPortEntry`] — a disabled rule was turned off by
/// whoever administers the host and does not currently allow anything, and
/// an inbound `Block` rule (or any outbound rule) has nothing to say about
/// which inbound ports a profile leaves open.
#[must_use]
pub fn summarize_inbound_ports(
    rules: &[FirewallRule],
    profiles: &[ProfileState],
) -> Vec<ProfilePortSummary> {
    let allowed: Vec<AllowedPortEntry> = rules
        .iter()
        .filter(|rule| rule.enabled && rule.direction == Direction::Inbound)
        .filter(|rule| rule.action == RuleAction::Allow)
        .map(|rule| AllowedPortEntry {
            rule_display_name: rule.display_name.clone(),
            port_label: rule.port_spec.display_label(),
        })
        .collect();

    profiles
        .iter()
        .map(|profile_state| ProfilePortSummary {
            profile: profile_state.profile,
            enabled: profile_state.enabled,
            default_inbound_action: profile_state.default_inbound_action,
            allowed: allowed.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;

    use super::{ProfilePortSummary, summarize_inbound_ports};
    use crate::domain::firewall_rule::{Direction, FirewallRule, RuleAction};
    use crate::domain::ids::RuleId;
    use crate::domain::policy_store::PolicyStore;
    use crate::domain::port_spec::PortSpec;
    use crate::domain::profile::{FirewallProfileKind, ProfileState};
    use crate::domain::protocol::Protocol;

    fn rule(
        display_name: &str,
        direction: Direction,
        action: RuleAction,
        enabled: bool,
        port_spec: PortSpec,
    ) -> FirewallRule {
        FirewallRule {
            rule_id: RuleId::generate(),
            display_name: display_name.to_owned(),
            direction,
            action,
            protocol: Protocol::Tcp,
            port_spec,
            program_filter: None,
            service_filter: None,
            enabled,
            policy_store: PolicyStore::Local,
        }
    }

    fn profile(
        kind: FirewallProfileKind,
        enabled: bool,
        default_inbound: RuleAction,
    ) -> ProfileState {
        ProfileState {
            profile: kind,
            enabled,
            default_inbound_action: default_inbound,
            default_outbound_action: RuleAction::Allow,
        }
    }

    #[test]
    fn only_enabled_inbound_allow_rules_contribute_an_entry() {
        let rules = vec![
            rule(
                "https",
                Direction::Inbound,
                RuleAction::Allow,
                true,
                PortSpec::from_str("443").unwrap(),
            ),
            rule(
                "disabled",
                Direction::Inbound,
                RuleAction::Allow,
                false,
                PortSpec::from_str("8080").unwrap(),
            ),
            rule(
                "outbound",
                Direction::Outbound,
                RuleAction::Allow,
                true,
                PortSpec::from_str("9090").unwrap(),
            ),
            rule(
                "block",
                Direction::Inbound,
                RuleAction::Block,
                true,
                PortSpec::from_str("22").unwrap(),
            ),
        ];
        let profiles = vec![profile(
            FirewallProfileKind::Public,
            true,
            RuleAction::Block,
        )];
        let summary = summarize_inbound_ports(&rules, &profiles);
        let public = summary.first().expect("one profile");
        assert_eq!(public.allowed.len(), 1);
        assert_eq!(public.allowed[0].rule_display_name, "https");
        assert_eq!(public.allowed[0].port_label, "443");
    }

    #[test]
    fn every_profile_receives_the_same_rule_set_since_rules_are_not_profile_scoped() {
        let rules = vec![rule(
            "https",
            Direction::Inbound,
            RuleAction::Allow,
            true,
            PortSpec::from_str("443").unwrap(),
        )];
        let profiles = vec![
            profile(FirewallProfileKind::Domain, true, RuleAction::Block),
            profile(FirewallProfileKind::Private, true, RuleAction::Allow),
            profile(FirewallProfileKind::Public, false, RuleAction::Block),
        ];
        let summary = summarize_inbound_ports(&rules, &profiles);
        assert_eq!(summary.len(), 3);
        for entry in &summary {
            assert_eq!(entry.allowed.len(), 1);
            assert_eq!(entry.allowed[0].rule_display_name, "https");
        }
    }

    #[test]
    fn each_profile_keeps_its_own_enabled_and_default_action_state() {
        let profiles = vec![
            profile(FirewallProfileKind::Domain, true, RuleAction::Allow),
            profile(FirewallProfileKind::Public, false, RuleAction::Block),
        ];
        let summary = summarize_inbound_ports(&[], &profiles);
        let by_kind = |kind: FirewallProfileKind| -> &ProfilePortSummary {
            summary
                .iter()
                .find(|entry| entry.profile == kind)
                .expect("profile present")
        };
        assert!(by_kind(FirewallProfileKind::Domain).enabled);
        assert_eq!(
            by_kind(FirewallProfileKind::Domain).default_inbound_action,
            RuleAction::Allow
        );
        assert!(!by_kind(FirewallProfileKind::Public).enabled);
        assert_eq!(
            by_kind(FirewallProfileKind::Public).default_inbound_action,
            RuleAction::Block
        );
    }

    #[test]
    fn no_rules_at_all_yields_an_empty_allowed_list_per_profile() {
        let profiles = vec![profile(
            FirewallProfileKind::Domain,
            true,
            RuleAction::Block,
        )];
        let summary = summarize_inbound_ports(&[], &profiles);
        assert!(summary.first().expect("one profile").allowed.is_empty());
    }

    #[test]
    fn wide_port_specs_use_the_honest_summarized_label() {
        let rules = vec![rule(
            "rpc",
            Direction::Inbound,
            RuleAction::Allow,
            true,
            PortSpec::from_str("RPC").unwrap(),
        )];
        let profiles = vec![profile(
            FirewallProfileKind::Domain,
            true,
            RuleAction::Block,
        )];
        let summary = summarize_inbound_ports(&rules, &profiles);
        assert_eq!(
            summary.first().expect("one profile").allowed[0].port_label,
            "RPC (dynamic)"
        );
    }
}
