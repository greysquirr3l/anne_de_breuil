//! [`FirewallRule`]: one effective firewall rule, as observed on a host.

use crate::domain::ids::RuleId;
use crate::domain::policy_store::PolicyStore;
use crate::domain::port_spec::PortSpec;
use crate::domain::process::ProcessPath;
use crate::domain::protocol::Protocol;
use crate::domain::service::ServiceName;

/// Whether a rule permits or denies matching traffic.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum RuleAction {
    /// Permits matching traffic.
    Allow,
    /// Denies matching traffic. Wins over an `Allow` when both apply.
    Block,
}

/// The traffic direction a rule governs.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Direction {
    /// Governs traffic arriving at the host.
    Inbound,
    /// Governs traffic leaving the host.
    Outbound,
}

/// One effective firewall rule as observed on a host.
///
/// Field names match what the reachability evaluator (built on top of this
/// type) reads directly: `protocol`, `port_spec`, `program_filter`,
/// `service_filter`, `action`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRule {
    /// Opaque identifier for this rule.
    pub rule_id: RuleId,
    /// Human-readable rule name, for display only — never matched on.
    pub display_name: String,
    /// Traffic direction this rule governs.
    pub direction: Direction,
    /// Whether the rule allows or blocks matching traffic.
    pub action: RuleAction,
    /// Transport protocol this rule applies to.
    pub protocol: Protocol,
    /// Local port specification this rule applies to.
    pub port_spec: PortSpec,
    /// Restricts the rule to a specific owning executable, if scoped.
    pub program_filter: Option<ProcessPath>,
    /// Restricts the rule to a specific hosted service, if scoped.
    pub service_filter: Option<ServiceName>,
    /// Whether the rule is currently enabled.
    pub enabled: bool,
    /// Where this rule's definition originates.
    pub policy_store: PolicyStore,
}

impl FirewallRule {
    /// A stable sort key for deterministic snapshot serialization.
    #[must_use]
    pub const fn sort_key(&self) -> RuleId {
        self.rule_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr as _;

    fn sample(rule_id: RuleId) -> FirewallRule {
        FirewallRule {
            rule_id,
            display_name: "Allow HTTPS".to_owned(),
            direction: Direction::Inbound,
            action: RuleAction::Allow,
            protocol: Protocol::Tcp,
            port_spec: PortSpec::from_str("443").unwrap(),
            program_filter: None,
            service_filter: None,
            enabled: true,
            policy_store: PolicyStore::Local,
        }
    }

    #[test]
    fn sort_key_is_the_rule_id() {
        let rule_id = RuleId::generate();
        let rule = sample(rule_id);
        assert_eq!(rule.sort_key(), rule_id);
    }
}
