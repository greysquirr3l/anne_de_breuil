//! Pure, platform-independent half of the WMI firewall collection path.
//!
//! Row DTOs matching the real `MSFT_NetFirewallRule`/
//! `MSFT_NetFirewallPortFilter`/`MSFT_NetFirewallApplicationFilter`/
//! `MSFT_NetFirewallServiceFilter`/`MSFT_NetFirewallProfile` WMI classes in
//! `root/standardcimv2`, and the `InstanceID`-keyed joins that turn them
//! into T04's `Raw*` DTOs.
//!
//! Nothing here touches `wmi::WMIConnection` or any other Windows-only API
//! — every function operates on already-deserialized rows in memory, so it
//! compiles and its tests run on any host. [`super::firewall`] is the
//! `#[cfg(windows)]` half that actually queries WMI and hands the results
//! here.
//!
//! # Numeric encodings
//!
//! `MSFT_NetFirewallRule`'s `Direction`/`Action`/`Enabled`/
//! `PolicyStoreSourceType` properties are `uint32` with an associated
//! enumeration, not strings — `Get-NetFirewallRule` translates them for
//! display, but a raw WMI query returns the numbers. This module owns that
//! translation, using the mapping documented on each `*_text` function
//! below. Without a live host to confirm this crate can't independently
//! verify it against Microsoft's provider; [`super::mod`]'s
//! `live_host_windows_collector_matches_powershell_collector` test is the
//! safety net for that — the PowerShell adapter (T05) sources the same
//! fields already translated by `Get-NetFirewallRule`, so any mismatch
//! shows up as a diff between the two adapters on a real host rather than
//! staying invisible.

use std::collections::HashMap;

use crate::application::collect::{RawProfile, RawRule};

/// One row from `SELECT * FROM MSFT_NetFirewallRule`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WmiFirewallRule {
    /// The rule's native identifier — joins to filters of every kind below.
    #[serde(rename = "InstanceID")]
    pub instance_id: String,
    /// Human-readable rule name.
    #[serde(rename = "DisplayName")]
    pub display_name: String,
    /// `1` = Inbound, `2` = Outbound.
    #[serde(rename = "Direction")]
    pub direction: u32,
    /// `1` = Allow, `2` = Block.
    #[serde(rename = "Action")]
    pub action: u32,
    /// `0` = False, nonzero = True.
    #[serde(rename = "Enabled")]
    pub enabled: u32,
    /// `0` = Local, `1` = `GroupPolicy`, `2` = Dynamic, `3` = Static.
    #[serde(rename = "PolicyStoreSourceType")]
    pub policy_store_source_type: u32,
}

/// One row from `SELECT * FROM MSFT_NetFirewallPortFilter`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WmiPortFilter {
    /// Joins to [`WmiFirewallRule::instance_id`].
    #[serde(rename = "InstanceID")]
    pub instance_id: String,
    /// e.g. `"TCP"`, `"UDP"`, `"Any"`.
    #[serde(rename = "Protocol")]
    pub protocol: Option<String>,
    /// e.g. `"443"`, `"5000-5010"`, `"Any"`.
    #[serde(rename = "LocalPort")]
    pub local_port: Option<String>,
}

/// One row from `SELECT * FROM MSFT_NetFirewallApplicationFilter`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WmiApplicationFilter {
    /// Joins to [`WmiFirewallRule::instance_id`].
    #[serde(rename = "InstanceID")]
    pub instance_id: String,
    /// The executable path the rule is scoped to.
    #[serde(rename = "Program")]
    pub program: Option<String>,
}

/// One row from `SELECT * FROM MSFT_NetFirewallServiceFilter`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WmiServiceFilter {
    /// Joins to [`WmiFirewallRule::instance_id`].
    #[serde(rename = "InstanceID")]
    pub instance_id: String,
    /// The service short name the rule is scoped to.
    #[serde(rename = "Service")]
    pub service: Option<String>,
}

/// One row from `SELECT * FROM MSFT_NetFirewallProfile`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WmiFirewallProfile {
    /// e.g. `"Domain"`, `"Private"`, `"Public"`.
    #[serde(rename = "Name")]
    pub name: String,
    /// `0` = False, nonzero = True.
    #[serde(rename = "Enabled")]
    pub enabled: u32,
    /// `1` = Allow, `2` = Block.
    #[serde(rename = "DefaultInboundAction")]
    pub default_inbound_action: u32,
    /// `1` = Allow, `2` = Block.
    #[serde(rename = "DefaultOutboundAction")]
    pub default_outbound_action: u32,
}

fn direction_text(direction: u32) -> String {
    match direction {
        1 => "Inbound".to_owned(),
        2 => "Outbound".to_owned(),
        other => other.to_string(),
    }
}

fn action_text(action: u32) -> String {
    match action {
        1 => "Allow".to_owned(),
        2 => "Block".to_owned(),
        other => other.to_string(),
    }
}

fn policy_store_text(policy_store_source_type: u32) -> String {
    match policy_store_source_type {
        0 => "Local".to_owned(),
        1 => "GroupPolicy".to_owned(),
        2 => "Dynamic".to_owned(),
        3 => "Static".to_owned(),
        other => other.to_string(),
    }
}

/// `None` reads more honestly than `Some("Any")` for "this rule carries no
/// filter of this kind" — `RawRule`'s own docs define `None` as that case.
fn none_if_any(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.eq_ignore_ascii_case("any"))
}

fn rule_from_wmi(rule: WmiFirewallRule, filter: Option<&WmiPortFilter>) -> RawRule {
    RawRule {
        rule_id: rule.instance_id,
        display_name: rule.display_name,
        direction: direction_text(rule.direction),
        action: action_text(rule.action),
        protocol: none_if_any(filter.and_then(|f| f.protocol.clone())),
        local_port_spec: none_if_any(filter.and_then(|f| f.local_port.clone())),
        program_filter: None,
        service_filter: None,
        enabled: rule.enabled != 0,
        policy_store: policy_store_text(rule.policy_store_source_type),
    }
}

/// Firewall rules joined to their port filters by `InstanceID`.
///
/// One bulk query each, never a per-rule round trip. A rule with no
/// matching filter row (e.g. a rule that doesn't filter by port at all)
/// ends up with `local_port_spec: None`, not a lookup error.
#[must_use]
pub fn join_rules_to_filters(
    rules: Vec<WmiFirewallRule>,
    filters: &[WmiPortFilter],
) -> Vec<RawRule> {
    let by_instance: HashMap<&str, &WmiPortFilter> = filters
        .iter()
        .map(|filter| (filter.instance_id.as_str(), filter))
        .collect();

    rules
        .into_iter()
        .map(|rule| {
            let filter = by_instance.get(rule.instance_id.as_str()).copied();
            rule_from_wmi(rule, filter)
        })
        .collect()
}

/// Joins rules to port, application, and service filters in one pass.
///
/// Four bulk WMI queries total, still zero per-rule round trips. This is
/// the full-fidelity assembly [`super::firewall::WmiFirewallPolicySource`]
/// actually calls; [`join_rules_to_filters`] alone stays a separate,
/// narrower function because that is the exact shape the task's mandated
/// `instance_id_join_matches_rule_to_filter` test exercises.
#[must_use]
pub fn assemble_rules(
    rules: Vec<WmiFirewallRule>,
    port_filters: &[WmiPortFilter],
    app_filters: &[WmiApplicationFilter],
    service_filters: &[WmiServiceFilter],
) -> Vec<RawRule> {
    let app_by_instance: HashMap<&str, &WmiApplicationFilter> = app_filters
        .iter()
        .map(|filter| (filter.instance_id.as_str(), filter))
        .collect();
    let service_by_instance: HashMap<&str, &WmiServiceFilter> = service_filters
        .iter()
        .map(|filter| (filter.instance_id.as_str(), filter))
        .collect();

    join_rules_to_filters(rules, port_filters)
        .into_iter()
        .map(|mut rule| {
            rule.program_filter = app_by_instance
                .get(rule.rule_id.as_str())
                .and_then(|filter| filter.program.clone());
            rule.service_filter = service_by_instance
                .get(rule.rule_id.as_str())
                .and_then(|filter| filter.service.clone());
            rule
        })
        .collect()
}

/// Maps queried `MSFT_NetFirewallProfile` rows to T04's `RawProfile`.
#[must_use]
pub fn profiles_from_wmi(profiles: Vec<WmiFirewallProfile>) -> Vec<RawProfile> {
    profiles
        .into_iter()
        .map(|profile| RawProfile {
            name: profile.name,
            enabled: profile.enabled != 0,
            default_inbound_action: action_text(profile.default_inbound_action),
            default_outbound_action: action_text(profile.default_outbound_action),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{WmiFirewallRule, WmiPortFilter, join_rules_to_filters};

    mod fixtures {
        use super::{WmiFirewallRule, WmiPortFilter};

        pub(super) fn wmi_rules_from_json(bytes: &[u8]) -> Vec<WmiFirewallRule> {
            serde_json::from_slice(bytes)
                .unwrap_or_else(|err| panic!("fixture is valid MSFT_NetFirewallRule JSON: {err}"))
        }

        pub(super) fn wmi_filters_from_json(bytes: &[u8]) -> Vec<WmiPortFilter> {
            serde_json::from_slice(bytes).unwrap_or_else(|err| {
                panic!("fixture is valid MSFT_NetFirewallPortFilter JSON: {err}")
            })
        }
    }

    /// The task's own test spec names this `r.local_port_filter` against a
    /// sketch-only field; T04's real `RawRule` field is `local_port_spec`
    /// (see `application/collect.rs`), which is what this asserts against.
    #[test]
    fn instance_id_join_matches_rule_to_filter() {
        let rules =
            fixtures::wmi_rules_from_json(include_bytes!("../../../fixtures/wmi/rules.json"));
        let filters =
            fixtures::wmi_filters_from_json(include_bytes!("../../../fixtures/wmi/filters.json"));

        let joined = join_rules_to_filters(rules, &filters);

        assert!(!joined.is_empty());
        assert!(joined.iter().all(|rule| rule.local_port_spec.is_some()));
    }

    /// The task's own test spec checks `r.policy_store_source_type ==
    /// PolicyStoreSourceType::Gpo` against a sketch-only enum this module
    /// never introduces (see the module docs on numeric encodings) — the
    /// real, preserved-on-every-rule field is `RawRule::policy_store`,
    /// which is what this asserts against.
    #[test]
    fn gpo_sourced_rule_present_in_active_store_result() {
        let rules = fixtures::wmi_rules_from_json(include_bytes!(
            "../../../fixtures/wmi/gpo_and_local_mixed.json"
        ));

        let joined = join_rules_to_filters(rules, &[]);

        assert!(joined.iter().any(|rule| rule.policy_store == "GroupPolicy"));
        assert!(joined.iter().any(|rule| rule.policy_store == "Local"));
    }

    #[test]
    fn any_protocol_and_port_flatten_to_none_not_the_literal_string() {
        let rules = vec![WmiFirewallRule {
            instance_id: "{X}".to_owned(),
            display_name: "Allow Everything".to_owned(),
            direction: 1,
            action: 1,
            enabled: 1,
            policy_store_source_type: 0,
        }];
        let filters = vec![WmiPortFilter {
            instance_id: "{X}".to_owned(),
            protocol: Some("Any".to_owned()),
            local_port: Some("Any".to_owned()),
        }];

        let joined = join_rules_to_filters(rules, &filters);

        assert_eq!(joined.len(), 1);
        assert_eq!(joined[0].protocol, None);
        assert_eq!(joined[0].local_port_spec, None);
    }

    #[test]
    fn unmatched_rule_gets_no_port_filter_not_a_join_error() {
        let rules = vec![WmiFirewallRule {
            instance_id: "{no-filter-row}".to_owned(),
            display_name: "Allow Everything".to_owned(),
            direction: 1,
            action: 1,
            enabled: 1,
            policy_store_source_type: 0,
        }];

        let joined = join_rules_to_filters(rules, &[]);

        assert_eq!(joined.len(), 1);
        assert_eq!(joined[0].local_port_spec, None);
    }
}
