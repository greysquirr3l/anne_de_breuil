//! Maps `application::collect`'s `RawRule`/`RawProfile` adapter DTOs into
//! domain `FirewallRule`/`ProfileState` values.
//!
//! Split out of `scan.rs` rather than grown inside it: this is the same
//! kind of "parse untrusted platform text into domain value objects at
//! the collection boundary" work `endpoint_from_collected` already does
//! for endpoints, just enough of it (four separate `FromStr`/`TryFrom`
//! calls per rule, plus the protocol-duplication case below) to be its
//! own file rather than another function bolted onto an already-busy
//! command handler.

use anne_de_breuil::application::collect::{CollectError, RawProfile, RawRule};
use anne_de_breuil::domain::{
    Direction, DomainError, FirewallRule, PolicyStore, PortSpec, ProcessPath, ProfileState,
    Protocol, RuleAction, RuleId, ServiceName,
};

/// Maps every collected rule into zero, one, or two domain `FirewallRule`
/// values (two when the rule carries no protocol filter — see
/// [`firewall_rule_from_raw`]) and flattens the result.
///
/// # Errors
///
/// Returns [`CollectError`] (via [`DomainError`]'s `From` impl) if any raw
/// rule's text fields don't parse into their corresponding domain value
/// objects.
pub fn firewall_rules_from_raw(raw_rules: Vec<RawRule>) -> Result<Vec<FirewallRule>, CollectError> {
    let mut rules = Vec::with_capacity(raw_rules.len());
    for raw in raw_rules {
        rules.extend(firewall_rule_from_raw(raw)?);
    }
    Ok(rules)
}

/// Maps every collected profile into a domain `ProfileState`.
///
/// # Errors
///
/// Returns [`CollectError`] if any raw profile's text fields don't parse
/// into their corresponding domain value objects.
pub fn firewall_profiles_from_raw(
    raw_profiles: Vec<RawProfile>,
) -> Result<Vec<ProfileState>, CollectError> {
    raw_profiles
        .into_iter()
        .map(|raw| firewall_profile_from_raw(&raw).map_err(CollectError::from))
        .collect()
}

/// A raw rule id is parsed as a UUID first (Windows Firewall's own
/// `InstanceID` GUIDs already are one); anything else — e.g. the Linux
/// nftables adapter's `"nftables/{table}/{chain}"` — falls back to
/// [`RuleId::synthesize`], which is deterministic, so re-scanning an
/// unchanged host reproduces the same id rather than fabricating a new
/// rule identity every scan.
fn rule_id_from_raw(raw_rule_id: &str) -> RuleId {
    raw_rule_id
        .parse()
        .unwrap_or_else(|_err| RuleId::synthesize(raw_rule_id))
}

/// Maps one [`RawRule`] into zero, one, or two [`FirewallRule`]s.
///
/// [`Protocol`] has no "any" variant (a real bound socket is always
/// concretely TCP or UDP — see that type's own doc comment), but a
/// firewall rule with no protocol filter genuinely does apply to both.
/// The honest domain representation of that is two `FirewallRule`
/// values, one per protocol this tool tracks, sharing the same
/// [`RuleId`] since they describe the same underlying platform rule
/// evaluated per protocol, not two distinct rules.
///
/// A rule scoped to a protocol this tool doesn't track at all (ICMP,
/// IGMP, GRE, ...) maps to zero rules rather than an error — it
/// genuinely has no bearing on TCP/UDP port reachability, this tool's
/// whole domain. Verified against a real Windows host: every host ships
/// several built-in ICMPv4/ICMPv6 rules, and hard-failing the entire
/// scan the first time one was collected (as this used to) was wrong,
/// not a sign of corrupt data.
fn firewall_rule_from_raw(raw: RawRule) -> Result<Vec<FirewallRule>, DomainError> {
    let rule_id = rule_id_from_raw(&raw.rule_id);
    let direction: Direction = raw.direction.parse()?;
    let action: RuleAction = raw.action.parse()?;
    let port_spec: PortSpec = match raw.local_port_spec.as_deref() {
        Some(spec) => spec.parse()?,
        None => PortSpec::Any,
    };
    let program_filter = raw.program_filter.map(ProcessPath::try_from).transpose()?;
    let service_filter = raw.service_filter.map(ServiceName::try_from).transpose()?;
    let policy_store: PolicyStore = raw.policy_store.parse()?;

    if let Some(protocol_text) = raw.protocol.as_deref() {
        return Ok(match protocol_text.parse() {
            Ok(protocol) => vec![FirewallRule {
                rule_id,
                display_name: raw.display_name,
                direction,
                action,
                protocol,
                port_spec,
                program_filter,
                service_filter,
                enabled: raw.enabled,
                policy_store,
            }],
            Err(DomainError::InvalidProtocol(_)) => Vec::new(),
            Err(other) => return Err(other),
        });
    }

    Ok([Protocol::Tcp, Protocol::Udp]
        .into_iter()
        .map(|protocol| FirewallRule {
            rule_id,
            display_name: raw.display_name.clone(),
            direction,
            action,
            protocol,
            port_spec: port_spec.clone(),
            program_filter: program_filter.clone(),
            service_filter: service_filter.clone(),
            enabled: raw.enabled,
            policy_store,
        })
        .collect())
}

/// Maps one [`RawProfile`] into a [`ProfileState`].
fn firewall_profile_from_raw(raw: &RawProfile) -> Result<ProfileState, DomainError> {
    Ok(ProfileState {
        profile: raw.name.parse()?,
        enabled: raw.enabled,
        default_inbound_action: raw.default_inbound_action.parse()?,
        default_outbound_action: raw.default_outbound_action.parse()?,
    })
}

#[cfg(test)]
mod tests {
    use super::{firewall_profiles_from_raw, firewall_rules_from_raw};
    use anne_de_breuil::application::collect::{RawProfile, RawRule};
    use anne_de_breuil::domain::Protocol;

    fn sample_rule(rule_id: &str, protocol: Option<&str>) -> RawRule {
        RawRule {
            rule_id: rule_id.to_owned(),
            display_name: "Allow HTTPS".to_owned(),
            direction: "Inbound".to_owned(),
            action: "Allow".to_owned(),
            protocol: protocol.map(str::to_owned),
            local_port_spec: Some("443".to_owned()),
            program_filter: None,
            service_filter: None,
            enabled: true,
            policy_store: "Local".to_owned(),
        }
    }

    #[test]
    fn a_windows_style_guid_rule_id_parses_as_a_uuid_directly() {
        let raw = sample_rule("7c7f6c3e-1b7b-4b0a-9c1d-3a5e2f9b0a11", Some("TCP"));
        let rules = firewall_rules_from_raw(vec![raw]).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].rule_id.to_string(),
            "7c7f6c3e-1b7b-4b0a-9c1d-3a5e2f9b0a11"
        );
    }

    #[test]
    fn a_non_uuid_rule_id_is_synthesized_deterministically() {
        let raw = sample_rule("nftables/inet-filter/input", Some("TCP"));
        let rules_a = firewall_rules_from_raw(vec![raw.clone()]).unwrap();
        let rules_b = firewall_rules_from_raw(vec![raw]).unwrap();
        assert_eq!(rules_a[0].rule_id, rules_b[0].rule_id);
    }

    #[test]
    fn a_rule_with_no_protocol_filter_expands_to_tcp_and_udp_sharing_one_rule_id() {
        let raw = sample_rule("nftables/inet-filter/input", None);
        let rules = firewall_rules_from_raw(vec![raw]).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].rule_id, rules[1].rule_id);
        let protocols: Vec<Protocol> = rules.iter().map(|r| r.protocol).collect();
        assert!(protocols.contains(&Protocol::Tcp));
        assert!(protocols.contains(&Protocol::Udp));
    }

    #[test]
    fn a_rule_with_a_protocol_filter_stays_a_single_rule() {
        let raw = sample_rule("some-id", Some("UDP"));
        let rules = firewall_rules_from_raw(vec![raw]).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].protocol, Protocol::Udp);
    }

    #[test]
    fn malformed_direction_text_produces_a_collect_error_not_a_panic() {
        let mut raw = sample_rule("some-id", Some("TCP"));
        raw.direction = "sideways".to_owned();
        assert!(firewall_rules_from_raw(vec![raw]).is_err());
    }

    #[test]
    fn nftables_policy_store_text_maps_to_local() {
        let mut raw = sample_rule("nftables/inet-filter/input", Some("TCP"));
        raw.policy_store = "nftables".to_owned();
        let rules = firewall_rules_from_raw(vec![raw]).unwrap();
        assert_eq!(
            rules[0].policy_store,
            anne_de_breuil::domain::PolicyStore::Local
        );
    }

    #[test]
    fn profiles_map_name_enabled_and_default_actions() {
        let raw = RawProfile {
            name: "Public".to_owned(),
            enabled: true,
            default_inbound_action: "Block".to_owned(),
            default_outbound_action: "Allow".to_owned(),
        };
        let profiles = firewall_profiles_from_raw(vec![raw]).unwrap();
        assert_eq!(profiles.len(), 1);
        assert!(profiles[0].enabled);
    }

    #[test]
    fn unknown_profile_name_produces_an_error() {
        let raw = RawProfile {
            name: "Guest".to_owned(),
            enabled: true,
            default_inbound_action: "Block".to_owned(),
            default_outbound_action: "Allow".to_owned(),
        };
        assert!(firewall_profiles_from_raw(vec![raw]).is_err());
    }
}
