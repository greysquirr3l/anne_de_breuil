//! Rule evaluation: the block-before-allow-before-default-action
//! precedence [`crate::domain::reachability::evaluate`] actually
//! implements, populated with the real rule display names that produced
//! this host's endpoints' verdicts.
//!
//! [`crate::domain::report_model::EndpointView::matched_rules`] is
//! naturally per-endpoint (it's the provenance of one endpoint's verdict),
//! but the precedence stack itself is a host-wide structure, so this
//! aggregates every non-loopback endpoint's matched rules into the three
//! layers rather than picking one endpoint arbitrarily. Loopback
//! endpoints never reach this evaluator at all (`evaluate` short-circuits
//! to [`ReachabilityView::LocalOnly`] before consulting any rule), so
//! they contribute nothing here.

use std::collections::BTreeSet;

use crate::domain::report_model::{HostSection, ReachabilityView};
use crate::domain::svg::SvgCanvas;

use super::short_host_id;

const CANVAS_WIDTH: i32 = 600;
const LAYER_HEIGHT: i32 = 60;
const LAYER_GAP: i32 = 12;
const TOP_MARGIN: i32 = 20;
const LEFT_MARGIN: i32 = 20;

struct Layer {
    heading: &'static str,
    class: &'static str,
    entries: Vec<String>,
}

pub(in crate::adapters::html_report) fn render(host: &HostSection) -> String {
    let mut block_rules = BTreeSet::new();
    let mut allow_rules = BTreeSet::new();
    let mut default_action_count = 0usize;

    for endpoint in &host.endpoints {
        match endpoint.reachability {
            ReachabilityView::Blocked => {
                for rule in &endpoint.matched_rules {
                    block_rules.insert(rule.display_name.clone());
                }
            }
            ReachabilityView::Allowed | ReachabilityView::Indeterminate => {
                for rule in &endpoint.matched_rules {
                    allow_rules.insert(rule.display_name.clone());
                }
            }
            ReachabilityView::DefaultAction => default_action_count += 1,
            ReachabilityView::LocalOnly => {}
        }
    }

    let layers = [
        Layer {
            heading: "1. Block",
            class: "svg-fill-blocked",
            entries: block_rules.into_iter().collect(),
        },
        Layer {
            heading: "2. Allow",
            class: "svg-fill-allowed",
            entries: allow_rules.into_iter().collect(),
        },
        Layer {
            heading: "3. Default action",
            class: "svg-fill-default-action",
            entries: vec![format!(
                "{default_action_count} endpoint(s) with no matching rule"
            )],
        },
    ];

    let layer_count = i32::try_from(layers.len()).unwrap_or(3);
    let height = TOP_MARGIN * 2 + layer_count * (LAYER_HEIGHT + LAYER_GAP);
    let mut canvas = SvgCanvas::new(CANVAS_WIDTH, height);

    let mut y = TOP_MARGIN;
    for layer in &layers {
        canvas.rect(
            LEFT_MARGIN,
            y,
            CANVAS_WIDTH - LEFT_MARGIN * 2,
            LAYER_HEIGHT,
            layer.class,
        );
        canvas.text(LEFT_MARGIN + 8, y + 20, layer.heading, "svg-text");
        let summary = if layer.entries.is_empty() {
            "no rules".to_owned()
        } else {
            layer.entries.join(", ")
        };
        canvas.text(LEFT_MARGIN + 8, y + 40, &summary, "svg-text-mono");
        y += LAYER_HEIGHT + LAYER_GAP;
    }

    let title = format!(
        "Rule evaluation precedence for host {}",
        short_host_id(host)
    );
    let desc = "Block rules are evaluated before allow rules; anything left ungoverned falls to \
                the profile's default action."
        .to_owned();
    canvas.render(&title, &desc)
}

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;

    use super::render;
    use crate::domain::bind_address::BindAddress;
    use crate::domain::endpoint::Endpoint;
    use crate::domain::firewall_rule::{Direction, FirewallRule, RuleAction};
    use crate::domain::ids::{HostId, RuleId, ScanId};
    use crate::domain::policy_store::PolicyStore;
    use crate::domain::port::Port;
    use crate::domain::port_spec::PortSpec;
    use crate::domain::protocol::Protocol;
    use crate::domain::publisher::SignatureStatus;
    use crate::domain::report_model::{HostSection, ReportModel};
    use crate::domain::snapshot::ScanSnapshot;
    use crate::domain::target_strategy::TargetStrategy;

    fn rule(display_name: &str, action: RuleAction, port: u16) -> FirewallRule {
        FirewallRule {
            rule_id: RuleId::generate(),
            display_name: display_name.to_owned(),
            direction: Direction::Inbound,
            action,
            protocol: Protocol::Tcp,
            port_spec: PortSpec::Single(Port::try_from(port).expect("nonzero port")),
            program_filter: None,
            service_filter: None,
            enabled: true,
            policy_store: PolicyStore::Local,
        }
    }

    fn endpoint_on(port: u16) -> Endpoint {
        Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").expect("valid ip"),
            Port::try_from(port).expect("nonzero port"),
            None,
            None,
            vec![],
            SignatureStatus::Unknown,
            None,
        )
    }

    fn host_with_rules(rules: Vec<FirewallRule>, endpoints: Vec<Endpoint>) -> HostSection {
        let snapshot = ScanSnapshot::new(
            HostId::generate(),
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "1.0.0".to_owned(),
            endpoints,
            rules,
            vec![],
            TargetStrategy::Execute,
        );
        let model = ReportModel::build(&[snapshot], None, true).expect("model builds");
        model.hosts.into_iter().next().expect("one host")
    }

    #[test]
    fn block_and_allow_rule_names_appear_in_their_own_layer() {
        let host = host_with_rules(
            vec![
                rule("Deny SMB", RuleAction::Block, 445),
                rule("Allow HTTPS", RuleAction::Allow, 443),
            ],
            vec![endpoint_on(445), endpoint_on(443)],
        );
        let svg = render(&host);
        assert!(svg.contains("Deny SMB"));
        assert!(svg.contains("Allow HTTPS"));
    }

    #[test]
    fn no_matching_rule_reports_a_default_action_endpoint_count() {
        let host = host_with_rules(vec![], vec![endpoint_on(9999)]);
        let svg = render(&host);
        assert!(svg.contains("1 endpoint(s) with no matching rule"));
    }

    #[test]
    fn loopback_endpoints_never_contribute_a_matched_rule() {
        let loopback = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("127.0.0.1").expect("valid ip"),
            Port::try_from(22u16).expect("nonzero port"),
            None,
            None,
            vec![],
            SignatureStatus::Unknown,
            None,
        );
        let host = host_with_rules(
            vec![rule("Deny all", RuleAction::Block, 22)],
            vec![loopback],
        );
        let svg = render(&host);
        assert!(!svg.contains("Deny all"));
    }

    #[test]
    fn rendering_twice_is_byte_identical() {
        let host = host_with_rules(
            vec![rule("Allow HTTPS", RuleAction::Allow, 443)],
            vec![endpoint_on(443)],
        );
        assert_eq!(render(&host), render(&host));
    }

    #[test]
    fn every_x_y_width_height_is_divisible_by_four() {
        let host = host_with_rules(
            vec![rule("Allow HTTPS", RuleAction::Allow, 443)],
            vec![endpoint_on(443)],
        );
        let svg = render(&host);
        for value in
            super::super::tests_support::extract_numeric_attrs(&svg, &["x", "y", "width", "height"])
        {
            assert!(value.is_multiple_of(4), "{value} is not divisible by 4");
        }
    }

    #[test]
    fn svg_has_title_and_escapes_a_malicious_rule_display_name() {
        let host = host_with_rules(
            vec![rule(
                "</svg><script>alert(1)</script>",
                RuleAction::Block,
                445,
            )],
            vec![endpoint_on(445)],
        );
        let svg = render(&host);
        assert!(svg.contains("<title>"));
        assert!(!svg.contains("<script>alert"));
    }
}
