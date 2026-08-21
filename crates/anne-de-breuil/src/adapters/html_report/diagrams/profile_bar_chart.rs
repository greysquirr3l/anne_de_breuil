//! Profile bar chart: allowed inbound rules per firewall profile, each bar
//! labeled with its own enabled state and default inbound action.
//!
//! Per-host, not fleet-wide -- [`crate::domain::report_model::HostSection`]
//! carries its own `profile_ports`, since firewall rules and profiles are
//! per-host data (`ScanSnapshot::firewall_rules`/`profiles`); there is no
//! fleet-wide "the" firewall policy to chart in this domain model.
//!
//! # A real, honest limitation
//!
//! [`crate::domain::firewall_rule::FirewallRule`] carries no
//! profile-scoping field in this domain model -- Windows Firewall rules
//! can in reality be scoped to specific profiles via `-Profile`, but
//! nothing in this collector's data model captures that, so
//! [`crate::domain::profile_ports::summarize_inbound_ports`] honestly
//! applies the same rule set to every profile and differentiates bars
//! only by each profile's own enabled/default-action state (see that
//! function's own module doc). Every bar's height below is real -- the
//! same real rule count, because the same rules genuinely apply under
//! this data model -- and the label text underneath is what actually
//! carries the per-profile difference, rather than implying the rule sets
//! themselves differ when they don't.

use crate::domain::report_model::{HostSection, ProfilePortSummaryView, RuleActionView};
use crate::domain::svg::SvgCanvas;

use super::{geometry_i32, short_host_id};

const CANVAS_WIDTH: i32 = 600;
const BAR_WIDTH: i32 = 120;
const BAR_GAP: i32 = 40;
const MAX_BAR_HEIGHT: i32 = 160;
const BASE_Y: i32 = 200;
const CANVAS_HEIGHT: i32 = 260;

const fn profile_kind_label(
    profile: crate::domain::report_model::FirewallProfileKindView,
) -> &'static str {
    use crate::domain::report_model::FirewallProfileKindView;
    match profile {
        FirewallProfileKindView::Domain => "Domain",
        FirewallProfileKindView::Private => "Private",
        FirewallProfileKindView::Public => "Public",
    }
}

pub(in crate::adapters::html_report) fn render(host: &HostSection) -> String {
    let mut canvas = SvgCanvas::new(CANVAS_WIDTH, CANVAS_HEIGHT);

    let max_rules = host
        .profile_ports
        .iter()
        .map(|profile| profile.allowed.len())
        .max()
        .unwrap_or(0)
        .max(1);

    let mut x = 40;
    for profile in &host.profile_ports {
        render_bar(&mut canvas, profile, x, max_rules);
        x += BAR_WIDTH + BAR_GAP;
    }

    // Every profile shares the same allow-rule set in this data model (see
    // the module doc), so the rule names themselves are listed once,
    // below the bars, rather than repeated per bar.
    if let Some(first) = host.profile_ports.first() {
        let names: Vec<&str> = first
            .allowed
            .iter()
            .map(|entry| entry.rule_display_name.as_str())
            .collect();
        let caption = if names.is_empty() {
            "no inbound allow rules observed".to_owned()
        } else {
            format!("Allowed: {}", names.join(", "))
        };
        canvas.text(40, CANVAS_HEIGHT - 12, &caption, "svg-text-mono");
    }

    let title = format!(
        "Inbound allow rules per firewall profile for host {}",
        short_host_id(host)
    );
    let desc = "The same rule set applies to every profile in this data model; bars differ by \
                each profile's own enabled state and default inbound action, not by a \
                profile-specific rule set."
        .to_owned();
    canvas.render(&title, &desc)
}

fn render_bar(canvas: &mut SvgCanvas, profile: &ProfilePortSummaryView, x: i32, max_rules: usize) {
    let rule_count = profile.allowed.len();
    let bar_height = (geometry_i32(rule_count) * MAX_BAR_HEIGHT / geometry_i32(max_rules)).max(8);
    let y = BASE_Y - bar_height;
    let class = if profile.enabled {
        "svg-fill-accent"
    } else {
        "svg-fill-muted"
    };
    canvas.rect(x, y, BAR_WIDTH, bar_height, class);

    let count_label = format!("{rule_count} allow rule(s)");
    canvas.text(x, y - 8, &count_label, "svg-text-mono");

    let name = profile_kind_label(profile.profile);
    canvas.text(x, BASE_Y + 16, name, "svg-text");

    let default_label = match profile.default_inbound_action {
        RuleActionView::Allow => "default: allow",
        RuleActionView::Block => "default: block",
    };
    canvas.text(x, BASE_Y + 32, default_label, "svg-text-muted");

    if !profile.enabled {
        canvas.text(x, BASE_Y + 48, "firewall disabled", "svg-text-muted");
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;

    use super::render;
    use crate::domain::firewall_rule::{Direction, FirewallRule, RuleAction};
    use crate::domain::ids::{HostId, RuleId, ScanId};
    use crate::domain::policy_store::PolicyStore;
    use crate::domain::port_spec::PortSpec;
    use crate::domain::profile::{FirewallProfileKind, ProfileState};
    use crate::domain::protocol::Protocol;
    use crate::domain::report_model::{HostSection, ReportModel};
    use crate::domain::snapshot::ScanSnapshot;
    use crate::domain::target_strategy::TargetStrategy;

    fn allow_rule(display_name: &str, port: &str) -> FirewallRule {
        FirewallRule {
            rule_id: RuleId::generate(),
            display_name: display_name.to_owned(),
            direction: Direction::Inbound,
            action: RuleAction::Allow,
            protocol: Protocol::Tcp,
            port_spec: PortSpec::from_str(port).expect("valid port spec"),
            program_filter: None,
            service_filter: None,
            enabled: true,
            policy_store: PolicyStore::Local,
        }
    }

    fn host_with_profiles(rules: Vec<FirewallRule>, profiles: Vec<ProfileState>) -> HostSection {
        let snapshot = ScanSnapshot::new(
            HostId::generate(),
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "1.0.0".to_owned(),
            vec![],
            rules,
            profiles,
            TargetStrategy::Execute,
        );
        let model = ReportModel::build(&[snapshot], None, true).expect("model builds");
        model.hosts.into_iter().next().expect("one host")
    }

    #[test]
    fn every_profile_gets_its_own_bar_and_label() {
        let host = host_with_profiles(
            vec![allow_rule("Allow HTTPS", "443")],
            vec![
                ProfileState {
                    profile: FirewallProfileKind::Domain,
                    enabled: true,
                    default_inbound_action: RuleAction::Block,
                    default_outbound_action: RuleAction::Allow,
                },
                ProfileState {
                    profile: FirewallProfileKind::Public,
                    enabled: false,
                    default_inbound_action: RuleAction::Block,
                    default_outbound_action: RuleAction::Allow,
                },
            ],
        );
        let svg = render(&host);
        assert!(svg.contains("Domain"));
        assert!(svg.contains("Public"));
        assert!(svg.contains("firewall disabled"));
        assert!(svg.contains("1 allow rule(s)"));
    }

    #[test]
    fn no_profiles_renders_an_empty_but_valid_chart() {
        let host = host_with_profiles(vec![], vec![]);
        let svg = render(&host);
        assert!(svg.contains("<title>"));
    }

    #[test]
    fn rendering_twice_is_byte_identical() {
        let host = host_with_profiles(
            vec![allow_rule("Allow HTTPS", "443")],
            vec![ProfileState {
                profile: FirewallProfileKind::Private,
                enabled: true,
                default_inbound_action: RuleAction::Block,
                default_outbound_action: RuleAction::Allow,
            }],
        );
        assert_eq!(render(&host), render(&host));
    }

    #[test]
    fn every_x_y_width_height_is_divisible_by_four() {
        let host = host_with_profiles(
            vec![allow_rule("Allow HTTPS", "443")],
            vec![ProfileState {
                profile: FirewallProfileKind::Private,
                enabled: true,
                default_inbound_action: RuleAction::Block,
                default_outbound_action: RuleAction::Allow,
            }],
        );
        let svg = render(&host);
        for value in
            super::super::tests_support::extract_numeric_attrs(&svg, &["x", "y", "width", "height"])
        {
            assert!(value.is_multiple_of(4), "{value} is not divisible by 4");
        }
    }

    #[test]
    fn svg_has_title_and_escapes_a_malicious_rule_name() {
        let host = host_with_profiles(
            vec![allow_rule("</svg><script>alert(1)</script>", "443")],
            vec![ProfileState {
                profile: FirewallProfileKind::Private,
                enabled: true,
                default_inbound_action: RuleAction::Block,
                default_outbound_action: RuleAction::Allow,
            }],
        );
        let svg = render(&host);
        assert!(svg.contains("<title>"));
        assert!(!svg.contains("<script>alert"));
    }
}
