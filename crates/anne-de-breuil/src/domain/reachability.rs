//! [`evaluate`]: pure reachability evaluation of one endpoint against firewall policy.

use crate::domain::endpoint::Endpoint;
use crate::domain::exposure::Exposure;
use crate::domain::firewall_rule::{FirewallRule, RuleAction};
use crate::domain::port_spec::PortSpec;
use crate::domain::process::ProcessPath;
use crate::domain::profile::ProfileState;

/// The outcome of evaluating one endpoint against firewall policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachability {
    /// Bound to loopback only; never reachable off-host regardless of policy.
    LocalOnly,
    /// At least one applicable rule blocks the traffic. Blocks always win over allows.
    Blocked,
    /// At least one applicable rule allows the traffic, and none block it.
    Allowed,
    /// No rule applies. The caller must consult the governing profile's
    /// default action rather than assume one.
    DefaultAction,
    /// An applicable allow rule uses a dynamic port keyword whose concrete
    /// range cannot be statically resolved here. Never collapsed into
    /// [`Reachability::Allowed`] or [`Reachability::Blocked`].
    Indeterminate,
}

/// A reachability verdict together with the rules that produced it.
///
/// Carrying `matched_rules` alongside the verdict is what makes the result
/// auditable — an unexplained verdict is not useful in a security report.
#[derive(Debug, Clone)]
pub struct ReachabilityVerdict<'r> {
    /// The resolved reachability classification.
    pub reachability: Reachability,
    /// The rules that produced this verdict, in evaluation order.
    pub matched_rules: Vec<&'r FirewallRule>,
}

/// Decides whether traffic can reach `endpoint`, given the effective
/// firewall rule set.
///
/// Pure and deterministic: no I/O, no clock, no environment access. Loopback
/// endpoints short-circuit to [`Reachability::LocalOnly`] before any rule is
/// consulted. `profiles` is accepted for a future caller that needs to
/// resolve [`Reachability::DefaultAction`] into a concrete allow/block by
/// reading a profile's default action — this function deliberately does not
/// do that resolution itself, since inbound/outbound direction and which
/// profile is active are decisions that belong to the caller, not to a pure
/// per-endpoint evaluator.
#[must_use]
pub fn evaluate<'r>(
    endpoint: &Endpoint,
    rules: &'r [FirewallRule],
    _profiles: &[ProfileState],
) -> ReachabilityVerdict<'r> {
    if endpoint.exposure == Exposure::Loopback {
        return ReachabilityVerdict {
            reachability: Reachability::LocalOnly,
            matched_rules: Vec::new(),
        };
    }

    let applicable: Vec<&FirewallRule> = rules
        .iter()
        .filter(|rule| rule_applies(rule, endpoint))
        .collect();

    if let Some(&block) = applicable
        .iter()
        .find(|rule| rule.action == RuleAction::Block)
    {
        return ReachabilityVerdict {
            reachability: Reachability::Blocked,
            matched_rules: vec![block],
        };
    }

    let allows: Vec<&FirewallRule> = applicable
        .into_iter()
        .filter(|rule| rule.action == RuleAction::Allow)
        .collect();

    if allows
        .iter()
        .any(|rule| matches!(rule.port_spec, PortSpec::Dynamic(_)))
    {
        return ReachabilityVerdict {
            reachability: Reachability::Indeterminate,
            matched_rules: allows,
        };
    }

    if allows.is_empty() {
        ReachabilityVerdict {
            reachability: Reachability::DefaultAction,
            matched_rules: Vec::new(),
        }
    } else {
        ReachabilityVerdict {
            reachability: Reachability::Allowed,
            matched_rules: allows,
        }
    }
}

/// Reports whether `rule` governs traffic to `endpoint`.
///
/// All four conditions gate independently: protocol, port spec, program
/// filter (absent, or present and matching), and service filter (absent, or
/// present and matching a hosted service). A rule scoped to a program the
/// endpoint does not run never applies, regardless of port — including when
/// `endpoint.process_path` is `None`, since there is nothing for a present
/// filter to match against.
fn rule_applies(rule: &FirewallRule, endpoint: &Endpoint) -> bool {
    if rule.protocol != endpoint.protocol {
        return false;
    }
    if !rule.port_spec.matches(endpoint.port) {
        return false;
    }
    if let Some(filter) = &rule.program_filter
        && !program_filter_matches(filter, endpoint.process_path.as_ref())
    {
        return false;
    }
    if let Some(service_filter) = &rule.service_filter
        && !endpoint
            .hosted_services
            .iter()
            .any(|hosted| hosted == service_filter)
    {
        return false;
    }
    true
}

/// Compares a rule's program filter against an endpoint's owning process path.
///
/// A `None` process path can never satisfy a present filter — there is
/// nothing to compare against, not even the empty string.
fn program_filter_matches(filter: &ProcessPath, process_path: Option<&ProcessPath>) -> bool {
    let Some(process_path) = process_path else {
        return false;
    };
    // Standing limitation, no task currently owns it: no collector this
    // project has ever built (PowerShell, native Win32, Linux) captures
    // the host's environment variables into any Raw* payload, and
    // `evaluate` is deliberately pure -- reading `%VAR%` here directly via
    // `std::env::var` would mean evaluating against *this process's* own
    // environment, not the remote or at-rest host's, which is simply
    // wrong. A real fix needs a collector adapter to snapshot environment
    // state at scan time and thread it through `evaluate`'s caller as
    // data, not add I/O to this function. Until then, filters containing
    // `%VAR%` pass through unexpanded.
    let expanded = expand_env_vars(filter.as_str(), |_var_name| None);
    compare_program_paths(&expanded, process_path.as_str())
}

/// The kernel-owned pseudo-path a program filter or process path may hold.
const SYSTEM_PSEUDO_PATH: &str = "System";

/// Compares two program-path strings under this evaluator's matching rules.
///
/// Case-insensitive on Windows (matching that platform's own path
/// comparison semantics), case-sensitive everywhere else. The `System`
/// pseudo-path is a fixed platform label, not a filesystem path, so it is
/// always compared case-insensitively regardless of target platform.
///
/// Split by `#[cfg]` rather than left as one non-`const fn` with an
/// internal branch: `str::eq_ignore_ascii_case` is const-stable on this
/// toolchain but `str`'s `PartialEq` (`==`, the non-Windows branch) is
/// not, so only the Windows body can be `const`. clippy only sees
/// whichever branch the current target actually compiles, so this only
/// surfaced on a real windows-latest CI run.
#[cfg(windows)]
const fn compare_program_paths(filter: &str, process_path: &str) -> bool {
    if filter.eq_ignore_ascii_case(SYSTEM_PSEUDO_PATH)
        || process_path.eq_ignore_ascii_case(SYSTEM_PSEUDO_PATH)
    {
        return filter.eq_ignore_ascii_case(process_path);
    }
    filter.eq_ignore_ascii_case(process_path)
}

#[cfg(not(windows))]
fn compare_program_paths(filter: &str, process_path: &str) -> bool {
    if filter.eq_ignore_ascii_case(SYSTEM_PSEUDO_PATH)
        || process_path.eq_ignore_ascii_case(SYSTEM_PSEUDO_PATH)
    {
        return filter.eq_ignore_ascii_case(process_path);
    }
    filter == process_path
}

/// Expands Windows-style `%VAR%` placeholders in a program-filter string.
///
/// Domain code must stay I/O-free, so environment values come in as data —
/// a lookup closure supplied by the caller — rather than being read live via
/// `std::env::var`. A placeholder with no registered value, or an unmatched
/// `%`, is left in the output unexpanded rather than silently dropped.
fn expand_env_vars(input: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            output.push(ch);
            continue;
        }
        let mut var_name = String::new();
        let mut closed = false;
        for next_ch in chars.by_ref() {
            if next_ch == '%' {
                closed = true;
                break;
            }
            var_name.push(next_ch);
        }
        if !closed {
            output.push('%');
            output.push_str(&var_name);
        } else if var_name.is_empty() {
            output.push('%');
            output.push('%');
        } else if let Some(value) = lookup(&var_name) {
            output.push_str(&value);
        } else {
            output.push('%');
            output.push_str(&var_name);
            output.push('%');
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;

    use super::*;
    use crate::domain::bind_address::BindAddress;
    use crate::domain::firewall_rule::Direction;
    use crate::domain::ids::RuleId;
    use crate::domain::policy_store::PolicyStore;
    use crate::domain::port::Port;
    use crate::domain::port_spec::DynamicKeyword;
    use crate::domain::protocol::Protocol;
    use crate::domain::publisher::SignatureStatus;
    use crate::domain::service::ServiceName;

    fn endpoint_on(port: u16) -> Endpoint {
        Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").unwrap(),
            Port::try_from(port).unwrap(),
            None,
            None,
            vec![],
            SignatureStatus::Unknown,
            None,
        )
    }

    fn endpoint_owned_by(process_path: &str, port: u16) -> Endpoint {
        Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").unwrap(),
            Port::try_from(port).unwrap(),
            None,
            Some(ProcessPath::from_str(process_path).unwrap()),
            vec![],
            SignatureStatus::Unknown,
            None,
        )
    }

    fn base_rule(port_spec: PortSpec, action: RuleAction) -> FirewallRule {
        FirewallRule {
            rule_id: RuleId::generate(),
            display_name: "test rule".to_owned(),
            direction: Direction::Inbound,
            action,
            protocol: Protocol::Tcp,
            port_spec,
            program_filter: None,
            service_filter: None,
            enabled: true,
            policy_store: PolicyStore::Local,
        }
    }

    fn allow_rule(port: u16) -> FirewallRule {
        base_rule(
            PortSpec::Single(Port::try_from(port).unwrap()),
            RuleAction::Allow,
        )
    }

    fn block_rule(port: u16) -> FirewallRule {
        base_rule(
            PortSpec::Single(Port::try_from(port).unwrap()),
            RuleAction::Block,
        )
    }

    fn program_scoped_allow_any_port(process_path: &str) -> FirewallRule {
        let mut rule = base_rule(PortSpec::Any, RuleAction::Allow);
        rule.program_filter = Some(ProcessPath::from_str(process_path).unwrap());
        rule
    }

    fn allow_rule_with_spec(port_spec: PortSpec) -> FirewallRule {
        base_rule(port_spec, RuleAction::Allow)
    }

    #[test]
    fn block_overrides_matching_allow() {
        let endpoint = endpoint_on(443);
        let rules = vec![allow_rule(443), block_rule(443)];
        let verdict = evaluate(&endpoint, &rules, &[]);
        assert_eq!(verdict.reachability, Reachability::Blocked);
    }

    #[test]
    fn program_scoped_any_port_rule_allows_unlisted_port() {
        let endpoint = endpoint_owned_by("C:\\svc\\app.exe", 54321);
        let rules = vec![program_scoped_allow_any_port("C:\\svc\\app.exe")];
        let verdict = evaluate(&endpoint, &rules, &[]);
        assert_eq!(verdict.reachability, Reachability::Allowed);
    }

    #[test]
    fn dynamic_rpc_keyword_is_indeterminate_not_allowed() {
        let endpoint = endpoint_on(49666);
        let rules = vec![allow_rule_with_spec(PortSpec::Dynamic(DynamicKeyword::Rpc))];
        let verdict = evaluate(&endpoint, &rules, &[]);
        assert_eq!(verdict.reachability, Reachability::Indeterminate);
    }

    #[test]
    fn no_matching_rule_yields_default_action() {
        let endpoint = endpoint_on(9999);
        let verdict = evaluate(&endpoint, &[], &[]);
        assert_eq!(verdict.reachability, Reachability::DefaultAction);
        assert!(verdict.matched_rules.is_empty());
    }

    #[test]
    fn service_filter_mismatch_alone_excludes_an_otherwise_matching_rule() {
        let mut endpoint = endpoint_on(443);
        endpoint.hosted_services = vec![ServiceName::from_str("Dnscache").unwrap()];
        let mut rule = allow_rule(443);
        rule.service_filter = Some(ServiceName::from_str("W32Time").unwrap());
        let rules = [rule];
        let verdict = evaluate(&endpoint, &rules, &[]);
        assert_eq!(verdict.reachability, Reachability::DefaultAction);
        assert!(verdict.matched_rules.is_empty());
    }

    #[test]
    fn program_filter_never_matches_a_process_path_of_none() {
        let endpoint = endpoint_on(443);
        let mut rule = allow_rule(443);
        rule.program_filter = Some(ProcessPath::from_str("C:\\svc\\app.exe").unwrap());
        let rules = [rule];
        let verdict = evaluate(&endpoint, &rules, &[]);
        assert_eq!(verdict.reachability, Reachability::DefaultAction);
    }

    #[test]
    fn system_pseudo_path_matches_kernel_owned_endpoint() {
        let endpoint = endpoint_owned_by("System", 445);
        let mut rule = allow_rule(445);
        rule.program_filter = Some(ProcessPath::from_str("System").unwrap());
        let rules = [rule];
        let verdict = evaluate(&endpoint, &rules, &[]);
        assert_eq!(verdict.reachability, Reachability::Allowed);
    }

    #[test]
    fn loopback_endpoint_is_local_only_regardless_of_rules() {
        let endpoint = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("127.0.0.1").unwrap(),
            Port::try_from(443u16).unwrap(),
            None,
            None,
            vec![],
            SignatureStatus::Unknown,
            None,
        );
        let rules = vec![block_rule(443)];
        let verdict = evaluate(&endpoint, &rules, &[]);
        assert_eq!(verdict.reachability, Reachability::LocalOnly);
        assert!(verdict.matched_rules.is_empty());
    }

    #[test]
    fn expand_env_vars_substitutes_known_variables() {
        let expanded = expand_env_vars("%ProgramFiles%\\app\\app.exe", |name| {
            (name == "ProgramFiles").then(|| "C:\\Program Files".to_owned())
        });
        assert_eq!(expanded, "C:\\Program Files\\app\\app.exe");
    }

    #[test]
    fn expand_env_vars_leaves_unknown_variables_and_unmatched_percent_untouched() {
        assert_eq!(expand_env_vars("%UNKNOWN%\\x", |_| None), "%UNKNOWN%\\x");
        assert_eq!(expand_env_vars("50%done", |_| None), "50%done");
    }

    #[derive(Debug, Clone, Copy)]
    enum PortSpecVariant {
        SingleMatching,
        SingleNonMatching,
        Any,
        Dynamic,
    }

    #[derive(Debug, Clone, Copy)]
    enum FilterVariant {
        Absent,
        PresentMatching,
        PresentNonMatching,
    }

    struct MatrixCase {
        name: String,
        endpoint: Endpoint,
        rules: Vec<FirewallRule>,
        expected: Reachability,
    }

    const MATRIX_ENDPOINT_PORT: u16 = 8080;
    const MATRIX_OWNING_PROCESS: &str = "C:\\svc\\app.exe";
    const MATRIX_OTHER_PROCESS: &str = "C:\\other\\thing.exe";
    const MATRIX_HOSTED_SERVICE: &str = "Dnscache";
    const MATRIX_OTHER_SERVICE: &str = "W32Time";

    fn build_matrix_case(
        action: RuleAction,
        port_variant: PortSpecVariant,
        program_variant: FilterVariant,
        service_variant: FilterVariant,
    ) -> MatrixCase {
        let (port_spec, port_matches) = match port_variant {
            PortSpecVariant::SingleMatching => (
                PortSpec::Single(Port::try_from(MATRIX_ENDPOINT_PORT).unwrap()),
                true,
            ),
            PortSpecVariant::SingleNonMatching => {
                (PortSpec::Single(Port::try_from(9090u16).unwrap()), false)
            }
            PortSpecVariant::Any => (PortSpec::Any, true),
            PortSpecVariant::Dynamic => (PortSpec::Dynamic(DynamicKeyword::Rpc), true),
        };

        let (program_filter, program_ok) = match program_variant {
            FilterVariant::Absent => (None, true),
            FilterVariant::PresentMatching => (
                Some(ProcessPath::from_str(MATRIX_OWNING_PROCESS).unwrap()),
                true,
            ),
            FilterVariant::PresentNonMatching => (
                Some(ProcessPath::from_str(MATRIX_OTHER_PROCESS).unwrap()),
                false,
            ),
        };

        let (service_filter, service_ok) = match service_variant {
            FilterVariant::Absent => (None, true),
            FilterVariant::PresentMatching => (
                Some(ServiceName::from_str(MATRIX_HOSTED_SERVICE).unwrap()),
                true,
            ),
            FilterVariant::PresentNonMatching => (
                Some(ServiceName::from_str(MATRIX_OTHER_SERVICE).unwrap()),
                false,
            ),
        };

        let applies = port_matches && program_ok && service_ok;
        let expected = if !applies {
            Reachability::DefaultAction
        } else if action == RuleAction::Block {
            Reachability::Blocked
        } else if matches!(port_variant, PortSpecVariant::Dynamic) {
            Reachability::Indeterminate
        } else {
            Reachability::Allowed
        };

        let rule = FirewallRule {
            rule_id: RuleId::generate(),
            display_name: "matrix rule".to_owned(),
            direction: Direction::Inbound,
            action,
            protocol: Protocol::Tcp,
            port_spec,
            program_filter,
            service_filter,
            enabled: true,
            policy_store: PolicyStore::Local,
        };

        let endpoint = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").unwrap(),
            Port::try_from(MATRIX_ENDPOINT_PORT).unwrap(),
            None,
            Some(ProcessPath::from_str(MATRIX_OWNING_PROCESS).unwrap()),
            vec![ServiceName::from_str(MATRIX_HOSTED_SERVICE).unwrap()],
            SignatureStatus::Unknown,
            None,
        );

        MatrixCase {
            name: format!(
                "action={action:?} port={port_variant:?} program={program_variant:?} service={service_variant:?}"
            ),
            endpoint,
            rules: vec![rule],
            expected,
        }
    }

    fn reachability_matrix() -> Vec<MatrixCase> {
        let actions = [RuleAction::Allow, RuleAction::Block];
        let port_variants = [
            PortSpecVariant::SingleMatching,
            PortSpecVariant::SingleNonMatching,
            PortSpecVariant::Any,
            PortSpecVariant::Dynamic,
        ];
        let program_variants = [
            FilterVariant::Absent,
            FilterVariant::PresentMatching,
            FilterVariant::PresentNonMatching,
        ];
        let service_variants = [
            FilterVariant::Absent,
            FilterVariant::PresentMatching,
            FilterVariant::PresentNonMatching,
        ];

        let mut cases = Vec::new();
        for action in actions {
            for port_variant in port_variants {
                for program_variant in program_variants {
                    for service_variant in service_variants {
                        cases.push(build_matrix_case(
                            action,
                            port_variant,
                            program_variant,
                            service_variant,
                        ));
                    }
                }
            }
        }
        cases
    }

    #[test]
    fn cross_product_of_action_port_spec_and_filters() {
        let cases = reachability_matrix();
        assert_eq!(cases.len(), 72);
        for case in cases {
            let verdict = evaluate(&case.endpoint, &case.rules, &[]);
            assert_eq!(verdict.reachability, case.expected, "case: {}", case.name);
        }
    }
}
