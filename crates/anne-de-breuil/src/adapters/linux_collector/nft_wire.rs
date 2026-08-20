//! Pure nftables netlink wire framing and classification.
//!
//! No `#[cfg(target_os = "linux")]` anywhere in this file: every function
//! here operates on plain `&[u8]` buffers, so it compiles and its tests run
//! on any host without a socket, root, or a live kernel. [`super::firewall`]
//! is the thin `#[cfg(target_os = "linux")]` half that actually opens a
//! `NETLINK_NETFILTER` socket, sends [`encode_getchain_dump_request`]'s
//! output, and feeds the raw response bytes to [`parse_nl_buffer`].
//!
//! # Protocol notes and their epistemic status
//!
//! The constants below (`NFNL_SUBSYS_NFTABLES`, the `NFT_MSG_*`/`NFTA_*`
//! numeric values, the big-endian encoding of nftables' numeric netlink
//! attributes) are taken from the documented, long-stable
//! `linux/netfilter/nfnetlink.h` and `linux/netfilter/nf_tables.h` UAPI
//! headers. This project's dev machine has no Linux kernel to verify
//! decoding against a real `NEWCHAIN` dump response, so
//! [`tests::decodes_a_synthetic_input_chain_dump_message`] validates this
//! module's understanding of the wire format against bytes this module
//! itself constructs from that same documented layout, not against kernel
//! output — the same position T06's WMI numeric-encoding module docs are
//! already honest about for `MSFT_NetFirewallRule`'s `Direction`/`Action`
//! fields. A live-host differential test is future work once a Linux test
//! host is available, mirroring
//! [`super::super::windows_collector::live_host_windows_collector_matches_powershell_collector`].
//!
//! # Why chain-level, not full rule/expression decoding
//!
//! `nftnl`/`rustables` (the two crates this task names) both bind
//! `libnftnl`, a native C library located via `pkg-config`; neither
//! `libnftnl` nor a musl build of it is available on this dev machine or
//! its cross-compile toolchain, and attempting to add either as a plain
//! dependency breaks `cargo build` on macOS outright (confirmed: `cargo
//! build` against a throwaway crate depending on `nftnl` fails in
//! `nftnl-sys`'s build script with `Package libnftnl was not found in the
//! pkg-config search path`). Hand-rolling full nftables rule/expression
//! decoding (deeply nested `NFTA_RULE_EXPRESSIONS` trees describing every
//! match/verdict primitive) to replace it is a much larger, genuinely
//! separate task; this module stops at chain granularity, which is enough
//! to answer the question this task actually asks for ("is there an
//! nftables policy here, and is the base input chain's default policy
//! allow or block") without fabricating per-rule protocol/port data this
//! collector never observed. See the `TODO(future task)` on
//! [`nft_chain_to_raw_rule`].

use crate::application::collect::RawRule;

const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_GETCHAIN: u16 = 4;
const NEWCHAIN_MSG_TYPE: u16 = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN;
const GETCHAIN_MSG_TYPE: u16 = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETCHAIN;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_DUMP: u16 = 0x0300;
const NLMSG_ERROR: u16 = 0x0002;
const NLMSG_DONE: u16 = 0x0003;

const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NLA_TYPE_MASK: u16 = 0x3FFF;

/// `NF_INET_LOCAL_IN`: the hook number for a base chain attached to the
/// inbound path -- the only hook this task's `inbound_rules()` cares about.
const NF_INET_LOCAL_IN: u32 = 1;
/// The only chain-policy value this module distinguishes; every other
/// value (including `NF_ACCEPT = 1` and an unset policy) is "Allow".
const NF_DROP: u32 = 0;

/// One decoded `NFTA_CHAIN_*` attribute set from a `NEWCHAIN` dump message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NftChain {
    /// The owning table's name (`NFTA_CHAIN_TABLE`).
    pub table: Option<String>,
    /// The chain's own name (`NFTA_CHAIN_NAME`).
    pub name: Option<String>,
    /// The base chain's hook number (`NFTA_HOOK_HOOKNUM`, nested inside
    /// `NFTA_CHAIN_HOOK`), or `None` for a non-base (regular) chain.
    pub hooknum: Option<u32>,
    /// The base chain's default policy (`NFTA_CHAIN_POLICY`): `0` = drop,
    /// `1` = accept.
    pub policy: Option<u32>,
}

/// Why a live nftables ruleset query could not be answered at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesetQueryError {
    /// The kernel refused the query (`EPERM`/`EACCES`).
    PermissionDenied,
    /// The query failed for any other reason (socket, other errno).
    Unreachable,
}

/// The outcome of asking this host for its nftables policy.
///
/// Deliberately distinct from `Result<Vec<RawRule>, _>` at the type level:
/// [`FirewallSource::Nftables`] with an empty vector means the query
/// succeeded and the ruleset is genuinely empty; [`FirewallSource::NoPolicySource`]
/// means there is nothing this collector could read at all (unreachable
/// netlink, denied permission, or a legacy iptables-only host with no
/// nftables ruleset to query) -- a report reader needs to tell these apart,
/// so they are never collapsed into the same `Ok(vec![])`.
#[derive(Debug, Clone)]
pub enum FirewallSource {
    /// The nftables policy was read successfully; the rules may be empty.
    Nftables(Vec<RawRule>),
    /// No nftables policy source was available to read at all.
    NoPolicySource,
}

/// Builds a `NFT_MSG_GETCHAIN` dump request: no attributes, `nfgen_family`
/// `NFPROTO_UNSPEC` (dump every table family).
#[must_use]
pub fn encode_getchain_dump_request(seq: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    buf.extend_from_slice(&20u32.to_le_bytes()); // nlmsg_len
    buf.extend_from_slice(&GETCHAIN_MSG_TYPE.to_le_bytes());
    buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_le_bytes());
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // nlmsg_pid
    buf.push(0); // nfgen_family = NFPROTO_UNSPEC
    buf.push(0); // nfgenmsg version = NFNETLINK_V0
    buf.extend_from_slice(&0u16.to_be_bytes()); // res_id
    buf
}

/// What one buffer's worth of netlink response messages decoded to.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BufferOutcome {
    /// Every chain successfully decoded from this buffer.
    pub chains: Vec<NftChain>,
    /// Whether an `NLMSG_DONE`/`NLMSG_ERROR` terminal message was seen.
    pub done: bool,
    /// The decoded error, if a terminal `NLMSG_ERROR` message was seen.
    pub error: Option<RulesetQueryError>,
}

/// Decodes every complete netlink message in `buf`.
///
/// Stops at the first `NLMSG_DONE`/`NLMSG_ERROR`, or at the first message
/// this buffer doesn't fully contain (the caller is expected to `recv`
/// more and continue).
#[must_use]
pub fn parse_nl_buffer(buf: &[u8]) -> BufferOutcome {
    let mut outcome = BufferOutcome::default();
    let mut offset = 0usize;
    while let Some((msg_type, msg_len, payload)) = read_nl_message(buf, offset) {
        match msg_type {
            NLMSG_DONE => {
                outcome.done = true;
                return outcome;
            }
            NLMSG_ERROR => {
                let errno = read_i32_le(payload, 0).unwrap_or(0);
                outcome.error = Some(classify_errno(errno));
                outcome.done = true;
                return outcome;
            }
            NEWCHAIN_MSG_TYPE => {
                if let Some(chain) = parse_chain_payload(payload) {
                    outcome.chains.push(chain);
                }
            }
            _ => {}
        }
        offset += msg_len.next_multiple_of(4);
    }
    outcome
}

const fn classify_errno(errno: i32) -> RulesetQueryError {
    match errno {
        -1 | -13 => RulesetQueryError::PermissionDenied, // -EPERM, -EACCES
        _ => RulesetQueryError::Unreachable,
    }
}

/// Reads one `nlmsghdr`-framed message at `offset`, returning its type,
/// declared total length (header + payload, unpadded), and payload slice.
/// `None` if `offset` doesn't point at a complete message.
fn read_nl_message(buf: &[u8], offset: usize) -> Option<(u16, usize, &[u8])> {
    let len = read_u32_le(buf, offset)? as usize;
    let msg_type = read_u16_le(buf, offset + 4)?;
    if len < 16 {
        return None;
    }
    let payload = buf.get(offset + 16..offset + len)?;
    Some((msg_type, len, payload))
}

/// Decodes one `NEWCHAIN` message's payload (`nfgenmsg` + `NFTA_CHAIN_*` attributes).
fn parse_chain_payload(payload: &[u8]) -> Option<NftChain> {
    let attrs = payload.get(4..)?; // skip the 4-byte nfgenmsg header
    let mut chain = NftChain::default();
    for (attr_type, value) in iter_nlattrs(attrs) {
        match attr_type & NLA_TYPE_MASK {
            NFTA_CHAIN_TABLE => chain.table = decode_nla_string(value),
            NFTA_CHAIN_NAME => chain.name = decode_nla_string(value),
            NFTA_CHAIN_HOOK => {
                for (hook_attr_type, hook_value) in iter_nlattrs(value) {
                    if hook_attr_type & NLA_TYPE_MASK == NFTA_HOOK_HOOKNUM {
                        chain.hooknum = decode_nla_u32_be(hook_value);
                    }
                }
            }
            NFTA_CHAIN_POLICY => chain.policy = decode_nla_u32_be(value),
            _ => {}
        }
    }
    Some(chain)
}

/// Walks a flat `nlattr` sequence, 4-byte aligned per the netlink ABI.
fn iter_nlattrs(buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= buf.len() {
        let Some(nla_len) = read_u16_le(buf, offset).map(usize::from) else {
            break;
        };
        let Some(nla_type) = read_u16_le(buf, offset + 2) else {
            break;
        };
        if nla_len < 4 {
            break;
        }
        let Some(value) = buf.get(offset + 4..offset + nla_len) else {
            break;
        };
        out.push((nla_type, value));
        offset += nla_len.next_multiple_of(4);
    }
    out
}

fn decode_nla_string(value: &[u8]) -> Option<String> {
    let trimmed = if value.last() == Some(&0) {
        value.get(..value.len().saturating_sub(1))?
    } else {
        value
    };
    core::str::from_utf8(trimmed).ok().map(ToOwned::to_owned)
}

/// nftables' numeric netlink attributes are transmitted big-endian
/// (`__be32` in the UAPI header), unlike e.g. rtnetlink's host-order convention.
fn decode_nla_u32_be(value: &[u8]) -> Option<u32> {
    value.get(0..4)?.try_into().ok().map(u32::from_be_bytes)
}

fn read_u16_le(buf: &[u8], offset: usize) -> Option<u16> {
    buf.get(offset..offset + 2)?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}

fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn read_i32_le(buf: &[u8], offset: usize) -> Option<i32> {
    buf.get(offset..offset + 4)?
        .try_into()
        .ok()
        .map(i32::from_le_bytes)
}

/// Maps one decoded input-hook base chain to a [`RawRule`].
///
/// `None` for any chain that isn't a base chain on the inbound
/// (`NF_INET_LOCAL_IN`) hook -- forward/output/prerouting/postrouting
/// chains and regular (non-base) chains aren't part of the host's inbound
/// listening-port exposure this task collects. `protocol`/`local_port_spec`/
/// `program_filter`/`service_filter` are always `None`: this module decodes
/// chain-level policy only, not per-rule match expressions.
///
/// TODO(future task): decode `NFT_MSG_GETRULE`'s `NFTA_RULE_EXPRESSIONS`
/// tree to recover per-rule protocol/port/verdict data instead of only the
/// chain's default policy.
fn nft_chain_to_raw_rule(chain: &NftChain) -> Option<RawRule> {
    if chain.hooknum != Some(NF_INET_LOCAL_IN) {
        return None;
    }
    let table = chain.table.clone().unwrap_or_else(|| "?".to_owned());
    let name = chain.name.clone().unwrap_or_else(|| "?".to_owned());
    // nftables' documented default when a base chain carries no explicit
    // policy is accept, so every value other than an explicit drop is
    // "Allow".
    let action = if chain.policy == Some(NF_DROP) {
        "Block"
    } else {
        "Allow"
    }
    .to_owned();

    Some(RawRule {
        rule_id: format!("nftables/{table}/{name}"),
        display_name: format!("{table}/{name} (nftables input chain policy)"),
        direction: "Inbound".to_owned(),
        action,
        protocol: None,
        local_port_spec: None,
        program_filter: None,
        service_filter: None,
        enabled: true,
        policy_store: "nftables".to_owned(),
    })
}

/// Classifies a completed chain query into a [`FirewallSource`].
///
/// `legacy_iptables_active` is the caller's answer to "does this host have
/// a legacy iptables ruleset with content" (see [`super::firewall::legacy_iptables_active`]):
/// a genuinely empty nftables query on a host that's actually using legacy
/// iptables is [`FirewallSource::NoPolicySource`], not
/// [`FirewallSource::Nftables(vec![])`] -- nftables has nothing to say
/// because the real policy lives elsewhere, which is exactly the
/// "unreadable, not empty" case this task asks to distinguish.
#[must_use]
pub fn classify_ruleset(
    query: Result<Vec<NftChain>, RulesetQueryError>,
    legacy_iptables_active: bool,
) -> FirewallSource {
    query.map_or(FirewallSource::NoPolicySource, |chains| {
        let rules: Vec<RawRule> = chains.iter().filter_map(nft_chain_to_raw_rule).collect();
        if rules.is_empty() && legacy_iptables_active {
            FirewallSource::NoPolicySource
        } else {
            FirewallSource::Nftables(rules)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{
        BufferOutcome, FirewallSource, NEWCHAIN_MSG_TYPE, NftChain, RulesetQueryError,
        classify_ruleset, encode_getchain_dump_request, parse_nl_buffer,
    };

    mod fixtures {
        use super::{FirewallSource, NEWCHAIN_MSG_TYPE, RulesetQueryError, classify_ruleset};

        pub(super) fn firewall_source_from_permission_denied() -> FirewallSource {
            classify_ruleset(Err(RulesetQueryError::PermissionDenied), false)
        }

        pub(super) fn firewall_source_from_empty_ruleset() -> FirewallSource {
            classify_ruleset(Ok(Vec::new()), false)
        }

        /// Hand-builds one synthetic `NEWCHAIN` message the way the kernel's
        /// documented wire format describes it, independent of this
        /// module's own encoder (which only builds *requests*) -- so
        /// decoding it is a real check of [`super::super::parse_nl_buffer`],
        /// not a tautology.
        pub(super) fn synthetic_newchain_message(
            table: &str,
            name: &str,
            hooknum: u32,
            policy: u32,
        ) -> Vec<u8> {
            let mut attrs = Vec::new();
            push_nla_string(&mut attrs, 1, table); // NFTA_CHAIN_TABLE
            push_nla_string(&mut attrs, 3, name); // NFTA_CHAIN_NAME

            let mut hook_nested = Vec::new();
            push_nla_u32_be(&mut hook_nested, 1, hooknum); // NFTA_HOOK_HOOKNUM
            push_nla_raw(&mut attrs, 4 | 0x8000, &hook_nested); // NFTA_CHAIN_HOOK, nested

            push_nla_u32_be(&mut attrs, 5, policy); // NFTA_CHAIN_POLICY

            let mut payload = vec![0u8, 0, 0, 0]; // nfgenmsg: family/version/res_id, unused by the decoder
            payload.extend_from_slice(&attrs);

            let mut msg = Vec::new();
            let total_len = 16 + payload.len();
            msg.extend_from_slice(&u32::try_from(total_len).unwrap_or(0).to_le_bytes());
            msg.extend_from_slice(&NEWCHAIN_MSG_TYPE.to_le_bytes());
            msg.extend_from_slice(&2u16.to_le_bytes()); // flags: NLM_F_MULTI, unused by the decoder
            msg.extend_from_slice(&0u32.to_le_bytes()); // seq
            msg.extend_from_slice(&0u32.to_le_bytes()); // pid
            msg.extend_from_slice(&payload);
            msg
        }

        pub(super) fn done_message() -> Vec<u8> {
            let mut msg = Vec::new();
            msg.extend_from_slice(&16u32.to_le_bytes());
            msg.extend_from_slice(&3u16.to_le_bytes()); // NLMSG_DONE
            msg.extend_from_slice(&0u16.to_le_bytes());
            msg.extend_from_slice(&0u32.to_le_bytes());
            msg.extend_from_slice(&0u32.to_le_bytes());
            msg
        }

        pub(super) fn error_message(errno: i32) -> Vec<u8> {
            let mut msg = Vec::new();
            msg.extend_from_slice(&20u32.to_le_bytes());
            msg.extend_from_slice(&2u16.to_le_bytes()); // NLMSG_ERROR
            msg.extend_from_slice(&0u16.to_le_bytes());
            msg.extend_from_slice(&0u32.to_le_bytes());
            msg.extend_from_slice(&0u32.to_le_bytes());
            msg.extend_from_slice(&errno.to_le_bytes());
            msg
        }

        fn push_nla_raw(buf: &mut Vec<u8>, nla_type: u16, value: &[u8]) {
            let nla_len = u16::try_from(4 + value.len()).unwrap_or(u16::MAX);
            buf.extend_from_slice(&nla_len.to_le_bytes());
            buf.extend_from_slice(&nla_type.to_le_bytes());
            buf.extend_from_slice(value);
            let padding = (value.len().next_multiple_of(4)) - value.len();
            buf.extend(core::iter::repeat_n(0u8, padding));
        }

        fn push_nla_string(buf: &mut Vec<u8>, nla_type: u16, s: &str) {
            let mut value = s.as_bytes().to_vec();
            value.push(0);
            push_nla_raw(buf, nla_type, &value);
        }

        fn push_nla_u32_be(buf: &mut Vec<u8>, nla_type: u16, v: u32) {
            push_nla_raw(buf, nla_type, &v.to_be_bytes());
        }
    }

    #[test]
    fn unreadable_nft_ruleset_yields_no_policy_source() {
        let source = fixtures::firewall_source_from_permission_denied();
        assert!(matches!(source, FirewallSource::NoPolicySource));
    }

    #[test]
    fn empty_nft_ruleset_is_distinct_from_unreadable() {
        let source = fixtures::firewall_source_from_empty_ruleset();
        assert!(matches!(source, FirewallSource::Nftables(rules) if rules.is_empty()));
    }

    #[test]
    fn legacy_iptables_only_host_yields_no_policy_source_even_with_empty_nftables_query() {
        let source = classify_ruleset(Ok(Vec::new()), true);
        assert!(matches!(source, FirewallSource::NoPolicySource));
    }

    #[test]
    fn decodes_a_synthetic_input_chain_dump_message() {
        let mut buf = fixtures::synthetic_newchain_message("filter", "input", 1, 1);
        buf.extend_from_slice(&fixtures::done_message());

        let outcome = parse_nl_buffer(&buf);

        assert!(outcome.done);
        assert_eq!(outcome.error, None);
        assert_eq!(
            outcome.chains,
            vec![NftChain {
                table: Some("filter".to_owned()),
                name: Some("input".to_owned()),
                hooknum: Some(1),
                policy: Some(1),
            }]
        );
    }

    #[test]
    fn non_input_hook_chain_is_decoded_but_excluded_from_inbound_rules() {
        let buf = fixtures::synthetic_newchain_message("filter", "output", 3, 1);
        let outcome = parse_nl_buffer(&buf);
        assert!(
            outcome
                .chains
                .iter()
                .find_map(super::nft_chain_to_raw_rule)
                .is_none()
        );
    }

    #[test]
    fn input_hook_with_drop_policy_maps_to_block() {
        let buf = fixtures::synthetic_newchain_message("filter", "input", 1, 0);
        let outcome = parse_nl_buffer(&buf);
        let rules: Vec<_> = outcome
            .chains
            .iter()
            .filter_map(super::nft_chain_to_raw_rule)
            .collect();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, "Block");
        assert_eq!(rules[0].direction, "Inbound");
    }

    #[test]
    fn error_message_with_eperm_classifies_as_permission_denied() {
        let outcome = parse_nl_buffer(&fixtures::error_message(-1));
        assert!(outcome.done);
        assert_eq!(outcome.error, Some(RulesetQueryError::PermissionDenied));
        assert!(outcome.chains.is_empty());
    }

    #[test]
    fn error_message_with_eacces_classifies_as_permission_denied() {
        let outcome = parse_nl_buffer(&fixtures::error_message(-13));
        assert_eq!(outcome.error, Some(RulesetQueryError::PermissionDenied));
    }

    #[test]
    fn error_message_with_other_errno_is_unreachable_not_permission_denied() {
        let outcome = parse_nl_buffer(&fixtures::error_message(-22)); // -EINVAL
        assert_eq!(outcome.error, Some(RulesetQueryError::Unreachable));
    }

    #[test]
    fn request_encodes_expected_message_type_and_flags() {
        let buf = encode_getchain_dump_request(7);
        assert_eq!(buf.len(), 20);
        assert_eq!(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 20);
        let msg_type = u16::from_le_bytes([buf[4], buf[5]]);
        assert_eq!(msg_type, super::GETCHAIN_MSG_TYPE);
        let flags = u16::from_le_bytes([buf[6], buf[7]]);
        assert_eq!(flags, super::NLM_F_REQUEST | super::NLM_F_DUMP);
    }

    #[test]
    fn empty_buffer_yields_default_outcome() {
        assert_eq!(parse_nl_buffer(&[]), BufferOutcome::default());
    }
}
