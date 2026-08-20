//! [`LinuxFirewallPolicySource`]: nftables base-chain policy via a raw
//! `NETLINK_NETFILTER` `GETCHAIN` dump. [`super::nft_wire`] owns the wire
//! framing, decoding, and the empty-vs-unreadable classification; this
//! file only opens the socket, drives the request/response loop, and
//! checks for a legacy iptables-only host.

use async_trait::async_trait;
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};

use super::nft_wire::{
    FirewallSource, NftChain, RulesetQueryError, classify_ruleset, encode_getchain_dump_request,
    parse_nl_buffer,
};
use crate::application::collect::{CollectError, FirewallPolicySource, RawProfile, RawRule};

const RECV_BUFFER_SIZE: usize = 8192;

/// Queries the host's nftables base-chain policy through a hand-driven `NETLINK_NETFILTER` socket.
///
/// No `nftnl`/`rustables` (both bind `libnftnl`, a native C library
/// unavailable on this project's dev/CI hosts; see [`super::nft_wire`]'s
/// module docs) and no `nft` subprocess.
#[derive(Debug, Default)]
pub struct LinuxFirewallPolicySource;

impl LinuxFirewallPolicySource {
    /// Builds a source with no state to initialize -- each call opens its own socket.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl FirewallPolicySource for LinuxFirewallPolicySource {
    async fn inbound_rules(&self) -> Result<Vec<RawRule>, CollectError> {
        tokio::task::spawn_blocking(query_inbound_rules)
            .await
            .map_err(|source| CollectError::Spawn(source.to_string()))?
    }

    async fn profiles(&self) -> Result<Vec<RawProfile>, CollectError> {
        // nftables has no Windows-style Domain/Private/Public profile
        // concept -- there is exactly one host-wide ruleset, so an empty
        // list here is a true "no such concept," not a failed query (that
        // distinction lives in `inbound_rules`, via `CollectError::PolicyUnavailable`).
        Ok(Vec::new())
    }
}

fn query_inbound_rules() -> Result<Vec<RawRule>, CollectError> {
    let query = query_chains();
    let legacy = legacy_iptables_active();
    match classify_ruleset(query, legacy) {
        FirewallSource::Nftables(rules) => Ok(rules),
        FirewallSource::NoPolicySource => Err(CollectError::PolicyUnavailable(
            "no nftables policy source was reachable on this host (netlink unavailable, \
             permission denied, or a legacy iptables-only ruleset)"
                .to_owned(),
        )),
    }
}

fn query_chains() -> Result<Vec<NftChain>, RulesetQueryError> {
    let mut socket = Socket::new(NETLINK_NETFILTER).map_err(|err| classify_io_error(&err))?;
    socket.bind_auto().map_err(|err| classify_io_error(&err))?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(|err| classify_io_error(&err))?;

    let request = encode_getchain_dump_request(0);
    socket
        .send(&request, 0)
        .map_err(|err| classify_io_error(&err))?;

    let mut chains = Vec::new();
    let mut buf = [0u8; RECV_BUFFER_SIZE];
    loop {
        let received = socket
            .recv(&mut &mut buf[..], 0)
            .map_err(|err| classify_io_error(&err))?;
        let outcome = parse_nl_buffer(buf.get(..received).unwrap_or(&[]));
        chains.extend(outcome.chains);
        if let Some(err) = outcome.error {
            return Err(err);
        }
        if outcome.done {
            return Ok(chains);
        }
    }
}

fn classify_io_error(err: &std::io::Error) -> RulesetQueryError {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        RulesetQueryError::PermissionDenied
    } else {
        RulesetQueryError::Unreachable
    }
}

/// Whether this host has a legacy iptables ruleset with real content, read
/// directly from `/proc/net/{ip,ip6}_tables_names` -- never `iptables -S`/
/// `iptables-save`. A genuinely empty nftables dump on a host where this
/// is true means nftables has nothing to say because the real policy
/// lives elsewhere, not that the host allows/blocks nothing.
fn legacy_iptables_active() -> bool {
    ["/proc/net/ip_tables_names", "/proc/net/ip6_tables_names"]
        .iter()
        .any(|path| std::fs::read_to_string(path).is_ok_and(|contents| !contents.trim().is_empty()))
}
