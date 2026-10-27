//! Fuzz target for the hand-rolled nftables netlink decoder.
//!
//! `nft_wire` parses raw `NETLINK_NETFILTER` response bytes: a stream
//! of `nlmsghdr`-framed messages, each with a declared length, a message
//! type, and a payload of TLV attributes in nftables' own encoding. The
//! decoder walks that framing by hand -- reading lengths out of the
//! buffer, computing offsets, slicing payloads -- which is exactly the
//! shape of code where a crafted response causes an out-of-bounds slice,
//! an integer overflow on `offset + len`, or an infinite loop when a
//! message declares a length of zero.
//!
//! This is not hypothetical: the buffer comes from a netlink socket, and
//! the firewall policy of a compromised or merely unusual host is
//! attacker-influenced data that the collector reads and parses.
//!
//! The invariant: parsing any byte string must terminate and must not
//! panic. A malformed message is skipped, not fatal.

#![no_main]

use anne_de_breuil::adapters::linux_collector::nft_wire::parse_nl_buffer;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let outcome = parse_nl_buffer(data);

    // A decoded chain's name and table are either absent or non-empty.
    // They are `Option<String>` because the attribute that carries them
    // may legitimately be missing -- and an attribute that is present
    // but empty decodes to `None` rather than to `Some("")`, so that
    // the caller's "?" substitution for an unknown name actually
    // applies. This assertion is what caught that.
    for chain in &outcome.chains {
        assert!(
            chain.name.as_ref().is_none_or(|name| !name.is_empty()),
            "decoded an nftables chain with an empty name"
        );
        assert!(
            chain.table.as_ref().is_none_or(|table| !table.is_empty()),
            "decoded an nftables chain with an empty table"
        );
    }

    // `done` and `error` are set together: a terminal message either
    // was `NLMSG_DONE` (no error) or was `NLMSG_ERROR` (an error). A
    // `done` flag with an error present means the decoder reported
    // "finished" and "failed" at once, which is a state the caller
    // cannot act on correctly.
    if outcome.error.is_some() {
        assert!(
            outcome.done,
            "an nftables buffer reported an error without a terminal message"
        );
    }
});
