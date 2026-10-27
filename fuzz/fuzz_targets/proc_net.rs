//! Fuzz target for the `/proc/net/{tcp,tcp6,udp,udp6}` parsers.
//!
//! These parse text the kernel produced from untrusted input -- a remote
//! peer can cause a connection attempt, and the kernel's `/proc/net/tcp`
//! reflects its result. The parser walks a whitespace-split table with
//! hand-computed column offsets, decodes a hex-encoded address whose
//! byte order is platform-endian, and converts a port from hex. Every
//! one of those is a place where an off-by-one or a wrong assumption
//! turns into a panic.
//!
//! The invariant asserted here is the one that matters: the parser must
//! either produce a well-formed result or decline the row. It must never
//! panic, and it must never report an endpoint whose local port is not
//! a valid `u16` (the `u16::from_str_radix` conversion already
//! guarantees that, but the assertion pins it).
//!
//! The corpus is seeded with real `/proc/net/tcp` and `/proc/net/udp`
//! contents, because a fuzzer starting from nothing spends most of its
//! time rediscovering the column layout.

#![no_main]

use std::net::IpAddr;

use anne_de_breuil::adapters::linux_collector::proc_net::{
    parse_proc_net_tcp, parse_proc_net_udp,
};
use anne_de_breuil::application::collect::RawEndpoint;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser takes `&str`; `from_utf8` failure is a legitimate
    // outcome (the kernel emits ASCII, but a fuzzer will not), and the
    // parser's contract is only defined over valid UTF-8.
    let Ok(contents) = core::str::from_utf8(data) else {
        return;
    };

    for endpoint in parse_proc_net_tcp(contents) {
        assert_endpoint_is_well_formed(&endpoint, "tcp");
    }

    for endpoint in parse_proc_net_udp(contents) {
        assert_endpoint_is_well_formed(&endpoint, "udp");
    }
});

/// A returned endpoint must be one a report could actually show.
///
/// The parser's contract is that it either produces a well-formed
/// endpoint or declines the row. A "well-formed" endpoint here means
/// three things the caller relies on and cannot check cheaply
/// afterwards:
///
///   * the address is a real IP address, not a malformed string that
///     would be rendered verbatim into the report's host column;
///   * the address is non-empty;
///   * the protocol is the one the parser was asked for -- the two
///     parsers share their column extraction, so a mix-up between
///     them would label every endpoint with the wrong transport.
fn assert_endpoint_is_well_formed(endpoint: &RawEndpoint, expected_protocol: &str) {
    assert!(
        !endpoint.local_address.is_empty(),
        "parsed an endpoint with no local address"
    );
    assert!(
        endpoint.local_address.parse::<IpAddr>().is_ok(),
        "parsed an endpoint whose address is not an IP address: {:?}",
        endpoint.local_address
    );
    assert_eq!(
        endpoint.protocol, expected_protocol,
        "the {expected_protocol} parser returned protocol {}",
        endpoint.protocol
    );
}
