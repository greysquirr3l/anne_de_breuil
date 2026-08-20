//! Pure `/proc/net/{tcp,tcp6,udp,udp6}` parsing — the fallback path when
//! netlink `INET_DIAG` isn't available (containers, locked-down kernels, a
//! netlink permission denial).
//!
//! No `#[cfg(target_os = "linux")]` anywhere in this file: it operates on
//! already-read text, so it compiles and its tests run on any host, exactly
//! like [`super::windows_collector::firewall_join`] does for the WMI
//! firewall path.
//!
//! # Column layout
//!
//! A `/proc/net/tcp` data line, whitespace-split, is (0-indexed):
//! `sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt
//! uid timeout inode ...`. The header row uses two words to label a single
//! `tx_queue:rx_queue`-shaped data column (and again for `tr tm->when`), so
//! its token count doesn't match a data row's — callers always skip it
//! rather than deriving offsets from it.
//!
//! # Address encoding
//!
//! `local_address`/`rem_address` are `HEXADDR:HEXPORT`. The address hex
//! encodes the raw address as the kernel's native (little-endian on
//! `x86_64`/`aarch64`) byte order, in 4-byte words — for IPv4 that's one word;
//! for IPv6 it's four, each word individually byte-swapped the same way.
//! `0100007F` therefore decodes to `127.0.0.1`: parsing the 8 hex chars as
//! a big-endian-text `u32` gives `0x0100007F`, and taking its
//! little-endian bytes gives `[0x7F, 0x00, 0x00, 0x01]`.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::application::collect::RawEndpoint;

/// The `st` value the kernel reports for a TCP socket in `LISTEN` state.
const TCP_LISTEN: &str = "0A";

/// Parses a `/proc/net/tcp`-or-`tcp6`-shaped listing, keeping only sockets
/// in `LISTEN` state.
#[must_use]
pub fn parse_proc_net_tcp(contents: &str) -> Vec<RawEndpoint> {
    contents
        .lines()
        .skip(1) // header row
        .filter_map(parse_proc_net_line)
        .collect()
}

/// Parses a `/proc/net/udp`-or-`udp6`-shaped listing.
///
/// UDP is connectionless: the kernel's `st` field for a bound UDP socket
/// doesn't carry a `LISTEN`/`ESTABLISHED` distinction that means anything
/// to a listening-port surface, so every bound socket is a real endpoint —
/// the same choice [`super::windows_collector::endpoints`] makes for
/// `netstat2`'s UDP rows.
#[must_use]
pub fn parse_proc_net_udp(contents: &str) -> Vec<RawEndpoint> {
    contents
        .lines()
        .skip(1)
        .filter_map(|line| parse_fields(line, "udp", None))
        .collect()
}

/// Parses one `/proc/net/tcp` data line, keeping it only if its state is `LISTEN`.
fn parse_proc_net_line(line: &str) -> Option<RawEndpoint> {
    parse_fields(line, "tcp", Some(TCP_LISTEN))
}

/// Shared column extraction for one `/proc/net/{tcp,udp}[6]` data line.
///
/// `want_state`, when given, is the `st` hex value the caller requires
/// (rows with any other state are dropped); `None` accepts every state.
fn parse_fields(line: &str, protocol: &str, want_state: Option<&str>) -> Option<RawEndpoint> {
    let mut fields = line.split_whitespace();
    let local = fields.nth(1)?; // sl, local_address -> local_address
    let state = fields.nth(1)?; // rem_address, st -> st
    if let Some(want) = want_state
        && !state.eq_ignore_ascii_case(want)
    {
        return None;
    }
    // Position is now just past `st` (index 3); `tx_queue:rx_queue`,
    // `tr:tm->when`, `retrnsmt`, `uid`, `timeout` are the next five
    // tokens (indices 4-8), so `inode` is index 9 -- `.nth(5)` from here.
    let inode: u64 = fields.nth(5)?.parse().ok()?;
    let (addr, port) = local.split_once(':')?;

    Some(RawEndpoint {
        protocol: protocol.to_owned(),
        local_address: decode_hex_addr(addr)?,
        local_port: u16::from_str_radix(port, 16).ok()?,
        owning_pid: inode_to_pid(inode),
    })
}

/// Decodes a `/proc/net`-style hex-encoded IPv4 or IPv6 address into its
/// textual form, honoring the kernel's per-word little-endian encoding.
fn decode_hex_addr(hex: &str) -> Option<String> {
    let words = hex.len() / 8;
    if words == 0 || !hex.len().is_multiple_of(8) {
        return None;
    }
    let mut bytes = Vec::with_capacity(words * 4);
    for chunk in hex.as_bytes().chunks(8) {
        let chunk_str = core::str::from_utf8(chunk).ok()?;
        let word = u32::from_str_radix(chunk_str, 16).ok()?;
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    match bytes.as_slice() {
        [a, b, c, d] => Some(Ipv4Addr::new(*a, *b, *c, *d).to_string()),
        full16 if full16.len() == 16 => {
            let array: [u8; 16] = full16.try_into().ok()?;
            Some(Ipv6Addr::from(array).to_string())
        }
        _ => None,
    }
}

/// Walks `/proc/*/fd`, matching `socket:[inode]` symlinks back to a PID.
///
/// Real I/O over `/proc`, but deliberately not `#[cfg(target_os = "linux")]`-gated:
/// `/proc` simply doesn't exist off Linux, so `std::fs::read_dir("/proc")`
/// fails cleanly (`None`) on any other host rather than needing a
/// compile-time gate.
fn inode_to_pid(inode: u64) -> Option<u32> {
    let target = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).is_ok_and(|l| l.to_string_lossy() == target) {
                return Some(pid);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{decode_hex_addr, parse_proc_net_tcp, parse_proc_net_udp};

    #[test]
    fn parses_listening_tcp_line() {
        let fixture = include_str!("../../../fixtures/proc_net/tcp_listen.txt");
        let endpoints = parse_proc_net_tcp(fixture);
        assert!(endpoints.iter().any(|e| e.local_port == 8080));
    }

    #[test]
    fn skips_non_listen_states() {
        let fixture = include_str!("../../../fixtures/proc_net/tcp_established_only.txt");
        assert!(parse_proc_net_tcp(fixture).is_empty());
    }

    #[test]
    fn listen_line_carries_tcp_protocol_and_wildcard_address() {
        let fixture = include_str!("../../../fixtures/proc_net/tcp_listen.txt");
        let endpoints = parse_proc_net_tcp(fixture);
        let matched = endpoints
            .iter()
            .find(|e| e.local_port == 8080)
            .expect("fixture contains a port 8080 LISTEN row");
        assert_eq!(matched.protocol, "tcp");
        assert_eq!(matched.local_address, "0.0.0.0");
    }

    #[test]
    fn udp_fixture_keeps_every_bound_socket_regardless_of_state() {
        let fixture = include_str!("../../../fixtures/proc_net/udp_bound.txt");
        let endpoints = parse_proc_net_udp(fixture);
        assert_eq!(endpoints.len(), 2);
        assert!(endpoints.iter().all(|e| e.protocol == "udp"));
    }

    #[test]
    fn decodes_loopback_ipv4() {
        assert_eq!(decode_hex_addr("0100007F").as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn decodes_ipv6_localhost() {
        // `::1`'s 16 address bytes are 15 zero bytes then `0x01`, stored as
        // four little-endian 32-bit words; only the last word is nonzero,
        // and its little-endian bytes put the `1` in the last position.
        assert_eq!(
            decode_hex_addr("00000000000000000000000001000000").as_deref(),
            Some("::1")
        );
    }

    #[test]
    fn rejects_malformed_hex_length() {
        assert_eq!(decode_hex_addr("ABC"), None);
    }
}
