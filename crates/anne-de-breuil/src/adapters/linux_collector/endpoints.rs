//! [`LinuxEndpointSource`]: listening TCP/UDP sockets, preferring netlink
//! `INET_DIAG` via `netstat2` (the same crate [`super::super::windows_collector`]
//! uses for Windows -- it's genuinely cross-platform) and falling back to
//! parsing `/proc/net/{tcp,tcp6,udp,udp6}` when the netlink query itself
//! fails: containers without `CAP_NET_ADMIN`, locked-down kernels, or a
//! netlink socket the sandbox refuses to open.

use async_trait::async_trait;
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, get_sockets_info};

use super::proc_net::{parse_proc_net_tcp, parse_proc_net_udp};
use crate::application::collect::{CollectError, EndpointSource, RawEndpoint};

/// Lists listening TCP sockets and bound UDP sockets, netlink first.
#[derive(Debug, Default)]
pub struct LinuxEndpointSource;

impl LinuxEndpointSource {
    /// Builds a source with no state to initialize -- every call queries fresh.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl EndpointSource for LinuxEndpointSource {
    async fn listening_endpoints(&self) -> Result<Vec<RawEndpoint>, CollectError> {
        tokio::task::spawn_blocking(collect_sockets)
            .await
            .map_err(|source| CollectError::Spawn(source.to_string()))?
    }
}

fn collect_sockets() -> Result<Vec<RawEndpoint>, CollectError> {
    match collect_via_netlink() {
        Ok(endpoints) => Ok(endpoints),
        Err(_netlink_unavailable) => collect_via_proc_net(),
    }
}

fn collect_via_netlink() -> Result<Vec<RawEndpoint>, CollectError> {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets = get_sockets_info(af_flags, proto_flags)
        .map_err(|source| CollectError::Parse(source.to_string()))?;

    Ok(sockets
        .into_iter()
        .filter_map(|socket| {
            let owning_pid = socket.associated_pids.first().copied();
            match socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) if tcp.state == TcpState::Listen => {
                    Some(RawEndpoint {
                        protocol: "tcp".to_owned(),
                        local_address: tcp.local_addr.to_string(),
                        local_port: tcp.local_port,
                        owning_pid,
                    })
                }
                ProtocolSocketInfo::Tcp(_) => None,
                ProtocolSocketInfo::Udp(udp) => Some(RawEndpoint {
                    protocol: "udp".to_owned(),
                    local_address: udp.local_addr.to_string(),
                    local_port: udp.local_port,
                    owning_pid,
                }),
            }
        })
        .collect())
}

type ProcNetParser = fn(&str) -> Vec<RawEndpoint>;

const FALLBACK_SOURCES: [(&str, ProcNetParser); 4] = [
    ("/proc/net/tcp", parse_proc_net_tcp),
    ("/proc/net/tcp6", parse_proc_net_tcp),
    ("/proc/net/udp", parse_proc_net_udp),
    ("/proc/net/udp6", parse_proc_net_udp),
];

/// Reads `/proc/net/{tcp,tcp6,udp,udp6}` directly. A missing file (no IPv6
/// support, `udp6` absent in a container) contributes nothing and is not
/// an error; if none of the four could be read at all, that's reported as
/// a real failure rather than a false "this host has zero listening
/// sockets."
fn collect_via_proc_net() -> Result<Vec<RawEndpoint>, CollectError> {
    let mut endpoints = Vec::new();
    let mut any_readable = false;
    for (path, parser) in FALLBACK_SOURCES {
        if let Ok(contents) = std::fs::read_to_string(path) {
            any_readable = true;
            endpoints.extend(parser(&contents));
        }
    }
    if any_readable {
        Ok(endpoints)
    } else {
        Err(CollectError::Parse(
            "neither netlink INET_DIAG nor any /proc/net/{tcp,tcp6,udp,udp6} file was readable"
                .to_owned(),
        ))
    }
}
