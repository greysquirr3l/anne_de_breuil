//! [`NetstatEndpointSource`]: listening TCP/UDP sockets via `netstat2`.
//!
//! `netstat2` wraps `GetExtendedTcpTable`/`GetExtendedUdpTable` and returns
//! the owning pid directly (`associated_pids`), so this file needs no
//! `unsafe` of its own — this task's own fallback clause ("drop to the
//! `windows` crate only if `netstat2` cannot supply an owning PID") never
//! triggers here.

use async_trait::async_trait;
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, get_sockets_info};

use crate::application::collect::{CollectError, EndpointSource, RawEndpoint};

/// Lists listening TCP sockets and bound UDP sockets through `netstat2`.
#[derive(Debug, Default)]
pub struct NetstatEndpointSource;

impl NetstatEndpointSource {
    /// Builds a source with no state to initialize — `netstat2` queries
    /// the OS fresh on every call.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl EndpointSource for NetstatEndpointSource {
    async fn listening_endpoints(&self) -> Result<Vec<RawEndpoint>, CollectError> {
        // `get_sockets_info` is a blocking syscall; running it on a
        // blocking-pool thread keeps it off the async runtime's workers.
        tokio::task::spawn_blocking(collect_sockets)
            .await
            .map_err(|source| CollectError::Spawn(source.to_string()))?
    }
}

fn collect_sockets() -> Result<Vec<RawEndpoint>, CollectError> {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets = get_sockets_info(af_flags, proto_flags)
        .map_err(|source| CollectError::Parse(source.to_string()))?;

    Ok(sockets
        .into_iter()
        .filter_map(|socket| {
            let owning_pid = socket.associated_pids.first().copied();
            match socket.protocol_socket_info {
                // Only `Listen` sockets are a listening-port surface;
                // established/closing connections aren't a bound endpoint.
                ProtocolSocketInfo::Tcp(tcp) if tcp.state == TcpState::Listen => {
                    Some(RawEndpoint {
                        protocol: "tcp".to_owned(),
                        local_address: tcp.local_addr.to_string(),
                        local_port: tcp.local_port,
                        owning_pid,
                    })
                }
                ProtocolSocketInfo::Tcp(_) => None,
                // UDP has no listen/connected distinction at this layer —
                // every bound UDP socket netstat2 reports is a real
                // endpoint on the host's exposed surface.
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
