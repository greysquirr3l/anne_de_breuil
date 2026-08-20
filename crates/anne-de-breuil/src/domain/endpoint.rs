//! [`Endpoint`]: one observed listening socket, correlated with its owner.

use std::net::IpAddr;

use crate::domain::bind_address::BindAddress;
use crate::domain::exposure::Exposure;
use crate::domain::ids::ProcessId;
use crate::domain::port::Port;
use crate::domain::process::ProcessPath;
use crate::domain::protocol::Protocol;
use crate::domain::publisher::SignatureStatus;
use crate::domain::service::ServiceName;

/// One listening endpoint observed on a host, correlated with its owning
/// process, the services it hosts, and its binary's signature status.
///
/// `exposure` is always derived from `bind_address` at construction — it is
/// never set independently, so it can never drift out of sync with the
/// address it describes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// Transport protocol the socket is bound with.
    pub protocol: Protocol,
    /// Address the socket is bound to.
    pub bind_address: BindAddress,
    /// Port the socket is bound to.
    pub port: Port,
    /// Owning process id, if the collector could resolve one.
    pub process_id: Option<ProcessId>,
    /// Owning process executable path, if the collector could resolve one.
    /// May be the `System` pseudo-path for kernel-owned sockets.
    pub process_path: Option<ProcessPath>,
    /// Services hosted behind this endpoint, sorted for deterministic output.
    pub hosted_services: Vec<ServiceName>,
    /// Code-signing status of the owning binary.
    pub signature_status: SignatureStatus,
    /// Reachability exposure, derived from `bind_address`.
    pub exposure: Exposure,
}

impl Endpoint {
    /// Builds an endpoint, deriving `exposure` from `bind_address` and
    /// sorting `hosted_services` so that two endpoints observed with the
    /// same services in a different collection order compare and serialize
    /// identically.
    #[must_use]
    pub fn new(
        protocol: Protocol,
        bind_address: BindAddress,
        port: Port,
        process_id: Option<ProcessId>,
        process_path: Option<ProcessPath>,
        mut hosted_services: Vec<ServiceName>,
        signature_status: SignatureStatus,
    ) -> Self {
        hosted_services.sort();
        let exposure = Exposure::classify(bind_address.ip());
        Self {
            protocol,
            bind_address,
            port,
            process_id,
            process_path,
            hosted_services,
            signature_status,
            exposure,
        }
    }

    /// A stable sort key for deterministic snapshot serialization.
    #[must_use]
    pub const fn sort_key(&self) -> (Protocol, IpAddr, u16) {
        (self.protocol, self.bind_address.ip(), self.port.get())
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;

    use super::*;

    fn endpoint_on(port: u16) -> Endpoint {
        Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").unwrap(),
            Port::try_from(port).unwrap(),
            None,
            None,
            vec![],
            SignatureStatus::Unknown,
        )
    }

    #[test]
    fn exposure_is_derived_from_bind_address() {
        let loopback = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("127.0.0.1").unwrap(),
            Port::try_from(8080u16).unwrap(),
            None,
            None,
            vec![],
            SignatureStatus::Unknown,
        );
        assert_eq!(loopback.exposure, Exposure::Loopback);

        let wildcard = endpoint_on(443);
        assert_eq!(wildcard.exposure, Exposure::AllInterfaces);
    }

    #[test]
    fn hosted_services_are_sorted_at_construction() {
        let shuffled = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").unwrap(),
            Port::try_from(443u16).unwrap(),
            None,
            None,
            vec![
                ServiceName::try_from("W32Time".to_owned()).unwrap(),
                ServiceName::try_from("Dnscache".to_owned()).unwrap(),
            ],
            SignatureStatus::Unknown,
        );
        assert_eq!(shuffled.hosted_services[0].as_str(), "Dnscache");
        assert_eq!(shuffled.hosted_services[1].as_str(), "W32Time");
    }

    #[test]
    fn sort_key_orders_by_protocol_then_address_then_port() {
        let a = endpoint_on(80);
        let b = endpoint_on(443);
        assert!(a.sort_key() < b.sort_key());
    }
}
