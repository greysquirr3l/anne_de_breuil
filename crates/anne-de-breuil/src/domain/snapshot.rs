//! [`ScanSnapshot`]: the complete, deterministic output of one scan.

use crate::domain::endpoint::Endpoint;
use crate::domain::firewall_rule::FirewallRule;
use crate::domain::ids::{HostId, ScanId};
use crate::domain::profile::ProfileState;
use crate::domain::target_strategy::TargetStrategy;

/// The complete, self-contained result of one scan of one host.
///
/// Every collection is sorted by a stable key at construction, so two
/// snapshots built from the same logical data — regardless of the order
/// the collector happened to enumerate it in — serialize to byte-identical
/// JSON. That property is what makes content-addressing and diffing
/// meaningful downstream.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanSnapshot {
    /// The host this snapshot describes.
    pub host_id: HostId,
    /// Unique identifier for this scan run.
    pub scan_id: ScanId,
    /// When the collector gathered this data.
    pub collected_at: time::OffsetDateTime,
    /// Version string of the collector that produced this snapshot.
    pub collector_version: String,
    /// Observed listening endpoints, sorted by protocol/address/port.
    pub endpoints: Vec<Endpoint>,
    /// Observed firewall rules, sorted by rule id.
    pub firewall_rules: Vec<FirewallRule>,
    /// Observed firewall profile states, sorted by profile kind.
    pub profiles: Vec<ProfileState>,
    /// Which collection tier produced this snapshot — a report reader must
    /// never have to guess whether a host section is authoritative or
    /// inferred. See [`TargetStrategy`].
    pub strategy: TargetStrategy,
}

impl ScanSnapshot {
    /// Builds a snapshot, sorting every collection by its stable key so
    /// construction order never affects serialized output.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "one parameter per field keeps every ScanSnapshot field explicit at every call \
                  site; a builder would let a caller construct a half-filled snapshot, which is \
                  exactly the ambiguity this type exists to rule out"
    )]
    pub fn new(
        host_id: HostId,
        scan_id: ScanId,
        collected_at: time::OffsetDateTime,
        collector_version: String,
        mut endpoints: Vec<Endpoint>,
        mut firewall_rules: Vec<FirewallRule>,
        mut profiles: Vec<ProfileState>,
        strategy: TargetStrategy,
    ) -> Self {
        endpoints.sort_by_key(Endpoint::sort_key);
        firewall_rules.sort_by_key(FirewallRule::sort_key);
        profiles.sort_by_key(ProfileState::sort_key);
        Self {
            host_id,
            scan_id,
            collected_at,
            collector_version,
            endpoints,
            firewall_rules,
            profiles,
            strategy,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;
    use std::net::{IpAddr, Ipv4Addr};

    use proptest::prelude::*;

    use super::*;
    use crate::domain::bind_address::BindAddress;
    use crate::domain::port::Port;
    use crate::domain::protocol::Protocol;
    use crate::domain::publisher::SignatureStatus;

    fn endpoint_at(protocol: Protocol, ip: IpAddr, port: u16) -> Endpoint {
        Endpoint::new(
            protocol,
            BindAddress::from_str(&ip.to_string()).unwrap(),
            Port::try_from(port).unwrap(),
            None,
            None,
            vec![],
            SignatureStatus::Unknown,
        )
    }

    fn sample_endpoints() -> Vec<Endpoint> {
        vec![
            endpoint_at(Protocol::Tcp, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443),
            endpoint_at(Protocol::Tcp, IpAddr::V4(Ipv4Addr::new(10, 0, 1, 4)), 22),
            endpoint_at(Protocol::Udp, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53),
        ]
    }

    fn build(endpoints: Vec<Endpoint>) -> ScanSnapshot {
        ScanSnapshot::new(
            HostId::generate(),
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "1.0.0".to_owned(),
            endpoints,
            vec![],
            vec![],
            TargetStrategy::LocalOnly,
        )
    }

    #[test]
    fn scan_snapshot_roundtrips() {
        let snap = build(sample_endpoints());
        let json = serde_json::to_string(&snap).unwrap();
        let back: ScanSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn scan_snapshot_deny_unknown_fields_rejects_tampered_json() {
        let snap = build(sample_endpoints());
        let mut value: serde_json::Value = serde_json::to_value(&snap).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("injected".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<ScanSnapshot>(value).is_err());
    }

    #[test]
    fn scan_snapshot_is_order_independent() {
        let host_id = HostId::generate();
        let scan_id = ScanId::generate();
        let collected_at = time::OffsetDateTime::UNIX_EPOCH;

        let mut shuffled = sample_endpoints();
        shuffled.reverse();

        let a = ScanSnapshot::new(
            host_id,
            scan_id,
            collected_at,
            "1.0.0".to_owned(),
            sample_endpoints(),
            vec![],
            vec![],
            TargetStrategy::LocalOnly,
        );
        let b = ScanSnapshot::new(
            host_id,
            scan_id,
            collected_at,
            "1.0.0".to_owned(),
            shuffled,
            vec![],
            vec![],
            TargetStrategy::LocalOnly,
        );

        assert_eq!(
            serde_json::to_vec(&a).unwrap(),
            serde_json::to_vec(&b).unwrap()
        );
    }

    proptest! {
        #[test]
        fn snapshot_roundtrips_for_arbitrary_endpoint_sets(
            entries in prop::collection::vec((any::<bool>(), any::<u8>(), 1u16..=65535), 0..12),
        ) {
            let endpoints: Vec<Endpoint> = entries
                .into_iter()
                .map(|(is_tcp, last_octet, port)| {
                    let protocol = if is_tcp { Protocol::Tcp } else { Protocol::Udp };
                    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet));
                    endpoint_at(protocol, ip, port)
                })
                .collect();

            let snap = build(endpoints);
            let json = serde_json::to_string(&snap).unwrap();
            let back: ScanSnapshot = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(snap, back);
        }
    }
}
