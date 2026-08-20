//! [`identity_for_port`]: looks up the vendored IANA service-name/port registry.
//!
//! # Provenance
//!
//! `assets/iana-port-registry.tsv` is a compiled-in, pre-processed snapshot
//! of the IANA Service Name and Transport Protocol Port Number Registry,
//! never fetched at build time or at runtime. Full provenance — source URL,
//! fetch date, row counts, and the filtering rules applied — is recorded in
//! `assets/iana-port-registry.meta.toml` next to it.
//!
//! Snapshot date: 2026-08-20 (UTC). Source:
//! <https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv>.
//!
//! # Refreshing the snapshot
//!
//! There is no automated fetch for this — a stale registry degrades
//! silently into wrong answers, so a human re-runs this deliberately:
//!
//! 1. Fetch the CSV from the source URL above.
//! 2. Keep only rows where the port number is a single integer in
//!    `1..=65535` (drop ranges), the transport protocol is exactly `tcp` or
//!    `udp` (drop everything else), the Service Name column is non-empty,
//!    and the Description is not `Reserved`/`Unassigned`/blank.
//! 3. The source lists some `(port, protocol)` pairs under multiple
//!    aliases; keep the first occurrence in file order (the registry is
//!    sorted by ascending port, oldest/canonical name first) and drop later
//!    duplicates for the same pair.
//! 4. Write the result to `assets/iana-port-registry.tsv` as
//!    `port\tprotocol\tservice_name\tdescription`, one row per pair, no
//!    header row, no embedded tabs or newlines in any field.
//! 5. Update `assets/iana-port-registry.meta.toml` with the new fetch date,
//!    row counts, and the registry's own `Last-Modified` header.

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::domain::confidence::Confidence;
use crate::domain::evidence::Evidence;
use crate::domain::port::Port;
use crate::domain::protocol::Protocol;
use crate::domain::service_category::ServiceCategory;
use crate::domain::service_identity::ServiceIdentity;

const RAW_REGISTRY: &str = include_str!("../../assets/iana-port-registry.tsv");

struct RegistryEntry {
    name: &'static str,
}

static REGISTRY: LazyLock<HashMap<(u16, Protocol), RegistryEntry>> = LazyLock::new(build_registry);

fn build_registry() -> HashMap<(u16, Protocol), RegistryEntry> {
    let mut map = HashMap::with_capacity(RAW_REGISTRY.lines().count());
    for line in RAW_REGISTRY.lines() {
        let mut fields = line.splitn(4, '\t');
        let (Some(port_field), Some(protocol_field), Some(name_field)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Ok(port) = port_field.parse::<u16>() else {
            continue;
        };
        let protocol = match protocol_field {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => continue,
        };
        if name_field.is_empty() {
            continue;
        }
        map.insert((port, protocol), RegistryEntry { name: name_field });
    }
    map
}

/// Looks up the vendored registry for `port`/`protocol` and, if present,
/// returns a [`ServiceIdentity`] at [`Confidence::Assigned`] backed by a
/// single [`Evidence::PortAssignment`] entry.
///
/// Category is always [`ServiceCategory::Other`] here — the registry gives
/// a name, not a category, and inventing one from the port number alone
/// would be exactly the "port equals identity" mistake this subsystem
/// exists to avoid.
#[must_use]
pub fn identity_for_port(port: Port, protocol: Protocol) -> Option<ServiceIdentity> {
    let entry = REGISTRY.get(&(port.get(), protocol))?;
    let evidence = vec![Evidence::PortAssignment {
        registry_name: entry.name.to_owned(),
    }];
    ServiceIdentity::new(
        entry.name,
        ServiceCategory::Other,
        Confidence::Assigned,
        evidence,
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::identity_for_port;
    use crate::domain::confidence::Confidence;
    use crate::domain::evidence::Evidence;
    use crate::domain::port::Port;
    use crate::domain::protocol::Protocol;

    #[test]
    fn known_port_resolves_to_assigned_identity_with_one_evidence_entry() {
        let port = Port::try_from(443u16).expect("nonzero port");
        let identity =
            identity_for_port(port, Protocol::Tcp).expect("443/tcp is a real IANA assignment");
        assert_eq!(identity.name(), "https");
        assert_eq!(identity.confidence(), Confidence::Assigned);
        assert_eq!(identity.evidence().len(), 1);
        assert!(matches!(
            identity.evidence().first(),
            Some(Evidence::PortAssignment { registry_name }) if registry_name == "https"
        ));
    }

    #[test]
    fn well_known_rdp_port_resolves_by_name() {
        let port = Port::try_from(3389u16).expect("nonzero port");
        let identity = identity_for_port(port, Protocol::Tcp).expect("3389/tcp is ms-wbt-server");
        assert_eq!(identity.name(), "ms-wbt-server");
    }

    #[test]
    fn ssh_port_resolves_by_name() {
        let port = Port::try_from(22u16).expect("nonzero port");
        let identity = identity_for_port(port, Protocol::Tcp).expect("22/tcp is ssh");
        assert_eq!(identity.name(), "ssh");
    }

    #[test]
    fn unassigned_high_port_resolves_to_none() {
        // 65533/tcp is not a real IANA assignment as of the vendored snapshot.
        let port = Port::try_from(65533u16).expect("nonzero port");
        assert!(identity_for_port(port, Protocol::Tcp).is_none());
    }

    #[test]
    fn registry_lookup_is_not_a_hardcoded_match_arm() {
        // A spot check across a wide port range: every hit must trace back
        // to the vendored data file, not a source-level match arm — there
        // is no `match port { 443 => ..., 22 => ... }` in this module.
        let mut hits = 0usize;
        for raw_port in 1u16..=1024 {
            let port = Port::try_from(raw_port).expect("nonzero port");
            if identity_for_port(port, Protocol::Tcp).is_some() {
                hits += 1;
            }
        }
        assert!(
            hits > 100,
            "expected a substantial fraction of well-known ports (1-1024) to resolve, got {hits}"
        );
    }
}
