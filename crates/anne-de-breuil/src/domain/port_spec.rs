//! [`PortSpec`]: the firewall local-port grammar — any, a number, a range,
//! a comma list, or a dynamic keyword.

use crate::domain::error::DomainError;
use crate::domain::port::Port;

/// A parsed firewall local-port specification.
///
/// Firewall rules express local ports far more richly than a single number:
/// `Any`, a bare number, an inclusive range like `5000-5010`, a comma list
/// of any of those, or a platform keyword whose resolved port range is
/// dynamic and cannot be known statically (`RPC`, `IPHTTPSIn`, ...). This
/// grammar is parsed once, here, so nothing downstream re-parses raw rule
/// text.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PortSpec {
    /// Matches every port.
    Any,
    /// Matches exactly one port.
    Single(Port),
    /// Matches every port in an inclusive range.
    Range(PortRange),
    /// Matches if any member spec matches.
    List(Vec<Self>),
    /// A platform keyword whose concrete port range is resolved dynamically
    /// at runtime and cannot be statically known from the rule alone.
    Dynamic(DynamicKeyword),
}

impl PortSpec {
    /// Reports whether this spec covers `port`.
    ///
    /// A [`DynamicKeyword`] spec always reports `true`: its concrete range
    /// cannot be statically excluded, so callers that need to distinguish
    /// "definitely matches" from "might match" should check for
    /// [`PortSpec::Dynamic`] separately rather than trusting a `false` here
    /// that never happens.
    #[must_use]
    pub fn matches(&self, port: Port) -> bool {
        match self {
            Self::Single(p) => *p == port,
            Self::Range(range) => range.contains(port),
            Self::List(specs) => specs.iter().any(|spec| spec.matches(port)),
            Self::Any | Self::Dynamic(_) => true,
        }
    }
}

impl core::str::FromStr for PortSpec {
    type Err = DomainError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let s = input.trim();
        if s.is_empty() {
            return Err(DomainError::MalformedPortSpec(input.to_owned()));
        }
        if s == "*" || s.eq_ignore_ascii_case("any") {
            return Ok(Self::Any);
        }
        if s.contains(',') {
            return s
                .split(',')
                .map(|part| part.trim().parse())
                .collect::<Result<Vec<_>, _>>()
                .map(Self::List);
        }
        if let Some((start, end)) = s.split_once('-') {
            return parse_range(start, end, s);
        }
        if let Some(keyword) = DynamicKeyword::from_name(s) {
            return Ok(Self::Dynamic(keyword));
        }
        let value: u16 = s
            .parse()
            .map_err(|_err| DomainError::MalformedPortSpec(s.to_owned()))?;
        Port::try_from(value).map(Self::Single)
    }
}

fn parse_range(start: &str, end: &str, original: &str) -> Result<PortSpec, DomainError> {
    let start: u16 = start
        .trim()
        .parse()
        .map_err(|_err| DomainError::MalformedPortSpec(original.to_owned()))?;
    let end: u16 = end
        .trim()
        .parse()
        .map_err(|_err| DomainError::MalformedPortSpec(original.to_owned()))?;
    PortRange::try_from((start, end)).map(PortSpec::Range)
}

/// An inclusive, validated port range (`start..=end`, both bounds nonzero, `start <= end`).
///
/// Backed by [`core::range::Range`] for its `Copy` storage — the legacy
/// `std::ops::Range` deliberately isn't `Copy`, which invites defensive
/// clones throughout matching code for no benefit on an 8-byte pair of
/// `u16`s. `serde` has no impl for `core::range::Range`, so this type
/// carries its own `Serialize`/`Deserialize` as an inclusive `{start, end}`
/// pair rather than the half-open bounds that type's own `RangeBounds`
/// impl would imply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortRange(core::range::Range<u16>);

impl PortRange {
    /// The inclusive lower bound.
    #[must_use]
    pub const fn start(self) -> u16 {
        self.0.start
    }

    /// The inclusive upper bound.
    #[must_use]
    pub const fn end(self) -> u16 {
        self.0.end
    }

    /// Reports whether `port` falls within `start..=end`.
    #[must_use]
    pub const fn contains(self, port: Port) -> bool {
        let value = port.get();
        self.0.start <= value && value <= self.0.end
    }
}

impl TryFrom<(u16, u16)> for PortRange {
    type Error = DomainError;

    fn try_from((start, end): (u16, u16)) -> Result<Self, Self::Error> {
        if start == 0 || end == 0 || start > end {
            return Err(DomainError::MalformedPortSpec(format!("{start}-{end}")));
        }
        Ok(Self(core::range::Range { start, end }))
    }
}

impl serde::Serialize for PortRange {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(serde::Serialize)]
        struct Repr {
            start: u16,
            end: u16,
        }
        Repr {
            start: self.0.start,
            end: self.0.end,
        }
        .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for PortRange {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Repr {
            start: u16,
            end: u16,
        }
        let Repr { start, end } = Repr::deserialize(deserializer)?;
        Self::try_from((start, end)).map_err(serde::de::Error::custom)
    }
}

/// A firewall keyword whose concrete port range is resolved dynamically by
/// the platform at runtime rather than fixed in the rule text.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum DynamicKeyword {
    /// Remote Procedure Call endpoint mapper range.
    Rpc,
    /// The RPC endpoint mapper itself (port 135).
    RpcEpMap,
    /// IP-HTTPS tunnelling inbound.
    IpHttpsIn,
    /// Multicast DNS.
    Mdns,
    /// Teredo IPv6 transition tunnelling.
    Teredo,
    /// Play To (DLNA/UPnP media) discovery.
    PlayToDiscovery,
}

impl DynamicKeyword {
    /// Parses a platform keyword name, case-insensitively.
    ///
    /// Returns `None` rather than a default variant for anything that
    /// isn't one of the known keywords — the caller falls through to
    /// numeric parsing.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "rpc" => Some(Self::Rpc),
            "rpcepmap" => Some(Self::RpcEpMap),
            "iphttpsin" => Some(Self::IpHttpsIn),
            "mdns" => Some(Self::Mdns),
            "teredo" => Some(Self::Teredo),
            "playtodiscovery" => Some(Self::PlayToDiscovery),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portspec_parses_any() {
        assert_eq!("*".parse::<PortSpec>().unwrap(), PortSpec::Any);
        assert_eq!("Any".parse::<PortSpec>().unwrap(), PortSpec::Any);
    }

    #[test]
    fn portspec_parses_single_port() {
        assert_eq!(
            "443".parse::<PortSpec>().unwrap(),
            PortSpec::Single(Port::try_from(443u16).unwrap())
        );
    }

    #[test]
    fn portspec_parses_range() {
        let spec: PortSpec = "5000-5010".parse().unwrap();
        let PortSpec::Range(range) = spec else {
            panic!("expected Range variant")
        };
        assert_eq!(range.start(), 5000);
        assert_eq!(range.end(), 5010);
        assert!(range.contains(Port::try_from(5005u16).unwrap()));
        assert!(!range.contains(Port::try_from(4999u16).unwrap()));
        assert!(!range.contains(Port::try_from(5011u16).unwrap()));
    }

    #[test]
    fn portspec_rejects_inverted_range() {
        assert!("100-50".parse::<PortSpec>().is_err());
    }

    #[test]
    fn portspec_parses_comma_list() {
        let spec: PortSpec = "80,443,5000-5010".parse().unwrap();
        let PortSpec::List(items) = spec else {
            panic!("expected List variant")
        };
        assert_eq!(items.len(), 3);
    }

    #[test]
    fn portspec_parses_each_dynamic_keyword() {
        for (name, expected) in [
            ("RPC", DynamicKeyword::Rpc),
            ("RPCEPMap", DynamicKeyword::RpcEpMap),
            ("IPHTTPSIn", DynamicKeyword::IpHttpsIn),
            ("mDNS", DynamicKeyword::Mdns),
            ("Teredo", DynamicKeyword::Teredo),
            ("PlayToDiscovery", DynamicKeyword::PlayToDiscovery),
        ] {
            let spec: PortSpec = name.parse().unwrap();
            assert_eq!(spec, PortSpec::Dynamic(expected), "keyword {name}");
        }
    }

    #[test]
    fn portspec_dynamic_keyword_is_distinct_variant() {
        let spec: PortSpec = "RPC".parse().unwrap();
        assert!(matches!(spec, PortSpec::Dynamic(DynamicKeyword::Rpc)));
    }

    #[test]
    fn portspec_rejects_malformed() {
        assert!("not-a-port".parse::<PortSpec>().is_err());
        assert!("".parse::<PortSpec>().is_err());
        assert!("70000".parse::<PortSpec>().is_err());
    }

    #[test]
    fn dynamic_spec_always_reports_a_match() {
        let spec = PortSpec::Dynamic(DynamicKeyword::Rpc);
        assert!(spec.matches(Port::try_from(49666u16).unwrap()));
    }

    #[test]
    fn port_range_roundtrips_through_json() {
        let range = PortRange::try_from((5000u16, 5010u16)).unwrap();
        let json = serde_json::to_string(&range).unwrap();
        let back: PortRange = serde_json::from_str(&json).unwrap();
        assert_eq!(range, back);
    }

    #[test]
    fn port_range_rejects_zero_bounds() {
        assert!(PortRange::try_from((0u16, 10u16)).is_err());
        assert!(PortRange::try_from((10u16, 0u16)).is_err());
    }
}
