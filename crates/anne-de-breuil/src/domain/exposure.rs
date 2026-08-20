//! [`Exposure`]: how far a bound address reaches, derived purely from the address.

use std::net::IpAddr;

/// Classification of how broadly a bind address exposes a listener.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Exposure {
    /// Bound to a loopback address; reachable only from the same host.
    Loopback,
    /// Bound to one concrete, non-loopback interface address.
    SpecificInterface,
    /// Bound to the unspecified address (`0.0.0.0` or `::`); reachable on every interface.
    AllInterfaces,
}

impl Exposure {
    /// Derives the exposure classification of a bind address.
    ///
    /// Pure function of the address alone: loopback beats unspecified beats
    /// everything else, matching how an OS actually resolves a listening
    /// socket's reachability.
    #[must_use]
    pub const fn classify(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(v4) if v4.is_loopback() => Self::Loopback,
            IpAddr::V6(v6) if v6.is_loopback() => Self::Loopback,
            IpAddr::V4(v4) if v4.is_unspecified() => Self::AllInterfaces,
            IpAddr::V6(v6) if v6.is_unspecified() => Self::AllInterfaces,
            _ => Self::SpecificInterface,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_loopback_and_wildcard() {
        assert_eq!(
            Exposure::classify("127.0.0.1".parse().unwrap()),
            Exposure::Loopback
        );
        assert_eq!(
            Exposure::classify("::1".parse().unwrap()),
            Exposure::Loopback
        );
        assert_eq!(
            Exposure::classify("0.0.0.0".parse().unwrap()),
            Exposure::AllInterfaces
        );
        assert_eq!(
            Exposure::classify("::".parse().unwrap()),
            Exposure::AllInterfaces
        );
        assert_eq!(
            Exposure::classify("10.0.1.4".parse().unwrap()),
            Exposure::SpecificInterface
        );
    }
}
