//! [`BindAddress`]: a validated IP address a listener is bound to.

use std::net::IpAddr;

use crate::domain::error::DomainError;

/// A validated bind address for a listening endpoint.
///
/// Wraps [`IpAddr`] rather than reimplementing address parsing; the value
/// this newtype adds is that it can only be constructed from text that
/// actually parsed, and it carries a domain-specific error on failure.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct BindAddress(IpAddr);

impl BindAddress {
    /// Returns the underlying IP address.
    #[must_use]
    pub const fn ip(self) -> IpAddr {
        self.0
    }
}

impl core::str::FromStr for BindAddress {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.trim()
            .parse::<IpAddr>()
            .map(Self)
            .map_err(|_err| DomainError::InvalidBindAddress(s.to_owned()))
    }
}

impl core::fmt::Display for BindAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_ipv6() {
        assert_eq!(
            "127.0.0.1".parse::<BindAddress>().unwrap().ip(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            "::1".parse::<BindAddress>().unwrap().ip(),
            "::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn rejects_malformed_address() {
        assert!("not-an-ip".parse::<BindAddress>().is_err());
    }
}
