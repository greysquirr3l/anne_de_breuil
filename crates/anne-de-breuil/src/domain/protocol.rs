//! [`Protocol`]: the transport protocol a listening endpoint or firewall rule covers.

use crate::domain::error::DomainError;

/// A transport-layer protocol.
///
/// Every listening endpoint this tool observes is concretely TCP or UDP —
/// there is no "any" variant here because a real bound socket always has
/// one of these two.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

impl core::str::FromStr for Protocol {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("tcp") {
            Ok(Self::Tcp)
        } else if trimmed.eq_ignore_ascii_case("udp") {
            Ok(Self::Udp)
        } else {
            Err(DomainError::InvalidProtocol(s.to_owned()))
        }
    }
}

impl core::fmt::Display for Protocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tcp => f.write_str("TCP"),
            Self::Udp => f.write_str("UDP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_case_insensitively() {
        assert_eq!("tcp".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("UDP".parse::<Protocol>().unwrap(), Protocol::Udp);
    }

    #[test]
    fn rejects_unknown_protocol() {
        assert!("sctp".parse::<Protocol>().is_err());
    }
}
