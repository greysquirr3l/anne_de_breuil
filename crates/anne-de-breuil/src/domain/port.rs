//! [`Port`]: a validated, nonzero TCP/UDP port number.

use crate::domain::error::DomainError;

/// A validated port number in the range `1..=65535`.
///
/// Zero is "any port" territory in most APIs, not a real bind target, so it
/// is rejected at construction.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct Port(u16);

impl Port {
    /// Returns the underlying port number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for Port {
    type Error = DomainError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if value == 0 {
            return Err(DomainError::InvalidPort(value));
        }
        Ok(Self(value))
    }
}

impl core::str::FromStr for Port {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value: u16 = s
            .trim()
            .parse()
            .map_err(|_err| DomainError::MalformedPortSpec(s.to_owned()))?;
        Self::try_from(value)
    }
}

impl core::fmt::Display for Port {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero() {
        assert!(Port::try_from(0u16).is_err());
    }

    #[test]
    fn accepts_nonzero() {
        assert_eq!(Port::try_from(443u16).unwrap().get(), 443);
    }

    #[test]
    fn parses_from_str() {
        assert_eq!("8080".parse::<Port>().unwrap().get(), 8080);
    }

    #[test]
    fn rejects_out_of_range_from_str() {
        assert!("70000".parse::<Port>().is_err());
    }
}
