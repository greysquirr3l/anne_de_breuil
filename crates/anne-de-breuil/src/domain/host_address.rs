//! [`HostAddress`]: a validated hostname or IP address for an inventory host.

use std::net::IpAddr;

use crate::domain::error::DomainError;

/// A validated remote host address: either an IP address or a hostname.
///
/// Unlike [`crate::domain::BindAddress`], which only ever wraps an
/// already-parsed [`IpAddr`], an inventory entry legitimately names a host
/// by DNS name as often as by IP — resolution happens at connect time, not
/// here. What this type guarantees is narrower: the text is non-empty and
/// contains nothing outside the character set an IP address or a
/// [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123) hostname label can
/// ever legitimately contain, so a malformed inventory entry is rejected at
/// parse time rather than reaching a connection string later.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "String")]
pub struct HostAddress(String);

impl HostAddress {
    /// Returns the address as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for HostAddress {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(DomainError::InvalidHostAddress(value));
        }
        if trimmed.parse::<IpAddr>().is_ok() || is_valid_hostname(trimmed) {
            return Ok(Self(trimmed.to_owned()));
        }
        Err(DomainError::InvalidHostAddress(value))
    }
}

impl core::str::FromStr for HostAddress {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl core::fmt::Display for HostAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Checks a candidate against a pragmatic subset of RFC 1123: dot-separated
/// labels of 1-63 ASCII alphanumerics/hyphens/underscores, never starting
/// or ending a label with a hyphen, whole name at most 253 characters.
fn is_valid_hostname(candidate: &str) -> bool {
    candidate.len() <= 253 && candidate.split('.').all(is_valid_hostname_label)
}

fn is_valid_hostname_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ipv4_and_ipv6() {
        assert_eq!(
            HostAddress::try_from("10.0.0.5".to_owned())
                .unwrap()
                .as_str(),
            "10.0.0.5"
        );
        assert_eq!(
            HostAddress::try_from("::1".to_owned()).unwrap().as_str(),
            "::1"
        );
    }

    #[test]
    fn accepts_hostnames() {
        assert_eq!(
            HostAddress::try_from("bastion.internal".to_owned())
                .unwrap()
                .as_str(),
            "bastion.internal"
        );
        assert_eq!(
            HostAddress::try_from("db-1".to_owned()).unwrap().as_str(),
            "db-1"
        );
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert!(HostAddress::try_from(String::new()).is_err());
        assert!(HostAddress::try_from("   ".to_owned()).is_err());
    }

    #[test]
    fn rejects_a_label_with_a_leading_hyphen() {
        assert!(HostAddress::try_from("-bad.example".to_owned()).is_err());
    }

    #[test]
    fn deserialize_goes_through_validation_not_a_bare_string() {
        let ok: HostAddress = serde_json::from_str("\"10.0.0.9\"").unwrap();
        assert_eq!(ok.as_str(), "10.0.0.9");

        let err = serde_json::from_str::<HostAddress>("\"\"").unwrap_err();
        assert!(err.to_string().contains("invalid host address"));
    }
}
