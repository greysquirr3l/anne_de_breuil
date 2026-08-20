//! [`ServiceName`]: a validated hosted-service identifier (Windows service name, systemd unit, ...).

use crate::domain::error::DomainError;

/// The name of a service hosted behind an endpoint.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ServiceName(String);

impl ServiceName {
    /// Returns the service name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ServiceName {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(DomainError::EmptyField {
                field: "ServiceName",
            });
        }
        Ok(Self(trimmed.to_owned()))
    }
}

impl core::str::FromStr for ServiceName {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl core::fmt::Display for ServiceName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert!(ServiceName::try_from(String::new()).is_err());
    }

    #[test]
    fn accepts_and_trims() {
        assert_eq!(
            ServiceName::try_from("  W32Time  ".to_owned())
                .unwrap()
                .as_str(),
            "W32Time"
        );
    }
}
