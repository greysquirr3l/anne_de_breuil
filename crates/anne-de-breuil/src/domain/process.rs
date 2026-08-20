//! [`ProcessPath`]: a validated executable path or pseudo-path.

use crate::domain::error::DomainError;

/// The path to the executable that owns an endpoint, or a platform
/// pseudo-path such as `System` for kernel-owned sockets.
///
/// Validation is deliberately shallow — non-empty after trimming — because
/// the collector adapters run on the target platform and hand us paths the
/// OS itself already considers valid. What matters here is that an empty
/// or whitespace-only string can never masquerade as a real path.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ProcessPath(String);

impl ProcessPath {
    /// Returns the path as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProcessPath {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(DomainError::EmptyField {
                field: "ProcessPath",
            });
        }
        Ok(Self(trimmed.to_owned()))
    }
}

impl core::str::FromStr for ProcessPath {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl core::fmt::Display for ProcessPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_whitespace() {
        assert!(ProcessPath::try_from(String::new()).is_err());
        assert!(ProcessPath::try_from("   ".to_owned()).is_err());
    }

    #[test]
    fn accepts_pseudo_path() {
        assert_eq!(
            ProcessPath::try_from("System".to_owned()).unwrap().as_str(),
            "System"
        );
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(
            ProcessPath::try_from("  C:\\svc\\app.exe  ".to_owned())
                .unwrap()
                .as_str(),
            "C:\\svc\\app.exe"
        );
    }
}
