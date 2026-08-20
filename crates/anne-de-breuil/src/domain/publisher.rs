//! [`PublisherName`] and [`SignatureStatus`]: code-signing evidence for an owning process.

use crate::domain::error::DomainError;

/// The subject/publisher name recovered from a binary's code-signing certificate.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct PublisherName(String);

impl PublisherName {
    /// Returns the publisher name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PublisherName {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(DomainError::EmptyField {
                field: "PublisherName",
            });
        }
        Ok(Self(trimmed.to_owned()))
    }
}

impl core::str::FromStr for PublisherName {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl core::fmt::Display for PublisherName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The outcome of checking the code-signing signature on an endpoint's owning binary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SignatureStatus {
    /// Signed by a verifiable publisher.
    Signed(PublisherName),
    /// The binary carries no signature.
    Unsigned,
    /// Signature status was not evaluated (e.g. no collector evidence for it yet).
    Unknown,
    /// The platform has no code-signing concept this tool can evaluate
    /// (e.g. Linux, which has no Authenticode equivalent) — distinct from
    /// [`SignatureStatus::Unknown`], which means the platform *does* have a
    /// signing concept but this collector run didn't establish it.
    NotApplicable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_publisher() {
        assert!(PublisherName::try_from(String::new()).is_err());
    }

    #[test]
    fn signature_status_variants_are_distinct() {
        let signed =
            SignatureStatus::Signed(PublisherName::try_from("Contoso".to_owned()).unwrap());
        assert_ne!(signed, SignatureStatus::Unsigned);
        assert_ne!(SignatureStatus::Unsigned, SignatureStatus::Unknown);
        assert_ne!(SignatureStatus::Unknown, SignatureStatus::NotApplicable);
    }
}
