//! [`LinuxSignatureVerifier`]: there is no Linux Authenticode equivalent,
//! so every binary is reported [`SignatureStatus::NotApplicable`].
//!
//! TODO(future task): package-manager provenance (reading
//! `/var/lib/dpkg/status` or the rpm database directly -- never shelling
//! out to `dpkg -S`/`rpm -qf`) is scoped out of this task; see the module
//! docs on [`super`] for why.

use async_trait::async_trait;

use crate::application::collect::{CollectError, SignatureVerifier};
use crate::domain::{ProcessPath, SignatureStatus};

/// Always reports [`SignatureStatus::NotApplicable`] -- there is nothing
/// to verify on this platform yet.
#[derive(Debug, Default)]
pub struct LinuxSignatureVerifier;

impl LinuxSignatureVerifier {
    /// Builds a verifier with no state.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SignatureVerifier for LinuxSignatureVerifier {
    async fn verify(&self, _path: &ProcessPath) -> Result<SignatureStatus, CollectError> {
        Ok(SignatureStatus::NotApplicable)
    }
}
