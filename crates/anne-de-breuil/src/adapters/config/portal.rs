//! `[portal]` section: the `portal` feature's pre-shared bearer tokens and
//! rate-limit budget.
//!
//! Deliberately has no field an actual secret could occupy. Each
//! `[[portal.token]]` entry names an environment variable
//! (`secret_env`) that holds the bearer value at runtime -- the same
//! "reference a credential that lives elsewhere, never hold it" shape
//! `adapters::inventory::AuthMethod` already established for SSH
//! credentials. `deny_unknown_fields` means a stray `secret = "..."`
//! field in the TOML file itself is a hard parse error, not a silently
//! accepted footgun.
//!
//! This struct compiles unconditionally (no `portal` feature gate) so an
//! operator can validate a config file's `[portal]` section even in a
//! collector-only build; only `adapters::portal`'s actual token-resolution
//! and HTTP-serving logic requires the `portal` feature.

use crate::domain::HostId;

/// Settings for the `portal` feature's HTTP server.
///
/// An empty `tokens` list (the default -- no `[portal]` section at all is
/// valid) means the portal authenticates nobody: every request is
/// rejected. That is the correct fail-secure resting state, not a
/// configuration error, unlike `StoreConfig` -- there, silence would
/// silently pick a wrong place to persist data; here, silence already
/// yields the safe behaviour.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortalConfig {
    /// Pre-shared bearer tokens and the hosts each one may read.
    #[serde(default)]
    pub tokens: Vec<PortalTokenConfig>,
    /// Maximum requests per client per minute before the portal responds
    /// `429 Too Many Requests`. See `adapters::portal::rate_limit` for why
    /// this is a single fixed-window budget rather than a per-route one.
    #[serde(default = "default_rate_limit_per_minute")]
    pub rate_limit_per_minute: u32,
}

const fn default_rate_limit_per_minute() -> u32 {
    120
}

impl Default for PortalConfig {
    fn default() -> Self {
        Self {
            tokens: Vec::new(),
            rate_limit_per_minute: default_rate_limit_per_minute(),
        }
    }
}

/// One pre-shared bearer token: an operator-facing label, a pointer to
/// where the real secret lives, and the hosts it may read.
///
/// No `all_hosts` wildcard -- an operator who wants a token to cover every
/// host lists every host explicitly. That's more typing, but it means
/// `host_scopes` is always a literal, auditable set rather than a
/// resolve-at-request-time policy a reviewer has to reason about
/// separately.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortalTokenConfig {
    /// Human-readable label for this token -- safe to log, unlike the
    /// secret itself. Shows up in `AuthContext::token_id`.
    pub id: String,
    /// Name of the environment variable holding the bearer value.
    pub secret_env: String,
    /// Hosts this token may read.
    pub hosts: Vec<HostId>,
}

#[cfg(test)]
mod tests {
    use super::PortalConfig;

    #[test]
    fn default_has_no_tokens() {
        assert!(PortalConfig::default().tokens.is_empty());
    }

    #[test]
    fn default_rate_limit_is_positive() {
        assert!(PortalConfig::default().rate_limit_per_minute > 0);
    }
}
