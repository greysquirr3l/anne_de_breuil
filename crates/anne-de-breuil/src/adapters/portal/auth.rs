//! Bearer-token authentication for the `portal` feature.
//!
//! # Why a bearer header, not a cookie
//!
//! The task this module implements names either shape as acceptable. A
//! cookie needs an issuance step (something has to set it) and, once set,
//! is ambient browser authority -- which reopens CSRF as a concern this
//! module would then have to mitigate (`SameSite`, tokens on
//! state-changing requests, ...). This crate has no login page and no
//! session store by design (see the module doc comment on
//! `application::portal`), so there is nothing that would ever *set* such
//! a cookie without inventing exactly the issuance flow the task says is
//! out of scope. A bearer header has none of that: it's stateless,
//! there's no ambient-authority CSRF surface because a cross-site request
//! can't attach a header a page didn't choose to send, and it fits how
//! this tool is actually meant to be reached -- `curl`/scripts, or a
//! reverse proxy / internal auth gateway that injects the header after
//! doing its own authentication. The real cost: a bare browser address
//! bar cannot attach a custom header to a top-level navigation, so this
//! portal is not directly browsable by typing a URL into a fresh browser
//! tab without an extension or proxy in front of it. That's a genuine,
//! deliberate scope limitation, not an oversight -- building a
//! cookie-issuance endpoint to work around it would mean building the
//! login flow the task explicitly says isn't wanted.
//!
//! # Fail-secure token resolution
//!
//! [`PortalTokens::load`] runs once at process startup, never per
//! request. A `[[portal.token]]` entry whose `secret_env` is unset or
//! empty is a configuration error -- the whole portal refuses to start,
//! rather than silently running with fewer working tokens than the
//! operator configured (an operator's typo in an env var name should
//! never quietly narrow who can reach the fleet without anyone noticing).
//! Zero configured tokens is not an error: it's the correct fail-secure
//! resting state, since [`AuthContext`]'s extractor rejects every request
//! either way.
//!
//! Every configured secret is hashed with SHA-256 at load time; the raw
//! value is never retained past this function returning. This means a
//! stray `{:?}` on [`PortalTokens`] cannot print a token even by
//! accident -- the field that would hold it doesn't exist, structurally,
//! the same trick `adapters::inventory::AuthMethod` uses by having no
//! `Password` variant at all.

use std::collections::HashSet;

use axum::extract::FromRef;
use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use sha2::{Digest as _, Sha256};

use crate::adapters::config::PortalTokenConfig;
use crate::application::portal::AuthContext;
use crate::domain::HostId;

/// Failure resolving `[[portal.token]]` entries at startup.
#[derive(Debug, thiserror::Error)]
pub enum PortalAuthConfigError {
    /// `secret_env` was set for this token id, but the named environment
    /// variable is unset or empty.
    #[error("portal token \"{token_id}\": environment variable {secret_env} is unset or empty")]
    MissingSecret {
        /// The offending token's configured id.
        token_id: String,
        /// The environment variable name it named.
        secret_env: String,
    },
}

#[derive(Clone)]
struct TokenEntry {
    token_id: String,
    secret_hash: [u8; 32],
    host_scopes: HashSet<HostId>,
}

/// Every pre-shared token the portal will accept, resolved once at
/// startup.
///
/// `Clone` is derived so [`PortalState`](super::PortalState) can hold an
/// owned copy per request via axum's `State`/`FromRef` extraction (see
/// `router::router`) -- cheap, since this crate's own doc comment on
/// [`PortalTokens::authenticate`] already establishes the assumption of a
/// handful of tokens for a small operations team, and every field here is
/// either a hash or a label, never the raw secret. No `Debug`-derived
/// field ever exposes one -- see the module doc comment.
#[derive(Clone)]
pub struct PortalTokens {
    entries: Vec<TokenEntry>,
}

impl PortalTokens {
    /// Resolves `configs` into hashed, ready-to-check tokens by reading
    /// each entry's `secret_env` from the process environment.
    ///
    /// # Errors
    ///
    /// Returns [`PortalAuthConfigError::MissingSecret`] if any entry's
    /// named environment variable is unset or empty. An entry is never
    /// silently dropped -- a misconfigured token fails the whole load.
    pub fn load(configs: &[PortalTokenConfig]) -> Result<Self, PortalAuthConfigError> {
        let entries = configs
            .iter()
            .map(|config| {
                let secret = std::env::var(&config.secret_env)
                    .ok()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| PortalAuthConfigError::MissingSecret {
                        token_id: config.id.clone(),
                        secret_env: config.secret_env.clone(),
                    })?;
                Ok(TokenEntry {
                    token_id: config.id.clone(),
                    secret_hash: Sha256::digest(secret.as_bytes()).into(),
                    host_scopes: config.hosts.iter().copied().collect(),
                })
            })
            .collect::<Result<Vec<_>, PortalAuthConfigError>>()?;
        Ok(Self { entries })
    }

    /// An empty token set: every request is rejected. Used when no
    /// `[[portal.token]]` entries are configured at all.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Checks `presented` against every configured token, in constant
    /// time per candidate (see [`constant_time_eq`]), returning the
    /// matching [`AuthContext`] if any.
    ///
    /// Always compares against every entry rather than returning on the
    /// first match -- with only a handful of tokens for a small
    /// operations team, the cost is negligible, and it keeps the total
    /// time this function takes independent of *where* in the configured
    /// list a match falls, not just independent of the match itself.
    ///
    /// `pub(crate)` rather than private: `adapters::portal::rate_limit`
    /// also needs to resolve a presented bearer token to a stable key
    /// (the token id, not the raw value) so a rate-limit budget can be
    /// keyed per-caller rather than shared globally -- see that module's
    /// doc comment.
    #[must_use]
    pub(crate) fn authenticate(&self, presented: &str) -> Option<AuthContext> {
        let presented_hash: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        let mut matched: Option<&TokenEntry> = None;
        for entry in &self.entries {
            if constant_time_eq(&entry.secret_hash, &presented_hash) {
                matched = Some(entry);
            }
        }
        matched.map(|entry| AuthContext::new(entry.token_id.clone(), entry.host_scopes.clone()))
    }
}

/// Compares two equal-length byte arrays without early-exiting on the
/// first mismatch, so how many leading bytes match cannot be inferred
/// from comparison time. `[u8]::eq` makes no such guarantee (`memcmp` on
/// most targets short-circuits), which matters here because both
/// operands are attacker-influenced (a presented token is hashed and
/// compared against every configured hash on every request).
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl<S> FromRequestParts<S> for AuthContext
where
    PortalTokens: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    /// Fail-secure default deny: a missing `Authorization` header, a
    /// header that isn't `Bearer <token>` shaped, and a well-formed but
    /// unrecognised token all produce the identical `401` with no body --
    /// deliberately not distinguishable from one another by an attacker,
    /// per this task's own instruction not to leak which failure mode
    /// occurred.
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let tokens = PortalTokens::from_ref(state);
        bearer_token(&parts.headers)
            .and_then(|token| tokens.authenticate(token))
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}

/// Extracts the bearer token from an `Authorization: Bearer <token>`
/// header, or `None` for anything else -- missing header, a different
/// auth scheme, non-UTF-8 bytes, or an empty token after the scheme.
/// Every one of those collapses to the same `None` so the caller can't
/// tell them apart, matching the "don't leak which failure mode" rule
/// on [`AuthContext`]'s own extractor.
///
/// Takes a bare [`HeaderMap`] rather than `&Parts` so
/// `adapters::portal::rate_limit`'s middleware -- which sees a whole
/// `Request`, not `Parts` -- can call this without reconstructing one.
/// `pub` rather than `pub(crate)`: this module is already private to
/// `adapters::portal`, which caps the real visibility either way.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    (!token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::{HeaderMap, PortalTokenConfig, PortalTokens, bearer_token};

    fn headers_with_auth(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(value).expect("valid header value"),
        );
        headers
    }

    #[test]
    fn bearer_token_missing_header_is_none() {
        assert!(bearer_token(&HeaderMap::new()).is_none());
    }

    #[test]
    fn bearer_token_wrong_scheme_is_none() {
        let headers = headers_with_auth("Basic dXNlcjpwYXNz");
        assert!(bearer_token(&headers).is_none());
    }

    #[test]
    fn bearer_token_empty_after_scheme_is_none() {
        let headers = headers_with_auth("Bearer ");
        assert!(bearer_token(&headers).is_none());
    }

    #[test]
    fn bearer_token_extracts_the_value() {
        let headers = headers_with_auth("Bearer real-token");
        assert_eq!(bearer_token(&headers), Some("real-token"));
    }

    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    #[test]
    fn empty_token_set_authenticates_nobody() {
        assert!(PortalTokens::empty().authenticate("anything").is_none());
    }

    #[test]
    fn load_rejects_a_missing_secret_env_var() {
        let configs = vec![PortalTokenConfig {
            id: "ops".to_owned(),
            secret_env: "ANNE_PORTAL_TEST_UNSET_VAR_LOAD_REJECTS".to_owned(),
            hosts: vec![],
        }];
        // `.unwrap_err()` needs `PortalTokens: Debug`, deliberately not
        // implemented (see the module doc comment) -- match instead.
        let Err(err) = PortalTokens::load(&configs) else {
            panic!("expected a missing-secret error");
        };
        assert!(err.to_string().contains("ops"));
    }

    #[test]
    fn load_resolves_configured_secret_and_authenticates_it() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: serialized by `env_lock`; this test owns this var name.
        unsafe {
            std::env::set_var(
                "ANNE_PORTAL_TEST_LOAD_RESOLVES",
                "correct-horse-battery-staple",
            );
        }
        let configs = vec![PortalTokenConfig {
            id: "ops".to_owned(),
            secret_env: "ANNE_PORTAL_TEST_LOAD_RESOLVES".to_owned(),
            hosts: vec![],
        }];
        let tokens = PortalTokens::load(&configs);
        unsafe {
            std::env::remove_var("ANNE_PORTAL_TEST_LOAD_RESOLVES");
        }
        let tokens = tokens.expect("valid secret resolves");

        let matched = tokens
            .authenticate("correct-horse-battery-staple")
            .expect("correct token authenticates");
        assert_eq!(matched.token_id, "ops");
        assert!(tokens.authenticate("wrong-token").is_none());
    }
}
