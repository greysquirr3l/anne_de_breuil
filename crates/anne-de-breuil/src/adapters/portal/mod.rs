//! The `portal` feature: an `axum` HTTP server exposing stored snapshots
//! to a fleet-ops team, read-only, over pre-shared bearer tokens.
//!
//! # Module layout
//!
//! [`auth`] resolves `[[portal.token]]` config entries into hashed,
//! constant-time-comparable tokens and implements the `AuthContext`
//! extractor every route depends on. [`repository`] adapts an existing
//! `SnapshotStore` (T12) onto the `application::portal::SnapshotRepository`
//! port with zero authorization logic of its own -- enforcement lives
//! only in `application::portal::AuthorizingRepository`, which
//! [`PortalState::new`]'s only caller (`examples/portal_server.rs`) always
//! wraps `StoreBackedRepository` in before it ever reaches [`PortalState`].
//! [`rate_limit`] is a fixed-window budget per authenticated token (or
//! source IP before authentication), wired as the innermost `Router`
//! layer. [`security_headers`] is the outermost layer: CSP,
//! `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options` on every
//! response, `Strict-Transport-Security` when `X-Forwarded-Proto: https`
//! signals a TLS-terminating reverse proxy sits in front. [`templates`]
//! and [`assets`] hold the two new page shapes this feature needs (fleet
//! index, drift view) and the one vendored static asset (`htmx`'s
//! runtime) it serves; [`router`] wires all of the above into the actual
//! route table and owns every handler.
//!
//! # Ingestion is out of scope
//!
//! This module is read-only: it serves snapshots a scan already wrote via
//! `SnapshotStore`, never accepts new ones over HTTP. The task this
//! module implements explicitly allows deferring an ingestion endpoint
//! behind its own flag; nothing here half-builds one.
//! `// TODO(T31 or later)`: if a future task wants `portal` to accept
//! pushed snapshots directly (rather than only ones a local/SSH scan
//! wrote to the configured `SnapshotStore`), that's a new write-capable
//! port method and a new authorization question ("which token may write
//! to which host," not just read), not an extension of
//! [`crate::application::portal::SnapshotRepository`] as it stands today.

mod assets;
mod auth;
mod rate_limit;
mod repository;
mod router;
mod security_headers;
mod templates;

use std::sync::Arc;

use axum::extract::FromRef;

use crate::adapters::config::FontsMode;
use crate::application::portal::SharedSnapshotRepository;

pub use auth::{PortalAuthConfigError, PortalTokens};
pub use rate_limit::RateLimiter;
pub use repository::StoreBackedRepository;
pub use router::router;

/// Everything a route handler needs, cloned once per request via axum's
/// `State` extractor.
///
/// Every field is cheap to clone: `SharedSnapshotRepository` and
/// `Arc<RateLimiter>` are reference-counted handles, `PortalTokens` holds
/// at most a handful of entries (see its own doc comment), and
/// `FontsMode` is a bare enum.
#[derive(Clone)]
pub struct PortalState {
    pub(crate) repository: SharedSnapshotRepository,
    pub(crate) tokens: PortalTokens,
    pub(crate) rate_limiter: Arc<RateLimiter>,
    pub(crate) fonts_mode: FontsMode,
}

impl PortalState {
    /// Assembles portal state. `repository` should be an
    /// `application::portal::AuthorizingRepository` wrapping a
    /// `StoreBackedRepository` -- see this module's own doc comment for
    /// why that construction discipline is what makes "no route can
    /// bypass authorization" a real guarantee.
    #[must_use]
    pub const fn new(
        repository: SharedSnapshotRepository,
        tokens: PortalTokens,
        rate_limiter: Arc<RateLimiter>,
        fonts_mode: FontsMode,
    ) -> Self {
        Self {
            repository,
            tokens,
            rate_limiter,
            fonts_mode,
        }
    }
}

/// Lets `AuthContext`'s `FromRequestParts` impl (`auth.rs`, written
/// against a generic `S` bound by `PortalTokens: FromRef<S>`) resolve an
/// owned `PortalTokens` out of the concrete `PortalState` this module
/// actually runs the router with.
impl FromRef<PortalState> for PortalTokens {
    fn from_ref(state: &PortalState) -> Self {
        state.tokens.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    /// The task's own exit criterion: the default build (no `portal`, no
    /// `report-html` opted in beyond what `default = [...]` already
    /// carries) must show zero `axum` in the dependency graph. Runs the
    /// exact command this task's own hand-verification section names,
    /// against the real `Cargo.lock` -- not asserted in prose.
    #[test]
    fn default_build_excludes_axum() {
        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate manifest dir has a workspace root two levels up")
            .to_path_buf();

        let output = Command::new(env!("CARGO"))
            .current_dir(&workspace_root)
            .args([
                "tree",
                "--locked",
                "-p",
                "anne-de-breuil",
                "--no-default-features",
                "--features",
                "windows-collector,linux-collector",
            ])
            .output()
            .expect("running cargo tree");
        assert!(
            output.status.success(),
            "cargo tree failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let tree = String::from_utf8_lossy(&output.stdout);
        assert!(
            !tree.to_lowercase().contains("axum"),
            "default feature set pulled in axum:\n{tree}"
        );
    }
}
