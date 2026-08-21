//! [`SnapshotRepository`]: the auth-aware port `portal` route handlers
//! consume, and [`AuthorizingRepository`], the decorator that enforces
//! [`AuthContext`] scope before ever reaching a real store.
//!
//! This is a *different* port from [`crate::application::SnapshotStore`]
//! (T12's `put`/`get`/`list`, no notion of a caller identity at all) --
//! not a retrofit of one onto the other. `SnapshotStore` still has every
//! existing T12/T16/T18/T21 call site constructing a bare
//! `Arc<dyn SnapshotStore>`; adding an `AuthContext` parameter to it would
//! break all of them for a concern only `portal` has. Instead,
//! `adapters::portal::StoreBackedRepository` wraps an existing
//! `Arc<dyn SnapshotStore>` and implements this trait, and
//! [`AuthorizingRepository`] wraps *that* -- authorization sits on top of
//! persistence, not instead of it.
//!
//! # Why enforcement lives here, not in a handler
//!
//! [`AuthorizingRepository`]'s two methods check `ctx.host_scopes` before
//! ever calling `self.inner`. A route handler holds only
//! `Arc<dyn SnapshotRepository>` -- if that trait object is always an
//! `AuthorizingRepository` (which `adapters::portal::router` guarantees by
//! construction, never handing out a bare `StoreBackedRepository`), no
//! handler, however buggy, can reach snapshot data without the scope
//! check running first. The check cannot be skipped by forgetting to call
//! it, because there is no code path to snapshot data that doesn't pass
//! through it.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;

use crate::application::snapshot_store::StoreError;
use crate::domain::{HostId, ScanId, ScanSnapshot};

/// The authenticated caller of a `portal` request: which pre-shared token
/// was presented, and which hosts it may read.
///
/// Carries no session state and expires nothing -- a bearer token is
/// valid until an operator removes it from `[portal]` config and restarts
/// the process (see `adapters::portal::auth` for why tokens are read once
/// at startup, never per-request).
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// The operator-facing label of the token that authenticated this
    /// request (`PortalTokenConfig::id`) -- safe to log, unlike the token
    /// value itself, which never reaches this type at all.
    pub token_id: String,
    /// Hosts this token may read.
    pub host_scopes: HashSet<HostId>,
}

impl AuthContext {
    /// Builds a context for `token_id`, scoped to `host_scopes`.
    #[must_use]
    pub const fn new(token_id: String, host_scopes: HashSet<HostId>) -> Self {
        Self {
            token_id,
            host_scopes,
        }
    }
}

/// Failure reading snapshot data through a [`SnapshotRepository`].
#[derive(Debug, thiserror::Error)]
pub enum PortalError {
    /// `ctx` is not scoped to the requested host.
    ///
    /// Deliberately carries no detail about *why* -- whether the host
    /// simply isn't in `host_scopes`, or a scan id resolved to a
    /// different host than the caller named (see
    /// [`AuthorizingRepository::get_for_host`]) -- both collapse to the
    /// same variant so a caller mapping this to an HTTP response can't
    /// accidentally leak which case occurred.
    #[error("access denied")]
    Forbidden,
    /// The underlying store failed.
    #[error("snapshot store failure: {0}")]
    Store(#[from] StoreError),
}

/// Reads scan snapshots on behalf of an authenticated, host-scoped caller.
///
/// [`AuthContext`] is a required parameter on every method -- there is no
/// way to call this trait without one, so a route handler physically
/// cannot reach snapshot data without first passing through the
/// extractor that produces it.
#[async_trait]
pub trait SnapshotRepository: Send + Sync {
    /// Lists every [`ScanId`] recorded for `host`, if `ctx` may read it.
    ///
    /// # Errors
    ///
    /// Returns [`PortalError::Forbidden`] if `host` is outside
    /// `ctx.host_scopes`, or [`PortalError::Store`] if the underlying
    /// store fails.
    async fn list_for_host(
        &self,
        ctx: &AuthContext,
        host: HostId,
    ) -> Result<Vec<ScanId>, PortalError>;

    /// Fetches the snapshot recorded under `scan` for `host`, if `ctx` may
    /// read it.
    ///
    /// Returns `Ok(None)` both when no such scan exists and when `scan`
    /// resolves to a snapshot belonging to a *different* host than
    /// `host` -- see [`AuthorizingRepository::get_for_host`]'s doc
    /// comment for why that second case is treated identically to
    /// not-found rather than surfaced as a distinct error.
    ///
    /// # Errors
    ///
    /// Returns [`PortalError::Forbidden`] if `host` is outside
    /// `ctx.host_scopes`, or [`PortalError::Store`] if the underlying
    /// store fails.
    async fn get_for_host(
        &self,
        ctx: &AuthContext,
        host: HostId,
        scan: ScanId,
    ) -> Result<Option<ScanSnapshot>, PortalError>;
}

/// Wraps a [`SnapshotRepository`], enforcing `ctx.host_scopes` before
/// every call reaches `inner`.
///
/// `adapters::portal::router` is the only place that constructs one of
/// these, and it always wraps `StoreBackedRepository` (never hands a bare,
/// unauthorizing repository to a route). See the module doc comment for
/// why that construction discipline is what makes the "a route cannot
/// bypass authorization" guarantee real rather than aspirational.
pub struct AuthorizingRepository<R> {
    inner: R,
}

impl<R> AuthorizingRepository<R> {
    /// Wraps `inner`, an unauthorizing [`SnapshotRepository`].
    pub const fn new(inner: R) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<R: SnapshotRepository> SnapshotRepository for AuthorizingRepository<R> {
    async fn list_for_host(
        &self,
        ctx: &AuthContext,
        host: HostId,
    ) -> Result<Vec<ScanId>, PortalError> {
        if !ctx.host_scopes.contains(&host) {
            return Err(PortalError::Forbidden);
        }
        self.inner.list_for_host(ctx, host).await
    }

    async fn get_for_host(
        &self,
        ctx: &AuthContext,
        host: HostId,
        scan: ScanId,
    ) -> Result<Option<ScanSnapshot>, PortalError> {
        if !ctx.host_scopes.contains(&host) {
            return Err(PortalError::Forbidden);
        }
        let snapshot = self.inner.get_for_host(ctx, host, scan).await?;
        // `scan` is only guaranteed globally unique, not scoped to `host`
        // -- the underlying `SnapshotStore` keys purely on `ScanId`
        // (T12's `get(id: ScanId)`), with no notion of "this id belongs to
        // that host." Without this filter, a token scoped to {A, B}
        // requesting host=A with a `scan` id that actually belongs to
        // host C (outside its scope entirely) would receive C's data
        // returned as if it were A's -- the `host_scopes.contains(&host)`
        // check above would never catch it, since it only ever inspects
        // the *claimed* host, not the one the data actually came from.
        Ok(snapshot.filter(|snapshot| snapshot.host_id == host))
    }
}

/// A `SnapshotRepository` trait object, shared across the router.
pub type SharedSnapshotRepository = Arc<dyn SnapshotRepository>;

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use time::OffsetDateTime;

    use super::{AuthContext, AuthorizingRepository, PortalError, SnapshotRepository};
    use crate::domain::target_strategy::TargetStrategy;
    use crate::domain::{HostId, ScanId, ScanSnapshot};

    /// An in-memory fake, deliberately with no authorization logic of its
    /// own -- it exists so tests can prove `AuthorizingRepository` is
    /// where enforcement lives, not accidentally verify some enforcement
    /// baked into the fake instead.
    struct FakeRepository {
        snapshots: Mutex<Vec<ScanSnapshot>>,
    }

    #[async_trait::async_trait]
    impl SnapshotRepository for FakeRepository {
        async fn list_for_host(
            &self,
            _ctx: &AuthContext,
            host: HostId,
        ) -> Result<Vec<ScanId>, PortalError> {
            Ok(self
                .snapshots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .filter(|snapshot| snapshot.host_id == host)
                .map(|snapshot| snapshot.scan_id)
                .collect())
        }

        async fn get_for_host(
            &self,
            _ctx: &AuthContext,
            _host: HostId,
            scan: ScanId,
        ) -> Result<Option<ScanSnapshot>, PortalError> {
            Ok(self
                .snapshots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .find(|snapshot| snapshot.scan_id == scan)
                .cloned())
        }
    }

    fn fixture_snapshot(host: HostId) -> ScanSnapshot {
        ScanSnapshot::new(
            host,
            ScanId::generate(),
            OffsetDateTime::UNIX_EPOCH,
            "test".to_owned(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            TargetStrategy::LocalOnly,
        )
    }

    fn ctx_scoped_to(hosts: &[HostId]) -> AuthContext {
        AuthContext::new("test-token".to_owned(), hosts.iter().copied().collect())
    }

    #[tokio::test]
    async fn out_of_scope_host_rejected_at_repository_layer() {
        let web1 = HostId::generate();
        let db1 = HostId::generate();
        let repo = AuthorizingRepository::new(FakeRepository {
            snapshots: Mutex::new(vec![fixture_snapshot(db1)]),
        });
        let ctx = ctx_scoped_to(&[web1]);

        let err = repo
            .get_for_host(&ctx, db1, ScanId::generate())
            .await
            .unwrap_err();
        assert!(matches!(err, PortalError::Forbidden));
    }

    #[tokio::test]
    async fn out_of_scope_host_list_also_rejected() {
        let web1 = HostId::generate();
        let db1 = HostId::generate();
        let repo = AuthorizingRepository::new(FakeRepository {
            snapshots: Mutex::new(vec![fixture_snapshot(db1)]),
        });
        let ctx = ctx_scoped_to(&[web1]);

        let err = repo.list_for_host(&ctx, db1).await.unwrap_err();
        assert!(matches!(err, PortalError::Forbidden));
    }

    #[tokio::test]
    async fn in_scope_host_reads_succeed() {
        let web1 = HostId::generate();
        let snapshot = fixture_snapshot(web1);
        let scan_id = snapshot.scan_id;
        let repo = AuthorizingRepository::new(FakeRepository {
            snapshots: Mutex::new(vec![snapshot]),
        });
        let ctx = ctx_scoped_to(&[web1]);

        let found = repo.get_for_host(&ctx, web1, scan_id).await.unwrap();
        assert!(found.is_some());
    }

    /// The scenario `get_for_host`'s post-filter exists for: the inner
    /// repository returns a snapshot whose real `host_id` doesn't match
    /// the host the caller claimed (a scan id that belongs to a host
    /// outside the token's scope). Even though `host` itself
    /// (`claimed_host`) *is* in `ctx.host_scopes` -- so the scope guard
    /// clause alone would let this through -- the returned data must not
    /// be handed back mislabeled as belonging to a host the caller is
    /// authorized for.
    #[tokio::test]
    async fn mismatched_scan_and_host_never_leaks_another_hosts_data() {
        let claimed_host = HostId::generate();
        let real_owner = HostId::generate();
        let leaked_snapshot = fixture_snapshot(real_owner);
        let scan_id = leaked_snapshot.scan_id;
        let repo = AuthorizingRepository::new(FakeRepository {
            snapshots: Mutex::new(vec![leaked_snapshot]),
        });
        // The token is scoped to `claimed_host`, not `real_owner` -- the
        // fake repository doesn't care and will happily return the
        // mismatched snapshot if asked, since it does no scope checking.
        let ctx = ctx_scoped_to(&[claimed_host]);

        let result = repo.get_for_host(&ctx, claimed_host, scan_id).await;
        assert!(matches!(result, Ok(None)));
    }
}
