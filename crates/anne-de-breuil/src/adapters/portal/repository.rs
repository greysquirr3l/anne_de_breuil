//! [`StoreBackedRepository`]: a `SnapshotRepository` adapter that
//! translates onto an existing `SnapshotStore`, with no authorization
//! logic of its own.
//!
//! Deliberately dumb -- `application::portal::AuthorizingRepository` is
//! the only place scope enforcement happens; `router` never hands a bare
//! `StoreBackedRepository` to a handler, only ever the authorizing
//! wrapper around it, so this type existing without its own auth check
//! isn't a gap, it's the point (see the `application::portal` module doc
//! comment).

use std::sync::Arc;

use async_trait::async_trait;

use crate::application::portal::{AuthContext, PortalError, SnapshotRepository};
use crate::application::snapshot_store::SnapshotStore;
use crate::domain::{HostId, ScanId, ScanSnapshot};

/// Adapts an existing `Arc<dyn SnapshotStore>` (T12's filesystem or
/// `SQLite` backend) onto the `portal` feature's [`SnapshotRepository`]
/// port.
pub struct StoreBackedRepository {
    store: Arc<dyn SnapshotStore>,
}

impl StoreBackedRepository {
    /// Wraps `store`.
    #[must_use]
    pub const fn new(store: Arc<dyn SnapshotStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl SnapshotRepository for StoreBackedRepository {
    async fn list_for_host(
        &self,
        _ctx: &AuthContext,
        host: HostId,
    ) -> Result<Vec<ScanId>, PortalError> {
        Ok(self.store.list(host).await?)
    }

    async fn get_for_host(
        &self,
        _ctx: &AuthContext,
        _host: HostId,
        scan: ScanId,
    ) -> Result<Option<ScanSnapshot>, PortalError> {
        Ok(self.store.get(scan).await?)
    }
}
