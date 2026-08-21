//! Minimal binary standing up the `portal` feature's HTTP server.
//!
//! Loads `AnneConfig` (config file path from the first CLI argument, or
//! `PORTAL_SERVER_CONFIG`, defaulting to `./anne.toml` -- `AnneConfig::load`
//! itself treats a missing file as "no values from this layer," not an
//! error, so `ANNE_`-prefixed environment variables alone are enough to
//! run this without a file on disk at all), builds a `SnapshotStore` from
//! `[store]`, resolves `[[portal.tokens]]` entries against the process
//! environment, and serves the router on `PORTAL_SERVER_ADDR` (default
//! `127.0.0.1:8088`).
//!
//! Deliberately *not* `ANNE_PORTAL_CONFIG`/`ANNE_PORTAL_ADDR` -- T17's own
//! Accumulated Learnings entry documents that `AnneConfig::load`'s env
//! provider (`Env::prefixed("ANNE_")`) intercepts *every* `ANNE_`-prefixed
//! variable in the process environment, not just ones it recognizes, and
//! fails the whole load on an unrecognized one. An `ANNE_`-prefixed knob
//! for this binary's own concerns (which port to bind, which file to
//! read) would collide with that the moment both are set at once --
//! confirmed by hitting exactly this failure while hand-verifying this
//! example.
//!
//! This is a hand-verification harness and the shape a later task
//! (`T31`, matching this project's established pattern of deferring final
//! CLI wiring -- see `anne-de-breuil-cli/src/cli.rs`'s own `--config`
//! `TODO(T31)`) would promote into a real `anne portal` subcommand, not
//! itself a subcommand today.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anne_de_breuil::adapters::config::{AnneConfig, StoreBackend};
use anne_de_breuil::adapters::portal::{PortalState, PortalTokens, router};
use anne_de_breuil::adapters::snapshot_store::FsSnapshotStore;
use anne_de_breuil::application::portal::AuthorizingRepository;
use anne_de_breuil::application::snapshot_store::SnapshotStore;
use anyhow::{Context as _, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = config_path();
    let config = AnneConfig::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    let store = build_store(&config)?;
    let repository = Arc::new(AuthorizingRepository::new(
        anne_de_breuil::adapters::portal::StoreBackedRepository::new(store),
    ));
    let tokens = PortalTokens::load(&config.portal.tokens).context("resolving portal tokens")?;
    if config.portal.tokens.is_empty() {
        eprintln!(
            "warning: no [[portal.token]] entries configured -- every request will be rejected"
        );
    }
    let rate_limiter = Arc::new(anne_de_breuil::adapters::portal::RateLimiter::new(
        config.portal.rate_limit_per_minute,
    ));

    let state = PortalState::new(repository, tokens, rate_limiter, config.report.fonts);
    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();

    let addr = bind_addr();
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    eprintln!("anne-de-breuil portal listening on http://{addr}");
    axum::serve(listener, app).await.context("serving portal")?;
    Ok(())
}

fn config_path() -> PathBuf {
    std::env::args()
        .nth(1)
        .or_else(|| std::env::var("PORTAL_SERVER_CONFIG").ok())
        .map_or_else(|| PathBuf::from("anne.toml"), PathBuf::from)
}

fn bind_addr() -> SocketAddr {
    std::env::var("PORTAL_SERVER_ADDR")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8088)))
}

fn build_store(config: &AnneConfig) -> Result<Arc<dyn SnapshotStore>> {
    match config.store.backend {
        StoreBackend::FileSystem => {
            let store = FsSnapshotStore::new(&config.store.path)
                .with_context(|| format!("opening store at {}", config.store.path.display()))?;
            Ok(Arc::new(store))
        }
        StoreBackend::Sqlite => sqlite_store(config),
    }
}

#[cfg(feature = "store-sqlite")]
fn sqlite_store(config: &AnneConfig) -> Result<Arc<dyn SnapshotStore>> {
    let store =
        anne_de_breuil::adapters::snapshot_store::SqliteSnapshotStore::open(&config.store.path)
            .with_context(|| format!("opening sqlite store at {}", config.store.path.display()))?;
    Ok(Arc::new(store))
}

#[cfg(not(feature = "store-sqlite"))]
fn sqlite_store(_config: &AnneConfig) -> Result<Arc<dyn SnapshotStore>> {
    anyhow::bail!(
        "config selects the sqlite store backend, but this binary wasn't built with \
         --features store-sqlite"
    )
}
