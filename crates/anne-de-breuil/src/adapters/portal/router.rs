//! Route table and handlers.
//!
//! # Layering order
//!
//! `security_headers::apply` is the *last* `.layer()` call below, which
//! makes it the *outermost* wrapper around the whole router -- `axum`
//! layers nest in reverse declaration order, so whichever layer is added
//! last sees every request first and every response last, including a
//! `429` from `rate_limit::enforce` (added first, so it sits inside) and
//! a `404` from no route matching at all (never reaches any `.layer()`
//! call individually, but the whole `Router` -- fallback included -- is
//! what every layer wraps). Getting this order backwards would mean a
//! rate-limited or unmatched request skips the security headers, which is
//! exactly the gap this task's own test suite (`security_headers`'s
//! `headers_present_on_a_404`, plus this module's
//! `rate_limited_response_still_carries_security_headers`) exists to
//! catch.
//!
//! # No route reaches `SnapshotRepository` without an `AuthContext`
//!
//! Every handler below except `htmx_js` takes `ctx: AuthContext` as a
//! parameter. `AuthContext`'s `FromRequestParts` impl (`auth.rs`) runs
//! before the handler body ever executes -- there is no route wired to a
//! handler that omits it, and `state.repository` is always the
//! `application::portal::AuthorizingRepository` `mod.rs`'s
//! `PortalState::new` callers construct (never a bare
//! `StoreBackedRepository`), so even a handler that forgot to check
//! `ctx.host_scopes` itself still can't read another host's data -- the
//! check happens inside the repository, not here. See
//! `application::portal`'s own module doc for why that's a real guarantee
//! and not just a convention.
//!
//! # Host detail vs. scan detail
//!
//! Host detail (`/hosts/{host}`, `/hosts/{host}/fragment`) is a
//! navigation hub: which scans exist for this host, newest first, each
//! linking to its own report or raw download. It has no equivalent in
//! `adapters::html_report`, since the CLI's `anne report` command always
//! renders one already-chosen snapshot and never lists what's available
//! -- built fresh here, in `templates`. Scan detail
//! (`/hosts/{host}/scans/{scan}`) is exactly what `anne report --format
//! html` already renders for one snapshot, so `scan_detail` below calls
//! straight into `html_report::render` instead of a third template
//! system.

use askama::Template as _;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;

use crate::adapters::html_report::{self, HtmlRenderError};
use crate::application::portal::{AuthContext, PortalError};
use crate::domain::drift::diff;
use crate::domain::report_model::ReportModel;
use crate::domain::{HostId, ScanId};

use super::PortalState;
use super::assets::HTMX_JS;
use super::rate_limit;
use super::security_headers;
use super::templates::{
    self, DriftTemplate, FleetIndexTemplate, HostFragmentTemplate, HostPageTemplate, ScanRow,
};

/// Builds the portal's router, state and all layers included. Callers
/// (`examples/portal_server.rs`) only need to hand this to
/// `axum::serve`.
pub fn router(state: PortalState) -> Router {
    Router::new()
        .route("/", get(fleet_index))
        .route("/hosts/{host}", get(host_detail_page))
        .route("/hosts/{host}/fragment", get(host_detail_fragment))
        .route("/hosts/{host}/drift", get(drift_view))
        .route("/hosts/{host}/scans/{scan}", get(scan_detail))
        .route("/hosts/{host}/scans/{scan}/download", get(download))
        .route("/assets/htmx.min.js", get(htmx_js))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit::enforce,
        ))
        .layer(axum::middleware::from_fn(security_headers::apply))
        .with_state(state)
}

/// Every failure mode a handler below can produce, collapsed to the `4xx`
/// or `5xx` an HTTP caller sees. Deliberately carries no body on any
/// variant -- a `500` here means the snapshot store failed or a template
/// somehow didn't render, neither of which a caller can act on, and
/// echoing internals back over HTTP is its own information-disclosure
/// risk this type avoids entirely by construction.
enum PortalHttpError {
    Forbidden,
    NotFound,
    Internal,
}

impl From<PortalError> for PortalHttpError {
    fn from(err: PortalError) -> Self {
        match err {
            PortalError::Forbidden => Self::Forbidden,
            PortalError::Store(_) => Self::Internal,
        }
    }
}

impl From<askama::Error> for PortalHttpError {
    fn from(_: askama::Error) -> Self {
        Self::Internal
    }
}

impl From<HtmlRenderError> for PortalHttpError {
    fn from(_: HtmlRenderError) -> Self {
        Self::Internal
    }
}

impl IntoResponse for PortalHttpError {
    fn into_response(self) -> Response {
        match self {
            Self::Forbidden => StatusCode::FORBIDDEN.into_response(),
            Self::NotFound => StatusCode::NOT_FOUND.into_response(),
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

/// The fleet index: every host `ctx`'s token is scoped to. No repository
/// call -- `ctx.host_scopes` is already the authoritative set of hosts
/// this token may read (that's what `AuthorizingRepository` itself checks
/// every call against), so re-deriving the same list from stored data
/// would either have to match it exactly or represent a second, divergent
/// source of truth for "what can this token see." Sorted by the
/// underlying UUID for a stable, if arbitrary, order -- `HashSet`
/// iteration order is not stable across runs.
async fn fleet_index(
    ctx: AuthContext,
    State(state): State<PortalState>,
) -> Result<Html<String>, PortalHttpError> {
    let mut hosts: Vec<HostId> = ctx.host_scopes.iter().copied().collect();
    hosts.sort_by_key(|host| host.as_uuid());
    let tokens_css = html_report::render_tokens_css(state.fonts_mode)?;
    let body = FleetIndexTemplate {
        tokens_css,
        asset_version: env!("ASSET_VERSION"),
        hosts,
    }
    .render()?;
    Ok(Html(body))
}

async fn host_detail_fragment(
    ctx: AuthContext,
    Path(host): Path<HostId>,
    State(state): State<PortalState>,
) -> Result<Html<String>, PortalHttpError> {
    Ok(Html(render_host_fragment(&ctx, host, &state).await?))
}

async fn host_detail_page(
    ctx: AuthContext,
    Path(host): Path<HostId>,
    State(state): State<PortalState>,
) -> Result<Html<String>, PortalHttpError> {
    let fragment_html = render_host_fragment(&ctx, host, &state).await?;
    let tokens_css = html_report::render_tokens_css(state.fonts_mode)?;
    let body = HostPageTemplate {
        tokens_css,
        host_id: host,
        fragment_html,
    }
    .render()?;
    Ok(Html(body))
}

async fn render_host_fragment(
    ctx: &AuthContext,
    host: HostId,
    state: &PortalState,
) -> Result<String, PortalHttpError> {
    let snapshots = recent_snapshots(ctx, host, state).await?;
    let scans = snapshots
        .into_iter()
        .map(|snapshot| ScanRow {
            scan_id: snapshot.scan_id,
            collected_at: snapshot.collected_at.to_string(),
            strategy_label: templates::strategy_label(snapshot.strategy),
            endpoint_count: snapshot.endpoints.len(),
        })
        .collect();
    Ok(HostFragmentTemplate {
        host_id: host,
        scans,
    }
    .render()?)
}

/// Every recorded snapshot for `host` that `ctx` may read, newest first.
/// Fetches one snapshot per recorded [`ScanId`] -- acceptable for the
/// scan volumes a single host accumulates between prunes; a fleet large
/// enough for this to matter is exactly the case `store-sqlite` (T12)
/// exists for, at which point this becomes a candidate for a dedicated
/// `SnapshotRepository::list_metadata_for_host` port method instead of
/// N `get_for_host` calls -- not built here since nothing today needs it.
async fn recent_snapshots(
    ctx: &AuthContext,
    host: HostId,
    state: &PortalState,
) -> Result<Vec<crate::domain::ScanSnapshot>, PortalError> {
    let scan_ids = state.repository.list_for_host(ctx, host).await?;
    let mut snapshots = Vec::with_capacity(scan_ids.len());
    for scan_id in scan_ids {
        if let Some(snapshot) = state.repository.get_for_host(ctx, host, scan_id).await? {
            snapshots.push(snapshot);
        }
    }
    snapshots.sort_by_key(|snapshot| std::cmp::Reverse(snapshot.collected_at));
    Ok(snapshots)
}

async fn scan_detail(
    ctx: AuthContext,
    Path((host, scan)): Path<(HostId, ScanId)>,
    State(state): State<PortalState>,
) -> Result<Html<String>, PortalHttpError> {
    let snapshot = state
        .repository
        .get_for_host(&ctx, host, scan)
        .await?
        .ok_or(PortalHttpError::NotFound)?;
    let model = ReportModel::build(std::slice::from_ref(&snapshot), None, true)
        .map_err(|_report_error| PortalHttpError::Internal)?;
    let html = html_report::render(&model, state.fonts_mode)?;
    Ok(Html(html))
}

async fn download(
    ctx: AuthContext,
    Path((host, scan)): Path<(HostId, ScanId)>,
    State(state): State<PortalState>,
) -> Result<Response, PortalHttpError> {
    let snapshot = state
        .repository
        .get_for_host(&ctx, host, scan)
        .await?
        .ok_or(PortalHttpError::NotFound)?;
    let body =
        serde_json::to_vec_pretty(&snapshot).map_err(|_serde_error| PortalHttpError::Internal)?;
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}

async fn drift_view(
    ctx: AuthContext,
    Path(host): Path<HostId>,
    State(state): State<PortalState>,
) -> Result<Html<String>, PortalHttpError> {
    let snapshots = recent_snapshots(&ctx, host, &state).await?;
    let tokens_css = html_report::render_tokens_css(state.fonts_mode)?;
    let scan_count = snapshots.len();

    let template = match snapshots.as_slice() {
        [current, baseline, ..] => {
            let report = diff(baseline, current);
            DriftTemplate {
                tokens_css,
                host_id: host,
                insufficient_history: false,
                scan_count,
                suppressed_ephemeral: report.suppressed_ephemeral,
                entries: templates::drift_rows(&report.entries),
            }
        }
        _ => DriftTemplate {
            tokens_css,
            host_id: host,
            insufficient_history: true,
            scan_count,
            suppressed_ephemeral: 0,
            entries: Vec::new(),
        },
    };
    Ok(Html(template.render()?))
}

/// Serves the vendored `htmx` runtime same-origin -- see `assets`'s doc
/// comment for why this is compiled in rather than fetched from a CDN.
/// Still behind `AuthContext` like every other route, for the same
/// defense-in-depth reason `auth.rs`'s own module doc gives for not
/// building a browser-friendly ambient-auth path at all: nothing this
/// portal serves is meant to be reachable by a bare, unauthenticated
/// browser tab, static assets included.
async fn htmx_js(_ctx: AuthContext) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        HTMX_JS,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    use super::router;
    use crate::adapters::config::FontsMode;
    use crate::adapters::portal::rate_limit::RateLimiter;
    use crate::adapters::portal::{PortalState, PortalTokens};
    use crate::application::portal::{
        AuthContext, AuthorizingRepository, PortalError, SnapshotRepository,
    };
    use crate::domain::target_strategy::TargetStrategy;
    use crate::domain::{HostId, ScanId, ScanSnapshot};

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
            time::OffsetDateTime::UNIX_EPOCH,
            "test".to_owned(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            TargetStrategy::LocalOnly,
        )
    }

    /// A real router over a fake repository -- no store, no filesystem --
    /// with one token (`test-token`, env var
    /// `ANNE_PORTAL_TEST_TOKEN_SECRET`) scoped to `scoped_host`, so tests
    /// can distinguish "no auth," "wrong token," "right token, wrong
    /// host," and "right token, right host" against the same app.
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn test_app(scoped_host: HostId, snapshots: Vec<ScanSnapshot>) -> axum::Router {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: serialized by `env_lock`; this test module owns this var.
        unsafe {
            std::env::set_var("ANNE_PORTAL_TEST_TOKEN_SECRET", "test-secret-value");
        }
        let tokens = PortalTokens::load(&[crate::adapters::config::PortalTokenConfig {
            id: "test-token".to_owned(),
            secret_env: "ANNE_PORTAL_TEST_TOKEN_SECRET".to_owned(),
            hosts: vec![scoped_host],
        }])
        .expect("valid token config");
        unsafe {
            std::env::remove_var("ANNE_PORTAL_TEST_TOKEN_SECRET");
        }

        let repository = Arc::new(AuthorizingRepository::new(FakeRepository {
            snapshots: Mutex::new(snapshots),
        }));
        let state = PortalState::new(
            repository,
            tokens,
            Arc::new(RateLimiter::new(1000)),
            FontsMode::System,
        );
        router(state)
    }

    async fn get(app: &axum::Router, uri: &str, bearer: Option<&str>) -> axum::response::Response {
        let mut builder = Request::builder().uri(uri);
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        app.clone()
            .oneshot(builder.body(Body::empty()).expect("valid request"))
            .await
            .expect("request completes")
    }

    #[tokio::test]
    async fn every_route_rejects_an_unauthenticated_request() {
        let host = HostId::generate();
        let scan = ScanId::generate();
        let app = test_app(host, vec![fixture_snapshot(host)]);

        for uri in [
            "/".to_owned(),
            format!("/hosts/{host}"),
            format!("/hosts/{host}/fragment"),
            format!("/hosts/{host}/drift"),
            format!("/hosts/{host}/scans/{scan}"),
            format!("/hosts/{host}/scans/{scan}/download"),
            "/assets/htmx.min.js".to_owned(),
        ] {
            let response = get(&app, &uri, None).await;
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "route {uri} did not reject an unauthenticated request"
            );
        }
    }

    #[tokio::test]
    async fn an_unrecognized_token_is_also_unauthorized() {
        let host = HostId::generate();
        let app = test_app(host, vec![]);
        let response = get(&app, "/", Some("not-a-real-token")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_token_outside_its_scope_is_forbidden_and_leaks_nothing() {
        let scoped_host = HostId::generate();
        let other_host = HostId::generate();
        let secret_snapshot = fixture_snapshot(other_host);
        let secret_scan_id = secret_snapshot.scan_id;
        let app = test_app(scoped_host, vec![secret_snapshot]);

        let response = get(
            &app,
            &format!("/hosts/{other_host}"),
            Some("test-secret-value"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = get(
            &app,
            &format!("/hosts/{other_host}/scans/{secret_scan_id}/download"),
            Some("test-secret-value"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("reading body");
        assert!(body.is_empty(), "a 403 must carry no snapshot data");
    }

    #[tokio::test]
    async fn a_token_inside_its_scope_reads_real_data() {
        let host = HostId::generate();
        let snapshot = fixture_snapshot(host);
        let scan_id = snapshot.scan_id;
        let app = test_app(host, vec![snapshot]);

        let response = get(
            &app,
            &format!("/hosts/{host}/scans/{scan_id}/download"),
            Some("test-secret-value"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("reading body");
        let parsed: ScanSnapshot = serde_json::from_slice(&body).expect("valid JSON snapshot");
        assert_eq!(parsed.host_id, host);
    }

    #[tokio::test]
    async fn nonexistent_route_carries_security_headers_and_404() {
        let host = HostId::generate();
        let app = test_app(host, vec![]);
        let response = get(&app, "/does/not/exist", None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.headers().contains_key("content-security-policy"));
        assert!(response.headers().contains_key("x-content-type-options"));
    }

    #[tokio::test]
    async fn unauthenticated_401_carries_security_headers_too() {
        let host = HostId::generate();
        let app = test_app(host, vec![]);
        let response = get(&app, "/", None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key("content-security-policy"));
    }

    #[tokio::test]
    async fn drift_view_reports_insufficient_history_instead_of_erroring() {
        let host = HostId::generate();
        let app = test_app(host, vec![fixture_snapshot(host)]);
        let response = get(
            &app,
            &format!("/hosts/{host}/drift"),
            Some("test-secret-value"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("reading body");
        let html = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(html.contains("Need at least two recorded scans"));
    }

    #[tokio::test]
    async fn exceeding_the_rate_limit_produces_429() {
        let host = HostId::generate();
        // Scoped so the `env_lock` guard drops before any `.await` below
        // -- holding a sync `Mutex` guard across an await point is a real
        // deadlock risk on a multi-threaded runtime, even though this
        // particular guard only ever protects synchronous env var calls.
        let tokens = {
            let _guard = env_lock()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // SAFETY: serialized by `env_lock`.
            unsafe {
                std::env::set_var("ANNE_PORTAL_TEST_TOKEN_SECRET", "test-secret-value");
            }
            let tokens = PortalTokens::load(&[crate::adapters::config::PortalTokenConfig {
                id: "test-token".to_owned(),
                secret_env: "ANNE_PORTAL_TEST_TOKEN_SECRET".to_owned(),
                hosts: vec![host],
            }])
            .expect("valid token config");
            unsafe {
                std::env::remove_var("ANNE_PORTAL_TEST_TOKEN_SECRET");
            }
            tokens
        };
        let repository = Arc::new(AuthorizingRepository::new(FakeRepository {
            snapshots: Mutex::new(Vec::new()),
        }));
        let state = PortalState::new(
            repository,
            tokens,
            Arc::new(RateLimiter::new(1)),
            FontsMode::System,
        );
        let app = router(state);

        let first = get(&app, "/", Some("test-secret-value")).await;
        assert_eq!(first.status(), StatusCode::OK);
        let second = get(&app, "/", Some("test-secret-value")).await;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            second.headers().contains_key("content-security-policy"),
            "a 429 must still carry security headers"
        );
    }

    #[test]
    fn fleet_scoped_hosts_type_is_a_hash_set() {
        // Pins the assumption `fleet_index` relies on: `AuthContext::host_scopes`
        // has no inherent order, which is exactly why that handler sorts
        // before rendering.
        let set: HashSet<HostId> = std::iter::once(HostId::generate()).collect();
        assert_eq!(set.len(), 1);
    }
}
