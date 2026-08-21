//! Fixed-window request budget, wired as an `axum` middleware layer.
//!
//! # Why hand-rolled instead of a crate
//!
//! Neither `tower`'s own `RateLimitLayer` nor `tower-http` (both already
//! in this crate's dependency graph via `axum`/`reqwest`) fit: `tower`'s
//! is a single global leaky bucket shared by every caller, with no notion
//! of a per-key budget, and `tower-http` ships no rate-limiting layer at
//! all. A real per-key limiter for the `tower` ecosystem exists
//! (`tower_governor`, built on the `governor` crate) but neither is
//! anywhere in this workspace's `Cargo.lock` today -- pulling either in
//! for one fixed-window counter would be a heavier dependency than the
//! ~30 lines this module needs. [`RateLimiter`] is that: one
//! `Mutex<HashMap<key, bucket>>`, reset every 60 seconds per key, with no
//! claim to be a general-purpose limiter -- if a future task needs a
//! sliding window, per-route budgets, or distributed state across
//! multiple portal processes, that's a real reason to reach for
//! `governor` then, not now.
//!
//! # Why keyed by token, falling back to source IP
//!
//! This feature is bearer-token authenticated (see `auth`'s module doc
//! comment for why, not cookies) -- once a request presents a valid
//! token, [`PortalTokens::authenticate`] resolves it to a stable
//! `token_id`, and budgeting by that identity is more meaningful than by
//! network address (one caller behind a NAT/reverse proxy shouldn't share
//! a budget with every other caller behind the same address, and one
//! caller rotating source addresses shouldn't dodge its own budget).
//! Requests that never authenticate -- no header, wrong scheme, or a
//! token that matches nothing -- have no `token_id` to key on; those fall
//! back to the connecting peer's IP address (via `ConnectInfo`, populated
//! by `axum::serve(...).into_make_service_with_connect_info::<SocketAddr>()`
//! in `examples/portal_server.rs`), so repeated credential-guessing from
//! one address still exhausts a budget rather than running unbounded.
//! This duplicates the `Authorization` header parse `auth::AuthContext`'s
//! own extractor already does later in the same request -- deliberately:
//! this middleware runs *before* routing, as a `Router::layer`, so it has
//! no access to an already-extracted `AuthContext` even if the route
//! being hit has one. The duplicate parse is cheap (one header lookup,
//! one SHA-256, already-hashed comparisons) and never itself grants or
//! denies access -- only `AuthContext`'s extractor does that.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::PortalState;
use super::auth::bearer_token;

const WINDOW: Duration = Duration::from_mins(1);

struct Bucket {
    window_start: Instant,
    count: u32,
}

/// A fixed-window request counter, one window per key, reset lazily the
/// first time a key is seen again after its window has elapsed.
pub struct RateLimiter {
    budget_per_window: u32,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    #[must_use]
    pub fn new(budget_per_window: u32) -> Self {
        Self {
            budget_per_window,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Records one request against `key`'s current window, returning
    /// whether it stays within budget. `budget_per_window == 0` denies
    /// every request outright -- a deliberately usable, fail-secure
    /// configuration (an operator can set `rate_limit_per_minute = 0` to
    /// take the portal fully offline for maintenance without stopping
    /// the process).
    // `buckets` has to stay locked for the whole read-reset-increment
    // sequence below -- there's no way to shrink that further without
    // either a second lock acquisition (races two callers against the
    // same key) or cloning `Bucket` out and writing it back (same race).
    // clippy's own suggested one-line rewrite for this lint doesn't
    // actually borrow-check (the `MutexGuard` temporary it produces gets
    // dropped at the end of that statement, before `bucket` is used
    // below it) -- verified by trying it, not assumed.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the lock must cover the whole read-reset-increment sequence; see comment above"
    )]
    fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bucket = buckets.entry(key.to_owned()).or_insert(Bucket {
            window_start: now,
            count: 0,
        });
        if now.duration_since(bucket.window_start) >= WINDOW {
            bucket.window_start = now;
            bucket.count = 0;
        }
        if bucket.count >= self.budget_per_window {
            false
        } else {
            bucket.count += 1;
            true
        }
    }
}

/// The `Router::layer` entry point: rejects with `429` once `state`'s
/// limiter reports the caller's key is over budget, otherwise passes the
/// request through unchanged. Runs ahead of routing (see the module doc
/// comment), so this applies uniformly to every route, including ones
/// that 404 or ones the caller never successfully authenticates against.
pub async fn enforce(State(state): State<PortalState>, request: Request, next: Next) -> Response {
    let key = budget_key(&state, &request);
    if state.rate_limiter.check(&key) {
        next.run(request).await
    } else {
        StatusCode::TOO_MANY_REQUESTS.into_response()
    }
}

fn budget_key(state: &PortalState, request: &Request) -> String {
    if let Some(token) = bearer_token(request.headers())
        && let Some(ctx) = state.tokens.authenticate(token)
    {
        return format!("token:{}", ctx.token_id);
    }
    let addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or_else(|| "unknown".to_owned(), |info| info.0.ip().to_string());
    format!("ip:{addr}")
}

#[cfg(test)]
mod tests {
    use super::RateLimiter;

    #[test]
    fn requests_within_budget_all_pass() {
        let limiter = RateLimiter::new(3);
        assert!(limiter.check("a"));
        assert!(limiter.check("a"));
        assert!(limiter.check("a"));
    }

    #[test]
    fn the_request_over_budget_is_rejected() {
        let limiter = RateLimiter::new(2);
        assert!(limiter.check("a"));
        assert!(limiter.check("a"));
        assert!(!limiter.check("a"));
    }

    #[test]
    fn distinct_keys_have_independent_budgets() {
        let limiter = RateLimiter::new(1);
        assert!(limiter.check("a"));
        assert!(!limiter.check("a"));
        assert!(limiter.check("b"));
    }

    #[test]
    fn zero_budget_denies_everything() {
        let limiter = RateLimiter::new(0);
        assert!(!limiter.check("a"));
    }
}
