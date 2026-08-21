//! Response headers applied to every request this router serves,
//! including ones that never reach a handler at all (404s) and ones the
//! `AuthContext` extractor rejects (401s) -- wired as the outermost layer
//! in `router::router` specifically so it wraps every other layer and
//! every route, per this task's own tested requirement.
//!
//! # HSTS and `X-Forwarded-Proto`
//!
//! This crate ships no TLS termination of its own (see `Cargo.toml`'s
//! comment on why `axum`'s `http1`-only feature set was chosen) -- a real
//! deployment terminates TLS at a reverse proxy in front of this process,
//! which means the connection `axum::serve` itself sees is always plain
//! HTTP even when the original client used HTTPS. Sending
//! `Strict-Transport-Security` on a response the browser received over
//! plain HTTP is harmless (RFC 6797 requires browsers to ignore the
//! header unless it arrived over a secure channel) but pointless if this
//! process is genuinely exposed without TLS anywhere in front of it. The
//! signal used here is `X-Forwarded-Proto: https`, the de facto standard
//! header a TLS-terminating reverse proxy sets on the request it forwards
//! -- present and `https` means "trust that a secure hop happened
//! upstream," anything else means don't claim one did. This is a
//! response-header toggle, not an authorization decision: a client that
//! spoofs the header against its own request only ever affects the HSTS
//! instruction its own browser receives back, never another caller's
//! request or any auth/authz outcome, so trusting it here carries none of
//! the real risk `X-Forwarded-For`-based IP trust normally does.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::header::{
    CONTENT_SECURITY_POLICY, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::middleware::Next;
use axum::response::Response;

const CSP: HeaderValue = HeaderValue::from_static(
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
     img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
);
const NOSNIFF: HeaderValue = HeaderValue::from_static("nosniff");
const NO_REFERRER: HeaderValue = HeaderValue::from_static("no-referrer");
const DENY_FRAMING: HeaderValue = HeaderValue::from_static("DENY");
// One year, plus `includeSubDomains` -- the conventional strict baseline;
// no `preload` since this is an internal ops tool, not a public site that
// wants HSTS-preload-list submission.
const HSTS: HeaderValue = HeaderValue::from_static("max-age=31536000; includeSubDomains");

/// The `Router::layer` entry point. Calls `next.run` first, then stamps
/// headers onto whatever `Response` came back -- an error response from a
/// rejected extractor or an unmatched route is still a `Response` by the
/// time it reaches this point, so it gets the same treatment as a `200`.
pub async fn apply(request: Request, next: Next) -> Response {
    let forwarded_https = request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("https"));

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(CONTENT_SECURITY_POLICY, CSP);
    headers.insert(X_CONTENT_TYPE_OPTIONS, NOSNIFF);
    headers.insert(REFERRER_POLICY, NO_REFERRER);
    headers.insert(X_FRAME_OPTIONS, DENY_FRAMING);
    if forwarded_https {
        headers.insert(STRICT_TRANSPORT_SECURITY, HSTS);
    }
    response
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt as _;

    use super::apply;

    fn app() -> Router {
        Router::new()
            .route("/ok", get(|| async { "hi" }))
            .layer(axum::middleware::from_fn(apply))
    }

    #[tokio::test]
    async fn headers_present_on_a_successful_response() {
        let response = app()
            .oneshot(
                HttpRequest::builder()
                    .uri("/ok")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("request completes");
        assert!(response.headers().contains_key("content-security-policy"));
        assert!(response.headers().contains_key("x-content-type-options"));
        assert!(response.headers().contains_key("referrer-policy"));
        assert!(response.headers().contains_key("x-frame-options"));
    }

    #[tokio::test]
    async fn headers_present_on_a_404() {
        let response = app()
            .oneshot(
                HttpRequest::builder()
                    .uri("/does-not-exist")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("request completes");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.headers().contains_key("content-security-policy"));
        assert!(response.headers().contains_key("x-content-type-options"));
    }

    #[tokio::test]
    async fn hsts_absent_without_forwarded_proto_header() {
        let response = app()
            .oneshot(
                HttpRequest::builder()
                    .uri("/ok")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("request completes");
        assert!(!response.headers().contains_key("strict-transport-security"));
    }

    #[tokio::test]
    async fn hsts_present_when_forwarded_proto_claims_https() {
        let response = app()
            .oneshot(
                HttpRequest::builder()
                    .uri("/ok")
                    .header("x-forwarded-proto", "https")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("request completes");
        assert!(response.headers().contains_key("strict-transport-security"));
    }
}
