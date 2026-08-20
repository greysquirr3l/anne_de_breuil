//! [`HttpProber`]: the [`Prober`] port implemented against `reqwest`.
//!
//! Read-only and minimal, per T09's scope: a plaintext GET of `/` and a
//! handful of common read-only paths, one HTTPS GET with normal (never
//! bypassed) certificate validation, and nothing else. Never any HTTP
//! method but GET, never a redirect followed off the connecting host,
//! never credentials sent. Deep TLS certificate-chain inspection with
//! relaxed validation is out of scope here by design — this prober's own
//! HTTPS attempt keeps normal validation always on. See
//! [`crate::adapters::tls_probe::TlsProber`] for the sibling prober that
//! does the relaxed-validation inspection, confined to its own module.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::{Mutex as TokioMutex, Semaphore};

use crate::application::identify::{ProbeConfig, ProbeError, Prober};
use crate::domain::{Endpoint, Evidence};

/// A short, defensible list of common read-only paths. This is read-only
/// recon, not a wordlist scan — kept deliberately small.
const CANDIDATE_PATHS: [&str; 4] = ["/", "/status", "/health", "/metrics"];

/// Response headers whose presence, absence, or weakness is itself a
/// finding.
const REQUIRED_SECURITY_HEADERS: [&str; 5] = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
];

/// Headers that disclose server/software version information.
const VERSION_DISCLOSURE_HEADERS: [&str; 3] = ["server", "x-powered-by", "x-aspnet-version"];

/// Header names whose values must never reach persisted [`Evidence`] —
/// dropped entirely, not merely masked, before any `Evidence::HttpHeader`
/// is constructed.
const REDACTED_HEADERS: [&str; 2] = ["set-cookie", "authorization"];

/// Per-host probing state: the concurrency gate and the running count
/// toward `max_probes_per_host`.
struct HostState {
    semaphore: Arc<Semaphore>,
    issued: usize,
}

/// HTTP-based [`Prober`] implementation.
///
/// Holds one pooled `reqwest::Client` (built once, with redirects disabled
/// entirely — the simplest way to guarantee a redirect is never followed
/// off the target host) plus the bookkeeping needed to make
/// [`ProbeConfig`]'s bounds real: a per-host `Semaphore` for
/// `max_concurrent_per_host`, a per-host counter for `max_probes_per_host`,
/// and a shared gate for `min_probe_interval`.
pub struct HttpProber {
    config: ProbeConfig,
    user_agent: String,
    client: reqwest::Client,
    host_state: StdMutex<HashMap<IpAddr, HostState>>,
    rate_gate: TokioMutex<Option<Instant>>,
}

impl HttpProber {
    /// Builds a prober with its own connection pool.
    ///
    /// # Errors
    ///
    /// Returns [`ProbeError::ClientBuild`] if the underlying HTTP client
    /// cannot be constructed.
    pub fn new(config: ProbeConfig) -> Result<Self, ProbeError> {
        let user_agent = format!(
            "anne-de-breuil/{} (+scanner; see logs)",
            env!("CARGO_PKG_VERSION")
        );
        let client = reqwest::Client::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.read_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(user_agent.clone())
            .build()
            .map_err(|err| ProbeError::ClientBuild(err.to_string()))?;
        Ok(Self::from_client(config, user_agent, client))
    }

    /// Builds a prober around an already-constructed client. Exists so
    /// tests can inject a client with a DNS resolver override (to prove a
    /// redirect target is never contacted) without duplicating the
    /// production builder settings.
    fn from_client(config: ProbeConfig, user_agent: String, client: reqwest::Client) -> Self {
        Self {
            config,
            user_agent,
            client,
            host_state: StdMutex::new(HashMap::new()),
            rate_gate: TokioMutex::new(None),
        }
    }

    /// The User-Agent every request identifies itself with.
    #[must_use]
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    /// Reserves one slot of this host's probe budget and returns a permit
    /// that must be held for the probe's duration, enforcing
    /// `max_concurrent_per_host`.
    async fn reserve_host_budget(
        &self,
        ip: IpAddr,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, ProbeError> {
        let semaphore = {
            let mut hosts = self
                .host_state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let state = hosts.entry(ip).or_insert_with(|| HostState {
                semaphore: Arc::new(Semaphore::new(self.config.max_concurrent_per_host)),
                issued: 0,
            });
            if state.issued >= self.config.max_probes_per_host {
                return Err(ProbeError::HostBudgetExhausted);
            }
            state.issued += 1;
            Arc::clone(&state.semaphore)
        };
        semaphore
            .acquire_owned()
            .await
            .map_err(|_closed| ProbeError::HostBudgetExhausted)
    }

    /// Blocks until at least `min_probe_interval` has passed since the
    /// last call, across every host this prober instance has ever probed.
    async fn throttle(&self) {
        let mut gate = self.rate_gate.lock().await;
        let now = Instant::now();
        if let Some(next_allowed) = *gate
            && next_allowed > now
        {
            tokio::time::sleep(next_allowed - now).await;
        }
        *gate = Some(Instant::now() + self.config.min_probe_interval);
    }

    /// Issues one GET, capping the body read at `max_response_bytes`.
    /// Never any method but GET.
    async fn attempt_get(&self, url: &str) -> Result<ProbeResponse, reqwest::Error> {
        let resp = self.client.get(url).send().await?;
        let headers = resp.headers().clone();
        let body_bytes = read_capped(resp, self.config.max_response_bytes).await?;
        Ok(ProbeResponse {
            headers,
            body: decode_capped_body(&body_bytes),
        })
    }
}

/// The parts of an HTTP response this adapter derives evidence from.
struct ProbeResponse {
    headers: reqwest::header::HeaderMap,
    body: String,
}

#[async_trait]
impl Prober for HttpProber {
    async fn probe(&self, endpoint: &Endpoint) -> Result<Vec<Evidence>, ProbeError> {
        let ip = endpoint.bind_address.ip();
        let port = endpoint.port.get();

        if self.config.exclude.excludes(ip, port) {
            return Err(ProbeError::Excluded);
        }

        let _host_permit = self.reserve_host_budget(ip).await?;

        let mut evidence = Vec::new();
        let host = host_for_url(ip);
        let mut plaintext_http_succeeded = false;

        for path in CANDIDATE_PATHS {
            self.throttle().await;
            let url = format!("http://{host}:{port}{path}");
            if let Ok(response) = self.attempt_get(&url).await {
                plaintext_http_succeeded = true;
                evidence_from_response(&response, &mut evidence);
            }
        }

        self.throttle().await;
        let https_url = format!("https://{host}:{port}/");
        match self.attempt_get(&https_url).await {
            Ok(response) => {
                evidence.push(Evidence::BannerMatch {
                    pattern: "tls-handshake:success".to_owned(),
                });
                evidence_from_response(&response, &mut evidence);
                if port == 80 {
                    evidence.push(Evidence::BannerMatch {
                        pattern: "tls-on-typical-plaintext-port".to_owned(),
                    });
                }
            }
            Err(_) => {
                // A failed handshake (including one rejected because the
                // target presents a self-signed/untrusted certificate) is
                // itself a valid T09-scope outcome, not an error to work
                // around. Never relax certificate validation to see more —
                // that inspection lives in the deliberately separate
                // `TlsProber`, confined to its own module.
                evidence.push(Evidence::BannerMatch {
                    pattern: "tls-handshake:failed".to_owned(),
                });
            }
        }

        if plaintext_http_succeeded && port == 443 {
            evidence.push(Evidence::BannerMatch {
                pattern: "plaintext-http-on-typical-tls-port".to_owned(),
            });
        }

        Ok(evidence)
    }
}

/// Formats `ip` for use inside an `http(s)://host:port/` URL, bracketing
/// IPv6 addresses as the URL grammar requires.
fn host_for_url(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

/// Reads a response body up to `cap` bytes, dropping the rest unread
/// rather than buffering an unbounded amount before truncating.
async fn read_capped(mut resp: reqwest::Response, cap: usize) -> Result<Vec<u8>, reqwest::Error> {
    let mut buf = Vec::with_capacity(cap.min(8192));
    while buf.len() < cap {
        let Some(chunk) = resp.chunk().await? else {
            break;
        };
        let remaining = cap - buf.len();
        if chunk.len() <= remaining {
            buf.extend_from_slice(&chunk);
        } else {
            buf.extend_from_slice(&chunk.slice(0..remaining));
            break;
        }
    }
    Ok(buf)
}

/// Decodes a byte-capped response body to text using
/// [`str::floor_char_boundary`] (stable 1.91) so the result never splits a
/// UTF-8 codepoint and never exceeds the original byte cap. A lossy decode
/// alone guarantees the former but not the latter — each `U+FFFD`
/// replacement character is 3 bytes and can be wider than the invalid
/// byte(s) it stands in for, so a naive `from_utf8_lossy` can grow past the
/// cap it was meant to respect.
fn decode_capped_body(bytes: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(bytes).into_owned();
    let boundary = lossy.floor_char_boundary(bytes.len().min(lossy.len()));
    lossy.get(..boundary).unwrap_or(&lossy).to_owned()
}

/// Derives [`Evidence`] from one probe response: redacted raw headers,
/// version-disclosure findings, missing/weak security-header findings, and
/// the (already byte-capped) body.
fn evidence_from_response(response: &ProbeResponse, evidence: &mut Vec<Evidence>) {
    for (name, value) in &response.headers {
        let lower = name.as_str().to_ascii_lowercase();
        if REDACTED_HEADERS.contains(&lower.as_str()) {
            continue;
        }
        let Ok(value_str) = value.to_str() else {
            continue;
        };
        evidence.push(Evidence::HttpHeader {
            name: name.as_str().to_owned(),
            value: value_str.to_owned(),
        });
        if VERSION_DISCLOSURE_HEADERS.contains(&lower.as_str()) {
            evidence.push(Evidence::BannerMatch {
                pattern: format!("version-disclosure:{lower}={value_str}"),
            });
        }
    }

    for header in REQUIRED_SECURITY_HEADERS {
        let present = response
            .headers
            .iter()
            .any(|(name, _value)| name.as_str().eq_ignore_ascii_case(header));
        if !present {
            evidence.push(Evidence::BannerMatch {
                pattern: format!("missing-security-header:{header}"),
            });
        }
    }

    if let Some(hsts) = response.headers.get("strict-transport-security")
        && let Ok(value) = hsts.to_str()
        && hsts_is_weak(value)
    {
        evidence.push(Evidence::BannerMatch {
            pattern: "weak-security-header:strict-transport-security".to_owned(),
        });
    }

    if !response.body.is_empty() {
        evidence.push(Evidence::HttpBodyPattern {
            snippet: response.body.clone(),
        });
    }
}

/// `true` if an HSTS header value lacks `includeSubDomains` or sets a
/// `max-age` under roughly six months.
fn hsts_is_weak(value: &str) -> bool {
    const WEAK_MAX_AGE_THRESHOLD_SECONDS: u64 = 15_768_000;

    if !value.to_ascii_lowercase().contains("includesubdomains") {
        return true;
    }
    let Some(max_age) = value
        .split(';')
        .find_map(|part| part.trim().strip_prefix("max-age="))
    else {
        return true;
    };
    max_age
        .trim()
        .parse::<u64>()
        .is_ok_and(|age| age < WEAK_MAX_AGE_THRESHOLD_SECONDS)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::net::SocketAddr;
    use std::str::FromStr as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    use super::{
        Arc, Endpoint, HttpProber, Instant, PoisonError, ProbeConfig, StdMutex, decode_capped_body,
    };
    use crate::application::identify::{ProbeExclusions, Prober as _};
    use crate::domain::{BindAddress, Evidence, Port, Protocol, SignatureStatus};

    /// One fixture HTTP/1.1 response, minimal by design — this project
    /// hand-rolls a raw-socket fixture server rather than pull in a full
    /// HTTP framework dev-dependency just to control slow/oversized/
    /// redirecting responses exactly.
    struct ResponsePlan {
        status_line: &'static str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        pre_delay: Duration,
    }

    struct FixtureServer {
        addr: SocketAddr,
        methods_seen: Arc<StdMutex<Vec<String>>>,
        _handle: JoinHandle<()>,
    }

    impl FixtureServer {
        async fn spawn<F>(behavior: F) -> Self
        where
            F: Fn(&str) -> ResponsePlan + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            let behavior = Arc::new(behavior);
            let methods_seen = Arc::new(StdMutex::new(Vec::new()));
            let methods_for_task = Arc::clone(&methods_seen);
            let handle = tokio::spawn(async move {
                loop {
                    let Ok((stream, _peer)) = listener.accept().await else {
                        break;
                    };
                    let behavior = Arc::clone(&behavior);
                    let methods = Arc::clone(&methods_for_task);
                    tokio::spawn(handle_connection(stream, behavior, methods));
                }
            });
            Self {
                addr,
                methods_seen,
                _handle: handle,
            }
        }

        fn endpoint(&self) -> Endpoint {
            endpoint_for(self.addr)
        }

        fn methods_seen(&self) -> Vec<String> {
            self.methods_seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    async fn handle_connection(
        mut stream: TcpStream,
        behavior: Arc<dyn Fn(&str) -> ResponsePlan + Send + Sync>,
        methods: Arc<StdMutex<Vec<String>>>,
    ) {
        let mut buf = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
                    if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                    if buf.len() > 16 * 1024 {
                        return;
                    }
                }
            }
        }

        let text = String::from_utf8_lossy(&buf);
        let request_line = text.lines().next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_owned();
        let path = parts.next().unwrap_or("/").to_owned();
        methods
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(method);

        let plan = behavior(&path);
        if plan.pre_delay > Duration::ZERO {
            tokio::time::sleep(plan.pre_delay).await;
        }

        let mut response = format!("{}\r\n", plan.status_line);
        for (name, value) in &plan.headers {
            let _ = write!(response, "{name}: {value}\r\n");
        }
        let _ = write!(response, "Content-Length: {}\r\n\r\n", plan.body.len());
        let mut out = response.into_bytes();
        out.extend_from_slice(&plan.body);
        let _ = stream.write_all(&out).await;
        let _ = stream.shutdown().await;
    }

    /// A listener that only ever counts real accepted connections — used
    /// to prove, at the socket layer, that an excluded or off-host target
    /// was never contacted.
    struct WatchedListener {
        addr: SocketAddr,
        connection_count: Arc<AtomicUsize>,
        _handle: JoinHandle<()>,
    }

    impl WatchedListener {
        async fn bind() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            let connection_count = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&connection_count);
            let handle = tokio::spawn(async move {
                loop {
                    let Ok((_stream, _peer)) = listener.accept().await else {
                        break;
                    };
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            });
            Self {
                addr,
                connection_count,
                _handle: handle,
            }
        }

        fn connections(&self) -> usize {
            self.connection_count.load(Ordering::SeqCst)
        }
    }

    fn endpoint_for(addr: SocketAddr) -> Endpoint {
        Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str(&addr.ip().to_string()).expect("valid ip"),
            Port::try_from(addr.port()).expect("valid port"),
            None,
            None,
            vec![],
            SignatureStatus::Unknown,
        )
    }

    mod fixtures {
        use super::{
            Duration, FixtureServer, HttpProber, ProbeConfig, ProbeExclusions, ResponsePlan,
        };

        pub(super) async fn server_returning_bytes(n: usize) -> FixtureServer {
            let body = vec![b'A'; n];
            FixtureServer::spawn(move |_path| ResponsePlan {
                status_line: "HTTP/1.1 200 OK",
                headers: vec![("Content-Type".to_owned(), "text/plain".to_owned())],
                body: body.clone(),
                pre_delay: Duration::ZERO,
            })
            .await
        }

        pub(super) async fn server_redirecting_to(location: &str) -> FixtureServer {
            let location = location.to_owned();
            FixtureServer::spawn(move |_path| ResponsePlan {
                status_line: "HTTP/1.1 302 Found",
                headers: vec![("Location".to_owned(), location.clone())],
                body: Vec::new(),
                pre_delay: Duration::ZERO,
            })
            .await
        }

        pub(super) async fn server_with_headers(
            headers: Vec<(&'static str, &'static str)>,
        ) -> FixtureServer {
            let headers: Vec<(String, String)> = headers
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect();
            FixtureServer::spawn(move |_path| ResponsePlan {
                status_line: "HTTP/1.1 200 OK",
                headers: headers.clone(),
                body: b"ok".to_vec(),
                pre_delay: Duration::ZERO,
            })
            .await
        }

        pub(super) async fn server_stalling(delay: Duration) -> FixtureServer {
            FixtureServer::spawn(move |_path| ResponsePlan {
                status_line: "HTTP/1.1 200 OK",
                headers: Vec::new(),
                body: b"late".to_vec(),
                pre_delay: delay,
            })
            .await
        }

        pub(super) fn prober_with_cap(cap: usize) -> HttpProber {
            HttpProber::new(ProbeConfig {
                max_response_bytes: cap,
                min_probe_interval: Duration::ZERO,
                connect_timeout: Duration::from_secs(2),
                read_timeout: Duration::from_secs(2),
                ..ProbeConfig::default()
            })
            .expect("client build")
        }

        pub(super) fn prober_excluding_port(port: u16) -> HttpProber {
            HttpProber::new(ProbeConfig {
                exclude: ProbeExclusions::new([port], Vec::new()),
                min_probe_interval: Duration::ZERO,
                ..ProbeConfig::default()
            })
            .expect("client build")
        }

        pub(super) fn default_prober() -> HttpProber {
            HttpProber::new(ProbeConfig {
                min_probe_interval: Duration::ZERO,
                connect_timeout: Duration::from_secs(2),
                read_timeout: Duration::from_secs(2),
                ..ProbeConfig::default()
            })
            .expect("client build")
        }
    }

    #[tokio::test]
    async fn oversized_body_is_truncated_at_cap() {
        let cap = 64 * 1024;
        let server = fixtures::server_returning_bytes(200 * 1024).await;
        let prober = fixtures::prober_with_cap(cap);

        let evidence = prober.probe(&server.endpoint()).await.unwrap();

        assert!(evidence.iter().any(|e| matches!(
            e,
            Evidence::HttpBodyPattern { snippet } if snippet.len() <= cap
        )));
    }

    #[tokio::test]
    async fn excluded_port_is_never_connected() {
        let listener = WatchedListener::bind().await;
        let prober = fixtures::prober_excluding_port(listener.addr.port());
        let endpoint = endpoint_for(listener.addr);

        let err = prober.probe(&endpoint).await.unwrap_err();

        assert!(matches!(err, super::ProbeError::Excluded));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(listener.connections(), 0);
    }

    #[tokio::test]
    async fn redirect_to_different_host_is_not_followed() {
        let sentinel = WatchedListener::bind().await;
        let server = fixtures::server_redirecting_to("http://example.invalid/").await;
        // Force "example.invalid" to resolve to the sentinel listener so a
        // redirect that were (bug) followed would show up as a real
        // connection to it — a stronger proof than trusting the redirect
        // policy alone.
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .resolve("example.invalid", sentinel.addr)
            .build()
            .expect("client build");
        let prober = HttpProber::from_client(
            ProbeConfig {
                min_probe_interval: Duration::ZERO,
                ..ProbeConfig::default()
            },
            "test-agent".to_owned(),
            client,
        );

        let evidence = prober.probe(&server.endpoint()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(sentinel.connections(), 0);
        assert!(evidence.iter().any(
            |e| matches!(e, Evidence::HttpHeader { name, .. } if name.eq_ignore_ascii_case("location"))
        ));
    }

    #[test]
    fn truncation_never_splits_a_multibyte_char() {
        let body = "café".repeat(100_000).into_bytes();
        let decoded = decode_capped_body(body.get(..250_003).unwrap_or(&body));
        assert!(std::str::from_utf8(decoded.as_bytes()).is_ok());
        assert!(decoded.len() <= 250_003);
    }

    #[tokio::test]
    async fn no_non_get_method_is_ever_issued() {
        let server = fixtures::server_returning_bytes(16).await;
        let prober = fixtures::default_prober();

        let _evidence = prober.probe(&server.endpoint()).await.unwrap();

        let methods = server.methods_seen();
        assert!(!methods.is_empty());
        assert!(methods.iter().all(|method| method == "GET"));
    }

    #[tokio::test]
    async fn slow_response_is_bounded_by_read_timeout() {
        let server = fixtures::server_stalling(Duration::from_secs(5)).await;
        let prober = HttpProber::new(ProbeConfig {
            connect_timeout: Duration::from_millis(500),
            read_timeout: Duration::from_millis(300),
            min_probe_interval: Duration::ZERO,
            ..ProbeConfig::default()
        })
        .expect("client build");

        let result =
            tokio::time::timeout(Duration::from_secs(3), prober.probe(&server.endpoint())).await;

        let evidence = result
            .expect("probe must not hang past its own configured per-request timeout")
            .unwrap();
        assert!(
            !evidence
                .iter()
                .any(|e| matches!(e, Evidence::HttpBodyPattern { .. }))
        );
    }

    #[tokio::test]
    async fn set_cookie_and_authorization_are_redacted() {
        let server = fixtures::server_with_headers(vec![
            ("Set-Cookie", "sid=SUPERSECRETCOOKIE; Path=/"),
            ("Authorization", "Bearer SUPERSECRETTOKEN"),
        ])
        .await;
        let prober = fixtures::default_prober();

        let evidence = prober.probe(&server.endpoint()).await.unwrap();

        let rendered = format!("{evidence:?}");
        assert!(!rendered.contains("SUPERSECRETCOOKIE"));
        assert!(!rendered.contains("SUPERSECRETTOKEN"));
    }

    #[tokio::test]
    async fn host_probe_budget_is_enforced() {
        let listener = WatchedListener::bind().await;
        let prober = HttpProber::new(ProbeConfig {
            max_probes_per_host: 1,
            connect_timeout: Duration::from_millis(200),
            read_timeout: Duration::from_millis(200),
            min_probe_interval: Duration::ZERO,
            ..ProbeConfig::default()
        })
        .expect("client build");
        let endpoint = endpoint_for(listener.addr);

        let first = prober.probe(&endpoint).await;
        assert!(first.is_ok());
        let connections_after_first = listener.connections();
        assert!(connections_after_first > 0);

        let second = prober.probe(&endpoint).await;
        assert!(matches!(
            second,
            Err(super::ProbeError::HostBudgetExhausted)
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(listener.connections(), connections_after_first);
    }

    #[tokio::test]
    async fn min_probe_interval_gates_successive_requests() {
        let server = fixtures::server_returning_bytes(4).await;
        let prober = HttpProber::new(ProbeConfig {
            min_probe_interval: Duration::from_millis(120),
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(2),
            ..ProbeConfig::default()
        })
        .expect("client build");

        let start = Instant::now();
        let _evidence = prober.probe(&server.endpoint()).await.unwrap();
        let elapsed = start.elapsed();

        // 5 requests (4 candidate paths + 1 TLS attempt) gated by a 120ms
        // floor between successive requests must together take at least
        // 4 * 120ms of enforced spacing.
        assert!(elapsed >= Duration::from_millis(4 * 120));
    }
}
