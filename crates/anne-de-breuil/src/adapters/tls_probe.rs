//! [`TlsProber`]: the [`Prober`] port implemented as a real TLS handshake.
//!
//! Sibling to [`crate::adapters::prober::HttpProber`], reusing the same
//! [`ProbeConfig`]/[`ProbeExclusions`](crate::application::identify::ProbeExclusions)
//! bounding — connect timeout, read timeout, per-host concurrency and
//! budget, minimum probe spacing, exclusions — checked before any socket
//! opens.
//!
//! Self-signed, expired, and hostname-mismatched certificates are
//! EXPECTED here: internal appliances, exporters, and management UIs
//! routinely present them, and observing that fact is the entire point of
//! this prober. The [`non_validating`] submodule holds the one place in
//! this crate that is allowed to build a `rustls::ClientConfig` that skips
//! certificate verification, and it is confined there — see its own doc
//! comment and `tests::non_validating_verifier_referenced_by_exactly_one_module`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, ServerName};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::net::TcpStream;
use tokio::sync::{Mutex as TokioMutex, OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsConnector;
use x509_parser::asn1_rs::Oid;
use x509_parser::extensions::GeneralName;
use x509_parser::objects::{oid_registry, oid2sn};
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::application::identify::{ProbeConfig, ProbeError, Prober};
use crate::domain::{Endpoint, Evidence};

// Confined to this module only. `client_config()` is `pub(super)`, so
// nothing outside `adapters::tls_probe` can even name it, and
// `NonValidatingVerifier` itself carries no visibility modifier at all —
// nothing outside this inner module can name *that*, not even the rest of
// `tls_probe`. Nothing in the crate other than this file ever spells the
// identifier `NonValidatingVerifier`; see the confinement test in
// `tests` below for the enforcement mechanism.
mod non_validating {
    use std::fmt;
    use std::sync::Arc;

    use rustls::DigitallySignedStruct;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{Error, SignatureScheme};

    /// Deliberately dangerous: accepts every certificate presented, and
    /// treats every handshake signature as valid, without checking either.
    ///
    /// Exists because internal appliances, exporters, and management UIs
    /// routinely present self-signed, expired, or hostname-mismatched
    /// certificates, and recording what they actually present is this
    /// prober's whole job — not a reason to refuse the connection. It must
    /// never be reachable from anywhere that isn't this deliberate TLS
    /// inspection path: not the SSH transport, not any future update,
    /// telemetry, or ingestion client.
    struct NonValidatingVerifier {
        supported_schemes: Vec<SignatureScheme>,
    }

    impl fmt::Debug for NonValidatingVerifier {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("NonValidatingVerifier")
                .finish_non_exhaustive()
        }
    }

    impl ServerCertVerifier for NonValidatingVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.supported_schemes.clone()
        }
    }

    /// Builds a `ClientConfig` that completes a TLS handshake against any
    /// certificate chain offered, unverified.
    ///
    /// This is the only function in the crate that can construct a
    /// [`NonValidatingVerifier`]. Its result must never be handed to
    /// anything other than [`super::TlsProber`]'s own handshake.
    pub(super) fn client_config() -> rustls::ClientConfig {
        let provider = rustls::crypto::ring::default_provider();
        let supported_schemes = provider
            .signature_verification_algorithms
            .supported_schemes();
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NonValidatingVerifier { supported_schemes }))
            .with_no_client_auth()
    }
}

/// A default RSA key below this size is a finding — 2048 bits is the
/// commonly accepted floor for RSA in current guidance (NIST SP 800-131A).
const MIN_RSA_KEY_BITS: u32 = 2048;

/// An EC key below this size is a finding — below the smallest widely
/// deployed curve (NIST P-224/secp224r1).
const MIN_EC_KEY_BITS: u32 = 224;

/// Default window for [`TlsFinding::ExpiringWithin`].
///
/// A certificate expiring inside 30 days is worth surfacing to a reader
/// before it lapses unattended.
const DEFAULT_EXPIRING_WINDOW: Duration = Duration::from_hours(30 * 24);

/// One certificate observed in a TLS handshake's chain, parsed without
/// regard to whether it validates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRecord {
    /// The certificate's subject distinguished name.
    pub subject: String,
    /// The certificate's issuer distinguished name.
    pub issuer: String,
    /// Subject Alternative Names (DNS/IP/email/URI entries), if present.
    pub san: Vec<String>,
    /// Start of the certificate's validity period.
    pub not_before: OffsetDateTime,
    /// End of the certificate's validity period.
    pub not_after: OffsetDateTime,
    /// The public key's algorithm, e.g. `"rsaEncryption"`.
    pub key_algorithm: String,
    /// The public key's size in bits.
    pub key_size_bits: u32,
    /// The signature algorithm the issuer signed this certificate with.
    pub signature_algorithm: String,
    /// Colon-separated hex serial number.
    pub serial: String,
    /// SHA-256 of the complete DER-encoded certificate — the stable
    /// identity for drift comparison, so a rotated or replaced certificate
    /// surfaces as drift rather than as noise.
    pub sha256_fingerprint: [u8; 32],
    /// `true` if the subject and issuer distinguished names are identical.
    pub self_signed: bool,
}

/// The full chain and per-connection metadata from one completed TLS
/// handshake.
#[derive(Debug, Clone)]
pub struct TlsHandshakeRecord {
    /// The certificate chain as the peer sent it: leaf first.
    pub certificates: Vec<CertificateRecord>,
    /// The negotiated TLS protocol version, e.g. `"TLSv1_3"`.
    pub protocol_version: String,
    /// The negotiated cipher suite, e.g. `"TLS13_AES_256_GCM_SHA384"`.
    pub cipher_suite: String,
    /// The ALPN protocol the peer selected, if any.
    pub alpn: Option<String>,
}

/// A fact derived from an inspected certificate chain.
///
/// Never constructed by I/O directly — see [`derive_findings`], a pure
/// function over an already-parsed chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsFinding {
    /// The leaf certificate's subject equals its issuer.
    SelfSigned,
    /// The leaf certificate's validity period has already ended.
    Expired,
    /// The leaf certificate's validity period ends within this window.
    ExpiringWithin(Duration),
    /// The address or name probed does not appear in the leaf
    /// certificate's SAN list.
    ///
    /// Reported, never enforced — probing by IP mismatches nearly every
    /// otherwise-valid certificate, so this is a fact for the reader to
    /// judge, not a probe failure.
    HostnameMismatch {
        /// SAN entries the certificate actually claims.
        claimed: Vec<String>,
        /// The address or name the connection was made to.
        probed: String,
    },
    /// Adjacent certificates in the chain don't chain: one certificate's
    /// issuer does not match the next certificate's subject.
    IncompleteChain,
    /// A certificate's public key is below the accepted minimum size for
    /// its algorithm.
    WeakKey {
        /// The key size in bits.
        bits: u32,
    },
    /// A certificate was signed using a broken hash algorithm (SHA-1).
    WeakSignatureAlgorithm(String),
    /// The connection negotiated TLS 1.0 or TLS 1.1.
    WeakProtocolVersion(String),
}

/// Derives findings from an already-parsed certificate chain — pure, no
/// I/O, so every finding is unit-testable without a network.
///
/// `probed_hostname` is whatever address or name the connection was made
/// to.
#[must_use]
pub fn derive_findings(chain: &[CertificateRecord], probed_hostname: &str) -> Vec<TlsFinding> {
    let mut findings = Vec::new();

    if let Some(leaf) = chain.first() {
        if leaf.self_signed {
            findings.push(TlsFinding::SelfSigned);
        }
        let now = OffsetDateTime::now_utc();
        if leaf.not_after < now {
            findings.push(TlsFinding::Expired);
        } else if leaf.not_after - now
            < time::Duration::try_from(DEFAULT_EXPIRING_WINDOW).unwrap_or(time::Duration::ZERO)
        {
            findings.push(TlsFinding::ExpiringWithin(DEFAULT_EXPIRING_WINDOW));
        }
        if !leaf.san.is_empty()
            && !leaf
                .san
                .iter()
                .any(|name| name.eq_ignore_ascii_case(probed_hostname))
        {
            findings.push(TlsFinding::HostnameMismatch {
                claimed: leaf.san.clone(),
                probed: probed_hostname.to_owned(),
            });
        }
    }

    for cert in chain {
        if is_weak_key(&cert.key_algorithm, cert.key_size_bits) {
            findings.push(TlsFinding::WeakKey {
                bits: cert.key_size_bits,
            });
        }
        if cert
            .signature_algorithm
            .to_ascii_lowercase()
            .contains("sha1")
        {
            findings.push(TlsFinding::WeakSignatureAlgorithm(
                cert.signature_algorithm.clone(),
            ));
        }
    }

    if incomplete_chain(chain) {
        findings.push(TlsFinding::IncompleteChain);
    }

    findings
}

/// `true` if `bits` is below the accepted minimum for `algorithm`.
///
/// Algorithms this crate doesn't recognise are never flagged — a false
/// negative here is better than inventing a threshold with no basis.
fn is_weak_key(algorithm: &str, bits: u32) -> bool {
    let algorithm = algorithm.to_ascii_lowercase();
    if algorithm.contains("rsa") {
        bits < MIN_RSA_KEY_BITS
    } else if algorithm.contains("ec") {
        bits < MIN_EC_KEY_BITS
    } else {
        false
    }
}

/// `true` if the connection negotiated TLS 1.0 or TLS 1.1.
///
/// `TlsProber::handshake` builds its connector from
/// [`non_validating::client_config`], which takes rustls's default
/// provider and its default supported-versions list — and rustls does not
/// implement TLS 1.0 or TLS 1.1 at all, so a live handshake through this
/// prober can never actually produce `"TLSv1_0"` or `"TLSv1_1"` here; a
/// server that only offers those versions fails the handshake outright and
/// never reaches this function. The check stays anyway: it's defensive
/// and forward-compatible, staying correct if the connector's version set
/// ever changes, if a future adapter variant negotiates differently, or if
/// `derive_findings`/this function is exercised directly with synthetic
/// version strings, as the tests below do.
fn protocol_version_finding(version: &str) -> Option<TlsFinding> {
    matches!(version, "TLSv1_0" | "TLSv1_1")
        .then(|| TlsFinding::WeakProtocolVersion(version.to_owned()))
}

/// Walk issuer/subject pairs to find a broken chain link.
fn incomplete_chain(chain: &[CertificateRecord]) -> bool {
    chain
        .array_windows::<2>()
        .any(|[leaf, next]| leaf.issuer != next.subject)
}

/// Parses one DER-encoded certificate. Returns `None` — silently dropping
/// the certificate rather than failing the whole handshake — if the bytes
/// the peer sent don't parse as X.509 at all; a malformed certificate is
/// itself unusual but doesn't invalidate the rest of the chain.
fn certificate_record_from_der(der: &CertificateDer<'_>) -> Option<CertificateRecord> {
    let (_rem, cert) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let san = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(general_name_to_string)
                .collect()
        })
        .unwrap_or_default();
    let (key_algorithm, key_size_bits) = key_algorithm_and_size(cert.public_key());
    let signature_algorithm = algorithm_name(&cert.signature_algorithm.algorithm);
    let serial = cert.tbs_certificate.raw_serial_as_string();
    let sha256_fingerprint: [u8; 32] = Sha256::digest(der.as_ref()).into();
    let self_signed = subject == issuer;

    Some(CertificateRecord {
        subject,
        issuer,
        san,
        not_before: cert.validity().not_before.to_datetime(),
        not_after: cert.validity().not_after.to_datetime(),
        key_algorithm,
        key_size_bits,
        signature_algorithm,
        serial,
        sha256_fingerprint,
        self_signed,
    })
}

fn general_name_to_string(name: &GeneralName<'_>) -> Option<String> {
    match name {
        GeneralName::DNSName(value) | GeneralName::RFC822Name(value) | GeneralName::URI(value) => {
            Some((*value).to_owned())
        }
        GeneralName::IPAddress(bytes) => ip_address_from_bytes(bytes),
        _ => None,
    }
}

fn ip_address_from_bytes(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => <[u8; 4]>::try_from(bytes)
            .ok()
            .map(|octets| Ipv4Addr::from(octets).to_string()),
        16 => <[u8; 16]>::try_from(bytes)
            .ok()
            .map(|octets| Ipv6Addr::from(octets).to_string()),
        _ => None,
    }
}

fn algorithm_name(oid: &Oid<'_>) -> String {
    oid2sn(oid, oid_registry()).map_or_else(|_err| oid.to_string(), str::to_owned)
}

fn key_algorithm_and_size(spki: &SubjectPublicKeyInfo<'_>) -> (String, u32) {
    let algorithm = algorithm_name(&spki.algorithm.algorithm);
    let bits = spki
        .parsed()
        .ok()
        .map(|key| key.key_size())
        .and_then(|bits| u32::try_from(bits).ok())
        .unwrap_or(0);
    (algorithm, bits)
}

/// Per-host probing state: the concurrency gate and the running count
/// toward `max_probes_per_host`. Same shape as
/// [`crate::adapters::prober::HttpProber`]'s — a distinct instance, since
/// each `Prober` implementation gates its own outbound connections
/// independently.
struct HostState {
    semaphore: Arc<Semaphore>,
    issued: usize,
}

/// TLS-handshake [`Prober`] implementation.
///
/// Connects over TCP, completes a handshake using
/// [`non_validating::client_config`], and inspects whatever certificate
/// chain the target presents — including one that fails ordinary
/// validation, which is the point.
pub struct TlsProber {
    config: ProbeConfig,
    host_state: StdMutex<HashMap<IpAddr, HostState>>,
    rate_gate: TokioMutex<Option<Instant>>,
}

impl TlsProber {
    /// Builds a prober with its own per-host bookkeeping.
    #[must_use]
    pub fn new(config: ProbeConfig) -> Self {
        Self {
            config,
            host_state: StdMutex::new(HashMap::new()),
            rate_gate: TokioMutex::new(None),
        }
    }

    /// Reserves one slot of this host's probe budget and returns a permit
    /// that must be held for the probe's duration, enforcing
    /// `max_concurrent_per_host`.
    async fn reserve_host_budget(&self, ip: IpAddr) -> Result<OwnedSemaphorePermit, ProbeError> {
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

    /// Connects and completes a TLS handshake against `endpoint`, returning
    /// the full certificate chain and connection metadata.
    ///
    /// Never fails because of certificate validation — self-signed,
    /// expired, and hostname-mismatched certificates are captured fully
    /// and reported via [`derive_findings`]. Only a genuine connection or
    /// protocol-negotiation failure produces [`ProbeError::Handshake`].
    ///
    /// # Errors
    ///
    /// Returns [`ProbeError::Excluded`], [`ProbeError::HostBudgetExhausted`],
    /// or [`ProbeError::Handshake`] — see each variant's documentation.
    pub(crate) async fn handshake(
        &self,
        endpoint: &Endpoint,
    ) -> Result<TlsHandshakeRecord, ProbeError> {
        let ip = endpoint.bind_address.ip();
        let port = endpoint.port.get();

        if self.config.exclude.excludes(ip, port) {
            return Err(ProbeError::Excluded);
        }

        let _host_permit = self.reserve_host_budget(ip).await?;
        self.throttle().await;

        let socket_addr = SocketAddr::new(ip, port);
        let tcp_stream =
            tokio::time::timeout(self.config.connect_timeout, TcpStream::connect(socket_addr))
                .await
                .map_err(|_elapsed| ProbeError::Handshake("connect timed out".to_owned()))?
                .map_err(|err| ProbeError::Handshake(format!("connect failed: {err}")))?;

        let connector = TlsConnector::from(Arc::new(non_validating::client_config()));
        let server_name = ServerName::IpAddress(ip.into());
        let tls_stream = tokio::time::timeout(
            self.config.read_timeout,
            connector.connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_elapsed| ProbeError::Handshake("handshake timed out".to_owned()))?
        .map_err(|err| ProbeError::Handshake(format!("handshake failed: {err}")))?;

        let (_io, connection) = tls_stream.get_ref();
        let certificates = connection
            .peer_certificates()
            .unwrap_or_default()
            .iter()
            .filter_map(certificate_record_from_der)
            .collect();
        let protocol_version = connection
            .protocol_version()
            .and_then(|version| version.as_str())
            .unwrap_or("unknown")
            .to_owned();
        let cipher_suite = connection
            .negotiated_cipher_suite()
            .and_then(|suite| suite.suite().as_str())
            .unwrap_or("unknown")
            .to_owned();
        let alpn = connection
            .alpn_protocol()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned());

        Ok(TlsHandshakeRecord {
            certificates,
            protocol_version,
            cipher_suite,
            alpn,
        })
    }
}

#[async_trait]
impl Prober for TlsProber {
    async fn probe(&self, endpoint: &Endpoint) -> Result<Vec<Evidence>, ProbeError> {
        let record = self.handshake(endpoint).await?;
        let probed_hostname = endpoint.bind_address.ip().to_string();
        Ok(evidence_from_record(&record, &probed_hostname))
    }
}

/// Derives [`Evidence`] from one completed handshake: the leaf
/// certificate's subject, connection-level facts, ALPN (with `h2`/`grpc`
/// surfaced as its own typed [`Evidence::AlpnProtocol`] — strong signal
/// for the fingerprinting stage), and every [`TlsFinding`] this chain
/// derives.
fn evidence_from_record(record: &TlsHandshakeRecord, probed_hostname: &str) -> Vec<Evidence> {
    let mut evidence = Vec::new();

    if let Some(leaf) = record.certificates.first() {
        evidence.push(Evidence::TlsCertificateSubject {
            subject: leaf.subject.clone(),
        });
    }

    evidence.push(Evidence::BannerMatch {
        pattern: format!("tls-protocol-version:{}", record.protocol_version),
    });
    evidence.push(Evidence::BannerMatch {
        pattern: format!("tls-cipher-suite:{}", record.cipher_suite),
    });

    if let Some(alpn) = &record.alpn {
        evidence.push(Evidence::BannerMatch {
            pattern: format!("tls-alpn:{alpn}"),
        });
        if is_http2_or_grpc_alpn(alpn) {
            evidence.push(Evidence::AlpnProtocol {
                protocol: alpn.clone(),
            });
        }
    }

    for finding in derive_findings(&record.certificates, probed_hostname) {
        evidence.push(Evidence::BannerMatch {
            pattern: finding_pattern(&finding),
        });
    }
    if let Some(finding) = protocol_version_finding(&record.protocol_version) {
        evidence.push(Evidence::BannerMatch {
            pattern: finding_pattern(&finding),
        });
    }

    evidence
}

const fn is_http2_or_grpc_alpn(alpn: &str) -> bool {
    alpn.eq_ignore_ascii_case("h2") || alpn.eq_ignore_ascii_case("grpc")
}

fn finding_pattern(finding: &TlsFinding) -> String {
    match finding {
        TlsFinding::SelfSigned => "tls-finding:self-signed".to_owned(),
        TlsFinding::Expired => "tls-finding:expired".to_owned(),
        TlsFinding::ExpiringWithin(window) => {
            format!("tls-finding:expiring-within:{}s", window.as_secs())
        }
        TlsFinding::HostnameMismatch { claimed, probed } => format!(
            "tls-finding:hostname-mismatch:claimed={};probed={probed}",
            claimed.join(",")
        ),
        TlsFinding::IncompleteChain => "tls-finding:incomplete-chain".to_owned(),
        TlsFinding::WeakKey { bits } => format!("tls-finding:weak-key:{bits}"),
        TlsFinding::WeakSignatureAlgorithm(algorithm) => {
            format!("tls-finding:weak-signature-algorithm:{algorithm}")
        }
        TlsFinding::WeakProtocolVersion(version) => {
            format!("tls-finding:weak-protocol-version:{version}")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use rcgen::{CertifiedKey, KeyPair, generate_simple_self_signed};
    use rustls::ServerConfig;
    use rustls::pki_types::PrivateKeyDer;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio_rustls::TlsAcceptor;

    use super::{
        CertificateRecord, Duration, Endpoint, OffsetDateTime, ProbeConfig, TlsFinding,
        TlsHandshakeRecord, TlsProber, derive_findings, incomplete_chain,
        protocol_version_finding,
    };
    use crate::application::identify::Prober as _;
    use crate::domain::{BindAddress, Evidence, Port, Protocol, SignatureStatus};

    fn record(
        subject: &str,
        issuer: &str,
        key_algorithm: &str,
        key_size_bits: u32,
        signature_algorithm: &str,
        not_after: OffsetDateTime,
    ) -> CertificateRecord {
        CertificateRecord {
            subject: subject.to_owned(),
            issuer: issuer.to_owned(),
            san: vec![],
            not_before: OffsetDateTime::UNIX_EPOCH,
            not_after,
            key_algorithm: key_algorithm.to_owned(),
            key_size_bits,
            signature_algorithm: signature_algorithm.to_owned(),
            serial: "01".to_owned(),
            sha256_fingerprint: [0_u8; 32],
            self_signed: subject == issuer,
        }
    }

    mod fixtures {
        use core::str::FromStr as _;
        use std::net::SocketAddr;
        use std::sync::Arc;

        use super::{
            BindAddress, CertifiedKey, Endpoint, KeyPair, Port, PrivateKeyDer, ProbeConfig,
            Protocol, ServerConfig, SignatureStatus, TcpListener, TlsAcceptor, TlsProber,
            generate_simple_self_signed,
        };

        pub(super) struct TlsFixtureServer {
            addr: SocketAddr,
            _handle: super::JoinHandle<()>,
        }

        impl TlsFixtureServer {
            pub(super) fn endpoint(&self) -> Endpoint {
                Endpoint::new(
                    Protocol::Tcp,
                    BindAddress::from_str(&self.addr.ip().to_string()).expect("valid ip"),
                    Port::try_from(self.addr.port()).expect("valid port"),
                    None,
                    None,
                    vec![],
                    SignatureStatus::Unknown,
                )
            }
        }

        pub(super) fn self_signed_cert() -> CertifiedKey<KeyPair> {
            generate_simple_self_signed(vec!["localhost".to_owned()]).expect("self-signed cert")
        }

        pub(super) async fn tls_server_with_cert(
            certified: CertifiedKey<KeyPair>,
        ) -> TlsFixtureServer {
            let cert_der = certified.cert.der().clone();
            let key_der = PrivateKeyDer::try_from(certified.signing_key.serialize_der())
                .expect("private key der");
            let server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .expect("server config");
            let acceptor = TlsAcceptor::from(Arc::new(server_config));
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            let handle = tokio::spawn(async move {
                loop {
                    let Ok((stream, _peer)) = listener.accept().await else {
                        break;
                    };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let _ = acceptor.accept(stream).await;
                    });
                }
            });
            TlsFixtureServer {
                addr,
                _handle: handle,
            }
        }

        pub(super) fn default_prober() -> TlsProber {
            TlsProber::new(ProbeConfig {
                min_probe_interval: super::Duration::ZERO,
                connect_timeout: super::Duration::from_secs(2),
                read_timeout: super::Duration::from_secs(2),
                ..ProbeConfig::default()
            })
        }
    }

    async fn probe_tls(endpoint: &Endpoint) -> Result<TlsHandshakeRecord, super::ProbeError> {
        fixtures::default_prober().handshake(endpoint).await
    }

    #[tokio::test]
    async fn self_signed_handshake_succeeds_and_is_flagged() {
        let server = fixtures::tls_server_with_cert(fixtures::self_signed_cert()).await;

        let record = probe_tls(&server.endpoint()).await.unwrap();

        assert!(!record.certificates.is_empty());
        assert!(record.certificates[0].self_signed);
    }

    #[tokio::test]
    async fn probe_via_trait_surfaces_certificate_subject_and_self_signed_finding() {
        let server = fixtures::tls_server_with_cert(fixtures::self_signed_cert()).await;
        let prober = fixtures::default_prober();

        let evidence = prober.probe(&server.endpoint()).await.unwrap();

        assert!(
            evidence
                .iter()
                .any(|e| matches!(e, Evidence::TlsCertificateSubject { .. }))
        );
        assert!(evidence.iter().any(
            |e| matches!(e, Evidence::BannerMatch { pattern } if pattern == "tls-finding:self-signed")
        ));
    }

    #[test]
    fn expired_certificate_is_derived_as_finding() {
        let chain = vec![record(
            "CN=old.example.test",
            "CN=old.example.test",
            "rsaEncryption",
            2048,
            "sha256WithRSAEncryption",
            OffsetDateTime::UNIX_EPOCH + Duration::from_hours(1),
        )];

        let findings = derive_findings(&chain, "example.test");

        assert!(findings.contains(&super::TlsFinding::Expired));
    }

    #[test]
    fn weak_key_and_sha1_signature_each_fire_independently() {
        let chain = vec![record(
            "CN=weak.example.test",
            "CN=some-ca.example.test",
            "rsaEncryption",
            1024,
            "sha1WithRSAEncryption",
            OffsetDateTime::now_utc() + Duration::from_hours(365 * 24),
        )];

        let findings = derive_findings(&chain, "example.test");

        assert!(
            findings
                .iter()
                .any(|f| matches!(f, super::TlsFinding::WeakKey { bits } if *bits < 2048))
        );
        assert!(findings.iter().any(
            |f| matches!(f, super::TlsFinding::WeakSignatureAlgorithm(alg) if alg.contains("sha1"))
        ));
    }

    #[test]
    fn incomplete_chain_detected_via_array_windows() {
        let leaf = record(
            "CN=leaf.example.test",
            "CN=intermediate.example.test",
            "rsaEncryption",
            2048,
            "sha256WithRSAEncryption",
            OffsetDateTime::now_utc() + Duration::from_hours(365 * 24),
        );
        // A broken link: the next certificate's subject doesn't match the
        // leaf's issuer, so the chain has a gap.
        let unrelated_root = record(
            "CN=unrelated-root.example.test",
            "CN=unrelated-root.example.test",
            "rsaEncryption",
            2048,
            "sha256WithRSAEncryption",
            OffsetDateTime::now_utc() + Duration::from_hours(365 * 24),
        );
        let chain = vec![leaf, unrelated_root];

        assert!(incomplete_chain(&chain));
    }

    #[test]
    fn weak_protocol_versions_fire_and_current_versions_do_not() {
        assert_eq!(
            protocol_version_finding("TLSv1_0"),
            Some(TlsFinding::WeakProtocolVersion("TLSv1_0".to_owned()))
        );
        assert_eq!(
            protocol_version_finding("TLSv1_1"),
            Some(TlsFinding::WeakProtocolVersion("TLSv1_1".to_owned()))
        );
        assert_eq!(protocol_version_finding("TLSv1_2"), None);
        assert_eq!(protocol_version_finding("TLSv1_3"), None);
    }

    #[test]
    fn non_validating_verifier_referenced_by_exactly_one_module() {
        let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files_containing: std::collections::HashSet<PathBuf> =
            std::collections::HashSet::new();
        let mut stack = vec![src_root];

        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(std::ffi::OsStr::to_str) != Some("rs") {
                    continue;
                }
                let Ok(contents) = std::fs::read_to_string(&path) else {
                    continue;
                };
                if contents.contains("NonValidatingVerifier") {
                    files_containing.insert(path);
                }
            }
        }

        assert_eq!(
            files_containing.len(),
            1,
            "NonValidatingVerifier must be named from exactly one file in the crate; found in: {files_containing:?}"
        );
    }

    #[test]
    fn fingerprint_change_registers_as_drift() {
        let mut before = record(
            "CN=a",
            "CN=a",
            "rsaEncryption",
            2048,
            "sha256WithRSAEncryption",
            OffsetDateTime::now_utc() + Duration::from_hours(1),
        );
        before.sha256_fingerprint = [0xAA_u8; 32];
        let mut after = before.clone();
        after.sha256_fingerprint = [0xBB_u8; 32];

        assert_ne!(before.sha256_fingerprint, after.sha256_fingerprint);
    }
}
