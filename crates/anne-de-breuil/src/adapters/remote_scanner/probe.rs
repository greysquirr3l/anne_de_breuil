//! `TargetStrategy::Probe` composition: turns one [`InventoryHost`] into a
//! set of [`Endpoint`]s by checking a small, bounded list of well-known
//! ports from outside, never a full sweep — matching T09's own "bounded,
//! non-intrusive" scope for active probing.
//!
//! There is no existing orchestration anywhere in this crate that probes a
//! *whole host* and assembles endpoints from the result — every existing
//! [`Prober`] implementation takes one already-known [`Endpoint`]. This
//! module is that composition, kept separate from
//! [`super::SshHostScanner`]'s trait impl so the impl itself stays a thin
//! dispatcher.
//!
//! # Liveness signal
//!
//! [`HttpProber::probe`] always returns *some* [`Evidence`] for a port that
//! refuses every connection: its own HTTPS attempt records
//! `"tls-handshake:failed"` on any failure, connection-refused included, so
//! "evidence is non-empty" is not a usable liveness signal on its own. This
//! module instead gates on a real, cheap, bounded TCP connect first — only
//! a port that actually accepts a connection gets treated as a live
//! endpoint (and only then does it also get the full `HttpProber`/
//! `TlsProber` treatment, which is why exclusions and the fleet-wide rate
//! gate matter here too: skipping the raw-connect probes entirely for an
//! excluded target is not optional).

use std::net::IpAddr;
use std::time::Duration;

use crate::adapters::inventory::InventoryHost;
use crate::adapters::prober::HttpProber;
use crate::adapters::tls_probe::TlsProber;
use crate::application::identify::{ProbeConfig, Prober as _};
use crate::domain::{BindAddress, Endpoint, Evidence, Port, Protocol, SignatureStatus};

/// A short, defensible list of well-known ports. Not a full 1-65535 sweep
/// — see the module doc.
const CANDIDATE_PORTS: [u16; 23] = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3000, 3306, 3389, 5432, 5900, 6379,
    8000, 8080, 8443, 9200,
];

/// Probes `host` across [`CANDIDATE_PORTS`], returning one [`Endpoint`] per
/// port that answered a real TCP connect within `config.connect_timeout`.
///
/// Every returned endpoint carries no process attribution (`process_id`,
/// `process_path`, `hosted_services` all empty/`None`) — correct and
/// expected for this tier, matching how `Fidelity::Inferred` documents the
/// same distinction elsewhere (`domain::report_model`). Evidence gathered
/// by `http_prober`/`tls_prober` has no field on `Endpoint`/`ScanSnapshot`
/// to live in yet (see `domain::report_model`'s documented
/// `assignment_mismatches`/`certificate_findings` gap) — probing still
/// runs for every live port because it's the composition this tier is
/// meant to exercise, but its result today only ever decides "was this
/// port worth including," not richer attribution.
pub(super) async fn probe_host(
    host: &InventoryHost,
    config: &ProbeConfig,
    http_prober: &HttpProber,
    tls_prober: &TlsProber,
) -> Vec<Endpoint> {
    let Some(ip) = resolve_ip(host).await else {
        return Vec::new();
    };

    let mut endpoints = Vec::new();
    for raw_port in CANDIDATE_PORTS {
        let Ok(port) = Port::try_from(raw_port) else {
            continue;
        };
        if config.exclude.excludes(ip, raw_port) {
            continue;
        }
        if !tcp_port_open(ip, raw_port, config.connect_timeout).await {
            continue;
        }

        let endpoint = candidate_endpoint(ip, port);
        let _http_evidence: Result<Vec<Evidence>, _> = http_prober.probe(&endpoint).await;
        let _tls_evidence: Result<Vec<Evidence>, _> = tls_prober.probe(&endpoint).await;
        endpoints.push(endpoint);
    }
    endpoints
}

/// Resolves `host.address` to one candidate IP: parsed directly if it's
/// already an address, or the first result of a real DNS lookup if it's a
/// hostname. `None` (never a panic) if resolution fails outright — an
/// unresolvable host simply probes nothing, same as an unreachable one.
async fn resolve_ip(host: &InventoryHost) -> Option<IpAddr> {
    if let Ok(ip) = host.address.as_str().parse::<IpAddr>() {
        return Some(ip);
    }
    let target = format!("{}:{}", host.address.as_str(), host.port.get());
    tokio::net::lookup_host(target)
        .await
        .ok()?
        .next()
        .map(|addr| addr.ip())
}

async fn tcp_port_open(ip: IpAddr, port: u16, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, tokio::net::TcpStream::connect((ip, port)))
        .await
        .is_ok_and(|result| result.is_ok())
}

/// Builds a bare, process-attribution-free `Endpoint` for a port that
/// answered a live TCP connect.
fn candidate_endpoint(ip: IpAddr, port: Port) -> Endpoint {
    Endpoint::new(
        Protocol::Tcp,
        BindAddress::from(ip),
        port,
        None,
        None,
        Vec::new(),
        SignatureStatus::Unknown,
        None,
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr as _;
    use std::time::Duration;

    use tokio::net::TcpListener;

    use super::{candidate_endpoint, probe_host, resolve_ip, tcp_port_open};
    use crate::adapters::inventory::{AuthMethod, InventoryHost};
    use crate::adapters::prober::HttpProber;
    use crate::adapters::tls_probe::TlsProber;
    use crate::application::identify::ProbeConfig;
    use crate::domain::{HostAddress, HostId, Port};

    fn host_at(address: &str, port: u16) -> InventoryHost {
        InventoryHost {
            host_id: HostId::generate(),
            address: HostAddress::from_str(address).expect("valid address"),
            port: Port::try_from(port).expect("valid port"),
            user: "anne".to_owned(),
            auth: AuthMethod::Agent,
            jump: None,
            tags: vec![],
        }
    }

    #[tokio::test]
    async fn resolve_ip_parses_a_literal_address_directly() {
        let host = host_at("127.0.0.1", 22);
        assert_eq!(
            resolve_ip(&host).await,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
    }

    #[tokio::test]
    async fn resolve_ip_returns_none_for_an_unresolvable_hostname() {
        let host = host_at("this-host-does-not-resolve.invalid", 22);
        assert_eq!(resolve_ip(&host).await, None);
    }

    #[tokio::test]
    async fn tcp_port_open_is_true_for_a_real_listener_and_false_for_a_closed_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        // Keep the listener alive for the duration of the true-case check.
        let _accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        assert!(tcp_port_open(addr.ip(), addr.port(), Duration::from_secs(2)).await);

        // Port 0 never has a real listener to connect to; grabbing a free
        // port and never binding it is the closed-port fixture.
        let closed = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind to find a free port");
        let closed_port = closed.local_addr().expect("local_addr").port();
        drop(closed);

        assert!(!tcp_port_open(addr.ip(), closed_port, Duration::from_millis(300)).await);
    }

    #[test]
    fn candidate_endpoint_carries_no_process_attribution() {
        let endpoint = candidate_endpoint(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Port::try_from(80u16).unwrap(),
        );
        assert!(endpoint.process_id.is_none());
        assert!(endpoint.process_path.is_none());
        assert!(endpoint.hosted_services.is_empty());
        assert!(endpoint.command_line.is_none());
    }

    #[tokio::test]
    async fn probe_host_finds_a_live_port_among_the_candidate_list() {
        // 3306 (MySQL) is one of the CANDIDATE_PORTS entries -- binding a
        // real listener there on loopback proves probe_host actually walks
        // the real candidate list and reports a genuinely live port, not a
        // hardcoded result.
        let listener = TcpListener::bind("127.0.0.1:3306").await;
        let Ok(listener) = listener else {
            // Best-effort: skip if something else on this machine already
            // owns 3306 (e.g. a real local MySQL) rather than fail a CI run
            // over a port collision unrelated to this code.
            return;
        };
        let _accept = tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let host = host_at("127.0.0.1", 22);
        let config = ProbeConfig {
            connect_timeout: Duration::from_millis(500),
            read_timeout: Duration::from_millis(500),
            min_probe_interval: Duration::ZERO,
            ..ProbeConfig::default()
        };
        let http_prober = HttpProber::new(config.clone()).expect("build http prober");
        let tls_prober = TlsProber::new(config.clone());

        let endpoints = probe_host(&host, &config, &http_prober, &tls_prober).await;

        assert!(
            endpoints.iter().any(|e| e.port.get() == 3306),
            "expected port 3306 to be reported live, got {endpoints:?}"
        );
        assert!(
            endpoints
                .iter()
                .all(|e| e.process_id.is_none() && e.process_path.is_none()),
            "probe-tier endpoints must never carry process attribution"
        );
    }

    #[tokio::test]
    async fn probe_host_excludes_a_configured_port_even_when_it_is_live() {
        let listener = TcpListener::bind("127.0.0.1:8080").await;
        let Ok(listener) = listener else {
            return;
        };
        let _accept = tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let host = host_at("127.0.0.1", 22);
        let config = ProbeConfig {
            connect_timeout: Duration::from_millis(500),
            read_timeout: Duration::from_millis(500),
            min_probe_interval: Duration::ZERO,
            exclude: crate::application::identify::ProbeExclusions::new([8080], Vec::new()),
            ..ProbeConfig::default()
        };
        let http_prober = HttpProber::new(config.clone()).expect("build http prober");
        let tls_prober = TlsProber::new(config.clone());

        let endpoints = probe_host(&host, &config, &http_prober, &tls_prober).await;

        assert!(!endpoints.iter().any(|e| e.port.get() == 8080));
    }
}
