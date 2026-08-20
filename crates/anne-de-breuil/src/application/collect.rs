//! Consumer-owned collector ports: [`EndpointSource`], [`ProcessResolver`],
//! [`FirewallPolicySource`], and [`SignatureVerifier`].
//!
//! Declared here, not in `adapters/`, because collection is a capability a
//! use case *consumes* — the platform-specific adapters that will satisfy
//! these traits (PowerShell, native Win32, procfs/netlink/nftables) don't
//! exist yet. [`collect_endpoints`] is the handler those adapters will
//! eventually be wired into; today it is exercised entirely against
//! `#[cfg(test)]` fakes defined in this module, so it never touches a real
//! host or spawns a real process.
//!
//! Every trait here does real I/O (spawning a child process, querying
//! WMI/netlink) and must stay object-safe so a fan-out orchestrator can
//! hold many of them behind `Arc<dyn _>` for concurrent hosts. Native
//! `async fn` in traits is not object-safe, so `#[async_trait]` is used
//! deliberately — the same sanctioned pattern already established by
//! [`crate::application::SnapshotStore`].

use async_trait::async_trait;

use crate::domain::{
    BindAddress, DomainError, Port, ProcessId, ProcessPath, Protocol, ServiceName, SignatureStatus,
};

/// Failure collecting raw platform data through one of this module's ports.
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    /// Spawning or communicating with a collector subprocess failed.
    #[error("spawning collector process failed: {0}")]
    Spawn(String),
    /// The collector did not respond within the allotted time.
    #[error("collector timed out after {0:?}")]
    Timeout(std::time::Duration),
    /// A raw payload could not be parsed into the shape this module expects.
    #[error("payload parse failed: {0}")]
    Parse(String),
}

impl From<DomainError> for CollectError {
    /// Every domain value-object parse failure becomes a [`CollectError::Parse`] —
    /// the handler's parse-don't-validate boundary has exactly one failure
    /// shape for "the adapter handed us a raw value the domain rejected."
    fn from(source: DomainError) -> Self {
        Self::Parse(source.to_string())
    }
}

/// Adapter-facing DTO for one observed listening socket.
///
/// [`collect_endpoints`] parses this into a [`Protocol`]/[`BindAddress`]/
/// [`Port`] triple at the boundary — nothing here is trusted until it has
/// gone through that parse.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RawEndpoint {
    /// The transport protocol name as the platform reports it (e.g. `"tcp"`, `"TCP6"`).
    pub protocol: String,
    /// The bound IP address as the platform reports it.
    pub local_address: String,
    /// The bound port number.
    pub local_port: u16,
    /// The pid the platform associates with this socket, if any.
    pub owning_pid: Option<u32>,
}

/// Adapter-facing DTO for one process the collector could describe.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RawProcess {
    /// The process id.
    pub pid: u32,
    /// The executable path, if the platform reported one.
    pub path: Option<String>,
    /// The full command line, if the platform reported one.
    pub command_line: Option<String>,
}

/// Adapter-facing DTO for one service hosted by a process.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RawService {
    /// The service's machine name (e.g. a Windows service name or systemd unit).
    pub name: String,
    /// The service's human-readable display name.
    pub display_name: String,
}

/// Adapter-facing DTO for one firewall rule.
///
/// Fields carry the platform's raw text (e.g. `direction: "Inbound"`,
/// `action: "Allow"`) rather than the parsed [`crate::domain::Direction`]/
/// [`crate::domain::RuleAction`] enums — like every other `Raw*` type here,
/// parsing into domain value objects happens once, at the collection
/// boundary, not in the adapter. `protocol`/`local_port_spec`/
/// `program_filter`/`service_filter` are `None` when the rule carries no
/// matching filter of that kind (e.g. a rule with no port filter applies
/// to every port).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RawRule {
    /// The rule's platform-native identifier (Windows Firewall `InstanceID`,
    /// or a synthesised id on platforms with no native rule GUID).
    pub rule_id: String,
    /// Human-readable rule name, for display only — never matched on.
    pub display_name: String,
    /// Traffic direction the rule governs, as the platform reports it (e.g. `"Inbound"`).
    pub direction: String,
    /// Whether the rule allows or blocks matching traffic, as the platform reports it (e.g. `"Allow"`).
    pub action: String,
    /// Transport protocol the rule's port filter applies to, if it has one.
    pub protocol: Option<String>,
    /// The rule's local-port filter text (e.g. `"443"`, `"5000-5010"`), if it has one.
    pub local_port_spec: Option<String>,
    /// The executable path the rule is scoped to, if it has a program filter.
    pub program_filter: Option<String>,
    /// The service name the rule is scoped to, if it has a service filter.
    pub service_filter: Option<String>,
    /// Whether the rule is currently enabled.
    pub enabled: bool,
    /// Where this rule's definition originates, as the platform reports it (e.g. `"Local"`, `"GroupPolicy"`).
    pub policy_store: String,
}

/// Adapter-facing DTO for one firewall profile (e.g. Domain/Private/Public).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RawProfile {
    /// The profile's name, as the platform reports it (e.g. `"Domain"`, `"Private"`, `"Public"`).
    pub name: String,
    /// Whether the firewall is enabled for this profile.
    pub enabled: bool,
    /// The default action for inbound traffic no rule explicitly covers, as the platform reports it.
    pub default_inbound_action: String,
    /// The default action for outbound traffic no rule explicitly covers, as the platform reports it.
    pub default_outbound_action: String,
}

/// Source of the raw listening-socket table for one host.
///
/// One method, no filtering or correlation — [`collect_endpoints`] handles
/// pairing sockets to owning processes and normalising raw data into
/// domain value objects.
///
/// # Examples
///
/// ```
/// use async_trait::async_trait;
/// use anne_de_breuil::application::collect::{CollectError, EndpointSource, RawEndpoint};
///
/// struct StaticEndpoints(Vec<RawEndpoint>);
///
/// #[async_trait]
/// impl EndpointSource for StaticEndpoints {
///     async fn listening_endpoints(&self) -> Result<Vec<RawEndpoint>, CollectError> {
///         Ok(self.0.clone())
///     }
/// }
/// ```
#[async_trait]
pub trait EndpointSource: Send + Sync {
    /// Returns every listening TCP/UDP socket currently bound on the host.
    ///
    /// # Errors
    ///
    /// Returns [`CollectError`] if the adapter cannot query or parse the socket table.
    async fn listening_endpoints(&self) -> Result<Vec<RawEndpoint>, CollectError>;
}

/// Resolves a process id to the process itself and the services it hosts.
///
/// # Examples
///
/// ```
/// use async_trait::async_trait;
/// use anne_de_breuil::application::collect::{CollectError, ProcessResolver, RawProcess, RawService};
/// use anne_de_breuil::domain::ProcessId;
///
/// struct NoSuchProcess;
///
/// #[async_trait]
/// impl ProcessResolver for NoSuchProcess {
///     async fn describe(&self, _pid: ProcessId) -> Result<Option<RawProcess>, CollectError> {
///         // The process had already exited by the time this ran — a real
///         // race the collection handler must record, not treat as an error.
///         Ok(None)
///     }
///
///     async fn hosted_services(&self, _pid: ProcessId) -> Result<Vec<RawService>, CollectError> {
///         Ok(vec![])
///     }
/// }
/// ```
#[async_trait]
pub trait ProcessResolver: Send + Sync {
    /// Describes the process behind `pid`, or `None` if it could not be
    /// found — most commonly because it exited between being observed in
    /// the socket table and this query running.
    ///
    /// # Errors
    ///
    /// Returns [`CollectError`] if the adapter's process query itself fails
    /// (as opposed to the process simply not existing, which is `Ok(None)`).
    async fn describe(&self, pid: ProcessId) -> Result<Option<RawProcess>, CollectError>;

    /// Lists the services `pid` hosts, or an empty list if it hosts none.
    ///
    /// # Errors
    ///
    /// Returns [`CollectError`] if the adapter's service query fails.
    async fn hosted_services(&self, pid: ProcessId) -> Result<Vec<RawService>, CollectError>;
}

/// Source of the host's effective inbound firewall policy.
///
/// # Examples
///
/// ```
/// use async_trait::async_trait;
/// use anne_de_breuil::application::collect::{CollectError, FirewallPolicySource, RawProfile, RawRule};
///
/// struct NoRules;
///
/// #[async_trait]
/// impl FirewallPolicySource for NoRules {
///     async fn inbound_rules(&self) -> Result<Vec<RawRule>, CollectError> {
///         Ok(vec![])
///     }
///
///     async fn profiles(&self) -> Result<Vec<RawProfile>, CollectError> {
///         Ok(vec![])
///     }
/// }
/// ```
#[async_trait]
pub trait FirewallPolicySource: Send + Sync {
    /// Returns every inbound firewall rule currently in effect.
    ///
    /// # Errors
    ///
    /// Returns [`CollectError`] if the adapter cannot query or parse the rule set.
    async fn inbound_rules(&self) -> Result<Vec<RawRule>, CollectError>;

    /// Returns the host's firewall profiles (e.g. Domain/Private/Public) and their state.
    ///
    /// # Errors
    ///
    /// Returns [`CollectError`] if the adapter cannot query or parse profile state.
    async fn profiles(&self) -> Result<Vec<RawProfile>, CollectError>;
}

/// Verifies the code-signing signature on an executable at rest.
///
/// # Examples
///
/// ```
/// use async_trait::async_trait;
/// use anne_de_breuil::application::collect::{CollectError, SignatureVerifier};
/// use anne_de_breuil::domain::{ProcessPath, SignatureStatus};
///
/// struct AlwaysUnknown;
///
/// #[async_trait]
/// impl SignatureVerifier for AlwaysUnknown {
///     async fn verify(&self, _path: &ProcessPath) -> Result<SignatureStatus, CollectError> {
///         Ok(SignatureStatus::Unknown)
///     }
/// }
/// ```
#[async_trait]
pub trait SignatureVerifier: Send + Sync {
    /// Checks the code-signing signature on the binary at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`CollectError`] if the adapter cannot read or verify the binary.
    async fn verify(&self, path: &ProcessPath) -> Result<SignatureStatus, CollectError>;
}

/// Whether the handler could resolve an endpoint's owning process by the
/// time it asked.
///
/// This models a race the collector must record, not paper over: a
/// listening socket is observed with an `owning_pid` in the raw socket
/// table, but by the time [`ProcessResolver::describe`] runs for that pid
/// the process may already have exited. The endpoint is still a real fact
/// about the host — it is never dropped from the collected output — so
/// this type always attaches to the endpoint's `owning_process` field
/// instead of the endpoint disappearing.
///
/// This is deliberately a *different* type from [`crate::domain::Attribution`]:
/// `Attribution` models who owns an endpoint with evidence-backed
/// confidence, for service identification, and is constructed from either
/// authoritative local-collector data or probe evidence. `ProcessAttribution`
/// models a narrower, collection-time-only concern — whether a pid seen in
/// the socket table could still be resolved to a live process before the
/// collector's follow-up query landed. Conflating the two would make a
/// process that legitimately exited mid-scan read as "low-confidence
/// service identity" instead of "process gone", which is a different fact
/// with a different meaning to a report reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessAttribution {
    /// The owning pid resolved to a live process, along with whatever the
    /// resolver and signature verifier could establish about it.
    Resolved {
        /// The owning process's id.
        pid: ProcessId,
        /// The owning process's executable path, if the platform reported one.
        path: Option<ProcessPath>,
        /// Services hosted by the owning process, sorted for determinism.
        hosted_services: Vec<ServiceName>,
        /// Code-signing status of the owning binary.
        signature: SignatureStatus,
    },
    /// The raw endpoint carried an owning pid, but the process had already
    /// exited by the time [`ProcessResolver::describe`] queried it.
    ProcessGone,
    /// The raw endpoint carried no owning pid at all (e.g. a kernel-owned
    /// or otherwise unattributed socket).
    Unresolved,
}

/// One listening endpoint collected from a host, before drift or report assembly.
///
/// This is the collection handler's own output type, distinct from
/// [`crate::domain::Endpoint`] — it exists so `owning_process` can carry
/// [`ProcessAttribution::ProcessGone`], a fact the `Endpoint` aggregate has
/// no field for. A later use case is expected to fold `CollectedEndpoint`
/// values into a [`crate::domain::ScanSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedEndpoint {
    /// Transport protocol the socket is bound with.
    pub protocol: Protocol,
    /// Address the socket is bound to.
    pub bind_address: BindAddress,
    /// Port the socket is bound to.
    pub port: Port,
    /// What the handler could establish about the endpoint's owning process.
    pub owning_process: ProcessAttribution,
}

/// Borrowed handle to the four collector ports for one collection run.
///
/// The fan-out orchestrator is expected to hold the concrete adapters
/// behind `Arc<dyn _>` and build one of these per host per scan. Delegating
/// implementations of all four traits are provided so a `CollectorSet` can
/// itself be passed anywhere a single port is expected, including to
/// [`collect_endpoints`].
pub struct CollectorSet<'a> {
    /// The listening-socket source for this run.
    pub endpoints: &'a dyn EndpointSource,
    /// The process resolver for this run.
    pub processes: &'a dyn ProcessResolver,
    /// The firewall policy source for this run.
    pub firewall: &'a dyn FirewallPolicySource,
    /// The signature verifier for this run.
    pub signatures: &'a dyn SignatureVerifier,
}

#[async_trait]
impl EndpointSource for CollectorSet<'_> {
    async fn listening_endpoints(&self) -> Result<Vec<RawEndpoint>, CollectError> {
        self.endpoints.listening_endpoints().await
    }
}

#[async_trait]
impl ProcessResolver for CollectorSet<'_> {
    async fn describe(&self, pid: ProcessId) -> Result<Option<RawProcess>, CollectError> {
        self.processes.describe(pid).await
    }

    async fn hosted_services(&self, pid: ProcessId) -> Result<Vec<RawService>, CollectError> {
        self.processes.hosted_services(pid).await
    }
}

#[async_trait]
impl FirewallPolicySource for CollectorSet<'_> {
    async fn inbound_rules(&self) -> Result<Vec<RawRule>, CollectError> {
        self.firewall.inbound_rules().await
    }

    async fn profiles(&self) -> Result<Vec<RawProfile>, CollectError> {
        self.firewall.profiles().await
    }
}

#[async_trait]
impl SignatureVerifier for CollectorSet<'_> {
    async fn verify(&self, path: &ProcessPath) -> Result<SignatureStatus, CollectError> {
        self.signatures.verify(path).await
    }
}

/// Collects every listening endpoint on a host and resolves each one's
/// owning process, hosted services, and binary signature.
///
/// Never drops an endpoint because its process could not be resolved — a
/// listening socket is a real fact about the host's exposure regardless of
/// whether the owning process could still be identified by the time this
/// ran. See [`ProcessAttribution`].
///
/// A raw `owning_pid` of `0` is treated the same as a missing pid
/// ([`ProcessAttribution::Unresolved`]) rather than a parse error: several
/// platforms report pid `0` for kernel/unowned sockets, and `0` is never a
/// live process id ([`ProcessId`] rejects it), so there is nothing to look
/// up.
///
/// # Errors
///
/// Returns [`CollectError`] if the endpoint source itself fails, or if any
/// raw value fails to parse into its corresponding domain value object.
pub async fn collect_endpoints<C>(sources: &C) -> Result<Vec<CollectedEndpoint>, CollectError>
where
    C: EndpointSource + ProcessResolver + SignatureVerifier + ?Sized,
{
    let raw_endpoints = sources.listening_endpoints().await?;
    let mut collected = Vec::with_capacity(raw_endpoints.len());
    for raw in raw_endpoints {
        let protocol: Protocol = raw.protocol.parse().map_err(CollectError::from)?;
        let bind_address: BindAddress = raw.local_address.parse().map_err(CollectError::from)?;
        let port = Port::try_from(raw.local_port).map_err(CollectError::from)?;
        let owning_process = resolve_process(sources, raw.owning_pid).await?;
        collected.push(CollectedEndpoint {
            protocol,
            bind_address,
            port,
            owning_process,
        });
    }
    Ok(collected)
}

/// Resolves one endpoint's owning process, if it named one.
async fn resolve_process<C>(
    sources: &C,
    owning_pid: Option<u32>,
) -> Result<ProcessAttribution, CollectError>
where
    C: ProcessResolver + SignatureVerifier + ?Sized,
{
    let Some(raw_pid) = owning_pid else {
        return Ok(ProcessAttribution::Unresolved);
    };
    let Ok(pid) = ProcessId::try_from(raw_pid) else {
        return Ok(ProcessAttribution::Unresolved);
    };
    let Some(raw_process) = sources.describe(pid).await? else {
        return Ok(ProcessAttribution::ProcessGone);
    };

    let path = raw_process
        .path
        .map(ProcessPath::try_from)
        .transpose()
        .map_err(CollectError::from)?;

    let signature = match &path {
        Some(path) => sources.verify(path).await?,
        None => SignatureStatus::Unknown,
    };

    let mut hosted_services = sources
        .hosted_services(pid)
        .await?
        .into_iter()
        .map(|raw_service| ServiceName::try_from(raw_service.name).map_err(CollectError::from))
        .collect::<Result<Vec<_>, _>>()?;
    hosted_services.sort();

    Ok(ProcessAttribution::Resolved {
        pid,
        path,
        hosted_services,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        CollectError, EndpointSource, FirewallPolicySource, ProcessAttribution, ProcessId,
        ProcessPath, ProcessResolver, RawEndpoint, RawProcess, RawProfile, RawRule, RawService,
        SignatureStatus, SignatureVerifier, async_trait, collect_endpoints,
    };

    #[derive(Debug, Default, Clone)]
    struct FakeEndpointSource(Vec<RawEndpoint>);

    #[async_trait]
    impl EndpointSource for FakeEndpointSource {
        async fn listening_endpoints(&self) -> Result<Vec<RawEndpoint>, CollectError> {
            Ok(self.0.clone())
        }
    }

    #[derive(Debug, Default)]
    struct FakeProcessResolver {
        processes: HashMap<u32, RawProcess>,
        services: HashMap<u32, Vec<RawService>>,
    }

    #[async_trait]
    impl ProcessResolver for FakeProcessResolver {
        async fn describe(&self, pid: ProcessId) -> Result<Option<RawProcess>, CollectError> {
            Ok(self.processes.get(&pid.get()).cloned())
        }

        async fn hosted_services(&self, pid: ProcessId) -> Result<Vec<RawService>, CollectError> {
            Ok(self.services.get(&pid.get()).cloned().unwrap_or_default())
        }
    }

    #[derive(Debug, Default)]
    struct FakeFirewallPolicySource {
        rules: Vec<RawRule>,
        profiles: Vec<RawProfile>,
    }

    #[async_trait]
    impl FirewallPolicySource for FakeFirewallPolicySource {
        async fn inbound_rules(&self) -> Result<Vec<RawRule>, CollectError> {
            Ok(self.rules.clone())
        }

        async fn profiles(&self) -> Result<Vec<RawProfile>, CollectError> {
            Ok(self.profiles.clone())
        }
    }

    #[derive(Debug, Default)]
    struct FakeSignatureVerifier {
        statuses: HashMap<String, SignatureStatus>,
    }

    #[async_trait]
    impl SignatureVerifier for FakeSignatureVerifier {
        async fn verify(&self, path: &ProcessPath) -> Result<SignatureStatus, CollectError> {
            Ok(self
                .statuses
                .get(path.as_str())
                .cloned()
                .unwrap_or(SignatureStatus::Unknown))
        }
    }

    /// Bundles fakes for all four collector ports so the collection handler
    /// can be built and driven with zero platform access.
    #[derive(Debug, Default)]
    struct FakeCollectorSet {
        endpoints: FakeEndpointSource,
        processes: FakeProcessResolver,
        firewall: FakeFirewallPolicySource,
        signatures: FakeSignatureVerifier,
    }

    impl FakeCollectorSet {
        fn with_endpoint(mut self, endpoint: RawEndpoint) -> Self {
            self.endpoints.0.push(endpoint);
            self
        }

        fn with_endpoint_owned_by_unresolvable_pid(mut self, pid: u32) -> Self {
            self.endpoints.0.push(RawEndpoint {
                protocol: "tcp".to_owned(),
                local_address: "0.0.0.0".to_owned(),
                local_port: 8080,
                owning_pid: Some(pid),
            });
            self
        }

        fn with_process(mut self, pid: u32, process: RawProcess) -> Self {
            self.processes.processes.insert(pid, process);
            self
        }

        fn with_hosted_service(mut self, pid: u32, name: &str) -> Self {
            self.processes
                .services
                .entry(pid)
                .or_default()
                .push(RawService {
                    name: name.to_owned(),
                    display_name: name.to_owned(),
                });
            self
        }

        fn with_signature(mut self, path: &str, status: SignatureStatus) -> Self {
            self.signatures.statuses.insert(path.to_owned(), status);
            self
        }
    }

    #[async_trait]
    impl EndpointSource for FakeCollectorSet {
        async fn listening_endpoints(&self) -> Result<Vec<RawEndpoint>, CollectError> {
            self.endpoints.listening_endpoints().await
        }
    }

    #[async_trait]
    impl ProcessResolver for FakeCollectorSet {
        async fn describe(&self, pid: ProcessId) -> Result<Option<RawProcess>, CollectError> {
            self.processes.describe(pid).await
        }

        async fn hosted_services(&self, pid: ProcessId) -> Result<Vec<RawService>, CollectError> {
            self.processes.hosted_services(pid).await
        }
    }

    #[async_trait]
    impl FirewallPolicySource for FakeCollectorSet {
        async fn inbound_rules(&self) -> Result<Vec<RawRule>, CollectError> {
            self.firewall.inbound_rules().await
        }

        async fn profiles(&self) -> Result<Vec<RawProfile>, CollectError> {
            self.firewall.profiles().await
        }
    }

    #[async_trait]
    impl SignatureVerifier for FakeCollectorSet {
        async fn verify(&self, path: &ProcessPath) -> Result<SignatureStatus, CollectError> {
            self.signatures.verify(path).await
        }
    }

    mod fixtures {
        use super::RawEndpoint;

        pub(super) fn raw_endpoint(port: u16) -> RawEndpoint {
            RawEndpoint {
                protocol: "tcp".to_owned(),
                local_address: "0.0.0.0".to_owned(),
                local_port: port,
                owning_pid: None,
            }
        }
    }

    #[tokio::test]
    async fn collection_handler_runs_against_fakes_with_no_platform_access() {
        let sources = FakeCollectorSet::default().with_endpoint(fixtures::raw_endpoint(443));

        let snapshot = collect_endpoints(&sources).await.unwrap();

        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].port.get(), 443);
        assert_eq!(snapshot[0].owning_process, ProcessAttribution::Unresolved);
    }

    #[tokio::test]
    async fn missing_process_is_recorded_not_dropped() {
        let sources = FakeCollectorSet::default().with_endpoint_owned_by_unresolvable_pid(9999);

        let snapshot = collect_endpoints(&sources).await.unwrap();

        assert_eq!(snapshot.len(), 1);
        assert!(matches!(
            snapshot[0].owning_process,
            ProcessAttribution::ProcessGone
        ));
    }

    #[tokio::test]
    async fn resolved_process_carries_signature_and_hosted_services() {
        let pid = 4242u32;
        let path = "C:\\svc\\app.exe".to_owned();
        let sources = FakeCollectorSet::default()
            .with_endpoint(RawEndpoint {
                protocol: "tcp".to_owned(),
                local_address: "0.0.0.0".to_owned(),
                local_port: 8443,
                owning_pid: Some(pid),
            })
            .with_process(
                pid,
                RawProcess {
                    pid,
                    path: Some(path.clone()),
                    command_line: None,
                },
            )
            .with_hosted_service(pid, "MyService")
            .with_signature(&path, SignatureStatus::Unsigned);

        let snapshot = collect_endpoints(&sources).await.unwrap();

        assert_eq!(snapshot.len(), 1);
        match &snapshot[0].owning_process {
            ProcessAttribution::Resolved {
                pid: got_pid,
                signature,
                hosted_services,
                ..
            } => {
                assert_eq!(got_pid.get(), pid);
                assert_eq!(*signature, SignatureStatus::Unsigned);
                assert_eq!(hosted_services.len(), 1);
                assert_eq!(hosted_services[0].as_str(), "MyService");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_bind_address_produces_collect_error_not_panic() {
        let sources = FakeCollectorSet::default().with_endpoint(RawEndpoint {
            protocol: "tcp".to_owned(),
            local_address: "not-an-ip".to_owned(),
            local_port: 80,
            owning_pid: None,
        });

        let result = collect_endpoints(&sources).await;

        assert!(matches!(result, Err(CollectError::Parse(_))));
    }

    #[tokio::test]
    async fn firewall_policy_source_fake_returns_seeded_rules_and_profiles() {
        let sources = FakeCollectorSet {
            firewall: FakeFirewallPolicySource {
                rules: vec![RawRule {
                    rule_id: "{11111111-1111-1111-1111-111111111111}".to_owned(),
                    display_name: "Allow HTTPS".to_owned(),
                    direction: "Inbound".to_owned(),
                    action: "Allow".to_owned(),
                    protocol: Some("TCP".to_owned()),
                    local_port_spec: Some("443".to_owned()),
                    program_filter: None,
                    service_filter: None,
                    enabled: true,
                    policy_store: "Local".to_owned(),
                }],
                profiles: vec![RawProfile {
                    name: "Public".to_owned(),
                    enabled: true,
                    default_inbound_action: "Block".to_owned(),
                    default_outbound_action: "Allow".to_owned(),
                }],
            },
            ..FakeCollectorSet::default()
        };

        assert_eq!(sources.inbound_rules().await.unwrap().len(), 1);
        assert_eq!(sources.profiles().await.unwrap().len(), 1);
    }
}
