//! `anne scan` — orchestrate a single local collection or fan out over SSH
//! to an inventory of remote hosts, then persist every snapshot through
//! the configured `SnapshotStore`.
//!
//! The two modes (`--emit-json` vs interactive) split here for the same
//! reason the task calls out: stdout under `--emit-json` carries the
//! snapshot bytes and nothing else, ever. Interactive mode is free to
//! print a human-readable summary to stdout and to keep stderr busy.
//! `--emit-json` has no defined stdout contract for a multi-host fan-out
//! result, so it stays local-scan-only — combining it with
//! `--target`/`--inventory` is rejected outright rather than silently
//! scanning the local machine instead of the host the operator asked for.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tracing::{info, warn};

use crate::application::firewall_mapping::{firewall_profiles_from_raw, firewall_rules_from_raw};
use crate::cli::{ExitCode, ScanArgs, StrategyArg};
use anne_de_breuil::adapters::config::{
    AnneConfig, RemoteConfig, ScanConfig, StoreBackend, StoreConfig,
};
use anne_de_breuil::adapters::inventory::parse_inventory;
use anne_de_breuil::adapters::remote_scanner::{SshHostScanner, SshHostScannerConfig};
use anne_de_breuil::adapters::snapshot_store::FsSnapshotStore;
use anne_de_breuil::adapters::ssh_transport::{DEFAULT_MAX_OUTPUT_BYTES, KnownHosts};
use anne_de_breuil::application::collect::{
    CollectError, CollectedEndpoint, FirewallPolicySource, ProcessAttribution, collect_endpoints,
};
use anne_de_breuil::application::fanout::{HostOutcome, HostScanner, run_fanout};
use anne_de_breuil::application::identify::ProbeConfig;
use anne_de_breuil::application::snapshot_store::{SnapshotStore, StoreError};
use anne_de_breuil::domain::{
    Endpoint, HostId, IdempotencyKey, ScanId, ScanSnapshot, TargetStrategy,
};

/// The `[scan]`/`[remote]`/`[store]` config sections relevant to this
/// command, resolved either from `--config` or from each section's own
/// built-in `Default`.
///
/// Deliberately *not* `AnneConfig::load(some_default_path)` when
/// `--config` is absent: `StoreConfig` has no `Default` (an operator must
/// say explicitly where scan data lands, see its own doc comment), so
/// calling `load` unconditionally would make every `anne scan` invocation
/// that never asked for `--config` start failing the moment neither a file
/// nor the environment supplies `[store]`. Loading only happens when the
/// flag is actually given — every existing call site that constructs
/// `ScanArgs` without `--config` keeps working exactly as before this
/// existed.
struct ResolvedConfig {
    scan: ScanConfig,
    remote: RemoteConfig,
    store: Option<StoreConfig>,
}

fn resolve_config(args: &ScanArgs) -> Result<ResolvedConfig> {
    match &args.config {
        Some(path) => {
            let config = AnneConfig::load(path)
                .with_context(|| format!("loading config from {}", path.display()))?;
            Ok(ResolvedConfig {
                scan: config.scan,
                remote: config.remote,
                store: Some(config.store),
            })
        }
        None => Ok(ResolvedConfig {
            scan: ScanConfig::default(),
            remote: RemoteConfig::default(),
            store: None,
        }),
    }
}

/// Dispatch `args` to either the bare-stdout emitter mode or the
/// interactive scan path.
///
/// `emit_json` is the contract: stdout = exactly one `ScanSnapshot`,
/// stderr = everything else.
pub async fn run(args: ScanArgs) -> Result<ExitCode> {
    let resolved = match resolve_config(&args) {
        Ok(resolved) => resolved,
        Err(e) => {
            eprintln!("error: {e:?}");
            return Ok(ExitCode::ConfigOrArgError);
        }
    };

    if args.emit_json {
        run_emit_json(args, &resolved).await
    } else {
        run_interactive(args, &resolved).await
    }
}

/// `--emit-json` mode: collect locally, write the snapshot to stdout
/// once, return clean.
///
/// Tracing was installed by `main` with stderr writer — so even at
/// `RUST_LOG=trace` nothing leaks to stdout here.
async fn run_emit_json(args: ScanArgs, resolved: &ResolvedConfig) -> Result<ExitCode> {
    if args.inventory.is_some() || args.target.is_some() {
        eprintln!(
            "--emit-json only supports a local scan; there is no defined single-snapshot \
             stdout contract for a multi-host remote fan-out -- drop --target/--inventory, or \
             drop --emit-json and use the interactive remote scan path instead"
        );
        return Ok(ExitCode::ConfigOrArgError);
    }

    let snapshot = match scan_local(&args, &resolved.scan).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "local scan failed in --emit-json mode");
            return Ok(ExitCode::OperationalError);
        }
    };

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer(&mut handle, &snapshot).context("serialize ScanSnapshot to stdout")?;
    Ok(ExitCode::Clean)
}

/// Interactive mode: collect locally, fan out over `--inventory`, or
/// acknowledge (without contacting anything) a `--target` that has no
/// login/auth information to connect with yet — then persist and print a
/// human summary.
async fn run_interactive(args: ScanArgs, resolved: &ResolvedConfig) -> Result<ExitCode> {
    if let Some(inventory_path) = args.inventory.clone() {
        return run_remote_fanout(&args, &inventory_path, resolved).await;
    }
    if let Some(target) = args.target.as_deref() {
        return Ok(run_remote_single_target(&args, target));
    }

    let snapshot = match scan_local(&args, &resolved.scan).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "local scan failed");
            return Ok(ExitCode::OperationalError);
        }
    };

    let host_id = snapshot.host_id;
    let store = match build_store(args.store.as_deref(), resolved.store.as_ref()) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("error: {e:?}");
            return Ok(ExitCode::ConfigOrArgError);
        }
    };
    match persist(store.as_ref(), &snapshot).await {
        Ok(scan_id) => {
            println!("scanned host {host_id}; snapshot {scan_id} persisted");
            Ok(ExitCode::Clean)
        }
        Err(e) => {
            tracing::error!(host_id = %host_id, error = %e, "persisting local snapshot failed");
            Ok(ExitCode::OperationalError)
        }
    }
}

/// Collect one snapshot from the local host using whatever collector
/// adapter matches this build's feature set (real PowerShell/native-Win32
/// collection on Windows, real netlink/`/proc` collection on Linux, an
/// honest empty stub everywhere else — see
/// `adapters::collector_factory`'s own module docs).
///
/// `include_udp` merges the CLI flag with `[scan]`'s config value (either
/// one turning it on is enough), though no real adapter filters by
/// transport on it yet — see `collector_factory::local_collectors`'s own
/// doc comment. `include_loopback`/`skip_signature`/`policy_store` stay
/// unwired CLI-only options for now: `include_loopback`/`skip_signature`
/// have no call site anywhere in this crate, and `policy_store` has
/// nothing to select between since `FirewallPolicySource::inbound_rules`
/// takes no policy-store parameter. Distinct, standing gaps from the one
/// this function closes (getting real endpoint/firewall data flowing at
/// all) — see `docs/integration-wiring-audit.md`.
async fn scan_local(args: &ScanArgs, scan_config: &ScanConfig) -> Result<ScanSnapshot> {
    let include_udp = args.include_udp || scan_config.include_udp;
    let (collector_set, _guard) = crate::adapters::collector_factory::local_collectors(include_udp);

    let collected = collect_endpoints(&collector_set)
        .await
        .map_err(|e: CollectError| anyhow!("collect_endpoints failed: {e}"))?;

    let endpoints: Vec<Endpoint> = collected
        .into_iter()
        .map(endpoint_from_collected)
        .collect::<Vec<_>>();

    // `PolicyUnavailable` means the platform's own policy source
    // (nftables netlink on Linux) genuinely couldn't be queried on this
    // host -- permission denied, netlink unreachable, or a legacy
    // iptables-only ruleset with nothing for it to find (see
    // `CollectError::PolicyUnavailable`'s own doc comment). That's a real,
    // common, non-root-user outcome, not a bug: an unprivileged `anne
    // scan` on a real Linux host routinely can't open a
    // `NETLINK_NETFILTER` socket. Degrading to an empty firewall rule set
    // and logging a warning mirrors the PowerShell path's own established
    // precedent (`payload::LanguageMode::Constrained` -- "reduced
    // fidelity, not failure") rather than aborting a scan that could
    // otherwise report real endpoint/process/signature data. Any other
    // `CollectError` variant here is a genuine, unexpected failure and
    // still aborts the scan, same as before.
    let raw_rules = match collector_set.inbound_rules().await {
        Ok(rules) => rules,
        Err(CollectError::PolicyUnavailable(reason)) => {
            warn!(
                reason = %reason,
                "firewall policy source unavailable; reporting endpoints with no firewall rules"
            );
            Vec::new()
        }
        Err(e) => return Err(anyhow!("inbound_rules failed: {e}")),
    };
    let firewall_rules =
        firewall_rules_from_raw(raw_rules).context("mapping collected firewall rules")?;

    let raw_profiles = collector_set
        .profiles()
        .await
        .map_err(|e: CollectError| anyhow!("profiles failed: {e}"))?;
    let profiles =
        firewall_profiles_from_raw(raw_profiles).context("mapping collected firewall profiles")?;

    let snapshot = ScanSnapshot::new(
        HostId::generate(),
        ScanId::generate(),
        time::OffsetDateTime::now_utc(),
        env!("CARGO_PKG_VERSION").to_owned(),
        endpoints,
        firewall_rules,
        profiles,
        forced_strategy(args.strategy),
    );

    Ok(snapshot)
}

/// Fold one `CollectedEndpoint` into a domain `Endpoint`. A `ProcessGone`
/// attribution is recorded with `process_id: None` (the pid is no longer
/// trustworthy as an identifier); a `Unresolved` attribution stays
/// `process_id: None` by definition; `Resolved` carries every field
/// through, including the still-unredacted `command_line` that the
/// `ReportModel` boundary sanitises downstream.
fn endpoint_from_collected(collected: CollectedEndpoint) -> Endpoint {
    match collected.owning_process {
        ProcessAttribution::Resolved {
            pid,
            path,
            hosted_services,
            signature,
            command_line,
        } => Endpoint::new(
            collected.protocol,
            collected.bind_address,
            collected.port,
            Some(pid),
            path,
            hosted_services,
            signature,
            command_line,
        ),
        ProcessAttribution::ProcessGone | ProcessAttribution::Unresolved => Endpoint::new(
            collected.protocol,
            collected.bind_address,
            collected.port,
            None,
            None,
            Vec::new(),
            anne_de_breuil::domain::SignatureStatus::Unknown,
            None,
        ),
    }
}

/// Map `StrategyArg` to a domain `TargetStrategy`. `Auto` becomes
/// `Execute` for the local path (it can always run the collector
/// directly, no SSH fanout is involved).
const fn forced_strategy(arg: StrategyArg) -> TargetStrategy {
    match arg {
        StrategyArg::Auto | StrategyArg::Execute | StrategyArg::LocalOnly => {
            TargetStrategy::Execute
        }
        StrategyArg::Probe => TargetStrategy::Probe,
    }
}

/// Fans out to every host in `inventory_path`, persisting each result as
/// it completes and printing one summary line per host.
async fn run_remote_fanout(
    args: &ScanArgs,
    inventory_path: &Path,
    resolved: &ResolvedConfig,
) -> Result<ExitCode> {
    let contents = match std::fs::read_to_string(inventory_path) {
        Ok(contents) => contents,
        Err(e) => {
            eprintln!(
                "error: reading inventory file {}: {e}",
                inventory_path.display()
            );
            return Ok(ExitCode::ConfigOrArgError);
        }
    };
    let hosts = match parse_inventory(&contents) {
        Ok(hosts) => hosts,
        Err(e) => {
            eprintln!(
                "error: invalid inventory file {}: {e}",
                inventory_path.display()
            );
            return Ok(ExitCode::ConfigOrArgError);
        }
    };
    if hosts.is_empty() {
        eprintln!("inventory file {} has no hosts", inventory_path.display());
        return Ok(ExitCode::Clean);
    }

    let known_hosts = match load_known_hosts(&resolved.remote.known_hosts) {
        Ok(known_hosts) => Arc::new(known_hosts),
        Err(e) => {
            eprintln!(
                "error: loading known_hosts {}: {e}",
                resolved.remote.known_hosts.display()
            );
            return Ok(ExitCode::OperationalError);
        }
    };

    // `--probe-exclude`/`--probe-timeout`/`--probe-rate` are not wired
    // into this tier's `ProbeConfig` -- they're a distinct, still-unwired
    // CLI surface for local active identification against a scan's own
    // already-discovered endpoints, not remote fleet port-guessing. See
    // docs/integration-wiring-audit.md.
    let scanner: Arc<dyn HostScanner> = match SshHostScanner::new(SshHostScannerConfig {
        known_hosts,
        accept_new: resolved.remote.accept_new,
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        probe_config: ProbeConfig::default(),
    }) {
        Ok(scanner) => Arc::new(scanner),
        Err(e) => {
            eprintln!("error: building remote host scanner: {e}");
            return Ok(ExitCode::OperationalError);
        }
    };

    let store = match build_store(args.store.as_deref(), resolved.store.as_ref()) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("error: {e:?}");
            return Ok(ExitCode::ConfigOrArgError);
        }
    };

    let progress = anne_de_breuil::adapters::progress::new();
    let results = run_fanout(
        hosts,
        resolved.remote.concurrency,
        resolved.remote.timeout,
        store,
        scanner,
        Arc::clone(&progress),
    )
    .await;
    progress.finish();

    let mut failures = 0usize;
    for result in &results {
        match &result.outcome {
            HostOutcome::Succeeded(scan_id) => {
                println!(
                    "host {}: scanned ({:?}); snapshot {scan_id} persisted",
                    result.host_id, result.strategy_used
                );
            }
            HostOutcome::Failed(err) => {
                failures += 1;
                println!(
                    "host {}: scan failed ({:?}): {err}",
                    result.host_id, result.strategy_used
                );
            }
            HostOutcome::TimedOut => {
                failures += 1;
                println!(
                    "host {}: scan timed out ({:?})",
                    result.host_id, result.strategy_used
                );
            }
        }
    }

    if failures > 0 {
        Ok(ExitCode::OperationalError)
    } else {
        Ok(ExitCode::Clean)
    }
}

/// Loads `path` as an OpenSSH `known_hosts` file, or falls back to an
/// empty book (every host reports `HostKeyStatus::Unknown` until
/// `--accept-new`/`[remote] accept_new` admits it) when the path simply
/// doesn't exist — a fresh installation with no `known_hosts` file on disk
/// yet is the common case, not an error to fail the whole scan over.
fn load_known_hosts(path: &Path) -> Result<KnownHosts> {
    if !path.exists() {
        return Ok(KnownHosts::empty());
    }
    KnownHosts::load_file(path).map_err(|e| anyhow!("{e}"))
}

/// Handle a single `--target` host. `--target` only ever carries a bare
/// hostname — there is no CLI flag yet for the login user or auth method a
/// real connection needs, so this stays a deliberate, honest no-op rather
/// than guessing a user (e.g. `"root"`) or silently scanning the local
/// machine instead of the host the operator named.
fn run_remote_single_target(args: &ScanArgs, target: &str) -> ExitCode {
    warn!(
        target,
        "single-target remote scanning needs a login user and auth method that --target alone \
         doesn't carry yet -- pass --inventory instead, or wait for a future task to add the \
         missing flags (see docs/integration-wiring-audit.md); no remote host was contacted"
    );
    info!(
        include_udp = args.include_udp,
        include_loopback = args.include_loopback,
        skip_signature = args.skip_signature,
        "scan options acknowledged (no remote host was contacted)"
    );
    ExitCode::Clean
}

/// Builds the configured `SnapshotStore`, in priority order: `--store` (a
/// bare filesystem directory, the original CLI-only path), then
/// `--config`'s `[store]` section, then the filesystem default
/// (`./anne-snapshots`). Mirrors `examples/portal_server.rs`'s own
/// `build_store` (backend match, `SQLite` behind its own feature gate)
/// rather than inventing a second store-selection shape for the same
/// config section.
fn build_store(
    cli_store: Option<&Path>,
    config_store: Option<&StoreConfig>,
) -> Result<Arc<dyn SnapshotStore>> {
    if let Some(path) = cli_store {
        let store = FsSnapshotStore::new(path)
            .with_context(|| format!("opening store at {}", path.display()))?;
        return Ok(Arc::new(store));
    }

    if let Some(config) = config_store {
        return match config.backend {
            StoreBackend::FileSystem => {
                let store = FsSnapshotStore::new(&config.path)
                    .with_context(|| format!("opening store at {}", config.path.display()))?;
                Ok(Arc::new(store))
            }
            StoreBackend::Sqlite => sqlite_store(&config.path),
        };
    }

    let path = PathBuf::from("anne-snapshots");
    std::fs::create_dir_all(&path)
        .with_context(|| format!("creating snapshot directory {}", path.display()))?;
    let store = FsSnapshotStore::new(&path)
        .with_context(|| format!("opening store at {}", path.display()))?;
    Ok(Arc::new(store))
}

// Not `#[cfg(feature = "store-sqlite")]`: that attribute checks *this*
// crate's own declared features, not a dependency's -- `anne-de-breuil-cli`
// has no `[features]` table at all. `store-sqlite` is instead an
// unconditional feature of the `anne-de-breuil` dependency itself (see
// this crate's `Cargo.toml`), so `SqliteSnapshotStore` is always compiled
// in and reachable here without any conditional compilation.
fn sqlite_store(path: &Path) -> Result<Arc<dyn SnapshotStore>> {
    let store = anne_de_breuil::adapters::snapshot_store::SqliteSnapshotStore::open(path)
        .with_context(|| format!("opening sqlite store at {}", path.display()))?;
    Ok(Arc::new(store))
}

/// Persist `snapshot` to `store`. Returns the `ScanId` that the store
/// assigned (or the existing one, on idempotent re-`put`).
async fn persist(store: &dyn SnapshotStore, snapshot: &ScanSnapshot) -> Result<ScanId, StoreError> {
    let key = IdempotencyKey::generate();
    store.put(key, snapshot.clone()).await
}
