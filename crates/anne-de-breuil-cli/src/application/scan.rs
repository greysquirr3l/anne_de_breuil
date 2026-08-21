//! `anne scan` — orchestrate a single local collection or fan out over SSH
//! to an inventory of remote hosts, then persist every snapshot through
//! the configured `SnapshotStore`.
//!
//! The two modes (`--emit-json` vs interactive) split here for the same
//! reason the task calls out: stdout under `--emit-json` carries the
//! snapshot bytes and nothing else, ever. Interactive mode is free to
//! print a human-readable summary to stdout and to keep stderr busy.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tracing::{info, warn};

use crate::cli::{ExitCode, ScanArgs, StrategyArg};
use anne_de_breuil::application::collect::{
    CollectError, CollectedEndpoint, ProcessAttribution, collect_endpoints,
};
use anne_de_breuil::application::snapshot_store::{SnapshotStore, StoreError};
use anne_de_breuil::domain::{
    Endpoint, HostId, IdempotencyKey, ScanId, ScanSnapshot, TargetStrategy,
};

/// Dispatch `args` to either the bare-stdout emitter mode or the
/// interactive scan path.
///
/// `emit_json` is the contract: stdout = exactly one `ScanSnapshot`,
/// stderr = everything else.
pub async fn run(args: ScanArgs) -> Result<ExitCode> {
    if args.emit_json {
        run_emit_json(args).await
    } else {
        run_interactive(args).await
    }
}

/// `--emit-json` mode: collect locally, write the snapshot to stdout
/// once, return clean.
///
/// Tracing was installed by `main` with stderr writer — so even at
/// `RUST_LOG=trace` nothing leaks to stdout here.
async fn run_emit_json(args: ScanArgs) -> Result<ExitCode> {
    let snapshot = match scan_local(&args).await {
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

/// Interactive mode: collect locally (or fan out, if `--inventory` is set),
/// persist each snapshot, and print a one-line human summary per host.
async fn run_interactive(args: ScanArgs) -> Result<ExitCode> {
    if let Some(inventory_path) = args.inventory.clone() {
        return Ok(run_remote_fanout(&args, &inventory_path));
    }
    if let Some(target) = args.target.as_deref() {
        return Ok(run_remote_single_target(&args, target));
    }

    let snapshot = match scan_local(&args).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "local scan failed");
            return Ok(ExitCode::OperationalError);
        }
    };

    let host_id = snapshot.host_id;
    match persist(&args, &snapshot).await {
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
/// adapter matches this build's feature set.
async fn scan_local(args: &ScanArgs) -> Result<ScanSnapshot> {
    let (collector_set, _guard) =
        crate::adapters::collector_factory::local_collectors(args.include_udp);

    let collected = collect_endpoints(&collector_set)
        .await
        .map_err(|e: CollectError| anyhow!("collect_endpoints failed: {e}"))?;

    let endpoints: Vec<Endpoint> = collected
        .into_iter()
        .map(endpoint_from_collected)
        .collect::<Vec<_>>();

    let snapshot = ScanSnapshot::new(
        HostId::generate(),
        ScanId::generate(),
        time::OffsetDateTime::now_utc(),
        env!("CARGO_PKG_VERSION").to_owned(),
        endpoints,
        // Firewall rules/profiles are pulled directly by the adapter in a
        // real wiring (T31); for now the local scan reports an empty
        // policy through the cross-platform collector-factory stub.
        vec![],
        vec![],
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

/// Fan out to every host in an inventory file, persisting each result.
/// T18 wires the surface; full fan-out integration (real `HostScanner`,
/// per-host retries) is T31's job — see the `TODO(T31)` callsite in
/// `application::fanout::HostScanner`.
fn run_remote_fanout(args: &ScanArgs, _inventory_path: &Path) -> ExitCode {
    warn!(
        "remote inventory fan-out is structurally wired but not yet integrated with the T16 \
         orchestrator; run a single host with --target, or wait for T31."
    );
    info!(
        include_udp = args.include_udp,
        include_loopback = args.include_loopback,
        skip_signature = args.skip_signature,
        "scan options acknowledged (no remote hosts were contacted)"
    );
    ExitCode::Clean
}

/// Handle a single `--target` host. Same boundary as `run_remote_fanout`:
/// there is no real `HostScanner`/`RemoteTransport` wiring yet (T31), so
/// this warns rather than silently scanning the local machine instead of
/// the host the operator actually asked for — an earlier version of this
/// function didn't check `args.target` at all here, which made
/// `anne scan --target somehost` silently report a clean local scan.
fn run_remote_single_target(args: &ScanArgs, target: &str) -> ExitCode {
    warn!(
        target,
        "remote single-target scanning is not yet wired to a real transport (see \
         HostScanner's TODO(T31)); run without --target to scan this host, or wait for T31."
    );
    info!(
        include_udp = args.include_udp,
        include_loopback = args.include_loopback,
        skip_signature = args.skip_signature,
        "scan options acknowledged (no remote host was contacted)"
    );
    ExitCode::Clean
}

/// Persist `snapshot` to the configured store. Returns the `ScanId` that
/// the store assigned (or the existing one, on idempotent re-`put`).
async fn persist(args: &ScanArgs, snapshot: &ScanSnapshot) -> Result<ScanId, StoreError> {
    let store: Arc<dyn SnapshotStore> = if let Some(path) = args.store.as_ref() {
        Arc::new(anne_de_breuil::adapters::snapshot_store::FsSnapshotStore::new(path)?)
    } else {
        let path = std::path::PathBuf::from("anne-snapshots");
        std::fs::create_dir_all(&path).map_err(StoreError::from)?;
        Arc::new(anne_de_breuil::adapters::snapshot_store::FsSnapshotStore::new(&path)?)
    };

    let key = IdempotencyKey::generate();
    store.put(key, snapshot.clone()).await
}
