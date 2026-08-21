//! Bounded-concurrency fan-out across an inventory of hosts, with per-host
//! timeout, per-host failure isolation, and a partial-result contract.
//!
//! Declared here, not in `adapters/`, for the same reason as every other
//! module in this package: [`run_fanout`] is a use case that *consumes*
//! ports ([`HostScanner`], [`crate::application::SnapshotStore`],
//! [`ProgressReporter`]), never a concrete adapter. Unbounded concurrent
//! connections against an MSP client's network looks like a port scan to
//! their IDS — because at that point it is one — so every host's work
//! happens behind a [`tokio::sync::Semaphore`] permit, held for the whole
//! scan-and-persist attempt, not just the network call.
//!
//! [`HostScanner`] is deliberately narrow: it does not know about
//! [`crate::application::SnapshotStore`] at all. `scan_one_host` owns the
//! persistence step so that a retried attempt always reuses the same
//! [`IdempotencyKey`], and `SnapshotStore::put`'s own idempotency contract
//! is what collapses a flaky host down to exactly one stored snapshot,
//! never a duplicate.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::adapters::inventory::InventoryHost;
use crate::application::snapshot_store::{SnapshotStore, StoreError};
use crate::domain::{HostId, IdempotencyKey, ScanId, ScanSnapshot, TargetStrategy};

/// A sane concurrency default for a caller (the future CLI) that doesn't
/// have a stronger opinion.
///
/// Not enforced by [`run_fanout`] itself — the task this module was
/// specified under puts "default 8" at the implementation-detail level,
/// but the concurrency bound is a user-facing tuning knob, so the default
/// belongs at the config/CLI layer that owns `--concurrency`, not baked
/// into the orchestrator.
pub const DEFAULT_CONCURRENCY: usize = 8;

/// A sane per-host timeout default for the same reason as
/// [`DEFAULT_CONCURRENCY`].
///
/// A suggestion for the CLI layer, not a value [`run_fanout`] assumes on
/// its own.
pub const DEFAULT_PER_HOST_TIMEOUT: Duration = Duration::from_mins(1);

/// Retry attempts per host, including the first. The code sketch this
/// module started from used 3; kept as a reasonable default for a
/// network operation against a fleet that may include flaky links.
const MAX_ATTEMPTS: u32 = 3;

/// Backoff before the first retry, doubled after each subsequent one.
const INITIAL_BACKOFF: Duration = Duration::from_millis(200);

/// How one host's scan attempt concluded.
#[derive(Debug)]
pub enum HostOutcome {
    /// The host was scanned and its snapshot persisted.
    Succeeded(ScanId),
    /// The host's scan failed in a way retries could not recover from.
    Failed(HostError),
    /// The host did not finish within its per-host time budget.
    TimedOut,
}

/// The result of fanning out to one host.
#[derive(Debug)]
pub struct HostResult {
    /// The host this result describes.
    pub host_id: HostId,
    /// Which collection tier was actually used for this host — always
    /// populated, even for a [`HostOutcome::Failed`] or
    /// [`HostOutcome::TimedOut`] outcome, so a report never has to guess
    /// whether a failed host section would have been authoritative or
    /// inferred. See [`TargetStrategy`].
    pub strategy_used: TargetStrategy,
    /// How the scan concluded.
    pub outcome: HostOutcome,
}

/// Failure scanning or persisting one host.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// The scan did not complete within the allotted time.
    #[error("host scan timed out")]
    Timeout,
    /// A transient failure `with_retry` should retry, given attempts remain.
    #[error("transient host scan failure, retry may succeed: {0}")]
    Retryable(String),
    /// A failure retrying will not fix (e.g. authentication rejected).
    #[error("host scan failed: {0}")]
    Fatal(String),
    /// The host's scan task panicked. Caught by Tokio at the `JoinSet`
    /// boundary, not by any `catch_unwind` in this crate's own code — see
    /// [`run_fanout`]'s doc comment for why that boundary is where this
    /// crate's panic isolation genuinely lives.
    #[error("host scan task panicked: {0}")]
    Panicked(String),
    /// Persisting a successfully scanned snapshot failed.
    #[error("persisting host snapshot failed: {0}")]
    Store(#[from] StoreError),
}

/// Scans one host: decides which collection tier is reachable, then
/// performs one scan attempt at that tier.
///
/// Consumer-owned, `#[async_trait]` for object safety — a fan-out
/// orchestrator holds many hosts' scanners concurrently behind
/// `Arc<dyn HostScanner>`, the same pattern already established by
/// [`crate::application::SnapshotStore`] and
/// [`crate::application::RemoteTransport`]. Split into two methods rather
/// than one opaque `scan`: `resolve_strategy` is infallible by design (a
/// host with no working execute transport degrades to
/// `TargetStrategy::Probe`, never a hard failure — matching
/// [`crate::application::remote`]'s own contract), so callers always know
/// which tier applies to a host even when the scan attempt itself fails or
/// times out.
/// The production implementation is
/// [`crate::adapters::remote_scanner::SshHostScanner`] (behind the `ssh`
/// feature, T31): it composes `SshTransport::connect` (T15) for
/// `TargetStrategy::Execute` — pushing this same running binary to the
/// target and running it with `--self-hash`/`--emit-json` — and
/// `HttpProber`/`TlsProber` (T09/T10) against a small, bounded candidate
/// port set for `TargetStrategy::Probe`. This module (T16) only declares
/// the port and the orchestration that drives it; the fakes in this file's
/// own test module exercise that orchestration independent of which real
/// collection pipeline eventually backs it.
#[async_trait]
pub trait HostScanner: Send + Sync {
    /// Decides which collection tier is available for `host`.
    async fn resolve_strategy(&self, host: &InventoryHost) -> TargetStrategy;

    /// Performs one scan attempt at `strategy`, tagged with
    /// `idempotency_key` so the caller's persistence step can recognise a
    /// retried attempt as the same logical scan, never a new one.
    ///
    /// # Errors
    ///
    /// Returns [`HostError`] if the attempt fails or times out.
    async fn scan(
        &self,
        host: &InventoryHost,
        strategy: TargetStrategy,
        idempotency_key: IdempotencyKey,
    ) -> Result<ScanSnapshot, HostError>;
}

/// Reports per-host progress so a CLI can render spinners and a portal can
/// stream events.
///
/// Sync, not `#[async_trait]`: this is UI/telemetry state a caller updates
/// in passing, not I/O worth making the orchestrator `.await` for. See
/// [`NullProgressReporter`] for the JSON-mode no-op adapter; the terminal
/// adapter (`adapters::progress::IndicatifProgress`, T19) implements this
/// same trait against a real spinner.
pub trait ProgressReporter: Send + Sync {
    /// Called once, right before a host's first scan attempt begins.
    fn host_started(&self, host_id: HostId);

    /// Called once, after a host's outcome (success, failure, or timeout)
    /// is final.
    fn host_finished(&self, host_id: HostId, outcome: &HostOutcome);

    /// Called once the whole fan-out run is over, successfully or not, so
    /// a terminal adapter can tear down its render loop and leave the
    /// screen clean.
    ///
    /// Default no-op keeps this addition non-breaking for
    /// [`NullProgressReporter`] and every existing implementor. Must be
    /// idempotent — a caller that finishes a run and then, on some error
    /// path, finishes it again should not see a second completion line.
    fn finish(&self) {}
}

/// A [`ProgressReporter`] that does nothing.
///
/// Used for JSON-mode output, where writing spinner frames to stderr would
/// be harmless noise at best and, on a terminal that isn't actually a TTY,
/// corrupt a piped machine-readable stream at worst.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullProgressReporter;

impl ProgressReporter for NullProgressReporter {
    fn host_started(&self, _host_id: HostId) {}
    fn host_finished(&self, _host_id: HostId, _outcome: &HostOutcome) {}
}

/// Fans out to every host in `inventory`, bounded to at most `concurrency`
/// scans running at once, each capped at `per_host_timeout`.
///
/// Each host's snapshot is persisted as it completes — `store.put` is
/// called from inside the spawned task itself, not batched after every
/// host finishes — so a run interrupted partway through keeps every result
/// obtained before the interruption.
///
/// One host's timeout, ordinary failure, or task panic never aborts the
/// run: `JoinSet::join_next_with_id` is used specifically (over a plain
/// `join_next`) so that when a task panics, its `JoinError` can still be
/// correlated back to the host it belonged to via a `host_id` recorded at
/// spawn time, and turned into a real [`HostResult`] carrying a
/// [`HostOutcome::Failed`] wrapping [`HostError::Panicked`] — not a
/// silently dropped result. There is no `catch_unwind` anywhere in this crate;
/// Tokio's own task boundary is what catches the panic, and this function
/// is what makes sure that catch isn't wasted.
///
/// A panic's `strategy_used` defaults to [`TargetStrategy::Probe`] — the
/// least-authoritative tier — since a panic can happen before strategy
/// resolution ever runs; this never overstates what was actually
/// established about the host. A [`HostOutcome::TimedOut`] instead reports
/// whatever strategy `resolve_strategy` had actually settled on before the
/// timeout fired (`Probe` only if the timeout hit *before* resolution
/// finished) — see `scan_one_host`'s doc comment for how that survives the
/// timeout cancelling the future it was computed in.
pub async fn run_fanout(
    inventory: Vec<InventoryHost>,
    concurrency: usize,
    per_host_timeout: Duration,
    store: Arc<dyn SnapshotStore>,
    scanner: Arc<dyn HostScanner>,
    progress: Arc<dyn ProgressReporter>,
) -> Vec<HostResult> {
    // A semaphore of size 0 would deadlock every host forever; there is no
    // meaningful "scan with zero concurrency", so 1 is the floor.
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = JoinSet::new();
    let mut host_ids: HashMap<tokio::task::Id, HostId> = HashMap::with_capacity(inventory.len());

    for host in inventory {
        let semaphore = Arc::clone(&semaphore);
        let store = Arc::clone(&store);
        let scanner = Arc::clone(&scanner);
        let progress = Arc::clone(&progress);
        let host_id = host.host_id;

        let abort_handle = tasks.spawn(async move {
            let permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                Err(_closed) => {
                    // Nothing in this function ever calls `Semaphore::close`,
                    // so this is unreachable in practice; handled as a
                    // failed host rather than an unwrap/expect on principle.
                    // `host_started`/`host_finished` still fire here so a
                    // progress consumer never sees a host silently vanish
                    // from its start/finish accounting, matching every
                    // other path through this task.
                    progress.host_started(host_id);
                    let outcome = HostOutcome::Failed(HostError::Fatal(
                        "fan-out concurrency semaphore was closed".to_owned(),
                    ));
                    progress.host_finished(host_id, &outcome);
                    return HostResult {
                        host_id,
                        strategy_used: TargetStrategy::Probe,
                        outcome,
                    };
                }
            };
            let result = scan_one_host(host, per_host_timeout, scanner, store, progress).await;
            drop(permit);
            result
        });
        host_ids.insert(abort_handle.id(), host_id);
    }

    let mut results = Vec::with_capacity(host_ids.len());
    while let Some(joined) = tasks.join_next_with_id().await {
        match joined {
            Ok((_id, result)) => results.push(result),
            Err(join_err) => {
                if let Some(&host_id) = host_ids.get(&join_err.id()) {
                    let outcome = HostOutcome::Failed(HostError::Panicked(join_err.to_string()));
                    progress.host_finished(host_id, &outcome);
                    results.push(HostResult {
                        host_id,
                        strategy_used: TargetStrategy::Probe,
                        outcome,
                    });
                }
            }
        }
    }
    results
}

/// Resolves `host`'s strategy, then runs [`with_retry`] around one scan
/// attempt, enforcing `per_host_timeout` across strategy resolution and
/// every retry combined — a host stuck resolving its strategy is exactly
/// as much "one unreachable host" as one stuck mid-scan, and both must be
/// bounded by the same budget.
async fn scan_one_host(
    host: InventoryHost,
    per_host_timeout: Duration,
    scanner: Arc<dyn HostScanner>,
    store: Arc<dyn SnapshotStore>,
    progress: Arc<dyn ProgressReporter>,
) -> HostResult {
    let host_id = host.host_id;
    progress.host_started(host_id);

    // Generated once per host-scan-attempt, before any retry — this is the
    // entire mechanism behind "retries reuse the same IdempotencyKey".
    let idempotency_key = IdempotencyKey::generate();
    let scanner_ref = scanner.as_ref();
    let store_ref = store.as_ref();

    // `tokio::time::timeout` drops `budget` in place on expiry without
    // producing its output, so a `(strategy, result)` tuple returned *from*
    // `budget` would lose `strategy` on every timeout — including a timeout
    // that hits well after `resolve_strategy` genuinely finished, which
    // would then misreport an Execute-resolved host as Probe. Recording the
    // strategy in a `Mutex` *outside* the cancellable future, the moment
    // it's known, means a late timeout during retries still reports the
    // strategy that was actually established. A `Mutex` rather than `Cell`
    // because `&Cell<_>` isn't `Send`, and `budget` must be `Send` to cross
    // the `JoinSet::spawn` boundary in `run_fanout`; the lock is held only
    // for the instant of the `set`/`get`, never across an `.await`.
    let resolved_strategy = Mutex::new(TargetStrategy::Probe);

    let budget = async {
        let strategy = scanner_ref.resolve_strategy(&host).await;
        *resolved_strategy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = strategy;
        with_retry(|| attempt_scan(&host, strategy, idempotency_key, scanner_ref, store_ref)).await
    };

    let outcome = match tokio::time::timeout(per_host_timeout, budget).await {
        Ok(Ok(scan_id)) => HostOutcome::Succeeded(scan_id),
        Ok(Err(HostError::Timeout)) => HostOutcome::TimedOut,
        Ok(Err(e)) => HostOutcome::Failed(e),
        Err(_elapsed) => HostOutcome::TimedOut,
    };
    let strategy = *resolved_strategy
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    progress.host_finished(host_id, &outcome);
    HostResult {
        host_id,
        strategy_used: strategy,
        outcome,
    }
}

/// One scan-and-persist attempt: scans `host`, then persists the result
/// under `key`. Called repeatedly, with the same `key`, by [`with_retry`].
///
/// `store.put` runs inside the same [`tokio::time::timeout`] budget as the
/// rest of [`scan_one_host`]. If `per_host_timeout` elapses while a
/// `SnapshotStore` adapter is mid-write on a `spawn_blocking` thread (as the
/// filesystem and `SQLite` adapters both are), dropping this future does
/// *not* cancel that blocking write — Tokio lets it run to completion on
/// its own thread regardless. The write can therefore still land after the
/// host has already been reported [`HostOutcome::TimedOut`]; this is
/// harmless (the store's own idempotency contract collapses it to the same
/// record a retry would have produced) but means `TimedOut` is not a
/// guarantee that nothing was persisted for this attempt.
async fn attempt_scan(
    host: &InventoryHost,
    strategy: TargetStrategy,
    key: IdempotencyKey,
    scanner: &dyn HostScanner,
    store: &dyn SnapshotStore,
) -> Result<ScanId, HostError> {
    let snapshot = scanner.scan(host, strategy, key).await?;
    store.put(key, snapshot).await.map_err(HostError::from)
}

/// Retries `attempt` up to [`MAX_ATTEMPTS`] times when it fails with
/// [`HostError::Retryable`], backing off exponentially with jitter between
/// tries. Any other error (including [`HostError::Timeout`]) is terminal
/// and returned immediately without consuming a retry.
async fn with_retry<F, Fut>(mut attempt: F) -> Result<ScanId, HostError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<ScanId, HostError>>,
{
    let mut backoff = INITIAL_BACKOFF;
    let mut last_err = HostError::Fatal("no attempt was made".to_owned());
    for attempt_number in 0..MAX_ATTEMPTS {
        match attempt().await {
            Ok(id) => return Ok(id),
            Err(HostError::Retryable(reason)) => {
                last_err = HostError::Retryable(reason);
                if attempt_number + 1 < MAX_ATTEMPTS {
                    tokio::time::sleep(backoff + jitter()).await;
                    backoff *= 2;
                }
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err)
}

/// Adds bounded, non-negative randomness to retry backoff so many
/// concurrently-retrying hosts don't wake in lock-step and hammer the
/// target (or this process's own `SnapshotStore`) at the exact same
/// instant — a thundering-herd retry.
///
/// This crate has no `rand` dependency, and deliberately doesn't gain one
/// for this: backoff jitter is not security-sensitive randomness, unlike
/// e.g. `RemotePath::random_under_temp`'s UUID. Mixing a monotonically
/// increasing counter with the wall clock's sub-second nanoseconds is
/// unpredictable enough to break lock-step retries without needing a
/// CSPRNG or a new dependency.
fn jitter() -> Duration {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = u64::from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos(),
    );
    let mixed = nanos ^ count.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    Duration::from_millis(mixed % 100)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use super::{
        Arc, Duration, HostError, HostId, HostOutcome, HostScanner, IdempotencyKey,
        NullProgressReporter, ProgressReporter, ScanId, ScanSnapshot, SnapshotStore, StoreError,
        TargetStrategy, async_trait, run_fanout, scan_one_host,
    };
    use crate::adapters::inventory::{AuthMethod, InventoryHost};
    use crate::domain::{HostAddress, Port};

    fn inventory_of(n: usize) -> Vec<InventoryHost> {
        (0..n)
            .map(|i| InventoryHost {
                host_id: HostId::generate(),
                address: HostAddress::try_from(format!("host-{i}.internal")).unwrap(),
                port: Port::try_from(22u16).unwrap(),
                user: "anne".to_owned(),
                auth: AuthMethod::Agent,
                jump: None,
                tags: vec![],
            })
            .collect()
    }

    fn dummy_snapshot(host_id: HostId) -> ScanSnapshot {
        ScanSnapshot::new(
            host_id,
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "test".to_owned(),
            vec![],
            vec![],
            vec![],
            TargetStrategy::Probe,
        )
    }

    #[derive(Default)]
    struct FakeStoreInner {
        puts: Vec<(IdempotencyKey, HostId)>,
        by_key: std::collections::HashMap<IdempotencyKey, ScanId>,
    }

    /// Records every `put` call and honours the real store's idempotency
    /// contract (same key -> same `ScanId`, no new record), without ever
    /// touching a filesystem.
    #[derive(Clone, Default)]
    struct FakeSnapshotStore(Arc<Mutex<FakeStoreInner>>);

    impl FakeSnapshotStore {
        fn distinct_idempotency_keys_seen(&self) -> usize {
            self.0
                .lock()
                .unwrap()
                .puts
                .iter()
                .map(|(key, _)| *key)
                .collect::<HashSet<_>>()
                .len()
        }

        fn stored_snapshot_count(&self) -> usize {
            self.0.lock().unwrap().puts.len()
        }
    }

    #[async_trait]
    impl SnapshotStore for FakeSnapshotStore {
        async fn put(
            &self,
            key: IdempotencyKey,
            snapshot: ScanSnapshot,
        ) -> Result<ScanId, StoreError> {
            let scan_id = {
                let mut inner = self.0.lock().unwrap();
                let scan_id = if let Some(&existing) = inner.by_key.get(&key) {
                    existing
                } else {
                    let scan_id = snapshot.scan_id;
                    inner.by_key.insert(key, scan_id);
                    scan_id
                };
                inner.puts.push((key, snapshot.host_id));
                scan_id
            };
            Ok(scan_id)
        }

        async fn get(&self, _id: ScanId) -> Result<Option<ScanSnapshot>, StoreError> {
            Ok(None)
        }

        async fn list(&self, _host: HostId) -> Result<Vec<ScanId>, StoreError> {
            Ok(vec![])
        }
    }

    /// Fails every scan for hosts in `fail_host_ids`, succeeds for every other.
    struct FakeHostScanner {
        fail_host_ids: HashSet<HostId>,
    }

    #[async_trait]
    impl HostScanner for FakeHostScanner {
        async fn resolve_strategy(&self, _host: &InventoryHost) -> TargetStrategy {
            TargetStrategy::Probe
        }

        async fn scan(
            &self,
            host: &InventoryHost,
            _strategy: TargetStrategy,
            _idempotency_key: IdempotencyKey,
        ) -> Result<ScanSnapshot, HostError> {
            if self.fail_host_ids.contains(&host.host_id) {
                return Err(HostError::Fatal("simulated unreachable host".to_owned()));
            }
            Ok(dummy_snapshot(host.host_id))
        }
    }

    /// Panics on `scan` for exactly one host — proves a panicking task is
    /// caught at the `JoinSet` boundary and recorded, not silently dropped.
    struct PanickingHostScanner {
        panic_host_id: HostId,
    }

    #[async_trait]
    impl HostScanner for PanickingHostScanner {
        async fn resolve_strategy(&self, _host: &InventoryHost) -> TargetStrategy {
            TargetStrategy::Probe
        }

        async fn scan(
            &self,
            host: &InventoryHost,
            _strategy: TargetStrategy,
            _idempotency_key: IdempotencyKey,
        ) -> Result<ScanSnapshot, HostError> {
            assert_ne!(
                host.host_id, self.panic_host_id,
                "simulated adapter bug scanning this host"
            );
            Ok(dummy_snapshot(host.host_id))
        }
    }

    /// Never resolves — proves `HostOutcome::TimedOut` is actually
    /// reachable, not just a documented-but-unexercised arm of the
    /// outcome enum. `resolve_strategy` returns immediately so the timeout
    /// is guaranteed to fire during the scan attempt itself, not during
    /// strategy resolution.
    struct StuckHostScanner;

    #[async_trait]
    impl HostScanner for StuckHostScanner {
        async fn resolve_strategy(&self, _host: &InventoryHost) -> TargetStrategy {
            TargetStrategy::Execute
        }

        async fn scan(
            &self,
            _host: &InventoryHost,
            _strategy: TargetStrategy,
            _idempotency_key: IdempotencyKey,
        ) -> Result<ScanSnapshot, HostError> {
            std::future::pending().await
        }
    }

    /// Never even resolves a strategy — the timeout must fire before
    /// `resolve_strategy` ever completes, so `strategy_used` has nothing to
    /// report but the `TargetStrategy::Probe` default.
    struct StuckBeforeResolveHostScanner;

    #[async_trait]
    impl HostScanner for StuckBeforeResolveHostScanner {
        async fn resolve_strategy(&self, _host: &InventoryHost) -> TargetStrategy {
            std::future::pending().await
        }

        async fn scan(
            &self,
            host: &InventoryHost,
            _strategy: TargetStrategy,
            _idempotency_key: IdempotencyKey,
        ) -> Result<ScanSnapshot, HostError> {
            Ok(dummy_snapshot(host.host_id))
        }
    }

    #[derive(Clone, Default)]
    struct ConcurrencyTracker(Arc<ConcurrencyTrackerInner>);

    #[derive(Default)]
    struct ConcurrencyTrackerInner {
        current: AtomicUsize,
        max_observed: AtomicUsize,
    }

    impl ConcurrencyTracker {
        fn max_observed(&self) -> usize {
            self.0.max_observed.load(AtomicOrdering::SeqCst)
        }
    }

    /// Records how many scans are in flight at once, holding each one open
    /// long enough (via a short sleep) for overlapping scans to actually be
    /// observable.
    struct TrackingHostScanner {
        tracker: ConcurrencyTracker,
    }

    #[async_trait]
    impl HostScanner for TrackingHostScanner {
        async fn resolve_strategy(&self, _host: &InventoryHost) -> TargetStrategy {
            TargetStrategy::Probe
        }

        async fn scan(
            &self,
            host: &InventoryHost,
            _strategy: TargetStrategy,
            _idempotency_key: IdempotencyKey,
        ) -> Result<ScanSnapshot, HostError> {
            let current = self.tracker.0.current.fetch_add(1, AtomicOrdering::SeqCst) + 1;
            self.tracker
                .0
                .max_observed
                .fetch_max(current, AtomicOrdering::SeqCst);
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.tracker.0.current.fetch_sub(1, AtomicOrdering::SeqCst);
            Ok(dummy_snapshot(host.host_id))
        }
    }

    /// Fails a specific host's scan `remaining_failures` times with
    /// `HostError::Retryable`, then succeeds — and records every
    /// `IdempotencyKey` it was called with, so a test can prove every
    /// retry reused the same one.
    struct FlakyHostScanner {
        remaining_failures: Mutex<u32>,
        keys_seen: Mutex<Vec<IdempotencyKey>>,
    }

    #[async_trait]
    impl HostScanner for FlakyHostScanner {
        async fn resolve_strategy(&self, _host: &InventoryHost) -> TargetStrategy {
            TargetStrategy::Probe
        }

        async fn scan(
            &self,
            host: &InventoryHost,
            _strategy: TargetStrategy,
            idempotency_key: IdempotencyKey,
        ) -> Result<ScanSnapshot, HostError> {
            self.keys_seen.lock().unwrap().push(idempotency_key);
            let should_fail = {
                let mut remaining = self.remaining_failures.lock().unwrap();
                if *remaining > 0 {
                    *remaining -= 1;
                    true
                } else {
                    false
                }
            };
            if should_fail {
                return Err(HostError::Retryable("flaky link".to_owned()));
            }
            Ok(dummy_snapshot(host.host_id))
        }
    }

    #[tokio::test]
    async fn failing_subset_does_not_abort_run() {
        let inventory = inventory_of(10);
        let fail_host_ids: HashSet<HostId> = [3, 7].iter().map(|&i| inventory[i].host_id).collect();
        let scanner = Arc::new(FakeHostScanner { fail_host_ids }) as Arc<dyn HostScanner>;
        let store = Arc::new(FakeSnapshotStore::default()) as Arc<dyn SnapshotStore>;
        let progress = Arc::new(NullProgressReporter) as Arc<dyn ProgressReporter>;

        let results = run_fanout(
            inventory,
            4,
            Duration::from_secs(5),
            store,
            scanner,
            progress,
        )
        .await;

        assert_eq!(results.len(), 10);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r.outcome, HostOutcome::Succeeded(_)))
                .count(),
            8
        );
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r.outcome, HostOutcome::Failed(_)))
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn panicking_host_does_not_abort_run_and_is_recorded_as_failed() {
        let inventory = inventory_of(5);
        let panic_host_id = inventory[2].host_id;
        let scanner = Arc::new(PanickingHostScanner { panic_host_id }) as Arc<dyn HostScanner>;
        let store = Arc::new(FakeSnapshotStore::default()) as Arc<dyn SnapshotStore>;
        let progress = Arc::new(NullProgressReporter) as Arc<dyn ProgressReporter>;

        let results = run_fanout(
            inventory,
            2,
            Duration::from_secs(5),
            store,
            scanner,
            progress,
        )
        .await;

        assert_eq!(
            results.len(),
            5,
            "a panicking host must still produce a result"
        );
        let panicked = results.iter().find(|r| r.host_id == panic_host_id).unwrap();
        assert!(matches!(panicked.outcome, HostOutcome::Failed(_)));
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r.outcome, HostOutcome::Succeeded(_)))
                .count(),
            4
        );
    }

    #[tokio::test]
    async fn stuck_host_is_reported_as_timed_out_not_failed() {
        let inventory = inventory_of(1);
        let scanner = Arc::new(StuckHostScanner) as Arc<dyn HostScanner>;
        let store = Arc::new(FakeSnapshotStore::default()) as Arc<dyn SnapshotStore>;
        let progress = Arc::new(NullProgressReporter) as Arc<dyn ProgressReporter>;

        let results = run_fanout(
            inventory,
            4,
            Duration::from_millis(20),
            store,
            scanner,
            progress,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert!(
            matches!(results[0].outcome, HostOutcome::TimedOut),
            "expected TimedOut, got {:?}",
            results[0].outcome
        );
        assert_eq!(
            results[0].strategy_used,
            TargetStrategy::Execute,
            "strategy_used must reflect the resolved strategy even when the \
             scan attempt itself times out"
        );
    }

    #[tokio::test]
    async fn timeout_before_strategy_resolves_reports_probe_default() {
        let inventory = inventory_of(1);
        let scanner = Arc::new(StuckBeforeResolveHostScanner) as Arc<dyn HostScanner>;
        let store = Arc::new(FakeSnapshotStore::default()) as Arc<dyn SnapshotStore>;
        let progress = Arc::new(NullProgressReporter) as Arc<dyn ProgressReporter>;

        let results = run_fanout(
            inventory,
            4,
            Duration::from_millis(20),
            store,
            scanner,
            progress,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].outcome, HostOutcome::TimedOut));
        assert_eq!(
            results[0].strategy_used,
            TargetStrategy::Probe,
            "strategy_used must fall back to the least-authoritative tier \
             when the timeout hits before resolve_strategy ever completes"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrency_never_exceeds_configured_bound() {
        let inventory = inventory_of(50);
        let tracker = ConcurrencyTracker::default();
        let scanner = Arc::new(TrackingHostScanner {
            tracker: tracker.clone(),
        }) as Arc<dyn HostScanner>;
        let store = Arc::new(FakeSnapshotStore::default()) as Arc<dyn SnapshotStore>;
        let progress = Arc::new(NullProgressReporter) as Arc<dyn ProgressReporter>;

        run_fanout(
            inventory,
            8,
            Duration::from_secs(5),
            store,
            scanner,
            progress,
        )
        .await;

        let observed = tracker.max_observed();
        assert!(
            observed <= 8,
            "observed concurrency {observed} exceeded the configured bound"
        );
        assert!(
            observed >= 2,
            "test is meaningless if scans never overlapped at all"
        );
    }

    #[tokio::test]
    async fn retried_host_reuses_idempotency_key() {
        let host = inventory_of(1).remove(0);
        let scanner = Arc::new(FlakyHostScanner {
            remaining_failures: Mutex::new(2),
            keys_seen: Mutex::new(vec![]),
        });
        let store = Arc::new(FakeSnapshotStore::default());

        let result = scan_one_host(
            host,
            Duration::from_secs(5),
            Arc::clone(&scanner) as Arc<dyn HostScanner>,
            Arc::clone(&store) as Arc<dyn SnapshotStore>,
            Arc::new(NullProgressReporter) as Arc<dyn ProgressReporter>,
        )
        .await;

        assert!(matches!(result.outcome, HostOutcome::Succeeded(_)));

        let (distinct_scanner_key_count, attempt_count) = {
            let keys_seen = scanner.keys_seen.lock().unwrap();
            let distinct: HashSet<_> = keys_seen.iter().copied().collect();
            (distinct.len(), keys_seen.len())
        };
        assert_eq!(
            distinct_scanner_key_count, 1,
            "every retry attempt must scan with the same idempotency key"
        );
        assert_eq!(attempt_count, 3, "expected 2 failures then 1 success");

        assert_eq!(store.distinct_idempotency_keys_seen(), 1);
        assert_eq!(store.stored_snapshot_count(), 1);
    }
}
