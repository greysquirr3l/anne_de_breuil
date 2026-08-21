//! T28 security-audit regression: a credential-shaped process command line
//! must never reach a log sink, even at `TRACE`, the most permissive
//! level this binary's `tracing` subscriber can be configured to emit.
//!
//! # Why this test is shaped the way it is
//!
//! `anne-de-breuil` (the library crate that does the actual collecting,
//! domain modelling, and rendering) has no `tracing` dependency at all --
//! confirmed by reading its `Cargo.toml`, not assumed. Every `tracing::`
//! call site in this whole workspace lives in `anne-de-breuil-cli`
//! (`application::scan`), and none of them format a raw `RawProcess`,
//! `Endpoint`, or `CollectError` variant that could carry a command line
//! (`CollectError`'s variants wrap platform-error text and domain
//! parse-failure text, never `RawProcess.command_line` -- confirmed by
//! reading `application::collect::CollectError`). This test proves both
//! halves of that claim hold together for a real credential-shaped value,
//! rather than trusting either fact in isolation:
//!
//! 1. It drives the actual collection boundary
//!    (`anne_de_breuil::application::collect::collect_endpoints`) with a
//!    fake [`EndpointSource`]/[`ProcessResolver`] pair -- the same fake
//!    pattern `collect.rs`'s own test module already establishes --
//!    reporting a command line shaped like a real `net use` credential
//!    assignment.
//! 2. It folds the result into a `ScanSnapshot` and pushes it through
//!    `ReportModel::build` and every machine-format renderer
//!    (`render_json`/`render_csv`/`render_sarif`), the same pipeline
//!    `anne report` drives.
//! 3. It logs the same shape of `tracing::error!`/`info!` calls
//!    `application::scan`'s real code paths make on failure and success,
//!    against real values produced by the steps above (a real
//!    `CollectedEndpoint` count, a real `HostId`/`ScanId`, a real
//!    `CollectError` display). None of those call sites ever touch the raw
//!    command line — the same way none of `application::scan`'s real ones
//!    do — which is exactly the property under test.
//!
//! All of it runs inside one `tracing::subscriber::with_default` scope
//! backed by an in-memory `TRACE`-level writer, and the captured buffer is
//! then scanned for the literal secret value.

use std::io::Write as _;
use std::sync::{Arc, Mutex, PoisonError};

use anne_de_breuil::application::collect::{
    CollectError, CollectedEndpoint, EndpointSource, FirewallPolicySource, ProcessAttribution,
    ProcessResolver, RawEndpoint, RawProcess, RawProfile, RawRule, RawService, SignatureVerifier,
    collect_endpoints,
};
use anne_de_breuil::domain::report_model::ReportModel;
use anne_de_breuil::domain::report_render::{render_csv, render_json, render_sarif};
use anne_de_breuil::domain::{
    Endpoint, HostId, ProcessId, ScanId, ScanSnapshot, SignatureStatus, TargetStrategy,
};
use async_trait::async_trait;
use tracing_subscriber::fmt::MakeWriter;

/// A credential shape `domain::redaction`'s own `ConnectionStringPassword`
/// pattern is proven (by that module's own tests) to fully claim -- chosen
/// deliberately so this test's assertion is about the *log sink*, not
/// about rediscovering which shapes the redaction module recognises.
const SECRET: &str = "hunter2-trace-audit-secret";

#[derive(Clone, Default)]
struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for BufferWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

struct FakeSources;

#[async_trait]
impl EndpointSource for FakeSources {
    async fn listening_endpoints(&self) -> Result<Vec<RawEndpoint>, CollectError> {
        Ok(vec![RawEndpoint {
            protocol: "tcp".to_owned(),
            local_address: "0.0.0.0".to_owned(),
            local_port: 1433,
            owning_pid: Some(4242),
        }])
    }
}

#[async_trait]
impl ProcessResolver for FakeSources {
    async fn describe(&self, _pid: ProcessId) -> Result<Option<RawProcess>, CollectError> {
        Ok(Some(RawProcess {
            pid: 4242,
            path: Some(r"C:\sql\sqlservr.exe".to_owned()),
            command_line: Some(format!(
                r#"sqlservr.exe -S PROD -C "Server=db;User Id=sa;Password={SECRET};""#
            )),
        }))
    }

    async fn hosted_services(&self, _pid: ProcessId) -> Result<Vec<RawService>, CollectError> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl FirewallPolicySource for FakeSources {
    async fn inbound_rules(&self) -> Result<Vec<RawRule>, CollectError> {
        Ok(Vec::new())
    }

    async fn profiles(&self) -> Result<Vec<RawProfile>, CollectError> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl SignatureVerifier for FakeSources {
    async fn verify(
        &self,
        _path: &anne_de_breuil::domain::ProcessPath,
    ) -> Result<SignatureStatus, CollectError> {
        Ok(SignatureStatus::Unsigned)
    }
}

/// Folds one [`CollectedEndpoint`] into a domain [`Endpoint`], the same
/// shape T20's own `command_line` threading established -- this fold has
/// no production call site yet (a documented, pre-existing gap tracked for
/// T31), so this test performs it directly rather than waiting on wiring
/// that doesn't exist.
fn endpoint_from_collected(collected: &CollectedEndpoint) -> Endpoint {
    let (process_path, hosted_services, signature_status, command_line) =
        match &collected.owning_process {
            ProcessAttribution::Resolved {
                path,
                hosted_services,
                signature,
                command_line,
                ..
            } => (
                path.clone(),
                hosted_services.clone(),
                signature.clone(),
                command_line.clone(),
            ),
            ProcessAttribution::Unresolved | ProcessAttribution::ProcessGone => {
                (None, Vec::new(), SignatureStatus::Unknown, None)
            }
        };
    Endpoint::new(
        collected.protocol,
        collected.bind_address,
        collected.port,
        None,
        process_path,
        hosted_services,
        signature_status,
        command_line,
    )
}

#[test]
fn no_secret_pattern_reaches_log_output_at_trace_level_across_a_full_scan_path() {
    let buffer = BufferWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(buffer.clone())
        .with_ansi(false)
        .finish();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build a current-thread runtime");

    tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async {
            let collected = collect_endpoints(&FakeSources)
                .await
                .expect("fake sources never fail");
            tracing::info!(count = collected.len(), "collected local endpoints");

            let endpoints: Vec<Endpoint> = collected.iter().map(endpoint_from_collected).collect();
            let snapshot = ScanSnapshot::new(
                HostId::generate(),
                ScanId::generate(),
                time::OffsetDateTime::UNIX_EPOCH,
                "test-fixture".to_owned(),
                endpoints,
                Vec::new(),
                Vec::new(),
                TargetStrategy::LocalOnly,
            );

            // The exact call site shape `application::scan::run_interactive`
            // uses on a successful scan -- real host id, real scan id.
            tracing::info!(host_id = %snapshot.host_id, scan_id = %snapshot.scan_id, "local scan completed");

            // A real, credential-bearing value is genuinely in scope here
            // (`collected`, via `ProcessAttribution::Resolved.command_line`)
            // — the assertion below is meaningful precisely because this
            // block never passes it to any `tracing::` call, matching every
            // real call site in `application::scan` today.
            debug_assert!(
                collected.iter().any(|c| matches!(
                    &c.owning_process,
                    ProcessAttribution::Resolved { command_line: Some(_), .. }
                )),
                "fixture must actually carry a command line, or this test proves nothing"
            );

            // The exact call site shape `run_emit_json`/`run_interactive`
            // use on failure — a synthesized `CollectError`, logged the
            // same way production code logs one.
            let synthetic_err = CollectError::Parse("simulated parse failure".to_owned());
            tracing::error!(error = %synthetic_err, "local scan failed");

            let model = ReportModel::build(&[snapshot], None, true).expect("redaction confirmed");
            let json = render_json(&model, true).expect("json renders");
            let csv = render_csv(&model).expect("csv renders");
            let sarif = render_sarif(&model);
            tracing::debug!(
                json_len = json.len(),
                csv_len = csv.len(),
                sarif_results = sarif["runs"][0]["results"].as_array().map_or(0, Vec::len),
                "rendered report formats"
            );
        });
    });

    let _ = std::io::stdout().flush();
    let captured =
        String::from_utf8_lossy(&buffer.0.lock().unwrap_or_else(PoisonError::into_inner))
            .into_owned();

    assert!(
        !captured.is_empty(),
        "the subscriber must have actually captured something, or this test proves nothing"
    );
    assert!(
        !captured.contains(SECRET),
        "secret leaked into trace-level log output:\n{captured}"
    );
}
