//! Shared fixtures for the `anne` binary's integration test suite.
//!
//! `tests/support/mod.rs` (not `tests/support.rs`) is deliberate: Cargo's
//! test-target autodiscovery only treats direct children of `tests/` as
//! their own test binaries, so nesting this one level down keeps it from
//! being compiled (and run, uselessly empty) as a sixth test target.
//!
//! Snapshot fixtures are built through the library's own `ScanSnapshot`
//! constructor rather than hand-typed as JSON literals — `ScanSnapshot`
//! carries `#[serde(deny_unknown_fields)]` and several hand-rolled `serde`
//! impls (`PortRange`, the `time::OffsetDateTime` field), so ad hoc JSON
//! drifts out of sync with the real schema silently. Building through the
//! constructor and letting `serde_json` serialize it keeps every fixture
//! file honestly shaped like whatever the collector would actually emit.
//!
//! This module is compiled once per `tests/*.rs` binary (each one does its
//! own `mod support;`), and no single test file calls every helper here —
//! same relationship `lib.rs` has with the binary, and the same reason it
//! carries `#![allow(dead_code)]` too.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::str::FromStr;

use anne_de_breuil::domain::{
    BindAddress, Endpoint, HostId, Port, Protocol, ScanId, ScanSnapshot, SignatureStatus,
    TargetStrategy,
};

/// A fresh `assert_cmd` handle for the `anne` binary under test.
///
/// # Panics
///
/// Panics if the `anne` binary was not built as part of this test run —
/// `assert_cmd` surfaces that as a clear message, which is what we want in
/// a test helper rather than silently returning a broken `Command`.
#[must_use]
pub fn anne_cmd() -> assert_cmd::Command {
    assert_cmd::Command::cargo_bin("anne").expect("the `anne` binary must be built for tests")
}

/// One endpoint bound to every interface — `Exposure::AllInterfaces`, the
/// widest-reaching case `domain::exposure::Exposure::classify` can produce.
fn all_interfaces_endpoint(port: u16) -> Endpoint {
    Endpoint::new(
        Protocol::Tcp,
        BindAddress::from_str("0.0.0.0").expect("0.0.0.0 is a valid bind address"),
        Port::try_from(port).expect("port is nonzero"),
        None,
        None,
        Vec::new(),
        SignatureStatus::Unknown,
        None,
    )
}

fn snapshot_at(host_id: HostId, endpoints: Vec<Endpoint>) -> ScanSnapshot {
    ScanSnapshot::new(
        host_id,
        ScanId::generate(),
        time::OffsetDateTime::UNIX_EPOCH,
        "test-fixture".to_owned(),
        endpoints,
        Vec::new(),
        Vec::new(),
        TargetStrategy::LocalOnly,
    )
}

/// A baseline/current snapshot pair whose diff produces exactly one
/// `EndpointAppeared` entry at `Severity::Critical` — a new listening port
/// on `0.0.0.0` is the top severity tier `domain::drift::severity_for`
/// assigns. `--fail-on-drift`'s default threshold is `High`, so this pair
/// reliably crosses it regardless of that default ever changing to
/// something below `Critical`.
#[must_use]
pub fn drift_snapshot_pair() -> (ScanSnapshot, ScanSnapshot) {
    let host_id = HostId::generate();
    let baseline = snapshot_at(host_id, Vec::new());
    let current = snapshot_at(host_id, vec![all_interfaces_endpoint(8443)]);
    (baseline, current)
}

/// A single-endpoint snapshot with no drift-relevant content — good enough
/// for tests that just need *a* valid, parseable `ScanSnapshot` on disk.
#[must_use]
pub fn sample_snapshot() -> ScanSnapshot {
    snapshot_at(HostId::generate(), vec![all_interfaces_endpoint(443)])
}

/// Serializes `snapshot` to `dir/name` as JSON and returns the path.
///
/// # Panics
///
/// Panics on I/O or serialization failure — both are the test's own setup
/// failing, not something under test.
#[must_use]
pub fn write_snapshot(dir: &Path, name: &str, snapshot: &ScanSnapshot) -> PathBuf {
    let path = dir.join(name);
    let bytes = serde_json::to_vec(snapshot).expect("ScanSnapshot always serializes");
    std::fs::write(&path, bytes).expect("write fixture snapshot");
    path
}

/// Absolute path to the small inventory fixture committed alongside the
/// CLI crate's own tests (`fixtures/inventory/valid.toml`), independent of
/// the working directory `cargo test` happens to invoke from.
#[must_use]
pub fn valid_inventory_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/inventory/valid.toml")
}

/// A table of malformed or edge-case argv combinations, one per documented
/// subcommand plus a few global cases, that must never make the process
/// die by panic/abort/signal — an assigned exit code, whatever its value,
/// is the only thing asserted against these.
#[must_use]
pub fn malformed_argument_table() -> Vec<Vec<&'static str>> {
    vec![
        // No subcommand at all.
        vec![],
        // Unknown subcommand.
        vec!["definitely-not-a-subcommand"],
        // scan: mutually exclusive flags.
        vec!["scan", "--target", "host.example", "--inventory", "x.toml"],
        // scan: invalid value_enum value.
        vec!["scan", "--strategy", "bogus"],
        // scan: non-numeric value for a numeric flag.
        vec!["scan", "--probe-rate", "not-a-number"],
        // scan: flag requires a value but none was given.
        vec!["scan", "--probe-exclude"],
        // scan: unknown flag.
        vec!["scan", "--not-a-real-flag"],
        // diff: no positional arguments.
        vec!["diff"],
        // diff: only one of two required positionals.
        vec!["diff", "only-one-file.json"],
        // diff: invalid value_enum value for --fail-on-drift.
        vec!["diff", "a.json", "b.json", "--fail-on-drift", "extreme"],
        // report: no positional argument.
        vec!["report"],
        // report: target that is neither a UUID nor an existing file.
        vec!["report", "not-a-uuid-or-a-path"],
        // inventory: missing required subcommand.
        vec!["inventory"],
        // inventory validate: missing required path.
        vec!["inventory", "validate"],
        // inventory validate: path that does not exist.
        vec!["inventory", "validate", "/nonexistent/path/inventory.toml"],
        // version: unexpected trailing positional.
        vec!["version", "extra-argument"],
        // Empty-string argument in an otherwise well-formed invocation.
        vec!["scan", "--target", ""],
    ]
}
