//! T31: structural regression tests for the integration-wiring audit,
//! adapted from the task file's own `every_port_trait_has_at_least_one_
//! adapter_construction_site` / `every_cli_subcommand_variant_is_dispatched`
//! sketches to this codebase's real trait/enum names.
//!
//! These are deliberately hand-written against a known table rather than a
//! generic trait/adapter-name grep: this codebase's actual wiring root is
//! `application::scan`/`application::report`/etc, not a single
//! `main.rs::build_collector_set`-style function the task's own sketch
//! imagined, so a fully generic version would either miss real wiring or
//! need a small parser to find it. `include_str!` still pulls the *real*
//! source at compile time, so a construction site that's deleted or
//! renamed without updating one of these tables fails `cargo test`, not
//! just a manual read of the source.

const CLI_RS: &str = include_str!("../src/cli.rs");
const LIB_RS: &str = include_str!("../src/lib.rs");
const SCAN_RS: &str = include_str!("../src/application/scan.rs");
const REPORT_RS: &str = include_str!("../src/application/report.rs");
const INVENTORY_RS: &str = include_str!("../src/application/inventory.rs");
const VERSION_RS: &str = include_str!("../src/application/version.rs");
const DIFF_RS: &str = include_str!("../src/application/diff.rs");

/// Every port trait this workspace declares (`application/*.rs` across
/// both crates) paired with at least one concrete adapter type that must
/// be constructed somewhere reachable from the `anne` binary's own source
/// (`lib.rs`'s dispatch plus the application handler files it calls into).
///
/// `Prober`/`RemoteTransport` have no *direct* construction site in the
/// CLI crate's own files — `SshHostScanner::new` (inside the library
/// crate's `adapters::remote_scanner`) constructs `HttpProber`, `TlsProber`,
/// and reaches `SshTransport::connect` internally. Reachability here means
/// "the crate/type that constructs it is itself reachable from the
/// binary," not "the exact `new()` call appears verbatim in
/// `anne-de-breuil-cli`" — `SshHostScanner` is constructed directly in
/// `scan.rs`, which is the reachability proof for all three.
const PORT_TRAIT_ADAPTER_TABLE: &[(&str, &[&str])] = &[
    ("SnapshotStore", &["FsSnapshotStore", "SqliteSnapshotStore"]),
    ("HostScanner", &["SshHostScanner"]),
    // `adapters::progress::new()` is the real construction site -- it
    // picks between `IndicatifProgress`/`NullProgressReporter` internally,
    // so neither concrete type name appears at this call site itself.
    ("ProgressReporter", &["progress::new()"]),
    // Constructed transitively via SshHostScanner::new (see doc comment
    // above) -- SshHostScanner itself is the adapter name checked for.
    ("Prober", &["SshHostScanner"]),
    ("RemoteTransport", &["SshHostScanner"]),
    (
        "EndpointSource/ProcessResolver/FirewallPolicySource/SignatureVerifier",
        &["collector_factory::local_collectors("],
    ),
];

fn reachable_source() -> String {
    [
        LIB_RS,
        SCAN_RS,
        REPORT_RS,
        INVENTORY_RS,
        VERSION_RS,
        DIFF_RS,
    ]
    .concat()
}

#[test]
fn every_port_trait_has_at_least_one_adapter_construction_site() {
    let source = reachable_source();
    for (trait_name, adapters) in PORT_TRAIT_ADAPTER_TABLE {
        let found = adapters.iter().any(|adapter| source.contains(adapter));
        assert!(
            found,
            "{trait_name} has no adapter reachable from the anne binary; expected one of \
             {adapters:?} in lib.rs/application/*.rs"
        );
    }
}

/// Every `Command` enum variant in `cli.rs` must have a matching arm in
/// `lib.rs`'s `run()` dispatch — a variant clap can parse but `run` never
/// handles would be a silent no-op, not a compile error (the match would
/// simply not have that arm and rustc would reject it... unless the match
/// isn't exhaustive over the real enum, which is exactly the class of bug
/// this test exists to catch structurally, independent of relying on
/// `-D warnings`/`non_exhaustive_omitted_patterns` to have caught it).
#[test]
fn every_cli_subcommand_variant_is_dispatched() {
    let variants = ["Scan", "Diff", "Report", "Inventory", "Version"];
    for variant in variants {
        assert!(
            CLI_RS.contains(&format!("{variant}("))
                || CLI_RS.contains(&format!("{variant} {{"))
                || CLI_RS.contains(&format!("{variant},")),
            "Command::{variant} is not declared in cli.rs's enum Command"
        );
        assert!(
            LIB_RS.contains(&format!("Command::{variant}")),
            "Command::{variant} has no match arm in lib.rs's run()"
        );
    }
}

/// Every `Command` variant's handler module (`application::{scan,diff,
/// report,inventory,version}`) is actually declared and reachable from
/// `lib.rs` — catches a handler file that exists on disk but was never
/// wired into `application/mod.rs`'s module tree.
#[test]
fn every_handler_module_is_declared_reachable_from_lib_rs() {
    for module in ["scan", "diff", "report", "inventory", "version"] {
        assert!(
            LIB_RS.contains(&format!("application::{module}::run")),
            "application::{module}::run is never called from lib.rs::run()"
        );
    }
}
