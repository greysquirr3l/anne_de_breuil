# Changelog

All notable changes to **anne-de-breuil** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Task identifiers (`T01`–`T32`) cross-reference the entries in
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) and
[`PROGRESS.md`](PROGRESS.md).

---

## [Unreleased]

### Added

- **`anne` CLI binary** (`T18`) — the user-facing surface for every prior
  module finally has a single entry point. Subcommands: `scan`, `diff`,
  `report`, `inventory`, `version`. `cli::Command` is `clap` derive
  with documented exit codes (`0` clean, `1` operational error,
  `2` config/arg error, `3` drift detected) so CI and RMM tooling can
  branch on results without parsing stderr.
  - [`crates/anne-de-breuil-cli/src/cli.rs`](crates/anne-de-breuil-cli/src/cli.rs) —
    `Cli`, `Command`, `ScanArgs`, `StrategyArg`, `SeverityArg`, `ExitCode`,
    `InventoryAction`.
  - [`crates/anne-de-breuil-cli/src/main.rs`](crates/anne-de-breuil-cli/src/main.rs) —
    binary entry point, tokio runtime bring-up, `MainResult` impls
    `Termination` with the documented exit-code contract.
  - [`crates/anne-de-breuil-cli/src/lib.rs`](crates/anne-de-breuil-cli/src/lib.rs) —
    re-exports so integration tests can drive the full handler chain
    with a pre-parsed `Cli`.
  - [`crates/anne-de-breuil-cli/src/observability.rs`](crates/anne-de-breuil-cli/src/observability.rs) —
    stderr-only `tracing` subscriber, idempotent install, `ANNE_LOG_FORMAT`
    switch between `Pretty` and `Json` output.
  - [`crates/anne-de-breuil-cli/build.rs`](crates/anne-de-breuil-cli/build.rs) —
    embeds the build-time `HEAD` short SHA so `anne version` reports
    build provenance; re-runs on every `HEAD` move.
  - [`.cargo/config.toml`](.cargo/config.toml) — pins `ANNE_CLI_GIT_HASH = "dev"`
    in the cargo env so the build script's cache output is stable across
    parallel `cargo build` / rust-analyzer invocations.

- **`anne scan`** (`T18`) — single-host or fan-out orchestration with
  `--emit-json` for the on-host collector mode (stdout carries exactly
  one `ScanSnapshot`, stderr carries everything else, never the other
  way around). Honors `--strategy`, `--policy-store`, `--probe`,
  `--probe-exclude`, `--probe-timeout`, `--probe-rate`, `--store`,
  `--config`, and the `--include-udp` / `--include-loopback` /
  `--skip-signature` knobs.
  [`crates/anne-de-breuil-cli/src/application/scan.rs`](crates/anne-de-breuil-cli/src/application/scan.rs).

- **`anne diff <baseline> <current> [--fail-on-drift <severity>]`** (`T18`) —
  loads two `ScanSnapshot` JSON envelopes (through `serde_json::from_reader`
  so `deny_unknown_fields` rejects tampered files), runs the pure-domain
  `drift::diff`, maps each entry through `DriftEntryView`, prints the
  JSON to stdout, and exits `3` when `--fail-on-drift`'s threshold is
  crossed.
  [`crates/anne-de-breuil-cli/src/application/diff.rs`](crates/anne-de-breuil-cli/src/application/diff.rs).

- **`anne report <scan-id-or-path>`** (`T21`, JSON path) — resolves a
  UUID against the default `anne-snapshots/` store or loads a `.json`
  file directly, builds the `ReportModel` with fail-closed redaction
  (callers must opt in to unredacted command lines), and serialises
  pretty JSON to stdout. HTML / CSV / SARIF remain T21's remaining
  scope.
  [`crates/anne-de-breuil-cli/src/application/report.rs`](crates/anne-de-breuil-cli/src/application/report.rs).

- **`anne inventory validate <path>`** (`T18`) — parses the TOML file
  and surfaces every validation error before any collector touches a
  host, so a broken inventory can't half-scan a fleet.
  [`crates/anne-de-breuil-cli/src/application/inventory.rs`](crates/anne-de-breuil-cli/src/application/inventory.rs).

- **`anne version`** (`T18`) — semver + the git SHA embedded at build
  time. The SHA comes through `ANNE_CLI_GIT_HASH` (set by `build.rs`)
  with a `"dev"` fallback for unpacked tarballs.
  [`crates/anne-de-breuil-cli/src/application/version.rs`](crates/anne-de-breuil-cli/src/application/version.rs).

- **Cross-platform local collector selection** (`T31`, stub) —
  `local_collectors(include_udp)` returns a `(LocalCollectorSet,
LocalCollectorGuard)` tuple today, with the `LocalCollectorGuard`
  reserved as a `kill_on_drop` / temp-file handle anchor so the real
  feature-gated adapters (procfs, netlink, nftables, WMI, PowerShell)
  can drop in without changing the call site.
  [`crates/anne-de-breuil-cli/src/adapters/collector_factory.rs`](crates/anne-de-breuil-cli/src/adapters/collector_factory.rs).

- **PowerShell v2 helper shipped and wired** (`T05b`) — the v1 helper
  script (`assets/collect.ps1`, 131 lines) is replaced by a v2 envelope
  (855 lines) with schema versioning, atomic publication, per-section
  status and diagnostics, opt-in redaction of command lines / executable
  paths / service `PathName` / disabled firewall rules, and an output
  size cap. The Rust parser is rewritten to read snake_case field
  names, route on `schema_name`/`schema_version` (rejecting unknown
  versions outright, not silently coercing), and tolerate partial
  payloads (real on CLM hosts where `NetSecurity` isn't allowlisted).
  All three on-disk fixtures are migrated in lockstep.
- **`RedactionPolicy` builder on both platforms** (`T05b`) — a single
  `RedactionPolicy { include_command_line, include_executable_path,
include_service_path, include_disabled_firewall_rules }` struct
  (all default `false`) gates sensitive-field collection on Windows
  _and_ Linux, so the same operator flag on both platforms produces
  a snapshot with the same omission semantics. `PowerShellCollector::
with_redaction_policy` and `LinuxProcessResolver::
with_redaction_policy` are the two consumers.
- **Operator-facing rationale in docs** — the v2 design rationale
  formerly at `collect-v2.txt` lives at
  [`docs/dev/collect-v2-rationale.md`](docs/dev/collect-v2-rationale.md),
  alongside the other dev docs. The workspace-root `collect-v2.ps1` /
  `collect-v2.txt` draft files are gone — T05b's exit criteria
  required they be deleted once the script shipped to its proper
  location.

- **Workspace dependency wiring** — `clap` (with `derive`, `env`),
  `tracing`, `tracing-subscriber` (with `env-filter`, `fmt`, `json`),
  `assert_cmd`, and `predicates` promoted to workspace-level
  dependencies and inherited by the new `anne-de-breuil-cli` crate.

### Changed

- **Module wiring** — `crates/anne-de-breuil-cli/src/adapters/mod.rs`
  and `crates/anne-de-breuil-cli/src/application/mod.rs` extended to
  expose the new subcommand handlers and the
  `adapters::collector_factory::local_collectors` selector.
- **`PowerShellCollector` argv builder** — `Backend::command` now
  accepts a `RedactionPolicy` and adds the matching `-Include*`
  switches as discrete `Command::arg(...)` calls (never a single
  concatenated string, so a flag value can't be confused for a new
  argv element). The v1 parser was the only consumer of the old
  signature; test-only `Backend::Fixed` arm ignores the policy.
- **`LinuxProcessResolver::build_process_map`** — reads
  `/proc/<pid>/exe` and `/proc/<pid>/cmdline` only when the
  corresponding `RedactionPolicy` opt-in flag is set. Under default
  policy, `RawProcess.path == None` and `RawProcess.command_line ==
None` for every process — matching Windows, matching the audit
  guarantee.

### Removed

- **Workspace-root `collect-v2.ps1` / `collect-v2.txt`** — T05b's
  exit criteria required moving them into `assets/` and
  `docs/dev/` respectively, then deleting the originals. Done.

### Fixed

- **Exit-code narrowing** — `MainResult::report` now pattern-matches
  `ExitCode` into the `u8` value via a `const fn` helper instead of
  `code.as_i32() as u8`, satisfying `cast_possible_truncation` and
  `cast_sign_loss` without an `#[allow]`. The `ExitCode::as_i32`
  accessor and its unit-test pair were dropped in favour of direct
  `Variant as i32` discriminant checks in the test.
- **Script diagnostic gap** — the v1 helper script's catch block
  silently set `$published = $false`; the parent got exit 1 and a
  missing file, no error message. The v2 catch block writes a
  structured `{section:'Fatal', severity:'Error', message,
script_stack_trace}` envelope to stderr via `Write-Error`, so
  the parent can distinguish exit-1-with-reason from
  exit-1-no-info.
- **Script output size cap** — added `-MaxOutputBytes` (default 8
  MiB, range 1 KiB..100 MiB); the script refuses to publish when
  serialized JSON exceeds the cap and exits 1. Closes the
  "parent reads an unexpectedly large file" gap before it ever
  opens.

### Security

- **Logger init is fail-soft** — `observability::init` no longer
  surfaces `Result<()>` to callers; the "subscriber already installed"
  case is swallowed so a panic in the tracing init path can't take
  down a hardened launcher that installs its own subscriber first.
- **`anne scan --emit-json` is stdout-monopolised** — `--emit-json`
  forces stdout = exactly one `ScanSnapshot` JSON; every `tracing`
  event goes to stderr. A `--emit-json` run can never leak log lines
  into a downstream parser's stdin.
- **Redaction-by-default on every collector** — `command_line`,
  `executable_path`, and `PathName` are absent from `RawProcess` /
  `RawService` by default on Windows _and_ Linux, gated behind a
  deliberate `RedactionPolicy::with_redaction_policy(...)` builder
  call. The PowerShell script records which switches were set in
  the payload's `Metadata` block, so a downstream auditor can prove
  what was and wasn't collected.

---

## [0.1.0] — prior development

Initial domain model, collectors, snapshot store, drift, SSH transport,
fan-out orchestrator, report model, and font vendoring — landed as the
T01–T22 series before the CLI surface existed. See
[`PROGRESS.md`](PROGRESS.md) for the per-task index and `git log` for
the commit-level detail.

[Unreleased]: https://github.com/greysquirr3l/anne_de_breuil/compare/HEAD
[0.1.0]: https://github.com/greysquirr3l/anne_de_breuil/releases/tag/0.1.0
