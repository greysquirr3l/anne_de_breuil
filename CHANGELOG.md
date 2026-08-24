# Changelog

All notable changes to **anne-de-breuil** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Task identifiers (`T01`–`T32`) cross-reference the entries in
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) and
[`PROGRESS.md`](PROGRESS.md).

---

## [Unreleased]

Nothing yet.

## [0.3.1] — 2026-08-24

### Changed

- **HTML report is dark mode only** — removed the light/dark theme
  toggle (`<input type="checkbox" id="theme-toggle">`) and the
  `@media (prefers-color-scheme: dark)` OS-preference query from
  `tokens.css` and every report template
  (`report.html`/`host_document.html`/`split_index.html`/
  `portal_index.html`). The unstyled checkbox rendered as a visible,
  out-of-place control right before the `<h1>`; the single remaining
  dark palette is now just `:root`'s only definition, no override
  mechanism needed.
- **Removed the per-host scroll-reveal fade** (`.host-section {
  animation: host-reveal ...; animation-timeline: view(); }`) — a
  section faded in from `opacity: 0` as it scrolled into view, which
  read as an adaptive-dimming effect that made a long report harder to
  read while scrolling, not easier. The reading-progress bar at the top
  of the page (`.reading-progress`, `animation-timeline:
  scroll(root)`) is unrelated and unchanged.
  [`crates/anne-de-breuil/templates/tokens.css`](crates/anne-de-breuil/templates/tokens.css).

## [0.3.0] — 2026-08-22

### Added

- **`anne update`** — checks GitHub Releases for a newer `anne` build and,
  with confirmation, downloads, checksum-verifies, and atomically
  replaces the running executable. Never automatic: only runs on an
  explicit invocation, and even then prompts `Update? [y/N]` unless
  `--yes` is given; `--check` reports status only and never installs.
  Checksum verification reuses
  [`anne_de_breuil::adapters::binary_hash::hash_bytes`](crates/anne-de-breuil/src/adapters/binary_hash.rs)
  — the same function `anne --self-hash` and the SSH push-side integrity
  check already use — against the release's own `SHA256SUMS.txt`, and
  aborts before touching the filesystem on any mismatch. ARM64 Windows
  falls back to the x86_64 build (no native `aarch64-pc-windows-msvc`
  release is published, a real `cargo-xwin`/`ring` cross-compile bug —
  see "Release artifacts" in `README.md`); the x86_64 build runs fine
  there under Windows 11 ARM64's built-in x64 emulation. Verified live
  against the real GitHub API and the real `v0.2.0`/`v0.1.0` tags.
  [`crates/anne-de-breuil-cli/src/application/update.rs`](crates/anne-de-breuil-cli/src/application/update.rs),
  [`crates/anne-de-breuil-cli/src/adapters/github_release.rs`](crates/anne-de-breuil-cli/src/adapters/github_release.rs),
  [`crates/anne-de-breuil-cli/src/ports/mod.rs`](crates/anne-de-breuil-cli/src/ports/mod.rs).

### Fixed

- **`Cargo.toml`'s `repository` field was a stale placeholder**
  (`https://github.com/anne-de-breuil/anne-de-breuil`, predating this
  repo's real location) — `anne update` reads it via
  `env!("CARGO_PKG_REPOSITORY")` to know which GitHub repo to query, so
  the fix is load-bearing for this release, not incidental cleanup. Now
  `https://github.com/greysquirr3l/anne_de_breuil`.
- **The `v0.2.0` README overhaul never actually reached `main`** — a race
  between pushing that commit to the `release/v0.2.0` branch and the PR
  being merged meant the merge captured an earlier point on the branch;
  the commit (`533395c`) existed on the remote branch but had no path
  into `main`'s history. Cherry-picked directly onto `main` once found.

## [0.2.0] — 2026-08-22

### Added

- **`xtask build-windows`** — `release.yml`'s Windows cross-build was two
  raw inline steps (`cargo xwin build --release --target
  x86_64-pc-windows-msvc -p anne-de-breuil-cli`, then `xtask
  verify-static`) with no local equivalent; a developer wanting a fresh
  `anne.exe` had to remember and re-type both by hand. Wraps them into one
  task, reusing `verify_static::assert_no_dynamic_crt_import` directly
  rather than shelling out to itself. Requires `cargo-xwin` and
  `llvm-objdump` already on `PATH` — matches every other xtask task's
  "never installs anything, only operates on what's already there"
  contract.
  [`xtask/src/build_windows.rs`](xtask/src/build_windows.rs).
- **`anne scan --include-*` redaction flags** — `RedactionPolicy`'s own doc
  comment already described a `--include-command-line` CLI switch, and
  `PowerShellCollector`/`LinuxProcessResolver` already implemented
  `with_redaction_policy` builders for it, but nothing in the CLI crate ever
  called them: every collector was built with the hardcoded all-off default,
  with no flag or config surface for an operator to opt in. Adds
  `--include-command-line`, `--include-executable-path`,
  `--include-service-path`, and `--include-disabled-firewall-rules` to
  `anne scan`, plus matching `[scan]` config fields, merged CLI-or-config the
  same way `--include-udp` already was and threaded through
  `collector_factory::local_collectors` into whichever adapter the platform
  actually constructs.
  [`crates/anne-de-breuil-cli/src/cli.rs`](crates/anne-de-breuil-cli/src/cli.rs),
  [`crates/anne-de-breuil/src/adapters/config/scan.rs`](crates/anne-de-breuil/src/adapters/config/scan.rs),
  [`crates/anne-de-breuil-cli/src/application/scan.rs`](crates/anne-de-breuil-cli/src/application/scan.rs),
  [`crates/anne-de-breuil-cli/src/adapters/collector_factory.rs`](crates/anne-de-breuil-cli/src/adapters/collector_factory.rs).

### Fixed

- **`WindowsProcessResolver` had no `RedactionPolicy` support at all** — the
  native Win32 fallback (used only when the embedded PowerShell helper can't
  be written to disk) unconditionally captured full executable paths and
  command lines via `sysinfo`, with no way to opt out, unlike the other two
  process-resolver adapters. Brought up to parity: a `redaction` field, a
  `with_redaction_policy` builder mirroring `LinuxProcessResolver`'s, and
  gated capture in `build_process_map`.
  [`crates/anne-de-breuil/src/adapters/windows_collector/processes.rs`](crates/anne-de-breuil/src/adapters/windows_collector/processes.rs).
- **HTML report branding and attribution** — the report's `<title>`/`<h1>`
  read the crate's hyphenated package name (`anne-de-breuil`) rather than
  the project's proper name, and carried no link back to the repo anywhere.
  Renamed to "Anne de Breuil" throughout, and added a footer
  (`Generated by <a href="…">Anne de Breuil</a>`) to the monolithic report,
  the per-host `--split` documents, and the split index. The project's
  existing "zero external resource references" tests (which assert the
  report never depends on a network fetch to render) were tightened rather
  than loosened: they now specifically allow `href="http…"` only on a plain
  `<a>` navigation link, while still hard-failing on any `src="http`,
  `url(http`, or non-anchor `href="http` — a real resource dependency would
  still be caught.
  [`crates/anne-de-breuil/templates/report.html`](crates/anne-de-breuil/templates/report.html),
  [`crates/anne-de-breuil/templates/host_document.html`](crates/anne-de-breuil/templates/host_document.html),
  [`crates/anne-de-breuil/templates/split_index.html`](crates/anne-de-breuil/templates/split_index.html).

Verified against a real Windows PowerShell 5.1 Desktop host (ARM64 VM), not
just `cargo xwin build`/`clippy`: `collect.ps1` run with every opt-in switch
produced real executable paths, command lines, service `PathName`s, and
disabled firewall rules, versus none of that surfacing with the flags off —
and the real capture round-trips through the actual `parse_payload`
deserializer.

### Documentation

- **README overhaul** — the "Redaction" and "What gets collected" sections
  claimed the collection-time opt-in fields had "no flag, CLI or otherwise"
  wiring them up, which this same release makes false; both sections now
  document the real `--include-*` flags and clearly separate the two
  redaction layers (collection-time inclusion vs. unconditional report-time
  secret scrubbing) rather than conflating them. Added a table of contents,
  an "Installation" section (GitHub Releases table + checksum verification,
  build-from-source), CI/release/license/toolchain badges, a "License"
  section (the dual MIT/Apache-2.0 terms already in `Cargo.toml` were never
  stated in the README itself), and a mention of `xtask build-windows` in
  both "Cross-compilation" and "Release artifacts". The local-scan usage
  example was re-run for real against the current build (`collector_version`
  was still showing `0.1.0`).
  [`README.md`](README.md).

## [0.1.0] — 2026-08-22

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
  pretty JSON to stdout. CSV, SARIF, and HTML rendering followed later
  in this same release — see the `T21`/`T23`/`T24` entries below; this
  bullet only covers the JSON path as it stood at `T18`.
  [`crates/anne-de-breuil-cli/src/application/report.rs`](crates/anne-de-breuil-cli/src/application/report.rs).

- **`anne inventory validate <path>`** (`T18`) — parses the TOML file
  and surfaces every validation error before any collector touches a
  host, so a broken inventory can't half-scan a fleet.
  [`crates/anne-de-breuil-cli/src/application/inventory.rs`](crates/anne-de-breuil-cli/src/application/inventory.rs).

- **`anne version`** (`T18`) — semver + the git SHA embedded at build
  time. The SHA comes through `ANNE_CLI_GIT_HASH` (set by `build.rs`)
  with a `"dev"` fallback for unpacked tarballs.
  [`crates/anne-de-breuil-cli/src/application/version.rs`](crates/anne-de-breuil-cli/src/application/version.rs).

- **Cross-platform local collector selection** (`T31`, stub at the time) —
  `local_collectors(include_udp)` returned a `(LocalCollectorSet,
LocalCollectorGuard)` tuple whose four port impls were unconditionally
  empty, reserved only as the call-site shape the real feature-gated
  adapters would later drop into. Superseded within this same release —
  see "Local collector wiring" near the end of this section for the real
  platform adapters that now back it.
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

- **`anne report --format csv|sarif`** (`T21`) — `domain/report_render.rs`
  (new, pure, zero I/O) turns a `ReportModel` into JSON, CSV, or SARIF.
  CSV is a flattened `(host, endpoint)` row per endpoint
  (`host_id,protocol,bind_address,port,process_path,hosted_services,
signature_status,exposure,reachability`), always with a fixed header
  row even when a model has zero endpoints across every host (a quiet
  host is an ordinary case, not an edge case — the header regression
  is covered by `csv_header_is_present_even_with_zero_endpoints`). SARIF
  turns each `DriftEntryView` into one `result`, validated in tests
  against a vendored SARIF 2.1.0 JSON Schema
  (`crates/anne-de-breuil/fixtures/sarif-schema-2.1.0.json`), with
  `logicalLocations` naming a network endpoint (`host:{uuid}/TCP:0.0.0.0:8443`)
  rather than forcing a file-shaped `physicalLocation` URI onto data
  that isn't a file. `adapters/report_writer.rs`'s `write_atomically`
  gives `anne report --output <path>` collision-safe atomic writes
  (a UUID-suffixed temp file plus `create_new(true)`, verified by a
  real 8-thread concurrent-writer test).
  [`crates/anne-de-breuil/src/domain/report_render.rs`](crates/anne-de-breuil/src/domain/report_render.rs),
  [`crates/anne-de-breuil/src/adapters/report_writer.rs`](crates/anne-de-breuil/src/adapters/report_writer.rs).

- **Self-contained HTML theming contract** (`T23`) — `domain/contrast.rs`
  computes real WCAG contrast ratios for every token-system colour pair
  against `--paper` (all clear 4.5:1 AA on the light theme; the dark-theme
  gap is documented, not silently fixed, and later flagged again by
  `T24`). `templates/tokens.css` carries the `:root` token block, a
  `prefers-color-scheme: dark` override, and a manual theme toggle;
  `--fonts embed|system` swaps the four vendored WOFF2 faces for a
  system font stack with zero `base64,`/`@font-face` bytes in `system`
  mode. `adapters/html_report.rs` renders through Askama with a strict
  `default-src 'none'` CSP.
  [`crates/anne-de-breuil/src/domain/contrast.rs`](crates/anne-de-breuil/src/domain/contrast.rs),
  [`crates/anne-de-breuil/src/adapters/html_report.rs`](crates/anne-de-breuil/src/adapters/html_report.rs).

- **HTML report shell — navigation, tables, drill-down, `--split`** (`T24`) —
  `adapters/html_report/` becomes a module directory (`view.rs` presentation
  mapping, `templates.rs` document shells). Every host section gets a
  zero-JavaScript sortable endpoint table (port / exposure / reachability,
  via radio + `:has()` CSS, no client script anywhere in the dependency
  tree), a fleet-wide drift summary sortable by severity or kind, and a
  pure-CSS honeycomb port-density grid. `--split <dir>` streams one
  self-contained `host-<uuid>.html` per host plus an `index.html`, instead
  of a single monolithic document; a synthetic 200-host fixture stays
  under 5.6 MB. XSS regression tests (`xss_payloads_never_appear_unescaped`,
  `xss_svg_context_payload_is_neutralized`) inject real script-tag payloads
  into process names and confirm entity-escaped output.
  [`crates/anne-de-breuil/src/adapters/html_report/`](crates/anne-de-breuil/src/adapters/html_report/).

- **Server-rendered editorial SVG diagrams** (`T25`) — five diagram types,
  all server-rendered inline `<svg>` from real `ReportModel` data, no
  charting library anywhere in the dependency tree: an exposure map
  (interface → port → process, degrading to a one-line summary above 60
  endpoints), a rule-evaluation precedence stack (Block/Allow/Default-action
  layers), a two-point drift timeline, an exposure-× -signature-confidence
  trust quadrant, and a per-host firewall-profile bar chart. `domain/svg.rs`
  snaps every coordinate to a 4px grid at construction (not just in a test)
  and escapes every interpolated string unconditionally; every diagram
  always emits `role="img"`/`aria-label`/`<title>`/`<desc>`.
  [`crates/anne-de-breuil/src/domain/svg.rs`](crates/anne-de-breuil/src/domain/svg.rs),
  [`crates/anne-de-breuil/src/adapters/html_report/diagrams/`](crates/anne-de-breuil/src/adapters/html_report/diagrams/).

- **Annotation callouts and executive-summary prose** (`T26`) — every
  render generates a plain-prose executive summary (`"Scanned N hosts and
  found N endpoints exposed on all interfaces, N unsigned binaries, and N
  drift entries since the baseline."`, or `"...No findings."` for a clean
  fleet) and, when a real finding qualifies, at most one fleet-wide margin
  callout naming the single highest-priority issue (worst `DriftEntryView`
  by severity, or the most-exposed unsigned all-interfaces listener),
  never hand-written and never an empty shell on a clean report.
  `domain::annotations::select_annotation` picks deterministically between
  exactly the two candidate types genuinely backed by real data in
  `ReportModel` today — a third "well-known-port mismatch" candidate was
  deliberately omitted rather than built as an unfounded heuristic (see
  the module's own "Two candidate types, not three" doc note).
  [`crates/anne-de-breuil/src/domain/annotations.rs`](crates/anne-de-breuil/src/domain/annotations.rs).

- **Optional `axum` + `htmx` portal for fleet browsing** (`T27`) —
  behind the `portal` feature, six bearer-token-authenticated routes
  (fleet index, host detail, host detail fragment, scan detail, snapshot
  download, drift view) reusing the same `ReportModel`/Askama rendering
  the standalone HTML report already built. `application::portal`'s
  `AuthorizingRepository` checks `host_scopes.contains(&host)` before
  every read and post-filters `get_for_host` on `snapshot.host_id == host`
  so a token scoped to host A can never see host B's data even via a
  mismatched scan id. Rate limiting (`adapters::portal::rate_limit`,
  fixed-window per token/IP) and security headers (CSP, HSTS gated on
  `X-Forwarded-Proto: https`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`) are both wired as outermost
  `Router` layers, verified against a real running server with `curl`
  (401 with no token, 403 for an out-of-scope host, 404 for a
  cross-tenant scan id, 429 on a real rate-limit budget of 1). `htmx`
  2.0.4 is vendored (`assets/vendor/htmx.min.js`), not CDN-fetched.
  Ships as `examples/portal_server.rs` only — no `anne portal` CLI
  subcommand exists (confirmed against `Command`'s variant list in
  `crates/anne-de-breuil-cli/src/cli.rs`: `Scan`, `Diff`, `Report`,
  `Inventory`, `Version` — no `Portal`).
  [`crates/anne-de-breuil/src/adapters/portal/`](crates/anne-de-breuil/src/adapters/portal/),
  [`crates/anne-de-breuil/examples/portal_server.rs`](crates/anne-de-breuil/examples/portal_server.rs).

- **`docs/security-audit.md`** (`T28`) — a full OWASP Top 10:2025 and
  OWASP API Security Top 10:2023 pass (the latter scoped to the `portal`
  feature's routes), every item a concrete finding tied to a real file
  and line or an explicit Not Applicable backed by the grep/read that
  established it. Two real findings, both fixed: CI jobs in
  `.github/workflows/ci.yml` had no least-privilege `permissions:` block
  (added a top-level `contents: read`), and remote-artifact cleanup under
  task cancellation (`JoinHandle::abort()` mid-`exec()`, as distinct from
  an ordinary `Drop`) had no direct test coverage. Everything else audited
  came back clean and re-verified rather than assumed: parameterised SQL
  everywhere, no credential ever reaches a `tracing` log line (the
  library crate has no `tracing` dependency at all), constant-time portal
  token comparison, POSIX-quote-escaped SSH exec arguments, Askama
  auto-escaping confirmed against real rendered output.
  [`docs/security-audit.md`](docs/security-audit.md).

- **Static builds, Authenticode signing, SBOM, and release automation**
  (`T29`) — `.github/workflows/release.yml`, triggered by
  `workflow_run` off a new `.github/workflows/auto-tag.yml` (a tag pushed
  with the default `GITHUB_TOKEN` never fires another workflow's
  `on: push: tags`, so `release.yml` reacts to the tagging workflow
  finishing instead). Eight jobs build musl x86_64/aarch64 (native,
  `ldd`-verified static), MSVC x86_64/aarch64 (cross-compiled via
  `cargo xwin` on `ubuntu-latest`, `xtask verify-static` gate against
  `llvm-objdump -p` finding zero dynamic `VCRUNTIME`/`MSVCP` imports),
  a real `windows-latest` smoke test of the cross-built exe, conditional
  Authenticode signing via `osslsigncode` (skipped with a clear
  `::notice::` when no signing certificate secret is configured — true
  for this repository today, so release binaries ship unsigned), a
  CycloneDX SBOM via `syft`, and `SHA256SUMS.txt` checksums computed
  after signing so the published hash matches the bytes actually shipped.
  `xtask/src/checksum.rs` and `xtask/src/verify_static.rs` are new.
  A genuine pre-existing compile bug was found and fixed by actually
  running the musl cross-build for the first time:
  `LinuxProcessResolver::new()`'s `const fn` called the non-`const`
  `RedactionPolicy::default()`, invisible until this task compiled that
  `#[cfg(target_os = "linux")]`-gated file on a non-Linux dev machine for
  the first time — fixed with a hand-written `const fn RedactionPolicy::none()`.
  [`.github/workflows/release.yml`](.github/workflows/release.yml),
  [`.github/workflows/auto-tag.yml`](.github/workflows/auto-tag.yml),
  [`xtask/src/checksum.rs`](xtask/src/checksum.rs),
  [`xtask/src/verify_static.rs`](xtask/src/verify_static.rs).

- **`docs/dev/security-hardening-review.md`** (`T30`) — a shorter,
  cross-referencing follow-up to `T28`'s full audit, scoped to what
  `T28` didn't already establish. One real, medium-severity finding
  fixed: `ProbeExclusions::default()` (`application/identify.rs`)
  excluded nothing, so the probe engine's operator-configured outbound
  HTTP/TLS fetches would happily hit `169.254.169.254`/`169.254.170.2`
  (AWS/Azure/GCP/ECS cloud-metadata addresses) with no flag required to
  trigger it and none available to prevent it — a real SSRF pivot for
  exfiltrating an instance's managed-identity credentials. Fixed by
  folding both addresses into every construction path unconditionally,
  with no override escape hatch. Rate limiting, security headers, and
  the absence of any upload/ingestion endpoint were re-verified against
  the real assembled portal router (not just isolated middleware tests)
  and against a real running server with `curl`.
  [`crates/anne-de-breuil/src/application/identify.rs`](crates/anne-de-breuil/src/application/identify.rs),
  [`docs/dev/security-hardening-review.md`](docs/dev/security-hardening-review.md).

- **The production `HostScanner`, `--self-hash`, and real remote fan-out**
  (`T31`) — `adapters::remote_scanner::SshHostScanner` (behind `ssh`)
  is the real implementation of the trait `application::fanout` has
  driven against a `TODO(T31)` placeholder since `T16`. `resolve_strategy`
  attempts a bounded 5-second SSH connect; success resolves `Execute`
  (push this same running `anne` binary to the target, hash it, run it
  with `--self-hash` then `--emit-json`, verify the echoed hash matches
  before trusting any output); any failure resolves `Probe` (a genuinely
  new 23-port well-known-port sweep gated on a real TCP connect before
  running `HttpProber`/`TlsProber`), never a hard error. `anne --self-hash`
  is a bare, subcommand-less invocation detected before `Cli::parse()`
  runs at all (`application::self_hash::is_self_hash_invocation`), backed
  by a SHA-256 implementation shared between this mode and
  `SshHostScanner` (`adapters::binary_hash`). `anne scan --inventory
<path> --config <path>` now does a real fan-out: parses the inventory,
  builds `KnownHosts`, constructs `SshHostScanner`, and calls the real
  `run_fanout` against a real `SnapshotStore`, printing a per-host summary
  and persisting every result. `InventoryHost` gained a required `user`
  field (`SshTransport::connect` needs a login user, and nothing before
  this task ever opened a real connection from inventory data).
  `anne-de-breuil-cli`'s own `ssh`/`store-sqlite` features were never
  actually enabled on its `anne-de-breuil` dependency before this task —
  every prior release build, including every artifact `release.yml`
  produces, shipped with zero SSH capability and zero SQLite support
  until this fix.
  [`crates/anne-de-breuil/src/adapters/remote_scanner/`](crates/anne-de-breuil/src/adapters/remote_scanner/),
  [`crates/anne-de-breuil/src/adapters/binary_hash.rs`](crates/anne-de-breuil/src/adapters/binary_hash.rs),
  [`crates/anne-de-breuil-cli/src/application/scan.rs`](crates/anne-de-breuil-cli/src/application/scan.rs),
  [`docs/dev/integration-wiring-audit.md`](docs/dev/integration-wiring-audit.md).

- **Stub and placeholder cleanup** (`T32`) — the task's own named
  placeholders (`FsSnapshotStore::get`/`list`, `SshTransport::push`/
  `exec`/`remove`, `ReportModel::build`, SARIF result rendering, `xtask
vendor-fonts`) were all already real and shipped by earlier tasks;
  the real work was a housekeeping sweep of five stale `// TODO(Txx)`
  comments and five `#[expect(dead_code, ...)]` annotations whose stated
  reasons no longer held. Two concrete fixes came out of the sweep: the
  SVG glyph-subset scan T25 left unbuilt now has a real end-to-end test
  (`adapters/fonts.rs`), and `PowerShellCollector`'s `SignatureVerifier`
  now delegates to the same `WinVerifyTrust`-backed
  `WinTrustSignatureVerifier` the native Win32 adapter (`T06`) uses on
  Windows, instead of staying `Unknown` forever — a real, safe, in-process
  delegation, since whichever collector gathered a host's other data, the
  running `anne` process is the same Windows process either way.
  `docs/dev/stub-cleanup-audit.md` also records, plainly, the single
  largest remaining gap at the time: a plain `anne scan` with no
  `--target`/`--inventory` collected zero endpoints on every real
  platform, because `collector_factory.rs` never constructed any of the
  real, fully-built PowerShell/native-Windows/Linux collector adapters —
  closed by the very next commit, described below.
  [`crates/anne-de-breuil/src/adapters/powershell_collector/mod.rs`](crates/anne-de-breuil/src/adapters/powershell_collector/mod.rs),
  [`crates/anne-de-breuil/src/adapters/fonts.rs`](crates/anne-de-breuil/src/adapters/fonts.rs),
  [`docs/dev/stub-cleanup-audit.md`](docs/dev/stub-cleanup-audit.md).

- **Local collector wiring** — `anne scan`'s default path (no `--target`/
  `--inventory`) collected zero endpoints on every real platform right up
  until this fix, despite real, fully-built collector adapters existing
  for both Windows and Linux — the tool's single most basic invocation
  simply never called them. `collector_factory.rs`'s `local_collectors`
  now constructs a real `LinuxCollectors` on Linux, a real
  `PowerShellCollector` on Windows (falling back to an infallible native
  `WindowsNativeCollectorSet` if the embedded helper script can't be
  written to a temp file), and keeps the previous stub's byte-for-byte
  empty-answer behaviour on every other platform (macOS, this project's
  own dev machine included). `scan_local` now also calls
  `inbound_rules()`/`profiles()` and maps them into the snapshot through
  a new `firewall_mapping` module — `ScanSnapshot::new`'s
  `firewall_rules`/`profiles` arguments were previously hardcoded
  `vec![]` on every local scan. Required teaching the domain layer
  `FromStr` for `Direction`/`RuleAction`/`FirewallProfileKind` and adding
  `RuleId::synthesize` for adapters (nftables) with no native rule GUID.
  A real `cargo xwin build` (not just `check`) along the way surfaced a
  pre-existing bug: `ssh_transport`'s agent auth unconditionally called a
  Unix-only `russh` method, so the crate had never actually cross-built
  for Windows with the `ssh` feature enabled — fixed by splitting the
  agent connection by platform.
  [`crates/anne-de-breuil-cli/src/adapters/collector_factory.rs`](crates/anne-de-breuil-cli/src/adapters/collector_factory.rs),
  [`crates/anne-de-breuil-cli/src/application/firewall_mapping.rs`](crates/anne-de-breuil-cli/src/application/firewall_mapping.rs).

- **`LICENSE-MIT` and `LICENSE-APACHE`** — dual MIT/Apache-2.0 licensing
  at the repository root, matching this project's Rust-ecosystem peers.
  [`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE).

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
- **`anne report`'s `--format` surface** (`T21`/`T23`) — `--format
csv|sarif|html` and `--output <path>` were added incrementally across
  `T21` (CSV/SARIF) and `T23` (HTML); `--format html` is accepted by
  `clap` from `T21` onward but rejected with `ConfigOrArgError` until
  `T23` actually wires a renderer for it. `--split <dir>` (`T24`)
  conflicts with `--output` and is only valid alongside `--format html`.
- **`docs/security-audit.md`'s OWASP category list** (`T28`) — audited
  against the real, current `owasp.org/Top10/2025/` release rather than
  assumed carried-over from the 2021 edition; the 2025 edition folded
  SSRF into Broken Access Control and renamed/reordered several
  categories.

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
- **`render_csv` dropped its header on a zero-endpoint model** (`T21`,
  post-commit fix) — `csv::Writer`'s automatic header inference derives
  column names from the first serialised row, so a model with zero
  endpoints across every host produced a completely empty file, no
  header at all — an ordinary "quiet host" outcome, not a contrived
  edge case. Fixed by disabling automatic headers and writing a fixed
  `CSV_HEADERS` array unconditionally before any data rows.
  [`crates/anne-de-breuil/src/domain/report_render.rs`](crates/anne-de-breuil/src/domain/report_render.rs).
- **`ci_workflow_audit.rs` counting its own explanatory comment as a
  permission grant** (`T29` follow-up) — a regression test counting
  literal occurrences of `"contents: write"` in `release.yml` also
  matched the comment lines explaining why only one job holds that
  permission, so a correctly least-privileged workflow tripped its own
  test. Fixed by filtering out `#`-prefixed lines before counting.
- **PowerShell firewall-rule JSON shape mismatch** — `RawRule`'s
  fields (a single `local_port_spec: Option<String>`, a required flat
  `policy_store: String`) were written in `T04`, before
  `assets/collect.ps1` existed. The real script emits `local_ports` as
  a JSON array and never emits a flat `policy_store` field at all, only
  `policy_store_source`/`policy_store_source_type` — deserialising
  `RawRule` directly against real script output failed on the first
  rule. This went uncaught because
  `fixtures/powershell/server2019_full_lm.json`, despite its name, was
  hand-written to match `RawRule`'s own shape rather than derived from
  real script output; every other payload section already had a
  translation struct bridging this exact gap (`PsSocketEndpoint`,
  `PsProcess`, `PsService`) — firewall rules never did. Added
  `PsFirewallRule`, following that same pattern: joins the `local_ports`
  array into `RawRule`'s single spec string (`"Any"`/empty collapses to
  no filter), and falls back `policy_store` through
  `policy_store_source_type` → `policy_store_source` → `"Local"`. Fixed
  the fixture to match the real script shape so the test suite actually
  protects against the regression going forward.
  [`crates/anne-de-breuil/src/adapters/powershell_collector/payload.rs`](crates/anne-de-breuil/src/adapters/powershell_collector/payload.rs),
  [`crates/anne-de-breuil/fixtures/powershell/server2019_full_lm.json`](crates/anne-de-breuil/fixtures/powershell/server2019_full_lm.json).
- **CI least-privilege identity** (`T28`) — `.github/workflows/ci.yml`
  had no top-level or job-level `permissions:` block on the
  `build-test-lint`/`cargo-deny` jobs; added a top-level
  `permissions: contents: read`, inherited by every job without its own
  override.
- **`LinuxProcessResolver::new()` const-fn compile error** (`T29`) —
  called the non-`const` `RedactionPolicy::default()` from a `const fn`
  constructor, invisible on this project's macOS dev machine because the
  file is `#[cfg(target_os = "linux")]`-gated and had never actually been
  compiled here before. Fixed with a hand-written `const fn
RedactionPolicy::none()`, matching `WindowsProcessResolver::new()`'s
  existing const-constructor sibling.
- **`SshTransport`'s agent auth never cross-built for Windows** (local
  collector wiring follow-up) — `authenticate_via_agent` called
  `AgentClient::connect_env()` unconditionally, a `#[cfg(unix)]`-only
  `russh` method; `anne-de-breuil-cli` always enables the `ssh` feature,
  so this had silently never cross-built for Windows until a real
  `cargo xwin build` (not just `check`) caught it. Split into
  `connect_agent()` (platform-gated) plus a platform-independent
  `offer_agent_identities<S>` generic over the stream type.
- **`collect.ps1` never actually worked end to end on real Windows**
  (post-`0.1.0`-tag CI hardening) — the script had only ever been
  exercised against hand-written fixtures and a macOS stub path; the
  first real `windows-latest` CI runs, and later a capture from a live
  Windows PowerShell 5.1 host, surfaced a chain of distinct real bugs,
  each one only reachable once the previous was fixed:
  - `Split-Path -LiteralPath $OutputPath -Parent` — PowerShell 7's
    `-LiteralPath` parameter set has no `-Parent` switch; the parent
    directory is its default, implicit return value.
  - The `PowerShellCollector` timeout (30s) was too tight for
    `Get-NetFirewallRule`'s one-time `NetSecurity` module/CIM
    registration cost on a cold VM — raised to 60s.
  - The top-level JSON envelope (`SchemaName`, `Metadata`,
    `CollectionStatus`, …) was `PascalCase` while every nested field,
    and the parser's whole schema, was `snake_case` — this project's
    own fixtures never caught it because they were hand-authored in
    the casing the parser expected, not derived from real script
    output.
  - `Get-NetFirewallRule.EnforcementStatus` is multi-valued on a
    domain-joined host; calling `.ToString()` directly on that array
    literally produced the text `"System.Object[]"`.
  - `@($servicesByProcessId[$processKey])` is PowerShell's classic
    `$null`-wrapping trap — a hashtable miss returns `$null`, and
    `@($null)` is a *one-element* array containing that `$null`, not
    an empty one, producing `"hosted_services":[null]` for any process
    with no hosted services.
  - `Get-NetFirewallPortFilter.Protocol` reports `"Any"` the same way
    it does for `local_ports`, and real hosts always carry several
    built-in ICMPv4/ICMPv6 (and other non-TCP/UDP) firewall rules —
    neither was handled, so `firewall_mapping::firewall_rule_from_raw`
    hard-failed the entire scan the first time it collected either.
  - Several `Get-NetFirewallRule`/`Get-NetFirewallProfile`/
    `Win32_Service` fields could be `$null` while the schema (and the
    Rust parser) declared them non-optional strings — nameless service
    records are now skipped outright; `rule_id`/`display_name`/
    `direction`/`action`/profile `name`/default actions now fall back
    to `''`, never `$null`.

  Diagnosed largely without a live Windows box: `parse_payload`'s
  errors were extended to show a slice of the raw JSON around the
  failure (`payload.rs`'s `reject_if_depth_truncated` and the new
  `describe_json_error`), turning "something failed" into "here is the
  exact field" on the next real CI run. The last few bugs were found
  and fixed directly against a real Windows PowerShell 5.1 Desktop VM
  (the exact binary/edition `PowerShellCollector` actually invokes),
  whose sanitized capture is now a permanent regression fixture
  (`fixtures/powershell/vm_real_capture.json`,
  `parses_real_capture_from_a_live_windows_vm`,
  `every_non_protocol_field_in_a_real_capture_maps_cleanly`).
  [`crates/anne-de-breuil/assets/collect.ps1`](crates/anne-de-breuil/assets/collect.ps1),
  [`crates/anne-de-breuil/src/adapters/powershell_collector/payload.rs`](crates/anne-de-breuil/src/adapters/powershell_collector/payload.rs),
  [`crates/anne-de-breuil-cli/src/application/firewall_mapping.rs`](crates/anne-de-breuil-cli/src/application/firewall_mapping.rs).
- **Three Windows-only clippy findings** — `missing_const_for_fn`
  (`domain::reachability::compare_program_paths`, which needed a real
  `#[cfg]` split: `str::eq_ignore_ascii_case` is const-stable on this
  toolchain but `str`'s `PartialEq` is not, so only the Windows body
  can be `const`), `duration_suboptimal_units`
  (`Duration::from_secs(60)` → `from_mins(1)`), and
  `too_long_first_doc_paragraph`. All three were invisible to `cargo
  xwin build` and to clippy on macOS/Linux, since they live behind
  `#[cfg(windows)]`; `cargo xwin clippy` (not just `cargo xwin build`)
  now catches this whole class locally before pushing.
- **`release.yml`'s musl and Windows cross-builds** — the musl job used
  bare `clang`, which cross-compiles against the *host*'s glibc headers
  (no musl sysroot on `PATH`), so `rusqlite`'s bundled `sqlite3.c`
  referenced large-file symbols (`open64`, `fstat64`, …) that don't
  exist in musl's static libc; switched to real `musl-gcc` cross
  toolchains (prebuilt by musl.cc) for both `x86_64` and `aarch64`,
  verified end to end in a real `ubuntu:latest` container. Separately,
  the Windows job installed the `llvm` apt package (providing
  `llvm-lib`, which `cc-rs` needs to archive `ring`'s C sources for the
  MSVC target) only *after* the `cargo xwin build` steps that actually
  needed it — moved earlier.
  [`.github/workflows/release.yml`](.github/workflows/release.yml).

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
- **Default cloud-metadata SSRF exclusion** (`T30`) —
  `ProbeExclusions::default()` (`application/identify.rs`) previously
  excluded nothing, meaning the probe engine's operator-configured
  outbound HTTP/TLS fetches would issue a real GET to
  `169.254.169.254`/`169.254.170.2` (AWS/Azure/GCP/ECS instance/task
  metadata) if either ever appeared as a scan target, with no flag
  available to prevent it. `ProbeExclusions::new` now unconditionally
  folds both addresses in alongside whatever the caller supplies, on
  every construction path, with no override escape hatch.
  [`crates/anne-de-breuil/src/application/identify.rs`](crates/anne-de-breuil/src/application/identify.rs).
- **Remote-cleanup guarantee under task cancellation, now tested**
  (`T28`) — `remote_cleanup_guarantee_holds_under_cancellation` proves
  `RemoteArtifactGuard`'s `Drop`-spawned cleanup survives the calling
  task itself being cancelled (`JoinHandle::abort()`) mid-`exec()`
  against a real, locally-spawned `sshd` — a materially different code
  path than a guard falling out of scope in otherwise-normal control
  flow, which the pre-existing tests already covered.
- **Collector binary integrity check now has a real production caller**
  (`T31`) — the hash-mismatch-rejects-before-trusting-output mechanism
  (`push_exec_collect_remove`) existed and was tested against a real
  `sshd` since `T15`, but had no real collector binary speaking its
  protocol until `SshHostScanner`'s `Execute` path (`T31`) pushed and
  ran the actual `anne` binary against itself for the first time.
- **This documentation pass** — brought `CHANGELOG.md` current through
  `T32` and the two follow-up fixes, and added the README's "What gets
  collected" and "Usage examples" sections (evidence-checked against
  the current collector adapters and CLI surface, not summarised from
  task descriptions).

## Pre-0.1.0 groundwork

Initial domain model, collectors, snapshot store, drift, SSH transport,
fan-out orchestrator, report model, and font vendoring — landed as the
T01–T22 series before the CLI surface existed. This section predates the
`v0.1.0` tag; the `[0.1.0]` version number used to sit on this heading
before any tag existed, back when it was aspirational placeholder text
rather than a real release marker — retitled once `v0.1.0` was actually
cut, so the version number isn't claimed twice. See
[`PROGRESS.md`](PROGRESS.md) for the per-task index and `git log` for
the commit-level detail.

[Unreleased]: https://github.com/greysquirr3l/anne_de_breuil/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/greysquirr3l/anne_de_breuil/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/greysquirr3l/anne_de_breuil/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/greysquirr3l/anne_de_breuil/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/greysquirr3l/anne_de_breuil/releases/tag/v0.1.0
