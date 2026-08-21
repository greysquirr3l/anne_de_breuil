# anne-de-breuil

Enumerates the listening-port surface of a host and correlates each endpoint
with its owning process, hosted services, binary signature, and the
effective host firewall policy that governs it.

Runs against the local machine or fans out over SSH to an inventory of
remote hosts, pushing a static collector, executing it, retrieving a signed
JSON snapshot, and removing the artifact. Snapshots are content-addressed
and diffable, so a baseline scan and a rescan produce a drift report rather
than a wall of noise.

Output targets are JSON, CSV, SARIF, and a self-contained HTML5 report with
server-rendered SVG diagrams, no external assets, and no network fetches at
view time.

## Authorized use only

This tool enumerates listening ports, running processes, and firewall
policy on every host it touches, and pushes an executable collector onto
remote hosts over SSH to do it. Only run it against systems you are
authorised to assess — your own infrastructure, or a client's under an
explicit engagement. Unauthorised port scanning and remote code execution
against systems you don't control is illegal in most jurisdictions,
independent of intent.

## Operational contract

### Exit codes

`anne`'s exit code is a contract other tooling (CI, RMM, cron) can branch
on without parsing output — defined once in
`crates/anne-de-breuil-cli/src/cli.rs::ExitCode` and never reused for an
unrelated meaning:

| Code | Name               | Meaning                                                                 |
| ---- | ------------------ | ------------------------------------------------------------------------ |
| `0`  | `Clean`             | The command completed successfully.                                     |
| `1`  | `OperationalError`  | Collector couldn't reach the host, snapshot couldn't be persisted, etc. |
| `2`  | `ConfigOrArgError`  | Bad configuration or arguments — missing config field, unparseable inventory, unknown `--strategy` value. |
| `3`  | `DriftDetected`     | `diff --fail-on-drift` found drift at or above the configured severity. |

### Redaction

Redaction is **always on** today. `domain/redaction.rs::redact` runs
unconditionally wherever a `ReportModel` is built — there is currently no
flag, CLI or otherwise, that disables it. A collected command line,
connection string, or bearer token is stripped to a
[`SecretCategory`](crates/anne-de-breuil/src/domain/redaction.rs) marker
before it can reach any output format (JSON, CSV, SARIF, or the HTML
report). This is the current shipped behaviour, not an aspiration —
opt-in switches for specific sensitive fields
(`RedactionPolicy::include_command_line` and friends, consumed by the
Windows and Linux collector adapters) exist for a future `--include-*`
CLI surface, but nothing wires them to an operator-facing flag yet.

### Host key verification

SSH host keys are verified strictly and fail-closed
(`adapters/ssh_transport/known_hosts.rs::verify_host_key`). An unknown
host key is rejected unless the caller explicitly opts into accepting new
keys; a host key that doesn't match what's on file is always rejected,
with no override. There is no accept-on-first-use behaviour by default —
nothing in the current CLI surface exposes a flag to weaken this.

## Layout

Two crates under `crates/`:

- `anne-de-breuil` — library crate. Hexagonal layout under `src/`:
  `domain/` (pure logic, no I/O), `ports/` (consumer-owned trait
  boundaries), `application/` (use-case orchestration), `adapters/`
  (implementations against the OS, PowerShell, SSH, SQLite, HTTP).
- `anne-de-breuil-cli` — binary crate, ships the `anne` executable. Same
  four-module layout for CLI-local glue.

## Toolchain

Pinned exactly to Rust 1.97.1 via `rust-toolchain.toml`. Never let this
float to bare 1.97.0 — that release has a known LLVM miscompilation
(rust-lang/rust#159035) fixed in the 1.97.1 patch.

## Build, test, lint

```bash
cargo build --workspace --all-features
cargo test --workspace --all-features
cargo l   # alias for the full clippy profile, see .cargo/config.toml
cargo audit
cargo deny check
```

`cargo l` runs clippy with `clippy::all`, `pedantic`, `nursery`, `cargo`,
and `perf` enabled, a small allow-list for lints that are too noisy to be
useful project-wide, and a deny-list (`unwrap_used`, `expect_used`,
`panic`, `indexing_slicing`, `cast_ptr_alignment`, `suspicious`) that turns
"never `.unwrap()`/`.expect()`/panicking index outside tests" into a
mechanically enforced rule instead of a review convention.

CI enforces `-D warnings` via `CARGO_BUILD_WARNINGS=deny` (stable as of
1.97), not by injecting `-D warnings` into `RUSTFLAGS` — `RUSTFLAGS`
changes bust the build cache between local and CI runs.

## Cross-compilation

Local development happens on macOS. The pinned toolchain carries four
extra targets so Windows- and Linux-specific adapter work can be
type-checked without a VM in the loop:

```bash
rustup target add x86_64-pc-windows-msvc aarch64-pc-windows-msvc \
  x86_64-unknown-linux-musl aarch64-unknown-linux-musl
```

The `-musl` targets link with `rustc`'s bundled musl support directly.
The `-msvc` targets need the Windows SDK and MSVC import libraries, which
[`cargo-xwin`](https://github.com/rust-cross/cargo-xwin) downloads on
first use — no Windows install or VM required:

```bash
cargo install cargo-xwin
cargo xwin check --target x86_64-pc-windows-msvc
```

This proves the cross-compile path works before any Windows-specific code
exists, and lets `windows-collector`/`powershell-collector` work (T05/T06)
be iterated on from macOS or Linux.

The native 3-OS CI matrix (ubuntu-latest, windows-latest, macos-latest) is
separate from this cross-compiled path — it exists to actually exercise
`#[cfg(windows)]`/`#[cfg(unix)]` code natively, not to replace it.

## Release artifacts

`.github/workflows/release.yml` builds and publishes all four targets
whenever `.github/workflows/auto-tag.yml` tags a new version. It doesn't
trigger off the tag push directly — a tag pushed with the default
`GITHUB_TOKEN` never fires another workflow's `on: push: tags`, so
`release.yml` instead reacts to `auto-tag.yml` finishing (`on:
workflow_run`) and re-derives the tag from the commit it ran against.

- **windows-msvc** (`x86_64`/`aarch64`) — cross-built via `cargo xwin
  build --release` on `ubuntu-latest`, statically linked
  (`target-feature=+crt-static` in `.cargo/config.toml`) so the collector
  starts on a bare host with neither Rust nor the Visual C++
  Redistributable installed. `cargo run -p xtask -- verify-static
  <exe>` fails the build if `llvm-objdump -p` finds a dynamic
  `VCRUNTIME*`/`MSVCP*` import. A real `windows-latest` runner then
  executes the cross-built exe (`--version` plus `inventory validate`
  against a committed fixture) — xwin's build only proves the exe links,
  not that it runs.
- **musl** (`x86_64`/`aarch64`) — built natively on `ubuntu-latest`,
  verified static via `ldd` (falls back to `readelf -d` if `ldd`'s wording
  ever drifts). This is the artifact pushed to remote hosts over SFTP.
- **SBOM** — a CycloneDX SBOM (via [`syft`](https://github.com/anchore/syft))
  covering the full dependency tree is generated per release and published
  alongside the binaries.
- **Checksums** — `cargo run -p xtask -- checksum write` SHA-256-hashes
  every artifact into `SHA256SUMS.txt`, computed after signing so the
  published hash matches the bytes actually shipped. `checksum verify`
  re-hashes and compares — the mechanism the SSH transport's own
  push-side integrity check (T15) mirrors.
- **Signing** — Windows binaries are Authenticode-signed via
  `osslsigncode` when `WINDOWS_CODESIGN_CERT`/`WINDOWS_CODESIGN_PASSWORD`
  repository secrets are configured. No certificate is configured for
  this repository today, so the release workflow ships unsigned Windows
  binaries and logs that plainly — an unsigned collector will be flagged
  by EDR on a real target host; this is a real gap to close before this
  tool is trusted against production Windows fleets, not a step that's
  silently faked.

## Supply chain

`deny.toml` configures `cargo-deny` for advisory, license, ban, and source
checks. `cargo audit` covers the RUSTSEC advisory database independently.

## Fonts (report-html)

The self-contained HTML report embeds four subsetted WOFF2 faces — no
external font requests, ever — compiled in via `include_bytes!` behind the
`report-html` feature (`crates/anne-de-breuil/src/adapters/fonts.rs`).
Vendored output lives in `crates/anne-de-breuil/assets/fonts/` and is
committed; the upstream source faces used to produce it are not.

**One-time setup** — populate `fonts-src/` (gitignored) manually from the
official upstream repositories:

```
fonts-src/
  instrument-serif/InstrumentSerif-Regular.ttf   # https://github.com/Instrument/instrument-serif
  instrument-serif/OFL.txt
  geist/Geist-Regular.ttf                        # https://github.com/vercel/geist-font
  geist/Geist-Medium.ttf
  geist/OFL.txt
  geist-mono/GeistMono-Regular.ttf               # https://github.com/vercel/geist-font
  geist-mono/OFL.txt
```

Install the subsetting toolchain once:

```bash
brew install harfbuzz woff2       # macOS
# or: apt install harfbuzz-utils woff2  (harfbuzz-tools on some distros)
```

**Re-subsetting** — after updating `fonts-src/`, or to reproduce the
currently vendored output:

```bash
cargo run -p xtask -- vendor-fonts
```

This shells out to `hb-subset` + `woff2_compress` on the local machine,
subsets each source face to Latin + digits + the punctuation the report
templates actually emit (`xtask/src/vendor_fonts.rs::SUBSET_UNICODES`),
writes the `.woff2` output into `crates/anne-de-breuil/assets/fonts/`, and
rewrites `manifest.toml` with the resulting SHA-256 digests. It never
touches the network — the fetch into `fonts-src/` is a separate, manual,
documented step, deliberately kept out of any build script.

Both font families are OFL 1.1. License texts are committed beside the
binaries (`OFL-instrument-serif.txt`, `OFL-geist.txt`) and reproduced in
full in `THIRD_PARTY_LICENSES.md` at the repository root.
