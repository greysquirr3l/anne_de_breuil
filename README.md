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

## What gets collected

An operator authorising a scan should know exactly what data leaves a
target host. This section is checked against the real collector code
(`crates/anne-de-breuil/src/adapters/{windows_collector,linux_collector,
powershell_collector}/`, `crates/anne-de-breuil/src/application/collect.rs`),
not summarised from a task description.

### Listening endpoints

Every collector implements the same four narrow ports
(`EndpointSource`/`ProcessResolver`/`FirewallPolicySource`/
`SignatureVerifier`, `application/collect.rs`). `EndpointSource` returns,
per listening TCP or UDP socket: transport protocol, bind address, bound
port, and the owning process id if the platform reports one. A listening
socket is never dropped from the collected output because its owning
process couldn't be resolved — a race where the process exits between
being observed in the socket table and the follow-up query is recorded as
"process gone," not silently discarded.

### Owning process

For every endpoint whose owning pid resolves to a live process:

- Process id.
- Executable path — **opt-in, off by default.** `RedactionPolicy::
include_executable_path` gates this on both platforms; a collector built
  with the default policy never reports it.
- Command line — **opt-in, off by default**, same mechanism
  (`include_command_line`). See "Redaction" below — even when opted in, a
  collected command line still passes through unconditional secret
  redaction before it can reach any report format.
- Hosted services: machine name and display name for every service the
  process hosts (Windows service, systemd unit), always collected —
  service names aren't treated as sensitive the way paths and command
  lines are.
- Binary signature status:
  - **Windows** — real Authenticode verification via `WinVerifyTrust`
    (`adapters/windows_collector/signatures.rs`'s `WinTrustSignatureVerifier`).
    Reports `Signed(publisher)`, `Unsigned`, or `Unknown` (signed but the
    publisher name couldn't be recovered). `PowerShellCollector` delegates
    to this exact same `WinVerifyTrust` call rather than staying `Unknown`
    forever or shelling out to `Get-AuthenticodeSignature` a second time —
    both collection paths report identical signature status on the same
    host.
  - **Linux** — always `NotApplicable`
    (`adapters/linux_collector/signatures.rs`'s `LinuxSignatureVerifier`).
    There is no Linux Authenticode equivalent implemented yet (package-manager
    provenance via `dpkg`/`rpm` database reads is a real, explicitly
    out-of-scope future gap, not something this reports as `Unknown` today).

### Firewall rules and profiles

`FirewallPolicySource` returns the host's inbound rule set and profile
state:

- Per rule: rule id, display name, direction, action (allow/block),
  protocol, port filter, program-path scope, service-name scope, enabled
  state, and policy-store origin (e.g. local, Group Policy, dynamic).
  - **Windows** — via WMI (`root/standardcimv2`'s `MSFT_NetFirewallRule`
    and its filter classes) or the PowerShell helper script
    (`Get-NetFirewallRule` and friends), both reading the *effective*
    (`ActiveStore`) policy rather than only the local store, so
    GPO-delivered rules on a domain-joined host are included. A real bug
    in the PowerShell path was found and fixed after this project's
    firewall-rule fixture turned out not to match what the script
    actually emits: the script reports `local_ports` as a JSON array and
    has no flat `policy_store` field at all, only `policy_store_source`/
    `policy_store_source_type` — the parser now translates that real
    shape instead of expecting one that was never produced.
  - **Linux** — via a raw `NETLINK_NETFILTER` socket query against
    nftables base chains (`adapters/linux_collector/nft_wire.rs`), never
    an `nft`/`iptables` subprocess. Chain-level default policy only; a
    firewall query that finds nothing distinguishes "genuinely no rules"
    from "no policy source was reachable" (permission denied, netlink
    unavailable, or a legacy iptables-only ruleset with real content
    detected via `/proc/net/{ip,ip6}_tables_names`) — these are different
    findings a report reader needs to tell apart, not collapsed into one.
- Per profile: name, whether the firewall is enabled, and the default
  inbound/outbound action for traffic no rule explicitly covers.
  - **Windows** — Domain/Private/Public, matching the platform's own
    model.
  - **Linux** — structurally different, not a re-skin of the Windows
    model: nftables has no per-profile concept at all. There is exactly
    one host-wide ruleset, so `profiles()` always returns an empty list —
    a true "no such concept" on this platform, not a failed query (that
    distinction is reserved for `inbound_rules`).

### What is not collected

- No packet capture and no inspection of connection payloads — only the
  fact that a socket is listening, and (with active `--probe` scanning
  opted in) a bounded set of protocol-identification handshake bytes.
- No file contents from the scanned host.
- No credentials beyond what's required to establish the SSH connection
  itself, and even there, never a password: `AuthMethod`
  (`adapters/inventory.rs`) has exactly three variants —
  `Agent`, `KeyFile(PathBuf)`, `KeyFromKeyring(String)` — none carries a
  `String` a raw secret could occupy. No password auth path exists
  anywhere in this codebase, by construction, not by convention.

See "Redaction" under "Operational contract" below for what happens to
the opt-in sensitive fields (command line, executable path, service path,
disabled firewall rules) once they're collected: redaction is
unconditional and cannot be disabled from the CLI today, regardless of
what a collector was told to include.

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

## Usage examples

Every flag below is checked against `anne <subcommand> --help` on the
current build; the local-scan and diff examples were run for real against
this checked-out repository.

### Local scan

`--emit-json` is the on-host collector mode: stdout carries exactly one
`ScanSnapshot` and nothing else, so it's the shape to pipe into `anne
report` or persist yourself.

```bash
$ anne scan --emit-json
{"host_id":"2e96d2b0-...","scan_id":"61303baf-...","collected_at":[2026,233,21,43,53,145566000,0,0,0],"collector_version":"0.1.0","endpoints":[],"firewall_rules":[],"profiles":[],"strategy":"Execute"}
```

(Zero endpoints above because this was run on macOS, where no collector
adapter is wired yet — see "What gets collected." The same command on
Windows or Linux constructs the real platform collector.)

Without `--emit-json`, `anne scan` persists the snapshot to the default
`./anne-snapshots` store and prints a one-line summary instead:

```bash
$ anne scan
scanned host 750671da-8aa1-48f2-a9a9-581e619755c3; snapshot 70eac046-7b13-4184-b166-6b6d81d2a9c0 persisted
```

### Remote fan-out against an inventory

```bash
anne scan --inventory hosts.toml --config anne.toml
```

A minimal inventory file (real field names, from
[`crates/anne-de-breuil/fixtures/inventory/valid.toml`](crates/anne-de-breuil/fixtures/inventory/valid.toml)):

```toml
[[host]]
host_id = "11111111-1111-1111-1111-111111111111"
address = "10.0.0.10"
port = 22
user = "ops"
auth = "agent"
tags = ["web", "prod"]

[[host]]
host_id = "22222222-2222-2222-2222-222222222222"
address = "db1.internal"
port = 2222
user = "svc-anne"
auth = { key_from_keyring = "anne/db1" }
```

A minimal `anne.toml` (see
[`crates/anne-de-breuil/assets/anne.default.toml`](crates/anne-de-breuil/assets/anne.default.toml)
for the full reference file — `[store]` has no built-in default and must
always be set explicitly):

```toml
[remote]
concurrency = 8
timeout = "2m"
accept_new = false

[store]
backend = "FileSystem"
path = "./anne-data/snapshots"
```

### Rendering a report

```bash
anne report <scan-id-or-path.json> --format json
anne report <scan-id-or-path.json> --format csv
anne report <scan-id-or-path.json> --format sarif
anne report <scan-id-or-path.json> --format html --output report.html
anne report <scan-id-or-path.json> --format html --split ./report-dir
```

Real output against a zero-endpoint local snapshot — `--format csv`
still emits its header row even with no data rows (a fixed regression
this project's own history caught once already):

```bash
$ anne report scan.json --format csv
host_id,protocol,bind_address,port,process_path,hosted_services,signature_status,exposure,reachability
```

`--split` writes one self-contained file per host plus a lightweight
index, instead of a single document:

```bash
$ anne report scan.json --format html --split split-out
$ ls split-out
host-2e96d2b0-0ae0-4138-adba-8fb944e541e0.html  index.html
```

### Comparing two scans

```bash
$ anne diff scan1.json scan2.json --fail-on-drift low
[]
$ echo $?
0
```

`--fail-on-drift` (`low`/`medium`/`high`/`critical`, default `high`)
exits `3` the moment any drift entry meets or exceeds the threshold —
useful in CI as a gate on unexpected new exposure.

### Running the portal

The `axum`/`htmx` fleet-browsing portal is not a CLI subcommand today —
`anne <subcommand>` has no `Portal` variant (see `Command` in
`crates/anne-de-breuil-cli/src/cli.rs`). It ships as a standalone example
binary behind the `portal` feature:

```bash
cargo run -p anne-de-breuil --example portal_server --features portal
```

It reads `anne.toml` (path from the first CLI argument or
`PORTAL_SERVER_CONFIG`) for `[[portal.token]]` entries and `[store]`, and
binds `PORTAL_SERVER_ADDR` (default `127.0.0.1:8088`). A token entry
names an environment variable holding the bearer secret, never the
secret itself:

```toml
[[portal.token]]
id = "team-a"
secret_env = "ANNE_PORTAL_TOKEN_TEAM_A"
hosts = ["11111111-1111-1111-1111-111111111111"]
```

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
