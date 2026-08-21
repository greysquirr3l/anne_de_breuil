# Integration Wiring Audit — T31

This task's own framing is an audit ("catch code that compiles but isn't
connected"), but its `TODO(T31)` markers — scattered across the codebase
since T16 — pointed at something bigger than a documentation pass: no
production `HostScanner` existed for remote SSH scanning, and the `anne`
binary had no `--self-hash` mode. Both were confirmed with the user before
this task started and built for real, not just documented as gaps. This
document is the audit half: every grep sweep the task's own "Code Sketch"
specified, run for real against the current tree, plus everything else
found while building the HostScanner and wiring `--config`/`--inventory`
for real. Findings are grouped **Fixed** and **Documented, not fixed**
(with the reason each one is correctly out of scope), matching T28/T30's
pattern of a dedicated findings document at a well-defined path.

## Fixed in this task

### 1. No production `HostScanner` — the tool's core remote-scan promise was unbuilt

**Location:** `crates/anne-de-breuil/src/application/fanout.rs`'s
`HostScanner` trait had zero non-test implementations anywhere in the
tree before this task (confirmed by `grep -rn "impl HostScanner for"
crates/` returning only the `#[cfg(test)]` fakes in `fanout.rs` itself).
`crates/anne-de-breuil-cli/src/application/scan.rs`'s `run_remote_fanout`
was a `warn!` stub that never called `run_fanout` at all.

**Fix.** `crates/anne-de-breuil/src/adapters/remote_scanner/{mod.rs,probe.rs}`
(behind the `ssh` feature): `SshHostScanner`, the real `HostScanner`.
`resolve_strategy` attempts a bounded (5s) `SshTransport::connect`;
success resolves `Execute`, any failure resolves `Probe` — never a hard
error, matching the trait's own documented contract. `scan`'s `Execute`
path hashes and pushes *this same running binary* (the orchestrator and
the collector are the same `anne` binary, per T18's design — see finding
3 below for what that actually required) via
`push_exec_collect_remove`, then stamps the returned snapshot's `host_id`
with the inventory's own id (the remote run self-generates one via
`HostId::generate()`, same as any local `--emit-json` invocation, and has
no way to know the orchestrator's inventory identity). `scan`'s `Probe`
path (`remote_scanner/probe.rs`) is new composition logic that didn't
exist anywhere: no prior code in this crate probed a *whole host* and
assembled `Endpoint`s from the result — every existing `Prober` took one
already-known `Endpoint`. It walks a bounded, 23-entry well-known-port
list (not a sweep), gates each candidate on a real TCP connect (see the
module doc for why `HttpProber`'s own evidence can't be used as the
liveness signal — it always records `"tls-handshake:failed"` on a closed
port too), and only then runs `HttpProber`/`TlsProber` against ports that
actually answered. Every `Probe`-tier endpoint carries no process
attribution, correct for that tier.

`crates/anne-de-breuil-cli/src/application/scan.rs`'s `run_remote_fanout`
now parses the inventory file for real, builds `KnownHosts` from
`[remote] known_hosts` (or an empty book if the file doesn't exist yet —
a fresh install has no `known_hosts` on disk, and that's not an error),
constructs `SshHostScanner`, and calls the real `run_fanout` with a real
`SnapshotStore` and `IndicatifProgress`, printing a per-host summary line
and persisting every result.

### 2. `ssh`/`store-sqlite` were never compiled into the actual `anne` binary

**Severity: High.** `crates/anne-de-breuil-cli/Cargo.toml`'s
`anne-de-breuil.workspace = true` dependency line carried no `features =
[...]` override, so it only ever pulled `anne-de-breuil`'s *default*
features (`windows-collector`, `linux-collector`, `report-html`) — never
`ssh` or `store-sqlite`. `SshTransport`/`SqliteSnapshotStore` only ever
compiled into the real `anne` binary under a `--all-features` build (this
project's own CI/test invocation), never under a plain `cargo build
--release -p anne-de-breuil-cli` — which is exactly what
`.github/workflows/release.yml` uses to build every shipped artifact.
Every release binary this project has ever built therefore shipped with
zero SSH capability and zero SQLite store support, regardless of any
`[remote]`/`[store]` config an operator might write.

**Fix.** `anne-de-breuil = { workspace = true, features = ["ssh",
"store-sqlite"] }` in `anne-de-breuil-cli/Cargo.toml` — additive on top of
the existing defaults, no `release.yml` change needed (dependency
features aren't a build-command flag, they're unconditional once declared
on the dependency spec).

### 3. `run_and_collect`'s `--emit-json` exec invoked an argument the real CLI has never accepted

**Severity: High — this is what a real end-to-end test is for.** The
task's own "required reading" asserted the `--emit-json` half of
`run_and_collect` "already works today via the existing `anne scan
--emit-json` path (T18), nothing to change there." That claim was wrong,
and only building `SshHostScanner` and pointing a real end-to-end test at
a real pushed `anne` binary caught it: `run_and_collect` ran
`RemoteCommand::new(remote_path.as_str(), ["--emit-json"])` — a bare
`anne --emit-json`, no subcommand. The real CLI has no top-level
`--emit-json` flag; it only exists as `ScanArgs::emit_json` under the
`scan` subcommand. Every prior test of this path (T15's own
`push_exec_collect_remove_round_trip` and siblings) used a hand-rolled
shell fixture that pattern-matches `$1` directly and doesn't care about
subcommand structure — so the mismatch was invisible until something that
does care (the real binary) was actually pushed and run. `--self-hash`
never had this problem because `main` intercepts it *before*
`Cli::parse()` runs at all.

**Fix.** `run_and_collect` now execs `RemoteCommand::new(remote_path.as_str(),
["scan", "--emit-json"])`. The fixture collector scripts in
`ssh_transport/tests.rs` were updated to match (`$1 $2` = `"scan
--emit-json"`) so they keep testing the real contract, not a stale one.
`crates/anne-de-breuil-cli/tests/remote_scan_end_to_end.rs` is the
regression test: a real local `sshd`, a real inventory + `--config` file,
the actual built `anne` binary run via `assert_cmd`, pushing and running
*itself* over SSH.

### 4. `AnneConfig::load` was never actually called anywhere — and broke immediately once it was

**Severity: High.** `ScanArgs.config: Option<PathBuf>` was parsed by clap
but read by nothing (`TODO(T31)` in `cli.rs`). Wiring it for real
(`application::scan::resolve_config`) surfaced a second, previously
unreachable bug within the first real test run: `cargo:rustc-env` from
`anne-de-breuil-cli/build.rs` sets a **real runtime process environment
variable** for `cargo test`/`cargo run` invocations of that package, not
just a compile-time constant for `env!()` (confirmed empirically —
`build.rs`'s own prior comment claimed the opposite, and was wrong). The
build script named that variable `ANNE_CLI_GIT_HASH`, which collided with
`AnneConfig::load`'s `Env::prefixed("ANNE_")` scan the moment `load` was
ever genuinely called under `cargo test` — exactly the failure mode T18's
own learning predicted for "whoever wires `--config` for real."

**Fix.** Renamed the build-time constant to `CLI_GIT_HASH` (no `ANNE_`
prefix) in both `build.rs` and `application/version.rs`'s `option_env!`
read — it has no user-facing reason to live under that prefix, unlike
`ANNE_LOG_FORMAT` (see the Documented-not-fixed section). `--config`
wiring itself: `resolve_config` only calls `AnneConfig::load` when
`--config` is actually given (not from a default path — `[store]` has no
`Default`, so calling `load` unconditionally would break every existing
`anne scan` invocation that never asked for `--config`); `scan.rs`'s
`build_store` mirrors `examples/portal_server.rs`'s own backend-selection
shape rather than inventing a second one.

### 5. `push_exec_collect_remove` discarded a successful scan on a cleanup failure

**Severity: Medium.** `Ok(snapshot) => guard.remove_now().await.map(|()|
snapshot)` — if the post-success remote cleanup (`rm` over SFTP) failed
for any reason (permission hiccup, a dropped connection), the whole
function returned `Err`, discarding a snapshot that had already been
collected successfully. Found while designing `HostScanner`'s error
mapping and confirmed by reading the existing control flow, not by a new
failing test.

**Fix.** A cleanup failure after a successful collect is now swallowed
(best-effort, matching the existing precedent for the failure-path
branch's own cleanup call) and the snapshot is still returned. An orphaned
remote artifact is harmless — the next scan of the same host pushes to a
fresh, unrelated random path (`RemotePath::random_under_temp`).

### 6. `InventoryHost` had no login-user field

**Severity: High — blocked `HostScanner::scan`'s `Execute` path entirely.**
`SshTransport::connect` requires a `user: &str`; `InventoryHost` had
`host_id`/`address`/`port`/`auth`/`jump`/`tags` and nothing naming which
account to authenticate as. This was a real, previously-latent gap: no
code before this task ever actually opened a connection using inventory
data, so it went uncaught.

**Fix.** Added `pub user: String` (required, no default — guessing a
login account, e.g. `"root"`, is exactly the kind of ambient assumption
`AuthMethod`'s own doc comment already rules out for credentials).
Updated both fixture inventory files and the `fanout.rs` test helper.

## Documented, not fixed (correctly out of scope)

### `assignment_mismatches`/`certificate_findings` always report `0`

Already documented by T31's own predecessor work in
`domain/report_model.rs`'s module doc — reconfirmed true here, not
re-investigated from scratch. Computing either needs an evidence-backed
*observed* `ServiceIdentity`/TLS finding threaded into `ScanSnapshot`,
which no current pipeline produces (the probe/fingerprint/reconciliation
modules have no call site folding into `ScanSnapshot` at all). This is a
distinct, large feature — a new evidence-carrying field on the aggregate
plus a real fold — well beyond "build the remote HostScanner." The
`report_model.rs` doc comment's `TODO(T31 ...)` tag was removed since
T31 closes without fixing it (a task tag pointing at a task that's about
to be marked done would be misleading); replaced with plain prose
pointing here.

### The local collector wiring is a stub — `anne scan` (no `--target`/`--inventory`) collects nothing

**Severity: High, but a distinct, large feature.**
`crates/anne-de-breuil-cli/src/adapters/collector_factory.rs`'s
`local_collectors` always returns `LocalCollectorSet`, whose four port
impls (`EndpointSource`/`ProcessResolver`/`FirewallPolicySource`/
`SignatureVerifier`) all return empty/`None` unconditionally — its own
doc comment already says so. Real, production adapters for all four
ports exist and are fully built: `PowerShellCollector`
(`adapters/powershell_collector`), `WindowsProcessResolver`/
`WinTrustSignatureVerifier`/`WmiFirewallPolicySource`
(`adapters/windows_collector`), `LinuxEndpointSource`/
`LinuxProcessResolver`/`LinuxSignatureVerifier`/`LinuxFirewallPolicySource`
(`adapters/linux_collector`) — none of them are ever constructed by
`collector_factory.rs`. This means `anne scan` with no `--target`/
`--inventory` (the plain local-scan case, arguably the tool's single most
basic use) always reports zero endpoints on every real platform today.
This is squarely a wiring gap in this audit's sense, but closing it means
picking the right collector per platform/mode
(PowerShell-preferring-native-fallback on Windows, procfs/netlink on
Linux — mirroring the task's own `build_collector_set` sketch) and is a
separate, large feature from "build the remote `HostScanner`," which is
what the user's confirmed scope for this session was. Flagged here as the
single largest remaining wiring gap in the codebase.

### `--target` remains a documented no-op

`--target <host>` only ever carries a bare hostname — there is no CLI
flag for the login user or auth method a real single-host connection
needs (unlike `--inventory`, whose TOML schema now has `user`/`auth`
fields). Guessing either would be the same kind of ambient assumption
finding 6 above ruled out for `InventoryHost`. `run_remote_single_target`
still warns and exits clean rather than silently scanning the local
machine instead of the named host (T18's original fix), with an updated
message pointing at this document.

### `--probe`/`--probe-exclude`/`--probe-timeout`/`--probe-rate` remain unwired

Confirmed via `grep -n "probe_exclude\|probe_timeout\|probe_rate"
crates/anne-de-breuil-cli/src/application/scan.rs` returning nothing.
These flags are for local active identification against a scan's own
already-discovered endpoints (`ScanArgs::probe: bool`, "makes outbound
connections to the target") — a distinct feature from
`SshHostScanner::Probe`'s remote fleet port-guessing, which this task
built and deliberately gave its own bounded default (`ProbeConfig::default()`)
rather than reusing or reinterpreting these flags for a different purpose.

### Portal has no `anne portal` subcommand

`crates/anne-de-breuil/examples/portal_server.rs` remains an example
binary, not a CLI subcommand. Confirmed via `grep -rn
"adapters::portal\|application::portal"
crates/anne-de-breuil-cli/src/` returning nothing — the portal feature is
entirely unreachable from the `anne` binary. The task file names this as
this task's likely job but explicitly lower priority than the
`HostScanner` work; given the size of the `HostScanner`/`--self-hash`/
`--config`/wiring-audit work above, promoting the example into a real
`anne portal` subcommand was not attempted this session. It's a
well-scoped, mechanical follow-up (a new `Command::Portal` variant
wrapping `portal_server.rs`'s existing `main` logic almost verbatim) —
deliberately deferred, not silently dropped, matching how T27 deferred
portal ingestion.

### `ANNE_LOG_FORMAT` can still collide with `AnneConfig::load`

T18's own learning: any `ANNE_`-prefixed environment variable with no
`__` in it (not just the git-hash one finding 4 fixed) lands as a single
unrecognised top-level key and fails the whole config load —
`ANNE_LOG_FORMAT`, read directly via `std::env::var` in `main.rs`, is a
real, live instance of this. Unlike the git-hash constant, this one is a
genuine user-facing operational knob with no reason to move outside the
`ANNE_` prefix; fixing it needs either a custom `figment` `Env` provider
or renaming the operator-facing variable, both bigger changes than this
task's scope. Still real, still open.

### `InventoryHost::jump` (bastion/jump hosts) is parsed but never honoured

`SshTransport::connect` has no bastion-hop parameter. `SshHostScanner`
always connects directly to `host.address`; a host only reachable through
a jump host simply fails to connect and degrades to `TargetStrategy::Probe`
— never a hard error, but not the double-hop the inventory schema
implies either. Real double-hop SSH (channel-in-channel proxying) is a
distinct, sizable feature, not attempted here.

## Grep sweeps run for real, this session

- `grep -rn "impl HostScanner for" crates/` — only the new
  `adapters::remote_scanner::SshHostScanner` outside `#[cfg(test)]` fakes.
- `grep -rn "trait.*Source\|trait.*Store\|trait.*Transport\|trait.*Verifier\|trait.*Reporter\|trait.*Scanner\|trait.*Prober" crates/*/src/application/`
  — eight port traits: `RemoteTransport`, `EndpointSource`,
  `FirewallPolicySource`, `SignatureVerifier`, `HostScanner`,
  `ProgressReporter`, `Prober`, `SnapshotStore`. Each has at least one
  adapter construction site reachable from the `anne` binary, checked
  structurally by `crates/anne-de-breuil-cli/tests/wiring_audit.rs`'s
  `every_port_trait_has_at_least_one_adapter_construction_site` (the
  `EndpointSource`/`ProcessResolver`/`FirewallPolicySource`/
  `SignatureVerifier` construction site is the documented stub above —
  reachable, not authentic; see that finding).
- `grep -n "enum Command"`/`grep -n "Command::"` (`cli.rs`/`lib.rs`) —
  five variants (`Scan`/`Diff`/`Report`/`Inventory`/`Version`), five match
  arms, checked structurally by the same test file's
  `every_cli_subcommand_variant_is_dispatched`.
- `grep -rn "adapters::portal\|application::portal" crates/anne-de-breuil-cli/src/`
  — zero hits, confirming the Portal finding above.
- `grep -n "\.probe\b\|probe_exclude\|probe_timeout\|probe_rate" crates/anne-de-breuil-cli/src/application/scan.rs`
  — zero hits, confirming the probe-flags finding above.

## Preflight

`cargo build --workspace --all-features`, `cargo test --workspace
--all-features` (498 total tests across both crates, doctests, and
`xtask`, all passing), `cargo clippy` (full pedantic+nursery+cargo+perf
profile, zero
`#[allow(clippy::...)]` anywhere in any new or touched file), `cargo fmt
--all -- --check`, `cargo audit` (clean; the pre-existing `paste`
unmaintained warning, RUSTSEC-2024-0436, is unrelated and unchanged),
`cargo deny check` (advisories/bans/licenses/sources all `ok`) — all pass.

Hand-verified independently of the test suite: `anne --self-hash`'s
output byte-compared against `shasum -a 256` on the same binary file
(exact match, 64 lowercase hex chars plus a trailing newline, nothing
else on stdout); a real end-to-end remote scan via `anne scan --inventory
<file> --config <file>` against a real locally-spawned `sshd`, producing
a real persisted snapshot file on disk — both also codified as automated
tests (`application::self_hash`'s unit tests plus
`tests/remote_scan_end_to_end.rs`), not trusted from the manual run alone.
