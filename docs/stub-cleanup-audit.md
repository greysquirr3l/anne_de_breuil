# Stub and Placeholder Cleanup Audit — T32

The task's own framing calls this an audit whose "known placeholders" section
names five specific `todo!()`s left by T12/T15/T20/T21/T22 — but by the time
this task was dispatched, all five had already been given real
implementations over the course of the project's earlier sessions (confirmed
below, briefly, not re-audited from scratch). The actual open work this task
found was five `// TODO`-style comments still live in `src/`, three of them
tagged with a task number that had already passed by the time this task ran
(`T31`, `T06`, `T04`), plus five `#[expect(dead_code, ...)]` annotations
carrying the same stale-reference problem, surfaced by the housekeeping sweep
this task's own "TODO / FIXME Sweep" section requires. This document is that
audit: every grep sweep the task's own "Code Sketch" specified, run for real
against the current tree, each of the five TODOs and how it was resolved or
re-scoped, and the two real code changes that came out of investigating them —
matching the evidence-based structure T28/T30/T31's own audit documents
already established in this repository.

## The five "Known placeholders" — confirmed real, not re-audited

The task file names these as the primary risk ("AI-generated code frequently
leaves behind placeholder implementations that compile but don't actually
work"). All five are genuinely implemented:

- `FsSnapshotStore::get`/`list` (`adapters/snapshot_store/fs.rs:95,100`) —
  real implementations, exercised by
  `get_returns_none_for_unknown_scan_id`/`list_filters_by_host_and_survives_a_fresh_store_handle`.
- `SshTransport::push`/`exec`/`remove` (`adapters/ssh_transport/mod.rs:218,222,226`)
  — real implementations over `russh`'s SFTP/exec channels, exercised end to
  end against a real spawned `sshd` (`ssh_transport::tests`,
  `remote_scan_end_to_end.rs`).
- `ReportModel::build` (`domain/report_model.rs:544`) — real, the whole
  view-model construction pipeline every report format renders from.
- `sarif_results_for_host` — the task file's own sketch name for this
  function; the real implementation that shipped under T21 is
  `render_sarif`/`sarif_result_for_drift_entry`/`sarif_locations`
  (`domain/report_render.rs:277,321,380`), schema-validated by
  `sarif_output_validates_against_the_vendored_schema`.
- `xtask vendor_fonts main()` — real, `xtask/src/main.rs` dispatches to
  `vendor_fonts::run()`, which drives `hb-subset`/`woff2_compress` for real
  (see `PROGRESS.md`'s T22 entry for the actual vendoring run's output
  sizes and hash verification).

## Grep sweeps run for real, this session

Every pattern from the task's own "Code Sketch" section, run against the
whole workspace (`crates/*/src/` and `xtask/src/`, not just the crate the
task file's own sketch commands listed):

```
$ grep -rn "todo!()" crates/*/src/ xtask/src/
zero hits

$ grep -rn "unimplemented!()" crates/*/src/ xtask/src/
zero hits

$ grep -rn 'panic!("not implemented"\|panic!("unimplemented"' crates/*/src/ xtask/src/
zero hits

$ grep -rn "// TODO\|// FIXME\|// HACK\|// XXX" crates/*/src/ xtask/src/
crates/anne-de-breuil/src/adapters/linux_collector/nft_wire.rs:284: /// TODO(future task): ...
(the only remaining hit, after this task's own fixes below — see "Left
as-is" section)

$ grep -rn "Default::default() // placeholder" crates/*/src/ xtask/src/
zero hits

$ grep -rn 'unreachable!("stub"' crates/*/src/ xtask/src/
zero hits
```

Before this task's fixes, the `// TODO` sweep returned five hits, listed
below.

## The five TODO comments

### 1. `adapters/portal/mod.rs:31` — portal ingestion, tagged `T31 or later`

**Was:** `// TODO(T31 or later): if a future task wants portal to accept
pushed snapshots directly...`

**Finding:** stale by the time this task ran. T27 (the task that built the
portal) deliberately deferred an ingestion endpoint as out of scope for a
read-only fleet-browsing portal. T30's security review reconfirmed the
absence is structural, not accidental
(`portal_upload_endpoint_does_not_exist_by_default`, `GET /ingest` → `404`).
T31 — the "or later" task this comment named — ran, closed most of the
project's remaining wiring gaps, and *did not* build ingestion either,
correctly, per its own documented scope decision
(`docs/integration-wiring-audit.md`). Three independent passes reached the
same conclusion. T32 is the last task in the project; there is no future
task left to defer to.

**Fix:** rewrote the comment to drop the task-number reference entirely and
state the deferral as a standing design decision with its rationale (a new
write-capable port method plus a new authorization question — "which token
may write to which host," not just read — neither of which
`SnapshotRepository` answers today), citing all three passes that
independently reached the same call instead of pointing at a task number
that no longer means anything.

### 2. `adapters/fonts.rs:225` — the SVG codepoint-subset scan, tagged T25

**Was:** `// TODO(T25): once the SVG diagram generator and HTML templates
exist, add the codepoint-subset scan...`

**Finding:** T25 (SVG diagrams) shipped; this comment's own stated
precondition is satisfied and nobody removed the comment or built the test.
Checked `adapters/html_report/diagrams/` (all five diagram renderers) and
`templates/` for an existing equivalent — none exists; this was a genuine,
still-open gap, not a stale comment pointing at work done elsewhere.

Investigating it surfaced a real design question the task's own phrasing
didn't quite anticipate: `SvgCanvas::text` accepts arbitrary caller-supplied
strings, and several diagram call sites pass through genuinely unbounded
collector-derived data (process paths in `exposure_map.rs`, firewall rule
display names in `rule_evaluation.rs`/`profile_bar_chart.rs`, interface
labels). That data can legitimately contain characters outside the vendored
font subset (a service named in Chinese, an accented executable path) — this
project cannot constrain what a remote host's firewall rule or binary is
named, and a subset violation there just means a graceful system-font
fallback for that one glyph, not a bug. What *is* fully within this
project's control, and therefore a real, testable invariant, is the report's
own authored vocabulary: every hardcoded label, heading, and caption
`html_report`/`templates` write themselves (`"Baseline"`, `"contained"`,
`"firewall disabled"`, and so on) must never introduce an out-of-subset
glyph, since that would defeat the point of embedding a font subset for
content this project fully controls.

**Fix:** implemented `no_glyph_outside_subset_is_emitted_as_text` for real
in `adapters/fonts.rs`, plus a non-tautological unit test for the subset
checker itself
(`is_within_vendored_subset_accepts_the_real_range_and_rejects_other_glyphs`,
matching this file's own established `font_matches_manifest_rejects_*`
precedent for "prove the checker can fail, not just pass"). The end-to-end
test builds a real `ReportModel` exercising all five diagram types (a block
rule and an allow rule so `rule_evaluation`'s both layers render, an
enabled and a disabled firewall profile so `profile_bar_chart`'s
`"firewall disabled"` branch renders, one `DriftEntry` per `DriftKind`
variant so every branch of `drift_timeline`'s labels renders), renders it
through the real `html_report::render` pipeline, and scans every character
of the actual output against the vendored subset
(`xtask/src/vendor_fonts.rs::SUBSET_UNICODES`, `"20-7E,2013,2014"` in
`hb-subset`'s range syntax, duplicated by hand in a doc comment since
`xtask` is a `[[bin]]`-only crate with no library target `anne-de-breuil`
could depend on instead). Fixture data is deliberately plain ASCII
throughout, documented in the test's own doc comment, so any failure this
test catches points at the report's own code, not at fixture noise.

**Hand-verification.** Before finishing, the test's rendered output was
written to a scratch file and inspected directly (not just trusted because
the assertion passed): confirmed `"Deny SMB"`/`"Allow HTTPS"` both appear
(rule evaluation's block and allow layers), `"1. Block"`/`"2. Allow"`/
`"3. Default action"` (the three precedence layers), `"Domain"`/`"Public"`/
`"firewall disabled"` (profile bar chart), all five
`"endpoint appeared"`/`"...disappeared"`/`"...process changed"`/
`"...signature status changed"`/`"...rule set changed"` drift labels, the
real process paths (`/usr/bin/app`, `/usr/sbin/sshd`, `/usr/sbin/smbd`) and
bind addresses (`0.0.0.0`, `127.0.0.1`) flowing through as real dynamic
content, and five `role="img"` SVG elements (one per diagram type actually
present in the output) — a substantial, real render, not a vacuous or
near-empty one.

### 3. `adapters/powershell_collector/mod.rs:366` — Authenticode verification, tagged T06

**Was:** `// TODO(T06): Authenticode verification... belongs with the
native adapter's signature handling, not invented ad hoc here against an
untested code path.` `SignatureVerifier::verify` returned
`Ok(SignatureStatus::Unknown)` unconditionally.

**Finding:** T06 (the native Win32 adapter) shipped
`WinTrustSignatureVerifier` (`adapters/windows_collector/signatures.rs`), a
real `WinVerifyTrust`-based Authenticode checker, cached by path. Checked
whether the PowerShell path could reuse it rather than reimplement
Authenticode checking from scratch: `powershell_collector` and
`windows_collector` are gated behind the same Cargo feature
(`windows-collector`), so both compile into the same binary together, and
`PowerShellCollector` is *not* itself platform-gated — it can hold a
`#[cfg(windows)]` field. Whichever collector gathered endpoints, processes,
and firewall data, the running `anne` process on a Windows host is the same
process either way; calling `WinVerifyTrust` from within
`PowerShellCollector::verify` needs nothing this binary doesn't already
link when `windows-collector` is enabled. This is a genuine, safe,
in-process delegation, not a cross-process trick — exactly the "could
reasonably call into the same underlying mechanism" case the task
description asked to check for.

**Fix:** `PowerShellCollector` gained a `#[cfg(windows)] signatures:
WinTrustSignatureVerifier` field (constructed in all three constructors:
`new`, `with_execution_policy_bypass`, `for_test_with_sleep_script`). Its
`SignatureVerifier::verify` impl is now `#[cfg(windows)]`-split: on Windows
it delegates straight to `self.signatures.verify(path)`; off Windows (or
on any platform where the Win32 trust provider genuinely doesn't exist) it
stays honestly `Ok(SignatureStatus::Unknown)`. Adding
`Get-AuthenticodeSignature` to the embedded PowerShell script itself was
considered and rejected: the script is a one-shot bulk collector, not built
for per-path follow-up queries, and doing this the script-based way would
mean either a second script round trip per unique binary path or a schema
bump touching the signed script, its redaction policy, and every payload
test that pins the current schema shape — a real feature addition, not a
TODO cleanup, and out of this task's scope.

This change could not be compiled on the real target (no Windows machine or
working `cargo xwin`/`ring` cross-toolchain in this environment — the same
limitation T01's own learnings record); it compiles clean on macOS (where
`#[cfg(windows)]` drops the field and branch entirely, proving the
non-Windows path and the struct-literal syntax are both sound) and was
reviewed by hand against `WinTrustSignatureVerifier`'s real, public
signature (`pub fn new() -> Self`, `async fn verify(&self, path:
&ProcessPath) -> Result<SignatureStatus, CollectError>`), which the
delegation calls exactly. This mirrors the precedent T06 itself set: that
module's own doc comment says "this crate has no Windows machine to verify
it against directly," and relies on an opt-in live-host differential test
for real verification.

### 4. `domain/reachability.rs:146` — environment-variable lookup, tagged T04

**Was:** `// TODO(T04): thread a real environment-lookup port through once
a collector adapter exposes one.`

**Finding:** T04 (consumer-owned collector ports) already happened and, per
its own Accumulated Learnings entry, deliberately did *not* add this — the
comment was forward-looking from the start, not a claim T04 forgot
something. Checked every collector adapter built since (PowerShell, native
Windows, Linux) for anything resembling an environment-variable snapshot:

```
$ grep -rn "environment\|EnvironmentVariable\|env_var\|GetEnvironmentVariable\|Environment::" \
    crates/anne-de-breuil/src/adapters/powershell_collector \
    crates/anne-de-breuil/src/adapters/windows_collector \
    crates/anne-de-breuil/src/adapters/linux_collector \
    crates/anne-de-breuil/src/application/collect.rs
zero hits (outside test code)
```

None of the three collector adapters capture host environment state in any
`Raw*` DTO. This is a real, live gap — not resolvable within this task's
scope, since `evaluate` is deliberately pure (`domain/reachability.rs`'s own
doc comment: "no I/O, no clock, no environment access") and a real fix needs
a collector adapter to snapshot environment variables at scan time and
thread that data through as a value, which is new collection surface, not a
TODO cleanup.

**Fix:** rewrote the comment to drop the stale `T04` reference and state
the gap honestly: no collector this project has built captures host
environment variables, reading `%VAR%` here via `std::env::var` would
evaluate against this process's own environment rather than the scanned
host's (simply wrong for a remote or at-rest scan), and a real fix needs a
collector-side environment snapshot threaded through as data. No task
currently owns this — T32 is the last task in the project's list, so unlike
the portal-ingestion comment (which explicitly names three tasks that all
independently declined it), this one is left as a plain standing limitation
with no scheduled owner.

### 5. `adapters/linux_collector/nft_wire.rs:284` — per-rule nftables decoding, `future task`

**Already correctly un-numbered** — no stale task reference to fix. Read in
full context: `nft_chain_to_raw_rule` decodes only chain-level default
policy (accept/drop) from `NFT_MSG_GETRULE` responses, explicitly leaving
`protocol`/`local_port_spec`/`program_filter`/`service_filter` as `None`
because the function doesn't walk `NFTA_RULE_EXPRESSIONS`. Confirmed this
is still an accurate description of a real, standing limitation (verified
against the current function body — the fields really are hardcoded
`None`, the comment isn't stale). Left as-is per this task's own guidance.

## A sixth, related finding: stale `#[expect(dead_code, ...)]` reasons

Step 5 of this task's instructions calls for spot-checking every
`#[expect(...)]` for an accurate, still-necessary reason, not just the five
named `// TODO`s. That sweep:

```
$ grep -rn "#\[allow(clippy" crates/*/src/ xtask/src/
zero hits
```

Confirmed: the project's "no `#[allow(clippy::...)]` anywhere" rule still
holds after T31's large integration-wiring changes.

```
$ grep -rn "#\[expect(" crates/*/src/ xtask/src/ | wc -l
19
```

Eighteen of nineteen are accurate and still necessary (`unsafe_code`
confinement in `windows_collector/services.rs`/`signatures.rs`,
`clippy::too_many_arguments` on `ScanSnapshot::new`/`Endpoint::new`,
`clippy::significant_drop_tightening` in the portal rate limiter,
`dead_code` on a kept-alive-for-`Drop` SSH test fixture, and one genuinely
inert PowerShell metadata field). Five, all in
`adapters/powershell_collector/payload.rs`, had the same stale-task-number
problem as the main five TODOs: four read `"...T21 will surface it in
reports"` and one read `"T20's redaction boundary governs visibility"`.
Checked git history — the schema-v2 rewrite that introduced these
`#[expect]`s (`53074f3`/`4f771ed`/`bf05a21`, this project's five most recent
commits before T32 started) landed *after* T31's integration-wiring commit
(`2035103`), meaning both T21 and T20 had already shipped by the time these
comments were written pointing forward at them. Checked whether either task
actually does surface this data:

```
$ grep -rln "collection_status\|CollectionStatus\|PsDiagnostic\|diagnostics" \
    crates/anne-de-breuil/src/domain crates/anne-de-breuil/src/application \
    crates/anne-de-breuil/src/adapters/html_report
(no real match — the one hit in html_report/mod.rs is cargo's own
--message-format=json-render-diagnostics flag string, unrelated)
```

Confirmed: no report format (JSON, CSV, SARIF, or HTML) surfaces
per-section collection status or diagnostics anywhere. The `path_name` field
is worse than merely unsurfaced — `RawService` (T04's own port DTO) has no
path field to carry it into the domain model at all, so there is nothing
downstream for "T20's redaction boundary" to govern the visibility of, and
separately, no CLI or config surface sets `include_service_path` today, so
the PowerShell script never even emits the field in production. Rewrote all
five `reason` strings to state this honestly (parsed for schema
completeness, no consumer today, standing gap not a scheduled follow-up)
instead of pointing at tasks that had already passed without addressing it.

This surfaced one further real, if minor, finding, documented here rather
than fixed (matching this task's own "no new features" boundary):
`application::collect::RedactionPolicy`'s four opt-in fields
(`include_command_line`, `include_executable_path`, `include_service_path`,
`include_disabled_firewall_rules`) are not wired to any CLI flag or config
key anywhere in `anne-de-breuil-cli` — confirmed by
`grep -rn "include_command_line\|include_executable_path\|include_service_path\|include_disabled_firewall_rules\|RedactionPolicy" crates/anne-de-breuil-cli/src crates/anne-de-breuil/src/adapters/config`
returning zero hits. An operator cannot currently opt in to any of these
four categories through the real `anne` binary; `with_redaction_policy` is
only ever called directly in Rust (tests, and library consumers embedding
this crate). This is a distinct wiring gap in the same family as the ones
`docs/integration-wiring-audit.md` catalogs, not something this task's
narrower TODO-cleanup scope should fix.

## Preflight

```
cargo build --workspace --all-features
cargo test --workspace --all-features    -> 500 tests passed, 0 failed (up from T31's 498; +2 new)
cargo clippy [full pedantic+nursery+cargo+perf profile, hard denies]  -> clean, zero warnings
cargo fmt --all -- --check               -> clean
cargo audit                               -> clean (the pre-existing `paste` unmaintained
                                              warning, RUSTSEC-2024-0436, is unrelated and
                                              unchanged, same as T30/T31)
cargo deny check                          -> advisories ok, bans ok, licenses ok, sources ok
```

Zero `#[allow(clippy::...)]` anywhere in any new or touched file.

## Final assessment

The five placeholders this task's own file names by function signature were
already real before this task started — T12/T15/T20/T21/T22 all did their
jobs. The actual stub-cleanup work this task found was five stale-task-number
comments (three genuinely stale, one already correctly un-numbered, and one
that resolved into a real, if modest, code fix) plus a parallel set of five
`#[expect(dead_code, ...)]` annotations with the identical problem, caught by
following the task's own housekeeping instructions past the headline list.

Whether the project is feature-complete depends on what "feature-complete"
is measured against. Every port trait has at least one real, non-stub
adapter; every CLI subcommand dispatches to real application logic; every
output format (JSON, CSV, SARIF, self-contained HTML5) renders from a real
pipeline with real tests, including a real end-to-end SSH round trip against
a locally spawned `sshd`. Read against the project's own accumulated
documentation, though, there are real, standing gaps a reader of
`PROGRESS.md` should know about going forward, none of them papered over by
this task or any before it:

- **The single largest one, from T31:** `anne scan` with no `--target`/
  `--inventory` — the plain local-scan case — collects zero endpoints on
  every real platform today. `collector_factory.rs`'s `local_collectors`
  always returns an empty stub; the real PowerShell/native-Windows/Linux
  collector adapters this project built are fully implemented but never
  constructed by the CLI. This is not a TODO-shaped gap (no comment marks
  it, nothing panics) — it's a wiring gap this task's grep sweeps cannot
  catch by design, since the stub code compiles clean and returns valid
  empty data rather than failing loudly.
- `assignment_mismatches`/`certificate_findings` in every report always
  read `0` — no call site folds the fingerprint/reconciliation/TLS-probe
  pipeline into `ScanSnapshot`.
- `--target` carries no login-user/auth-method flags and remains a
  documented no-op; `--probe`/`--probe-exclude`/`--probe-timeout`/
  `--probe-rate` are parsed but unwired; `InventoryHost::jump` (bastion
  hosts) is parsed but never honored.
- The portal has no `anne portal` CLI subcommand — it only runs via the
  `examples/portal_server.rs` example binary.
- `ANNE_LOG_FORMAT` can still collide with `AnneConfig::load`'s
  `Env::prefixed("ANNE_")` scan the same way the git-hash build constant
  used to, before T31 renamed that one out of the prefix.
- (New, from this task) `RedactionPolicy`'s four opt-in sensitive-field
  categories are not reachable from the CLI or config file at all.
- Two now-honestly-documented standing limitations with no task assigned to
  them: environment-variable expansion in firewall program filters
  (`%VAR%`) has no real collector-side data source, and nftables per-rule
  protocol/port/verdict decoding is chain-policy-only.

None of these are stubs, placeholders, or TODOs in the sense this task
exists to clean up — they're real, load-bearing features this project's own
prior audits (`docs/integration-wiring-audit.md` especially) already found
and chose, correctly, not to build inside an audit-scoped or
integration-scoped task. Manufacturing a fix for any of them here would be
exactly the "expanding beyond stub/placeholder/TODO cleanup into a general
refactor" this task's own rules rule out. So: the code that exists is real,
not decorative, and this task closes the last of the stale-comment debt
this project's task-numbered TODO convention accumulated — but "genuinely
feature-complete" is not an honest description of `anne-de-breuil` as it
stands. The tool's most basic invocation (a plain local scan) does not yet
collect real data, and that gap is the one future work on this project
should reach for first.
