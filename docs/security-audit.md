# Security Audit — anne-de-breuil

Last reviewed: 2026-08-21, against OWASP Top 10:2025 (confirmed via the
official `owasp.org/Top10/2025/` release, not assumed carried-over from the
2021 edition — the ranking and category set changed materially: two new
categories, one consolidation, several reordered) and OWASP API Security
Top 10:2023, the latter scoped to the `portal` feature's HTTP routes (T27).

Every item below is either a concrete finding tied to a real file and line,
or an explicit "Not Applicable" with the grep/read that established it.
Nothing here is boilerplate lifted from a generic checklist.

## Threat model

This tool is not a typical web application, and several OWASP categories
have to be read through its actual abuse paths rather than the generic
"user submits input to a server" shape they were written for:

1. **Elevated local execution.** `anne scan` reads every process's command
   line and owning binary on the host it runs on (`windows_collector`,
   `linux_collector`, `powershell_collector`), which on both platforms
   requires privilege beyond an unprivileged user in the general case
   (`WmiFirewallPolicySource` needs firewall-read rights; the Linux
   `NETLINK_NETFILTER` socket in `adapters/linux_collector/nft_wire.rs`
   typically needs `CAP_NET_ADMIN`; enumerating every service via
   `OpenSCManagerW` needs `SC_MANAGER_ENUMERATE_SERVICE`). A compromise of
   this binary is a compromise of whatever ran it — nothing in this audit
   changes that, and nothing could; it's inherent to the tool's job. What's
   in scope: it must not make that exposure *worse* than the read access it
   already requires (no arbitrary code execution beyond `powershell.exe`
   running a fixed script, no privilege-escalation primitive of its own).
2. **A pushed collector binary executing with elevated privilege on a
   remote host.** `SshTransport::push_exec_collect_remove`
   (`adapters/ssh_transport/mod.rs:144`) copies a binary to a remote host
   over SFTP and executes it. If that push could be tampered with in
   transit, or a wrong/malicious binary substituted, the remote host runs
   attacker-controlled code under whatever privilege the SSH session holds.
   See A08 below for the concrete integrity mechanism and its real
   coverage.
3. **A malicious process name or command line rendered into a report an
   administrator trusts and opens.** Every string this tool observes on a
   scanned host — a process path, a service display name, a firewall rule
   name, a command line — originates on that host, not from this tool's own
   operator. A host could be running something adversarial specifically to
   attack whoever reads the eventual report (a classic stored-XSS-via-log
   pattern, here via `Endpoint.command_line`/`hosted_services`/
   `FirewallRule.display_name` instead of a log line). See A05 (Injection)
   below; T24's own XSS regression tests already cover the HTML rendering
   half of this, cross-referenced rather than rebuilt.
4. **SSH credential handling.** `adapters/ssh_transport/handler.rs`
   authenticates to remote hosts via ssh-agent, a key file, or an OS
   keyring entry — see A02 (Security Misconfiguration) and A04
   (Cryptographic Failures) below for how "no password ever enters this
   codebase" is enforced structurally, not just by convention.
5. **The portal's multi-tenant host-scoping.** T27's `axum` portal serves
   fleet data to multiple bearer-token holders, each scoped to a subset of
   hosts. A bug here is a direct cross-tenant data leak. See the API
   Security Top 10:2023 section, which audits this surface specifically.

## OWASP Top 10:2025

### A01:2025 — Broken Access Control

Applies to: the `portal` feature's HTTP routes only. The CLI and collector
binaries have no multi-tenant concept — every user of `anne scan`/`anne
report` already has whatever local access they used to invoke the binary.

**Finding: mitigated.** `application/portal.rs:88` declares
`SnapshotRepository::list_for_host`/`get_for_host` as taking `&AuthContext`
as a required parameter — there is no method on the trait that reads
snapshot data without one. `AuthorizingRepository<R>`
(`application/portal.rs:133`) wraps any `SnapshotRepository` and checks
`ctx.host_scopes.contains(&host)` before ever calling `self.inner`
(`application/portal.rs:145-177`); `adapters/portal/router.rs` never
constructs a bare, unwrapped repository (confirmed by reading every
`PortalState::new` call site — grep for `StoreBackedRepository::new` outside
`AuthorizingRepository::new(...)` returns nothing). The router's own doc
comment states this precisely: "even a handler that forgot to check
`ctx.host_scopes` itself still can't read another host's data — the check
happens inside the repository, not here"
(`adapters/portal/router.rs:19-31`).

A second, easy-to-miss access-control gap is closed too:
`get_for_host`'s scope check alone only inspects the *claimed* host
parameter, not which host the resolved `ScanId` actually belongs to. A
token scoped to host A, requesting `host=A` with a `scan` id that in fact
belongs to host C (entirely outside scope), would pass the scope guard if
nothing else checked the returned data. `AuthorizingRepository::get_for_host`
adds `.filter(|snapshot| snapshot.host_id == host)`
(`application/portal.rs:176`) specifically for this — verified by a
dedicated test, `mismatched_scan_and_host_never_leaks_another_hosts_data`
(`application/portal.rs:303`), and independently by a real running-server
transcript in `PROGRESS.md`'s T27 section (a token scoped to team-a's host,
given team-b's real scan id, receives a `404`, not team-b's data).

SSRF is folded into this category in the 2025 edition. This tool's own
outbound HTTP/TLS probing (`adapters/prober.rs`, `adapters/tls_probe.rs`)
is the scanner's core function against operator-configured inventory
targets, not a proxy that fetches an arbitrary user-supplied URL on
someone's behalf — there is no route or CLI flag anywhere that takes a URL
from one caller and fetches it for another. `HttpProber`'s own module doc
(`adapters/prober.rs:1-11`) states its redirect policy is `never followed
off the connecting host`, verified by T09 against a DNS-sentinel test (see
`PROGRESS.md`'s T09 learnings) — a compromised or malicious scan target
cannot use a redirect response to make this tool fetch a third, unrelated
host on its behalf.

### A02:2025 — Security Misconfiguration

Applies to: the `portal` HTTP surface primarily, plus general
config-handling posture.

**Finding: mitigated, with the response headers actually verified wired,
not just defined.** `adapters/portal/security_headers.rs:53` (`apply`) sets
`Content-Security-Policy`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, and `X-Frame-Options: DENY` on every
response, including a `404` and a `401` — `adapters/portal/router.rs:83`
adds this layer *last*, which `axum` layers in reverse order, making it the
outermost wrapper around the whole router (route table, rate limiter, and
fallback alike); the module's own doc comment
(`adapters/portal/router.rs:1-17`) explains why the ordering matters and
names the two tests that would catch a regression
(`security_headers::headers_present_on_a_404`,
`router::nonexistent_route_carries_security_headers_and_404`, and
`router::unauthenticated_401_carries_security_headers_too` for the `401`
case specifically).
`Strict-Transport-Security` is conditioned on `X-Forwarded-Proto: https`
(`adapters/portal/security_headers.rs:47,66-68`), since this crate ships
no TLS termination of its own — sending HSTS unconditionally on a
plain-HTTP response the reverse proxy in front of it never claims was TLS
would be a lie the header itself makes false, not a hardening measure.

The CSP itself (`adapters/portal/security_headers.rs:37-40`) is
`default-src 'self'; script-src 'self'; ...; frame-ancestors 'none'` — no
`unsafe-inline`/`unsafe-eval` on `script-src`. `grep -rn "<script"
templates/portal_*.html` finds exactly one hit
(`templates/portal_index.html:8`,
`<script src="/assets/htmx.min.js?v={{ asset_version }}"></script>`) — a
same-origin `src` reference to the vendored `htmx` asset served by this
portal's own `/assets/htmx.min.js` route, which `script-src 'self'`
explicitly permits; there is no inline script *body* (no `<script>...
</script>` with executable content) anywhere in any template, which is
what `script-src 'self'` without `'unsafe-inline'` actually needs to be
true.

Rate limiting is present and verified wired to the router, not just
defined: `adapters/portal/rate_limit.rs:125` (`enforce`) is added as a
layer in `adapters/portal/router.rs:79-82`, ahead of routing, and a live
test (`router::exceeding_the_rate_limit_produces_429`) drives two real
requests through the assembled router and asserts the second gets a real
`429` — this is the same distinction the T28 task's own security rules
call out ("verify the middleware is wired to the router, not just
defined") and it's met here for real, not by inspection alone.

Config secrets (`[[portal.token]]` entries) are read from environment
variables named by `secret_env`, never hardcoded (`adapters/portal/auth.rs:104-123`,
`PortalTokens::load`), and a misconfigured entry (unset or empty env var)
fails the whole portal's startup rather than silently running with fewer
tokens than configured (`adapters/portal/auth.rs:29-36`).

**One real gap, not remediated in this task (documented, deferred):**
neither the router nor any CLI flag in this workspace terminates TLS —
by design, per the security-headers module doc — which means an operator
who runs the portal directly exposed (no reverse proxy) serves it over
plain HTTP with no way to force TLS from inside this binary. This is a
documented deployment requirement (see `security_headers.rs`'s own module
doc), not a code defect this task can fix without inventing TLS
termination the project's own scope (T29 packaging, T30 hardening) hasn't
asked for yet. Flagging here rather than silently treating "reverse proxy
required" as self-evident.

### A03:2025 — Software Supply Chain Failures

**Finding: mitigated by policy, with one honest pre-existing exception.**
`deny.toml`'s `[bans]` section (`wildcards = "deny"`) rejects any
dependency with no version constraint at all — confirmed present, not
assumed. `[advisories]` sets `yanked = "deny"`. `[graph] all-features =
true` (added in T12, see `PROGRESS.md`) ensures every feature-gated
dependency (the `ssh`/`portal`/`store-sqlite`/`windows-collector`/
`linux-collector` features this project relies on for its own supply-chain
isolation) is actually evaluated by `cargo deny check`, not silently
skipped because it's behind a Cargo feature no default build enables.

One documented, pre-existing advisory ignore: `RUSTSEC-2024-0436` (`paste`,
unmaintained, no fix available), reached transitively via
`netlink-packet-utils` → `netstat2` → `linux-collector`. `deny.toml:15-24`
carries a comment explaining exactly why it's ignored (no upstream fix
exists) rather than silently passing — this is the correct disposition for
an unmaintained-but-not-vulnerable transitive dependency with no
alternative, not a finding to remediate by removing the ignore.

CI runs `cargo-deny` (via `EmbarkStudios/cargo-deny-action@v2`,
`.github/workflows/ci.yml:47-52`) with genuine network access — no
`--offline` flag anywhere in the workflow, confirmed by
`crates/anne-de-breuil-cli/tests/ci_workflow_audit.rs`'s
`ci_runs_cargo_deny_with_network_access` test, which reads the real
workflow file via `include_str!` rather than trusting a one-time manual
check. This matters specifically because a stale local advisory database
reports "no advisory found" for a genuinely live advisory — running
offline would be silently worse than not running `cargo-deny` at all, per
this task's own stated risk.

`RUSTSEC-2023-0071` (the `rsa` crate's unpatched Marvin Attack timing
side-channel) was avoided at the dependency-selection level, not
allow-listed: `russh`'s `rsa` feature is deliberately left off
(`Cargo.toml`, `ssh = ["dep:russh", "dep:russh-sftp", ...]`, no `rsa`
sub-feature), so this crate's SSH transport supports ed25519/ECDSA keys
only, never RSA (see `PROGRESS.md`'s T15 learnings). This is a real
scope-narrowing decision, not a suppressed finding.

### A04:2025 — Cryptographic Failures

**Finding: mitigated.**

- No credential ever reaches this codebase as a raw password.
  `adapters/inventory.rs:48` (`AuthMethod`) has exactly three variants —
  `Agent`, `KeyFile(PathBuf)`, `KeyFromKeyring(String)` — and its own doc
  comment states the invariant is structural: "there is nowhere in this
  enum a secret could go." Confirmed by reading every variant: none carries
  a `String` that could hold a raw secret value, only a path or a lookup
  name.
- Portal tokens are hashed at load time (`adapters/portal/auth.rs:117`,
  `Sha256::digest(secret.as_bytes())`) and the raw value is never retained
  — `TokenEntry` (`adapters/portal/auth.rs:74-78`) has no `String` field
  that could hold it, and `PortalTokens` derives no `Debug` at all (the
  module doc explains why: "a stray `{:?}` ... cannot print a token even by
  accident — the field that would hold it doesn't exist, structurally").
- Token comparison is constant-time: `constant_time_eq`
  (`adapters/portal/auth.rs:168-174`) XORs every byte without
  early-exiting, specifically because both operands are attacker-influenced
  (a presented token, hashed, against every configured hash). `[u8]::eq`
  (which most targets implement via a short-circuiting `memcmp`) is
  deliberately not used here.
- TLS: `rustls` with the `ring` crypto provider throughout (`TlsProber`,
  `HttpProber` via `reqwest`'s `rustls-tls` feature) — confirmed no
  `openssl`/`native-tls`/`schannel` crate anywhere in the dependency tree
  (T09's own verification, re-confirmed by `cargo tree | grep -i
  openssl` returning nothing on this pass). Certificate verification is
  never disabled in the *normal* HTTP prober path
  (`adapters/prober.rs`'s own doc comment: "one HTTPS GET with normal
  (never bypassed) certificate validation"). `TlsProber`
  (`adapters/tls_probe.rs`) does use a non-validating verifier — this is
  its whole purpose (deep certificate-chain *inspection*, not
  connection trust), confined to its own module
  (`non_validating_verifier_referenced_by_exactly_one_module`, a real test
  per `PROGRESS.md`'s T10 section) and never used to establish a connection
  this tool subsequently trusts for anything beyond reading the
  certificate itself.
- SSH: `russh` with `default-features = false, features = ["ring",
  "flate2"]` (`Cargo.toml`) — pure-Rust crypto backend, matching the
  `rustls` precedent, confirmed via the same dependency-tree grep.
- Randomness: `Uuid::new_v4()` throughout for identifiers
  (`HostId`/`ScanId`/`RuleId`/`IdempotencyKey`, and
  `RemotePath::random_under_temp()` at `application/remote.rs:229-235`) —
  the `uuid` crate's `v4` feature draws from the OS CSPRNG by default (no
  separate `rand::thread_rng()` anywhere in this codebase; confirmed via
  `grep -rn "thread_rng" crates/` returning nothing).
- Hashing: `Sha256` (portal tokens) and `blake3` (content-addressing the
  snapshot store) — no MD5/SHA-1 used for anything security-relevant. The
  one SHA-1 usage in this codebase (`adapters/ssh_transport/known_hosts.rs`,
  the `hmac`/`sha1` crates) is not a security-relevance regression: it
  implements OpenSSH's own `known_hosts` HMAC-SHA1 hashed-hostname format
  (`|1|salt|hash`), matching a fixed on-disk file format this tool reads,
  not something this tool chose for its own cryptographic purposes — SHA-1
  inside an HMAC construction for hostname obfuscation (not a security
  boundary; the hostname isn't secret, just address-book privacy) is the
  format OpenSSH itself defines, and this parser has no choice but to
  speak it if it wants to read a real `known_hosts` file.

### A05:2025 — Injection

Includes XSS and SQL injection in the 2025 consolidation.

**SQL injection: Not Applicable, verified not assumed.** `grep -rn
"format!.*\(SELECT\|INSERT\|UPDATE\|DELETE\)" crates/` returns nothing
anywhere in the workspace. The only `rusqlite` usage is
`adapters/snapshot_store/sqlite.rs`; every query in that file is a literal
string with numbered placeholders (`?1`, `?2`, ...) bound via
`rusqlite::params![...]` — confirmed by reading the file in full:
`"SELECT scan_id FROM snapshots WHERE idempotency_key = ?1"`
(line 127), `"INSERT INTO snapshots (...) VALUES (?1, ?2, ?3, ?4, ?5)"`
(lines 153-154) with `rusqlite::params![snapshot.scan_id.to_string(), ...]`
supplying every value, `"SELECT snapshot_json FROM snapshots WHERE scan_id
= ?1"` (line 194), `"SELECT scan_id FROM snapshots WHERE host_id = ?1
ORDER BY scan_id"` (line 206). No string interpolation of caller-controlled
data into any query text anywhere in this file.

**Shell/command injection: mitigated.** `SshTransport::exec`
(`adapters/ssh_transport/exec.rs`) is the one place this codebase
constructs a shell string from data at all — SSH's exec channel request
(RFC 4254 §6.5) has no argv-array wire format, only a single string. Every
argument is POSIX single-quote escaped (`shell_quote`,
`adapters/ssh_transport/exec.rs:27-39`) before joining
(`command_line`, lines 41-46): each argument is wrapped in `'...'` with
embedded `'` replaced by `'\''`, so no argument content can terminate its
own quoting and inject additional shell syntax. `RemoteCommand`
(`application/remote.rs:177-202`) itself has no `FromStr`/`from_shell`
constructor at all — only `RemoteCommand::new(program, arguments)` taking
already-split, unescaped strings — so there is no code path anywhere in
this crate that builds a `RemoteCommand` by parsing a single shell-syntax
string, which is the compile-time half of the guarantee the escaping
provides at runtime. `PowerShellCollector` never uses `-EncodedCommand`
(the classic PowerShell obfuscation/injection vector — a base64
UTF-16LE-encoded command line) and never uses `-ExecutionPolicy Bypass` by
default (`adapters/powershell_collector/mod.rs:1-19` states this as the
module's own non-negotiable security posture; a dedicated test,
`script_never_uses_encoded_command`, greps the embedded script itself for
the literal string).

**XSS via observed-host data rendered into a report: mitigated, with the
mechanism actually re-verified, not re-derived from T24's own claim
alone.** `Askama`'s HTML template auto-escape (used throughout
`templates/*.html`) emits numeric character references (`&#60;`, `&#62;`,
`&#34;`), applied to every interpolated `{{ field }}` expression in every
report/portal template that doesn't carry an explicit `|safe` filter.
Every `|safe` usage in this codebase was enumerated (`grep -rn "|safe"
templates/ src/adapters/html_report/ src/adapters/portal/`) and each one
splices in either a fixed, non-interpolated constant (`LEADER_SVG`,
documented at `adapters/html_report/annotation_view.rs:20-21`), CSS text
this crate generates itself (`tokens_css`), or an already-Askama-escaped
HTML fragment produced by another `.render()` call one level down
(`summary_html`, `fragment_html`, `host_section_html`) — never a raw
observed string. SVG diagram text goes through a dedicated escaper,
`escape_svg_text` (`domain/svg.rs:53-66`), which neutralizes `&`, `<`, `>`,
`"`, `'` before any observed process/rule/service name is written into
`<text>` content — a test,
`escape_svg_text_neutralizes_every_structurally_significant_character`,
feeds it a literal `</svg><script>alert(1)</script>&"'` payload and
asserts every structurally significant character is gone. T24's own XSS
regression tests (per `PROGRESS.md`'s T24 section) already cover the
rendered-HTML half of this end to end against real multi-host output with
`<script>` payloads embedded in process paths and rule display names —
cross-referenced here rather than rebuilt, since re-deriving the same
coverage a second time would be redundant, not additional assurance.

**ReDoS: mitigated by engine choice, not by pattern review alone.** Every
regex in this codebase (`domain/redaction.rs`'s `SECRET_PATTERNS`,
`domain/fingerprint.rs`'s catalogue-driven patterns) runs on the `regex`
crate's finite-automaton engine, which is not backtracking-based — it
structurally cannot exhibit catastrophic-backtracking behavior regardless
of pattern shape, confirmed by the crate's own documented complexity
guarantees (linear in input length). `domain/fingerprint.rs`'s
`check_complexity` heuristic (nested-unbounded-quantifier detection, length
cap) is authoring hygiene for fast catalogue load time, not a defense the
engine doesn't already provide — documented honestly as such in that
module's own doc comment, per `PROGRESS.md`'s T11 section, rather than
overclaiming what the check does.

### A06:2025 — Insecure Design

**Finding: mitigated, with the design decisions actually named.**

- **No accept-on-first-use SSH host key trust.**
  `verify_host_key` (`adapters/ssh_transport/known_hosts.rs:226-243`) fails
  closed for any host with no recorded key unless the caller explicitly
  passes `accept_new = true` for that one invocation — and even then, a
  host whose *recorded* key differs from the one offered always errors
  (`HostKeyStatus::Changed` → `TransportError::HostKeyChanged`),
  regardless of `accept_new`. Verified by grep, not just by reading the
  one function: `grep -rn "accept_unknown\|trust_on_first_use"
  adapters/ssh_transport/` returns nothing — there is no second code path
  that could bypass this. Acceptance under `accept_new = true` is held
  only in an in-memory `Mutex`, never written to a `known_hosts` file
  (`known_hosts.rs:1-18`'s own module doc explains why: "opt in to
  trusting this key for this run" must never silently become "opt in
  forever" as a side effect).
- **Bearer-token auth, not a cookie, for the portal** — a deliberate
  choice documented in `adapters/portal/auth.rs:1-24`: a cookie needs an
  issuance step this tool has no login flow for, and reopens CSRF as a
  concern a stateless bearer header structurally avoids (a cross-site
  request can't attach a header a page didn't choose to send).
- **No cascading SSH auth fallback.** `authenticate`
  (`adapters/ssh_transport/handler.rs:95-112`) tries *exactly* the method
  the caller's `AuthMethod` names, never silently falling back from, say, a
  configured key file to whatever the ambient ssh-agent happens to hold —
  an operator who configured a specific credential for a host gets that
  credential offered, not a different identity the tool guessed at.
- **Fail-secure rate limiting.** `RateLimiter::check`
  (`adapters/portal/rate_limit.rs:97-117`) treats `budget_per_window == 0`
  as "deny every request" rather than "no limit configured" — a
  deliberately usable fail-secure configuration (an operator can take the
  portal fully offline for maintenance via config alone), documented
  inline as intentional, not an off-by-one.
- **Idempotent snapshot persistence survives a process restart, not just
  an in-process retry.** `SnapshotStore::put`'s idempotency key is folded
  into the same durable on-disk index `get`/`list` need anyway (T12), not
  a separate in-memory cache that a restarted orchestrator process would
  lose — a retried upload after a network timeout cannot create a
  duplicate scan record even across a full process restart, verified by a
  dedicated test per `PROGRESS.md`'s T12 section.

### A07:2025 — Authentication Failures

Applies to: the `portal` feature. (Renamed from "Identification and
Authentication Failures" in 2021 to "Authentication Failures" in 2025.)

**Finding: mitigated.** Every request to every route (`adapters/portal/router.rs:70-85`)
except none — `htmx_js` at line 294 still takes `_ctx: AuthContext` as a
parameter, so even the static vendored JS asset requires authentication —
passes through `AuthContext`'s `FromRequestParts` extractor
(`adapters/portal/auth.rs:176-195`) before any handler body runs. Failure
modes are deliberately indistinguishable: a missing header, a
non-`Bearer`-shaped header, and a well-formed-but-unrecognised token all
collapse to the identical `401 Unauthorized` with an empty body — verified
by a real running-server transcript in `PROGRESS.md`'s T27 section ("no
auth and wrong-token are indistinguishable... identical headers, identical
empty body") and by `router::an_unrecognized_token_is_also_unauthorized`.
Token comparison is constant-time (see A04 above). Tokens are resolved
once at process startup, never re-read per request, and a misconfigured
token entry fails the whole portal's startup rather than degrading
silently (A02 above).

No session state, no session fixation surface, no password reset flow, no
account lockout to bypass — this feature has none of those mechanisms by
design (a pre-shared, operator-issued bearer token per caller), which
removes an entire class of authentication-failure CWEs rather than
mitigating them individually.

### A08:2025 — Software or Data Integrity Failures

This is the category the pushed-collector-binary threat (item 2 in the
threat model above) belongs to.

**Finding: the client-side verification mechanism is real, fail-closed,
and tested against a real sshd — but it is not yet exercised end-to-end
against the real collector binary, and that gap is honestly pre-existing,
not something this task can close without expanding scope into T31.**

`SshTransport::push_exec_collect_remove` (`adapters/ssh_transport/mod.rs:144-165`)
pushes a binary, executes it with `--self-hash`, string-compares the
echoed hash against a caller-supplied `expected_hash` computed locally
*before* the push, and returns `TransportError::IntegrityMismatch`
(`mod.rs:177`) on any mismatch — critically, *before* the second exec
(`--emit-json`) ever runs, so a tampered or substituted binary's output is
never decoded or trusted (`run_and_collect`, `mod.rs:168-184`). This is
verified by a real test against a real, locally-spawned sshd:
`remote_artifact_removed_after_forced_mid_exec_failure`
(`adapters/ssh_transport/tests.rs:331-361`) forces a hash mismatch against
a fixture collector script and asserts `TransportError::IntegrityMismatch`
is returned — the fixture's `--emit-json` branch is never reached in that
run, which is the actual "cannot be bypassed" property under test, not
just the returned error variant.

What does *not* exist yet, confirmed by grep (`grep -rn "self-hash\|self_hash\|emit-json\|emit_json"
crates/anne-de-breuil-cli/src crates/anne-de-breuil/src`, excluding the SSH
adapter itself): the real `anne-collector` binary does not implement
`--self-hash`/`--emit-json` at all. `application/fanout.rs:123-130` and
`adapters/collector_factory.rs`'s own module doc both name this
explicitly as `T31`-scoped, unimplemented work — the CLI's local collector
today is a stub returning zero data from every port
(`adapters/collector_factory.rs:31-72`), and `HostScanner` (the trait that
would drive `push_exec_collect_remove` against a real inventory host in
production) has no real implementation yet either
(`application/fanout.rs:123-130`'s own `TODO(T31)`). This means: the
integrity-check *mechanism* is real, fail-closed, and covered by a genuine
test against a live SSH session — but there is no production code path
today that actually invokes it against a real collector binary, because
the collector binary that speaks this protocol doesn't exist yet. This is
a pre-existing, honestly-documented architectural gap from T15/T18, not a
new finding this audit introduces, and closing it is squarely T31's scope
(wiring `HostScanner` to a real collector binary), not a remediation this
task can make without building the T31 feature itself. Recorded here so
whoever picks up T31 knows the integrity check they're wiring into already
exists and is tested — they need to build the collector binary's own side
of the protocol, not invent the verification.

**Remote cleanup guarantee under cancellation — closed a real coverage gap
in this task.** Before this task, three tests covered remote-artifact
cleanup: the happy path
(`push_exec_collect_remove_round_trip`), a forced mid-exec failure
(`remote_artifact_removed_after_forced_mid_exec_failure`), and a bare
`Drop` (a guard falling out of scope normally,
`drop_without_explicit_remove_now_still_cleans_up`). None of them proved
the specific guarantee the module's own doc comment claims matters most —
that `RemoteArtifactGuard`'s `Drop`-spawned cleanup (`adapters/ssh_transport/mod.rs:229-240`)
survives the *calling task itself* being cancelled (`JoinHandle::abort()`)
mid-`exec()`, not just a value going out of scope in an otherwise-normal
control flow. Added `remote_cleanup_guarantee_holds_under_cancellation`
(`adapters/ssh_transport/tests.rs`): spawns
`push_exec_collect_remove` on its own task against a real sshd and a
fixture collector that sleeps before responding to either subcommand,
aborts that task mid-flight, and asserts (a) the join result confirms real
cancellation occurred (`JoinError::is_cancelled()`), and (b) the pushed
artifact is gone from `/tmp` after giving the detached `Drop`-spawned
cleanup task a moment to run. This closes the literal gap the T28 task
file's own test spec (`remote_cleanup_guarantee_holds_under_cancellation`)
names, using this codebase's real, already-proven-fast fixture-sshd
pattern (see `PROGRESS.md`'s T15 section) rather than the task sketch's
`fixtures::containerized_sshd()`, which doesn't exist anywhere in this
project and would be disproportionate new infrastructure (Docker/
testcontainers) this project has never otherwise needed.

### A09:2025 — Security Logging & Alerting Failures

**Finding: this codebase logs less than it could, and that turns out to be
the correct posture here, verified rather than assumed generous.**

The `anne-de-breuil` library crate — the one doing collection, domain
modelling, redaction, and rendering — has **no `tracing` dependency at
all**, confirmed by reading `crates/anne-de-breuil/Cargo.toml` in full:
`tracing` does not appear in `[dependencies]` or `[dev-dependencies]`.
Structurally, this crate cannot emit a log event through `tracing`,
because it never depends on the crate that would let it. Every
`tracing::` call site in this workspace lives in `anne-de-breuil-cli`
(`grep -rn "tracing::\|trace!\|debug!\|info!\|warn!\|error!" crates/ --
include=*.rs`, excluding test files, returns hits only in
`application/scan.rs`), and every one of them logs either a count, an id
(`HostId`/`ScanId`), or the `Display` of a typed error
(`CollectError`/`StoreError`) — never a raw `RawProcess`, `Endpoint`, or
command-line string. `CollectError`'s own variants
(`application/collect.rs:27-49`) were read in full: none of them wraps
`RawProcess.command_line` or any other field that could carry credential
material — `Spawn`/`Parse`/`PolicyUnavailable` wrap subprocess/parse-error
text, `Timeout` wraps a `Duration`, `UnsupportedPlatform` carries nothing.

A new regression test codifies this rather than leaving it as a read-once
audit claim:
`crates/anne-de-breuil-cli/tests/no_secret_in_trace_logs.rs`'s
`no_secret_pattern_reaches_log_output_at_trace_level_across_a_full_scan_path`
installs a real `tracing_subscriber` at `TRACE` (the most permissive
level this binary's subscriber can be configured to emit — see
`observability.rs`), drives a real credential-shaped command line
(`"sqlservr.exe -S PROD -C \"Server=db;User Id=sa;Password=...;\""`)
through the real `collect_endpoints` boundary, folds it into a
`ScanSnapshot`, renders it through `ReportModel::build` and all three
machine formats, and logs the same shape of `info!`/`error!`/`debug!`
calls `application::scan`'s real code paths make around a scan — all
inside the traced scope — then asserts the captured buffer never contains
the literal secret. The credential is genuinely in scope throughout (a
`debug_assert!` in the test itself confirms the fixture actually carries
it), so the passing assertion is meaningful, not vacuous.

This is a deliberately narrow logging surface for a tool that runs
elevated and handles credentials — "log nothing that could carry a
secret, rather than log generously and rely on redaction at every call
site" is a stronger property than trying to redact at the log layer, and
matches this project's stated rule ("never log credentials, private key
material, or SSH passphrases at any level, including trace"). The
trade-off, named honestly: this also means there's very little
operational telemetry for diagnosing *why* a remote scan failed beyond
the typed error's own message — acceptable for this tool's current size
and audience (a small ops team, per `PROGRESS.md`'s T27 rate-limiting
learning), and not a security gap.

### A10:2025 — Mishandling of Exceptional Conditions

New category in the 2025 edition (unwrapped/unhandled exceptions, missing
input validation on error paths, panics that crash a security-relevant
process mid-operation).

**Finding: mitigated by tooling, not just convention, and independently
re-confirmed for this task.** This project's clippy profile (`AGENTS.md`,
`.github/workflows/ci.yml:38-45`) hard-denies `clippy::unwrap_used`,
`clippy::expect_used`, `clippy::panic`, and `clippy::indexing_slicing`
under `-D warnings`, outside `#[cfg(test)]` code (exempted via
`clippy.toml`'s `allow-*-in-tests` settings, confirmed present at the repo
root). This is enforced on every task's own preflight and re-verified as
part of this task's own preflight (see below) — a production code path
that could panic on malformed input, a missing field, or an out-of-bounds
index fails CI, not just a style nit. `main.rs`'s own top-level handler
(`crates/anne-de-breuil-cli/src/main.rs:22-35`) collapses any
`Err(anyhow::Error)` — including one that would have been an unhandled
panic under a naive `main() -> Result<...>` — to exit code 1
(`OperationalError`), never 0 or an unclean process exit; `MainResult`'s
own doc comment states this explicitly.

`unsafe` code — the one place a mishandled exceptional condition could
mean real memory unsafety rather than a clean early return — is confined
to `adapters/` per this project's own rule, confirmed by grep
(`grep -rn "unsafe {" crates/*/src`): every hit is either a Windows WinAPI
FFI call in `adapters/windows_collector/{services,signatures}.rs` (each
wrapped in a narrowly-scoped safe function) or `std::env::set_var`/
`remove_var` calls inside `#[cfg(test)]` blocks (Rust 2024 makes these
`unsafe fn`), never in `domain/` or `application/`.

## API Security Top 10:2023

Scoped to the `portal` feature's HTTP routes (T27) — the only HTTP API
surface this project ships.

### API1:2023 — Broken Object Level Authorization

**Mitigated.** See OWASP A01:2025 above — `AuthorizingRepository`'s
`host_scopes.contains(&host)` check plus the `snapshot.host_id == host`
post-filter on `get_for_host` together prevent both "wrong host in scope"
and "right host claimed, wrong host's data actually returned" BOLA
variants. Every route parameter that names an object (`{host}`, `{scan}`
in `adapters/portal/router.rs:73-77`) passes through this repository, with
no route that reads snapshot data by any other path.

### API2:2023 — Broken Authentication

**Mitigated.** See OWASP A07:2025 above.

### API3:2023 — Broken Object Property Level Authorization

**Not Applicable, verified.** This API has no mass-assignment surface at
all — every route is a `GET` (`adapters/portal/router.rs:72-78`); there is
no endpoint that accepts a JSON/form body and writes fields onto a stored
object, so there is no way for a caller to set an object property it
shouldn't be able to. The one JSON-returning route (`/hosts/{host}/scans/{scan}/download`)
returns a whole, already-authorized `ScanSnapshot` verbatim
(`serde_json::to_vec_pretty`, `adapters/portal/router.rs:249-250`) — no
per-property filtering is needed because there is no property in a
`ScanSnapshot` a caller isn't already authorized to see once the object
itself passed the BOLA check above (a fleet-scoping token sees a whole
host's snapshot or none of it, never a redacted subset of one snapshot's
fields — this API has no notion of field-level sensitivity finer than
"which host").

### API4:2023 — Unrestricted Resource Consumption

**Mitigated.** Rate limiting (see A02:2025 above) bounds request volume
per caller. Response bodies are bounded by what a `ScanSnapshot`/report
actually contains — no endpoint streams an unbounded or caller-controlled
amount of data (`host_detail_fragment`/`host_detail_page` fetch "every
recorded snapshot for a host," documented as an accepted N+1-query cost at
today's expected scale in `adapters/portal/router.rs:200-206`, with a
named future mitigation — `list_metadata_for_host` — if fleet size ever
makes that concerning). No file upload endpoint exists on this surface
at all (ingestion is explicitly out of scope for the `portal` feature per
its own module doc), so the file-size/MIME-type class of resource
exhaustion this category also covers doesn't apply here.

### API5:2023 — Broken Function Level Authorization

**Not Applicable, structurally.** There is no privilege tier above "has a
valid bearer token scoped to some hosts" on this surface — no admin
function, no elevated route, nothing a lower-privileged authenticated
caller could escalate into. Every route requires the identical
`AuthContext` extractor (`adapters/portal/router.rs`); the only
authorization axis this API has is *which hosts*, not *which functions*,
and that axis is BOLA (API1 above), not BFLA.

### API6:2023 — Unrestricted Access to Sensitive Business Flows

**Not Applicable.** This API has no business flow with abuse value beyond
ordinary read access (no purchase, no account creation, no invite/referral
flow, nothing an attacker would want to automate beyond "read data faster
than a legitimate user would") — the entire surface is authenticated,
scoped, rate-limited read access to already-collected scan data.

### API7:2023 — Server Side Request Forgery

**Not Applicable to this API surface specifically** (see OWASP A01:2025
above for the tool-wide SSRF discussion) — no `portal` route accepts a URL
or hostname from a caller and fetches it; every route parameter is a
`HostId`/`ScanId` (both `Uuid`-backed, `axum`'s newtype path-deserializer
rejecting anything that doesn't parse as one — `PROGRESS.md`'s T27
learning on this).

### API8:2023 — Security Misconfiguration

**Mitigated.** See OWASP A02:2025 above (security headers, verified wired;
fail-secure token loading; rate limiting verified wired). One item
specific to this category's usual checklist, verified directly: the
default workspace build excludes `axum`/the whole `portal` feature
entirely — `cargo build -p anne-de-breuil --no-default-features --features
windows-collector,linux-collector` succeeds and `cargo tree` against that
feature set greps clean for `axum`, enforced by a real test
(`adapters::portal::tests::default_build_excludes_axum`, confirmed present
by reading `adapters/portal/mod.rs`) — an operator who never opts into
`portal` never even compiles an HTTP listener into their binary.

### API9:2023 — Improper Inventory Management

**Mitigated.** This is a small, closed API: six routes, all declared in
one place (`adapters/portal/router.rs:70-85`), no versioning surface, no
deprecated/shadow routes (the whole feature is new as of T27). A dedicated
test enumerates every route and asserts each one rejects an unauthenticated
request (`router::every_route_rejects_an_unauthenticated_request`,
iterating a literal list of every URI the router serves) — the kind of
test that would immediately catch a new route added without the
`AuthContext` parameter, which is exactly the "forgotten/undocumented
endpoint" failure mode this category is about.

### API10:2023 — Unsafe Consumption of APIs

**Not Applicable.** This portal consumes no third-party API on a caller's
behalf — it reads from its own local `SnapshotStore` only. The two
external network-facing adapters this project does have (`HttpProber`/
`TlsProber`) aren't reachable through the `portal` API at all; they're
part of the scan pipeline, invoked by the CLI/fan-out orchestrator, not by
an HTTP route.

## CI / supply-chain

`.github/workflows/ci.yml`, read in full, plus `deny.toml`, read in full.

- **Least-privilege CI identity — one real gap, remediated in this task.**
  Before this task, only the `codeql` job declared an explicit
  `permissions:` block; `build-test-lint` and `cargo-deny` had none,
  meaning both ran under the repository's own default `GITHUB_TOKEN`
  scope — which, depending on the repository's own settings, can be
  broader than either job needs (neither ever pushes, comments, or writes
  a package). Added a top-level `permissions: contents: read`
  (`.github/workflows/ci.yml:9-16`), which every job without its own
  override now inherits; `codeql`'s existing job-level override
  (`security-events: write, contents: read`) is unaffected and remains the
  more-privileged exception, scoped to exactly the one extra permission it
  needs. Codified as a regression test,
  `every_job_has_an_explicit_permissions_scope`
  (`crates/anne-de-breuil-cli/tests/ci_workflow_audit.rs`).
- **No `pull_request_target` misuse.** Verified by grep and by a
  regression test (`no_pull_request_target_trigger`) — this workflow only
  ever triggers on `push`/`pull_request` (both scoped to `branches:
  [main]`), never the fork-secrets-exposing `pull_request_target` variant.
- **No `workflow_run` chains.** Verified the same way
  (`no_workflow_run_trigger_chain`) — this is a single, flat workflow with
  three independent jobs, no second workflow acting on a first one's
  output/artifacts.
- **No secrets file checked into the repo.** `git ls-files | grep -iE
  "\.env|secret|credential|\.pem$|id_rsa|\.key$|\.p12|\.pfx"` returns
  nothing. `.gitignore` explicitly excludes `.env`/`.env.*` (keeping
  `.env.example`). No file in this repository needs "strict permissions on
  a local secret file" because no secret file is checked in at all — the
  portal's own tokens are read from environment variables at runtime
  (A02:2025 above), never from a file this repo ships.
- **`cargo-deny` runs with real network access.** See A03:2025 above.

## Secret-leakage regression tests

Two tests added by this task, both exercising real production code paths:

1. `crates/anne-de-breuil-cli/tests/no_secret_in_trace_logs.rs` —
   `no_secret_pattern_reaches_log_output_at_trace_level_across_a_full_scan_path`.
   See A09:2025 above for what it proves and why it's shaped the way it
   is.
2. `crates/anne-de-breuil/src/domain/report_render.rs`'s
   `render_json_and_render_csv_never_leak_a_credential_shaped_command_line`
   — builds a `ScanSnapshot` with a connection-string-shaped credential in
   `Endpoint.command_line`, pushes it through `ReportModel::build` (the
   real redaction boundary) and both `render_json`/`render_csv` (the real
   public rendering entry points a format consumer calls — not a
   re-serialization of the model directly, which
   `report_model.rs`'s own pre-existing
   `command_line_secrets_never_reach_the_serialized_view_model` test
   already covers one layer up), and asserts neither output contains the
   literal secret.

## Collector-integrity and remote-cleanup verification — how this task
## handled it

Per the task's own instruction to use judgment rather than build a
disproportionate containerized-sshd integration harness this project
doesn't otherwise have: T15's existing coverage (a real, locally-spawned
OpenSSH `sshd`, not a mock, not Docker — see `PROGRESS.md`'s T15 section
for why that fixture strategy was chosen and proven fast/reliable) already
satisfied most of this task's real intent for the integrity check. This
task:

- **Reused** the existing `remote_artifact_removed_after_forced_mid_exec_failure`
  test as the collector-binary-integrity-cannot-be-bypassed evidence — it
  already forces a real hash mismatch against a real sshd and proves the
  mismatch is caught before `--emit-json` output is ever trusted.
- **Built one new test**,
  `remote_cleanup_guarantee_holds_under_cancellation`, to close the one
  genuine gap: nothing previously exercised task-cancellation
  (`JoinHandle::abort()`) specifically, as distinct from a guard falling
  out of scope in otherwise-normal control flow. This is a real addition,
  not a restatement — it drives the actual `Drop`-spawned fire-and-forget
  cleanup path the module's own doc comment identifies as the one thing
  only `Drop` can cover, against a live sshd, and confirms both that
  cancellation genuinely occurred (`JoinError::is_cancelled()`) and that
  the artifact was actually removed afterward.
- **Did not** build a containerized-sshd harness (`fixtures::containerized_sshd()`
  from the task file's own illustrative sketch) — this project has no
  Docker/testcontainers infrastructure anywhere else, and the
  locally-spawned-sshd approach already exercises the real SSH protocol
  end to end (real TCP, real key exchange, real host-key verification,
  real SFTP, real exec channels) with none of the added complexity of
  container networking. Building the containerized variant just to match
  the sketch's illustration, rather than to close a real coverage gap,
  would have been disproportionate scope for what this task's exit
  criteria actually require.
- **Documented, rather than silently left unmentioned**, that end-to-end
  verification against the *real* collector binary (as opposed to this
  suite's fixture stand-in script) cannot exist yet, because the real
  collector binary's `--self-hash`/`--emit-json` support is T31-scoped,
  unimplemented work — see A08:2025 above.

## Preflight

`cargo build --workspace --all-features`, `cargo test --workspace
--all-features`, `cargo clippy --workspace --all-targets --all-features`
(full pedantic+nursery+cargo+perf profile, every hard deny from
`AGENTS.md`), `cargo fmt --all -- --check`, `cargo audit`, and `cargo deny
check` (real network access, not `--offline` — see A03:2025 above) all
run as part of this task's own completion; results recorded in
`PROGRESS.md`'s `## T28` section.
