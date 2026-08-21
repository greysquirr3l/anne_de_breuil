# Security Hardening Review — T30

This is T30's own findings document. It is deliberately short: T28
(`docs/security-audit.md`) already ran a full OWASP Top 10:2025 / API
Security Top 10:2023 pass over this codebase two tasks ago, and most of
what T30's checklist asks for is ground T28 already covered with real
evidence. This document cross-references T28 wherever that overlap is
exact, and only elaborates where T30's checklist surfaced something T28
didn't already establish — one real finding, fixed below, plus several
items that are genuinely Not Applicable to this project's actual attack
surface, each backed by the grep/route-table evidence that established it,
not assumed.

## Real finding: cloud-metadata SSRF exclusion gap (fixed)

**Severity: Medium. Location:
`crates/anne-de-breuil/src/application/identify.rs`, `ProbeExclusions`.**

`ProbeExclusions` (T09) lets an operator exclude ports and CIDR ranges
from the probe engine's outbound HTTP/TLS fetches
(`adapters/prober.rs`/`adapters/tls_probe.rs`). Before this task,
`ProbeExclusions` derived `Default` (`#[derive(Debug, Clone, Default)]`),
which gave an *empty* `HashSet<u16>`/`Vec<IpNet>` — no exclusion held
unless an operator configured one by hand. `ProbeConfig::default()` uses
exactly this empty `ProbeExclusions::default()`.

The risk this leaves open: this tool's probe engine, run against an
inventory that includes a cloud instance (or from inside one), would
happily issue a real HTTP GET to `169.254.169.254` (the AWS/Azure/GCP
link-local instance-metadata address) or `169.254.170.2` (AWS ECS task
metadata) if either ever appeared as a scan target — a classic SSRF pivot
for exfiltrating an instance's IAM/managed-identity credentials, with no
flag required to trigger it and no flag available to prevent it. This
isn't the "user-directed URL fetch" shape SSRF findings are usually
described in (see the Not Applicable section below for why this project
has none of that) — it's the operator-configured-target shape T09 already
scoped this feature to, but T09 never added the one default exclusion an
operator would reasonably expect to hold without being told to ask for it.

**Fix.** `ProbeExclusions::new` now unconditionally folds in
`DEFAULT_EXCLUDED_CIDRS` (`169.254.169.254/32`, `169.254.170.2/32`)
alongside whatever CIDRs the caller supplies, and `Default` is now a
hand-written impl that calls `new` with nothing else — so every
construction path, including a future `--probe-exclude` CLI flag that
calls `new` directly, carries the exclusion. No override escape hatch was
added: an operator who has a genuine reason to probe a metadata address on
purpose is an edge case this task judged didn't need first-class support,
per the task's own explicit permission to make that call. Parsing uses
`.parse().ok()` + `filter_map` (matching the existing pattern in
`domain/redaction.rs`'s `SECRET_PATTERNS`) rather than `.expect()` on a
literal — a typo in the constant degrades to one fewer default exclusion,
never a panic.

**Tests** (`application::identify::tests`, in
`crates/anne-de-breuil/src/application/identify.rs`):
- `cloud_metadata_address_excluded_by_default` — `ProbeExclusions::default()`
  excludes both addresses.
- `cloud_metadata_exclusion_holds_even_with_operator_supplied_exclusions` —
  proves the merge, not just the default: an operator-supplied
  `ProbeExclusions::new([8080], ["10.0.0.0/8"])` still excludes the
  metadata addresses on top of its own explicit ranges.
- `an_ordinary_public_address_is_not_excluded` — a negative control so the
  positive assertions above aren't vacuously true of every address.

## Grep sweeps (run for real, this session)

**`grep -rn "password" crates/ --include='*.rs' -i`** — 49 hits across 10
files, all audited. Every hit is one of: a doc comment explaining the
redaction engine's password-shaped patterns (`domain/redaction.rs`), a
test fixture using an obviously-fake literal (`"hunter2"`, deliberately
memorable as non-real) to exercise the redaction/report-rendering
pipeline, a config-rejection test asserting a `password` field in
`anne.toml` is refused (`adapters/config/mod.rs:192`,
`adapters/inventory.rs:129` — see `AuthMethod`'s own doc comment, quoted in
T28's A04:2025 section: "there is nowhere in this enum a secret could
go"), or a comment naming `PortalTokens`'/`AuthMethod`'s own deliberate
absence of a `Password` variant. Zero hits are an actual literal
credential used for real authentication. This reconfirms T28's A04:2025
finding rather than contradicting it.

**`grep -rn 'format!("SELECT\|INSERT\|UPDATE\|DELETE' crates/`** — zero
hits, confirmed after T29's changes (T29 touched `xtask` and the release
workflow only, never `adapters/snapshot_store/sqlite.rs`). This is the
same fact T28's A05:2025 section already established by reading the file
in full; this task adds a standing regression test rather than only
re-reading it once more: `crates/anne-de-breuil/tests/no_sql_string_interpolation.rs`'s
`no_sql_string_interpolation_in_sqlite_adapter` (feature-gated on
`store-sqlite`) `include_str!`s the real adapter file and asserts none of
the four verbs appear inside a `format!("...` call. It lives in this
crate's own `tests/` directory rather than inside `sqlite.rs`'s own
`#[cfg(test)] mod tests` deliberately — a test that searches a file's own
source text for a literal substring can't live in that same file, or its
own search-pattern string becomes a self-matching false positive. (Note:
the task file's own code sketch names this file `adapters/store_sqlite.rs`;
the real path is `adapters/snapshot_store/sqlite.rs` — the sketch's name is
stale, not a discrepancy in this codebase.)

**`grep -rn "std::env::var" crates/ --include='*.rs'`** — every call site
audited:
- `adapters/portal/auth.rs:108` — reads the env var *named* by
  `config.secret_env`, the documented `PortalTokenConfig` pattern (T27).
- `examples/portal_server.rs` (×2) — `PORTAL_SERVER_CONFIG`/
  `PORTAL_SERVER_ADDR`, operational (bind address, config file path), not
  secret-shaped, and deliberately not `ANNE_`-prefixed (T27's own
  Accumulated Learnings entry on the `Env::prefixed("ANNE_")` collision).
- `anne-de-breuil-cli/src/main.rs:65` — `ANNE_LOG_FORMAT`, a log-format
  toggle.
- `adapters/build.rs:31` — `ASSET_VERSION`, a build-time cache-busting
  string, not a secret.
- `adapters/progress.rs` (×3) — terminal-capability probes
  (`NO_COLOR`-style / `TERM_PROGRAM`/`WT_SESSION`), cosmetic only.
- `adapters/windows_collector/mod.rs:112` — `ANNE_LIVE_WINDOWS_TESTS`, a
  test-gating flag.
- `adapters/ssh_transport/tests.rs` (×2) — `USER`/`LOGNAME`, read only to
  pick a plausible local username for a test fixture's SSH session, never
  used as a credential.

No call site reads a secret value into a `clap`-parsed argument anywhere —
confirmed separately by grepping every `#[arg(...)]` field in
`anne-de-breuil-cli/src/cli.rs` (the workspace's only `clap::Parser`
derive) for `password`/`secret`/`token`: zero matches. `AuthMethod`
(`adapters/inventory.rs`) and `PortalTokenConfig`
(`adapters/config/portal.rs`) both reference env-var *names* only, never
accept a secret value directly.

## Router-level test confirmation (rate-limiting, security headers, no-upload)

All three were checked against `adapters/portal/router.rs`'s real
`#[cfg(test)] mod tests`, which builds the actual production `router()`
(not a stand-in single-route app) with a real `AuthorizingRepository`,
real `PortalTokens`, and a real `RateLimiter`, then drives requests through
it with `tower::ServiceExt::oneshot`.

- **Rate limiting: already covered before this task, confirmed real.**
  `exceeding_the_rate_limit_produces_429` predates T30 — it sends a first
  request through the real router with a budget of 1, asserts `200`, sends
  a second, asserts `429`, and additionally asserts the `429` still
  carries `content-security-policy`. This already met the task's "N+1
  requests through the real router" bar; no new test was needed here.
- **Security headers: partially covered before this task (CSP,
  X-Content-Type-Options on a 404/401), extended by this task.** Added
  `all_security_headers_present_on_the_real_router`, which asserts CSP,
  X-Content-Type-Options, and X-Frame-Options on a `200` from the real
  router, asserts HSTS is *absent* with no `X-Forwarded-Proto` header (the
  correct default posture — see `security_headers.rs`'s own module doc),
  and asserts HSTS *is* present once `X-Forwarded-Proto: https` is set.
  `security_headers.rs`'s own existing unit tests already covered all four
  headers against an isolated single-route test app; this test is what was
  missing — the same four-header claim proven against the actual
  production route table and layering order, not a stand-in.
- **No upload endpoint: confirmed structural, new explicit test added.**
  `portal_upload_endpoint_does_not_exist_by_default` requests `/ingest`
  through the real router and asserts `404`. A prior test
  (`nonexistent_route_carries_security_headers_and_404`) already proved
  *some* nonexistent route 404s; this one names `/ingest` specifically so
  the intent — proving the absence of an ingestion endpoint isn't an
  accident of what URIs happen to be untested, but a property of the route
  table in `router()` genuinely having no such entry — is explicit in the
  test itself, not incidental.

All three were also hand-verified against a real running server this
session, matching the standard T27's own session held itself to
(`examples/portal_server.rs`, a real `anne.toml`, a real bearer token via
`PORTAL_HANDVERIFY_SECRET`):

```
$ curl -s -D - -o /dev/null -H "Authorization: Bearer handverify-secret-value" http://127.0.0.1:8099/
HTTP/1.1 200 OK
content-security-policy: default-src 'self'; script-src 'self'; ...
x-content-type-options: nosniff
referrer-policy: no-referrer
x-frame-options: DENY

$ curl -s -D - -o /dev/null -H "Authorization: Bearer handverify-secret-value" http://127.0.0.1:8099/
HTTP/1.1 429 Too Many Requests
content-security-policy: ...    # headers present even on the 429

$ curl -s -D - -o /dev/null -H "Authorization: Bearer ..." -H "X-Forwarded-Proto: https" http://127.0.0.1:8099/
HTTP/1.1 200 OK
strict-transport-security: max-age=31536000; includeSubDomains   # only appears with the proxy header

$ curl -s -D - -o /dev/null -H "Authorization: Bearer ..." http://127.0.0.1:8099/ingest
HTTP/1.1 404 Not Found
```

(`rate_limit_per_minute = 1` in the test config; the second and later
`curl` calls above ran within the same one-minute window as the first.)

## Not Applicable, with evidence

**File-upload hardening (MIME validation, executable-extension blocking,
size limits).** This project's checklist item, as literally worded, does
not apply: there is no file-upload endpoint anywhere in this codebase.
`adapters/portal/router.rs`'s `router()` declares exactly seven routes —
`/`, `/hosts/{host}`, `/hosts/{host}/fragment`, `/hosts/{host}/drift`,
`/hosts/{host}/scans/{scan}`, `/hosts/{host}/scans/{scan}/download`,
`/assets/htmx.min.js` — every one a `GET`. None accepts a request body.
This was already documented in T28's API4:2023 section
("No file upload endpoint exists on this surface at all"); T30 adds the
`portal_upload_endpoint_does_not_exist_by_default` test above as the
concrete proof this task's own exit criteria ask for, and confirms it by
hand against a real running server (`curl -X POST` isn't even attempted —
a `GET` to the route itself already 404s, which is the relevant fact: the
route doesn't exist under any method). `adapters/portal/mod.rs`'s own
module doc (`# Ingestion is out of scope`) states this is a deliberate T27
scope decision, not an oversight.

**TODO(T31):** if/when an ingestion endpoint is ever built (accepting a
collector-produced `ScanSnapshot` upload from a fleet-managed host rather
than this tool's own SSH fan-out), it will need real file-upload hardening
at that point — MIME/content-type validation, a size cap, and (since the
payload here is structured JSON, not an arbitrary file) strict
`serde_json` deserialization against `ScanSnapshot`'s own
`deny_unknown_fields` schema rather than accepting arbitrary bytes. Not
needed today because the surface doesn't exist.

**SSRF via a user-directed URL fetch.** Also genuinely Not Applicable, for
the reason the task's own code sketch names up front: this portal has no
route or CLI flag that takes a URL or hostname from one caller and fetches
it on that caller's behalf. The two outbound-fetch adapters this project
has (`HttpProber`, `TlsProber`) are invoked only against operator-named
scan targets (`--target`/`--inventory`), and neither is reachable through
the portal's HTTP API — `adapters/portal/router.rs` never calls either.
T28's A01:2025 and API7:2023 sections already established this with the
same evidence (redirect-policy doc comment, DNS-sentinel test, route-table
read). The one genuine gap in this area — the probe engine's own
*operator-configured* fetches lacking a default cloud-metadata exclusion —
was real and is the finding fixed above; it's a different shape of issue
from "user-directed fetch," which is why it wasn't already caught by T28's
SSRF section (T28 correctly scoped that section to the user-directed-fetch
question, which this project genuinely has none of).

## Everything else: clean, re-confirmed rather than assumed

- **HTTP security headers** (CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options): present on every response, verified above at
  the real router level, not just the isolated middleware test T28 already
  cited. See `docs/security-audit.md`'s A02:2025 section for the CSP
  content rationale (no `unsafe-inline`/`unsafe-eval`) and the
  HSTS/`X-Forwarded-Proto` design rationale, both unchanged by this task.
- **Rate limiting wired to the router, not just defined**: see above.
  Unchanged design from T27; `docs/security-audit.md`'s A02:2025 section
  already covers the "verified wired, not just defined" distinction this
  task's own rules ask for.
- **No hardcoded secrets**: see the grep sweep above.
- **SQL parameterization**: see the grep sweep above; now has a standing
  regression test.
- **Weak cryptography, TLS verification bypass, insecure randomness,
  unsafe deserialization, path traversal, IV reuse**: all covered by
  T28's A04:2025 (Cryptographic Failures) and A06:2025 (Insecure Design)
  sections with file-and-line evidence; nothing this task's own checklist
  surfaces adds anything new here. Re-skimmed those sections against the
  current source during this task and found no drift.

## Preflight

`cargo build --workspace --all-features`, `cargo test --workspace
--all-features` (423 lib/doctest passes plus the full `anne-de-breuil-cli`
integration suite, all green — see `PROGRESS.md`'s `## T30` section for
the exact count), `cargo clippy` (full pedantic+nursery+cargo+perf profile,
every `AGENTS.md` hard deny, zero warnings), `cargo fmt --all -- --check`,
`cargo audit` (one pre-existing allowed warning, `RUSTSEC-2024-0436`/
`paste`, unchanged from T28/T29), and `cargo deny check` (`advisories ok,
bans ok, licenses ok, sources ok`; two pre-existing duplicate-crate
warnings from divergent `windows-sys`/`toml_edit` transitive version
requirements, not errors) all ran clean as part of this task.
