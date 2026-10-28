# Contributing

## Before you start

This project has two maintainers with write access, and the workflow
below is shaped around that rather than around a normal team process.
Two things follow from it, and both are worth reading before you
open a pull request.

- **Open a pull request rather than pushing to `main`.** `main` is
  protected by an OSSF branch-protection ruleset
  (`rulesets/25918976`); direct pushes are rejected.
- **Review requires two different accounts.** The ruleset requires an
  approving review that satisfies three conditions at once: at least
  one approval, from a **code owner**, and from **someone other than
  the last person to push**. `.github/CODEOWNERS` names both
  `@greysquirr3l` and `@sosh-ncampbell` on every rule, so either
  account can supply the code-owner approval — but the approving
  account must not be the one that pushed. In practice: one account
  pushes, the other approves and merges. See
  [Getting a PR merged](#getting-a-pr-merged) below.

  Both owners must appear on *every* `CODEOWNERS` rule, not only the
  default `/*` rule. GitHub resolves a path's owners from the last
  matching pattern and uses only that pattern's owners, so a specific
  rule naming just one owner would drop the other from those paths and
  re-create the deadlock for changes to them.

## Build, test, lint

```bash
cargo build --workspace --all-features
cargo test  --workspace --all-features
cargo l     # alias for the full clippy profile, see .cargo/config.toml
cargo deny check
cargo audit
```

`cargo l` is the project's clippy alias, configured in
`.cargo/config.toml`: `clippy::all`, `pedantic`, `nursery`, `cargo` and
`perf` enabled, a small allow-list for lints that are too noisy to be
useful project-wide, and a deny-list (`unwrap_used`, `expect_used`,
`panic`, `indexing_slicing`, `cast_ptr_alignment`, `suspicious`) that
turns "never `.unwrap()`/`.expect()`/panicking index outside tests"
into a mechanically enforced rule instead of a review convention. The
README's "Build, test, lint" section explains why `-D warnings` is
injected via `CARGO_BUILD_WARNINGS` rather than through `RUSTFLAGS`.

`just ci` runs the same build/test/clippy sequence CI does.

The toolchain is pinned exactly (`rust-toolchain.toml`, currently
1.99.1) — do not float it to a bare minor version; see the README's
"Toolchain" section for why.

The ruleset also requires the `cargo-deny` and `CodeQL` status checks,
so `cargo deny check` and `cargo audit` must be clean locally too.
`paste` is allowlisted in `deny.toml` as an unmaintained notice, not a
vulnerability; `cargo audit` reports it as one allowed warning.

## Commit and PR conventions

- Conventional commits: `feat:`, `fix:`, `refactor:`, `test:`,
  `docs:`.
- Commit messages explain *why* — what the change does is visible in
  the diff. Say what was wrong, what the fix is, and what was
  verified.
- Keep the commit history linear (`required_linear_history` is on).
  Rebase rather than merge.
- Commits must be signed (`required_signatures` is on).

## Getting a PR merged

The `require_last_push_approval` rule is the part that catches people
out, because the failure message does not say what it means:

> New changes require approval from someone other than `<name>`
> because they were the last pusher.

Two things have to line up.

**1. The push must authenticate as a different account than the
approver.** `git push` takes its credential from the configured
helpers, and the *first* helper that answers wins. With a global
`credential.helper` of `osxkeychain`, the push uses whichever token
the keychain happens to hold for `github.com` — not the account
`gh auth switch` last selected, and not the account the commit is
attributed to. Point this repository's credential at `gh`, so the
active `gh` account is the one that pushes:

```bash
git config --local credential.https://github.com.helper \
  '!/opt/homebrew/bin/gh auth git-credential'
```

Then select the account that will do the pushing before you push:

```bash
gh auth switch --hostname github.com --user <pusher>
```

Check it took effect before pushing — `gh auth status` prints
`Active account: true` against the account you want. A push that
reuses an identical commit is a no-op and is not re-attributed, so if
the wrong account pushed first, amend the commit (a new SHA) and
push again as the right one.

**2. The head commit must be authored and committed by the pushing
account**, and signed with a key that account has registered with
GitHub, so the commit attributes to the pusher rather than to the
approver.

Then author, sign, and push as the non-approver account and let the
code owner approve. If the review registers as approved but the
review decision stays `REVIEW_REQUIRED`, it is one of the two above
that is not actually in effect — check the recorded pusher, not the
commit's author.

**3. Order matters: push everything, then approve, then merge.** The
ruleset also sets `dismiss_stale_reviews_on_push`, so a push that
lands *after* an approval discards that approval. Get the branch to
its final state — all commits pushed, CI green — and only then
request the review. Approving early and then pushing again means
starting the approval cycle over, which is easy to mistake for the
ruleset rejecting a valid approval.

## Security

Report vulnerabilities privately through GitHub's private vulnerability
reporting, not as a public issue. See
[`SECURITY.md`](SECURITY.md).
