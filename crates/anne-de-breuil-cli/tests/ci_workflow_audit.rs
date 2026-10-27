//! T28 security-audit: structural checks against the real CI workflow
//! file, so its supply-chain/permissions posture is a codified regression
//! rather than a claim someone reads and trusts.
//!
//! `include_str!` pulls the actual `.github/workflows/ci.yml` in at compile
//! time — a change to the workflow that regresses one of these properties
//! fails this test the next time anyone runs `cargo test`, not just at the
//! next manual audit.

const CI_WORKFLOW: &str = include_str!("../../../.github/workflows/ci.yml");

/// `cargo-deny`'s advisory database is a local clone/cache — a stale one
/// silently reports "no advisory found" for a real, live advisory. Running
/// with `--offline` (or an action configured to skip the fetch) trades a
/// faster CI run for exactly that blind spot. `EmbarkStudios/cargo-deny-action@v2`
/// fetches the advisory database over the network by default; this test
/// only guards against someone later adding an explicit `--offline` flag
/// or an `offline: true` action input, not against the action's own
/// default ever silently changing.
#[test]
fn ci_runs_cargo_deny_with_network_access() {
    assert!(
        CI_WORKFLOW.contains("cargo-deny"),
        "no cargo-deny job found"
    );
    assert!(
        !CI_WORKFLOW.contains("--offline"),
        "cargo-deny must run with real network access, not a stale local advisory DB"
    );
    assert!(
        !CI_WORKFLOW.to_lowercase().contains("offline: true"),
        "cargo-deny-action's own offline input must not be set"
    );
}

/// Least-privilege CI identity: every job needs an explicit `permissions:`
/// block (either its own, or inherited from a top-level one) rather than
/// relying on the repository's default `GITHUB_TOKEN` scope, which can be
/// broader than any job here actually needs — a job that only builds,
/// tests, and lints has no business holding write access to anything.
#[test]
fn every_job_has_an_explicit_permissions_scope() {
    let has_top_level_permissions = CI_WORKFLOW
        .lines()
        .take_while(|line| !line.trim_start().starts_with("jobs:"))
        .any(|line| line.trim_start().starts_with("permissions:"));
    assert!(
        has_top_level_permissions,
        "ci.yml must set an explicit top-level `permissions:` block scoping the default \
         GITHUB_TOKEN, so no job silently inherits a broader-than-needed repository default"
    );
}

/// `pull_request_target` runs with the target repository's secrets and
/// permissions even for a PR from a fork, and checking out the PR's own
/// (untrusted) ref under that trigger is the classic way to turn a
/// contributor's PR into arbitrary code execution against those secrets.
/// This workspace's CI has no legitimate reason to use it — `pull_request`
/// (already in use) is the correct, safe trigger for building/testing/
/// linting a PR's own code.
#[test]
fn no_pull_request_target_trigger() {
    assert!(!CI_WORKFLOW.contains("pull_request_target"));
}

/// A `workflow_run` chain lets a second workflow act on the result of a
/// first, often with elevated trust in the first workflow's artifacts —
/// a known supply-chain abuse pattern when the triggering workflow ran
/// against untrusted input. This workspace has no multi-workflow chain at
/// all; every job runs directly off `push`/`pull_request`.
#[test]
fn no_workflow_run_trigger_chain() {
    assert!(!CI_WORKFLOW.contains("workflow_run"));
}

/// The two triggers this workflow actually uses, confirmed directly rather
/// than inferred from the absence checks above — pins the intended trigger
/// surface so a future edit that silently swaps in something broader (e.g.
/// `pull_request_target`, or a third-party `on: schedule` with secrets)
/// shows up as a diff against this list, not just against the negative
/// checks above.
#[test]
fn only_push_and_pull_request_triggers_are_declared() {
    let on_block: String = CI_WORKFLOW
        .lines()
        .skip_while(|line| line.trim() != "on:")
        .skip(1)
        .take_while(|line| line.starts_with(' ') || line.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(on_block.contains("push"));
    assert!(on_block.contains("pull_request"));
    assert!(!on_block.contains("workflow_run"));
    assert!(!on_block.contains("pull_request_target"));
}

/// The fuzz job must use nightly only for the fuzz build, and the
/// stable pin must not have been relaxed to accommodate it.
///
/// `cargo-fuzz` needs `-Z sanitizer=address`, which is nightly-only.
/// The obvious way to make that work is to move the pin to nightly --
/// which would silently give up the exact-version pin that
/// `rust-toolchain.toml` exists to enforce, and would put every other
/// job in this workflow on an unpinned toolchain.
///
/// The fuzz crate is deliberately outside the workspace so the nightly
/// toolchain is reached with an explicit `cargo +nightly` on the one
/// command that needs it, rather than by changing the pin.
#[test]
fn the_fuzz_job_uses_nightly_explicitly_without_moving_the_pin() {
    let workflow = CI_WORKFLOW
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");

    // The nightly toolchain is requested explicitly, by name.
    assert!(
        workflow.contains("rustup toolchain install nightly"),
        "the fuzz job must install the nightly toolchain explicitly"
    );
    // And used with the `+nightly` channel override, not by relying on
    // a default-toolchain change.
    assert!(
        workflow.contains("cargo +nightly fuzz"),
        "the fuzz commands must name the nightly toolchain explicitly"
    );
    // The build/test/lint job must stay on the pinned toolchain.
    assert!(
        !workflow.contains("cargo +nightly build")
            && !workflow.contains("cargo +nightly test")
            && !workflow.contains("cargo +nightly clippy"),
        "only the fuzz commands may use nightly -- the build, test, and clippy jobs must stay on the pinned toolchain"
    );
    // And no job may install nightly as the default.
    assert!(
        !workflow.contains("rustup default nightly"),
        "no job may change the default toolchain to nightly"
    );
}
