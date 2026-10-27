//! Structural checks against the real `publish-crate.yml` workflow file.
//!
//! Same pattern as `release_workflow_audit.rs` (T29) and
//! `ci_workflow_audit.rs` (T28): `include_str!` pulls the actual
//! `.github/workflows/publish-crate.yml` in at compile time, so a change
//! that regresses one of these properties fails `cargo test`, not just a
//! manual read of the YAML.
//!
//! The properties checked here are the ones whose failure mode is
//! silent and expensive:
//!
//!   * a `cargo publish` that runs on every push to `main` would
//!     attempt to upload a version that is already published, and
//!     crates.io's error for that looks like a build failure;
//!   * a publish triggered off a `workflow_run` that checks out
//!     `${{ github.event.workflow_run.head_sha }}` is Scorecard's
//!     "untrusted code checkout" pattern -- the pwn-request shape, where
//!     a privileged workflow builds attacker-influenced code;
//!   * a workflow that publishes without a dry-run verification step
//!     finds out about a packaging regression at tag time, when there
//!     is nothing left to fix it;
//!   * a publish step that runs without a token guard fails the whole
//!     release pipeline on a repository that has not claimed the crate
//!     names on crates.io yet.

const PUBLISH_WORKFLOW: &str = include_str!("../../../.github/workflows/publish-crate.yml");

/// The publish job must not run on every push to `main`.
///
/// `cargo publish` is not idempotent: publishing a version that already
/// exists on crates.io fails with "crate version `X` already exists",
/// which reads like a build break. The publish has to be gated on the
/// tagging workflow having actually created a new tag.
#[test]
fn publish_only_runs_for_a_new_tag() {
    let workflow = without_comments(PUBLISH_WORKFLOW);
    let publish_job = job_body(&workflow, "publish");

    assert!(
        publish_job.contains("github.event_name == 'workflow_run'"),
        "the publish job must be gated on the tagging workflow finishing, not on any push"
    );
    assert!(
        publish_job.contains("github.event.workflow_run.conclusion == 'success'"),
        "the publish job must only run when the tagging workflow succeeded"
    );
    assert!(
        !publish_job.contains("on: push"),
        "the publish job must not trigger off a raw push event"
    );
}

/// Scorecard's Dangerous-Workflow check flags any `actions/checkout`
/// whose `ref` derives from `github.event.workflow_run` as an
/// "untrusted code checkout" -- the pwn-request pattern.
///
/// The tag is read from `auto-tag.yml`'s artifact and used as the
/// checkout ref, so the checked-out commit is the one the tagging
/// workflow published, not an attacker-supplied SHA.
#[test]
fn publish_does_not_check_out_the_triggering_workflow_run_commit() {
    let workflow = without_comments(PUBLISH_WORKFLOW);

    assert!(
        !workflow.contains("github.event.workflow_run.head_sha"),
        "publish-crate.yml must not check out the triggering workflow_run's commit -- that is the untrusted-code-checkout pattern"
    );
    assert!(
        workflow.contains("ref: ${{ steps.tag.outputs.tag }}"),
        "publish-crate.yml must check out the tag resolved from the tagging workflow's artifact"
    );
}

/// The tag comes from the artifact, exactly as `release.yml` does it.
///
/// A `workflow_run` event carries no access to the triggering
/// workflow's job outputs, so the artifact is the only channel. The
/// literal `none` is the "no new tag" signal, and it has to be handled
/// explicitly -- an empty tag must not reach `cargo publish`.
#[test]
fn publish_reads_the_tag_from_the_artifact_and_handles_the_no_tag_case() {
    let workflow = without_comments(PUBLISH_WORKFLOW);
    let publish_job = job_body(&workflow, "publish");

    assert!(
        publish_job.contains("actions/download-artifact"),
        "publish-crate.yml must read the tag from the tagging workflow's artifact"
    );
    assert!(
        publish_job.contains("github.event.workflow_run.id"),
        "the artifact must be downloaded from the triggering workflow's run"
    );
    assert!(
        publish_job.contains("release-tag"),
        "publish-crate.yml must read the same `release-tag` artifact auto-tag.yml writes"
    );
    assert!(
        publish_job.contains("\"none\""),
        "publish-crate.yml must handle the `none` signal that means no new tag was created"
    );
}

/// A dry-run verification must exist, and it must run on pull
/// requests.
///
/// Without it, a packaging regression -- a file missing from the
/// published crate, a dependency that will not resolve, a metadata
/// field crates.io rejects -- is discovered at tag time, when the
/// release is already cut and there is nothing left to fix it.
#[test]
fn packaging_is_verified_by_a_dry_run_before_any_publish() {
    let workflow = without_comments(PUBLISH_WORKFLOW);

    assert!(
        workflow.contains("pull_request"),
        "publish-crate.yml must run on pull requests so a packaging regression fails the PR"
    );
    assert!(
        workflow.contains("cargo publish -p anne-de-breuil --dry-run"),
        "the library crate must be dry-run published"
    );
    assert!(
        workflow.contains("cargo publish -p anne-de-breuil-cli --dry-run"),
        "the CLI crate must be dry-run published"
    );
}

/// The CLI crate's dependency on the library resolves against the
/// crates.io index, so the library has to be published first.
///
/// The dry run for the CLI crate only works if the library's version
/// resolves -- locally that means patching the dependency to the path.
/// Without that patch, `cargo publish --dry-run` for the CLI crate
/// fails with "no matching package named `anne-de-breuil` found", and
/// the verification job would be red on every run.
#[test]
fn cli_dry_run_patches_the_library_dependency_to_the_local_path() {
    let workflow = without_comments(PUBLISH_WORKFLOW);

    assert!(
        workflow.contains("patch.crates-io.anne-de-breuil.path"),
        "the CLI crate's dry run must patch the library dependency to the local path, or it cannot resolve"
    );
}

/// The publish step must be guarded on the registry token existing.
///
/// A repository that has not claimed the crate names on crates.io yet
/// has no token. Without the guard, every release would fail at the
/// publish step -- turning "not published to crates.io yet" into a
/// broken release pipeline.
#[test]
fn publish_is_guarded_on_the_registry_token_being_configured() {
    let workflow = without_comments(PUBLISH_WORKFLOW);
    let publish_job = job_body(&workflow, "publish");

    assert!(
        publish_job.contains("secrets.CARGO_REGISTRY_TOKEN"),
        "the publish job must read the registry token from the repository secrets"
    );
    assert!(
        publish_job.contains("env.CARGO_REGISTRY_TOKEN != ''"),
        "the publish steps must be guarded on the token being present"
    );
    assert!(
        publish_job.contains("env.CARGO_REGISTRY_TOKEN == ''"),
        "there must be a path that reports cleanly when no token is configured"
    );
}

/// The token must be readable by a step-level `if:`.
///
/// `secrets` is not populated in a step-level `if:` expression, so a
/// guard written as `if: ${{ secrets.CARGO_REGISTRY_TOKEN != '' }}`
/// silently evaluates false and the publish never runs -- a failure
/// mode that looks like "the publish is broken" rather than "the guard
/// does not work". The token has to be exposed as a job-level `env:`
/// for the step guard to read it.
#[test]
fn the_token_is_exposed_as_a_job_level_env_so_step_guards_can_read_it() {
    let workflow = without_comments(PUBLISH_WORKFLOW);
    let publish_job = job_body(&workflow, "publish");

    assert!(
        publish_job.contains("env:\n      CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}"),
        "the token must be a job-level env: so a step-level if: can test it"
    );
    assert!(
        !publish_job.contains("if: ${{ secrets.CARGO_REGISTRY_TOKEN"),
        "a step-level if: cannot read the secrets context -- it would silently never match"
    );
}

/// The publish job must be able to read the artifact it needs.
///
/// A workflow-level `permissions:` block zeroes every scope it does not
/// name, so `actions: read` has to be re-granted on the job that
/// downloads the artifact.
#[test]
fn publish_job_grants_actions_read_for_the_artifact_download() {
    let workflow = without_comments(PUBLISH_WORKFLOW);
    let publish_job = job_body(&workflow, "publish");

    assert!(
        publish_job.contains("actions: read"),
        "the publish job must grant actions: read -- downloading an artifact from another workflow's run needs it"
    );
}

/// The workflow must not hand itself write access to the repository.
///
/// It publishes to crates.io, not to the repository. The registry token
/// is a secret, not a GitHub permission.
#[test]
fn publish_workflow_keeps_read_only_repository_permissions() {
    let workflow = without_comments(PUBLISH_WORKFLOW);

    assert!(
        !workflow.contains("contents: write"),
        "publish-crate.yml never writes to the repository -- it only publishes to crates.io"
    );
    assert!(
        workflow.contains("permissions:\n  contents: read"),
        "the workflow must declare read-only repository permissions explicitly"
    );
}

/// The workflow file's own `on:` block must not be a raw tag push.
///
/// A tag pushed with the default `GITHUB_TOKEN` never fires another
/// workflow's `on: push: tags` -- GitHub suppresses that specifically to
/// stop one workflow's automated push from recursively triggering
/// others. The same `workflow_run` shape `release.yml` uses is the only
/// thing that actually fires.
#[test]
fn publish_workflow_uses_workflow_run_not_a_tag_push() {
    let workflow = without_comments(PUBLISH_WORKFLOW);

    assert!(
        workflow.contains("workflow_run:"),
        "publish-crate.yml must trigger off the tagging workflow's completion"
    );
    assert!(
        !workflow.contains("tags: ["),
        "a plain `on: push: tags` trigger will never fire for a tag pushed by GITHUB_TOKEN"
    );
}

/// The workflow file must not be self-contradictory about what it
/// publishes.
///
/// The library crate and the CLI crate are separate crates.io entries
/// with separate publish steps, and the CLI's dependency on the library
/// means the order matters. If both steps were removed the workflow
/// would still pass every other check while publishing nothing.
#[test]
fn both_crates_are_published_in_dependency_order() {
    let workflow = without_comments(PUBLISH_WORKFLOW);
    let publish_job = job_body(&workflow, "publish");

    let library = publish_job.find("cargo publish -p anne-de-breuil\n");
    let cli = publish_job.find("cargo publish -p anne-de-breuil-cli;");

    assert!(library.is_some(), "the library crate must be published");
    assert!(cli.is_some(), "the CLI crate must be published");
    assert!(
        library < cli,
        "the library must be published before the CLI -- the CLI's dependency on it resolves against the crates.io index"
    );
}

/// The real publish must not use `--allow-dirty`.
///
/// The checkout is a clean tag, so the working tree should be clean. If
/// it is not, the publish has to fail loudly rather than upload a crate
/// whose contents differ from what was reviewed and tested. The dry
/// run in the `verify` job may use it -- that job runs against a
/// working tree that is not the thing being published.
#[test]
fn the_real_publish_does_not_allow_a_dirty_tree() {
    let workflow = without_comments(PUBLISH_WORKFLOW);
    let publish_job = job_body(&workflow, "publish");

    assert!(
        !publish_job.contains("--allow-dirty"),
        "the publish job must not use --allow-dirty -- a dirty tree has to fail the publish, not be published anyway"
    );
}

/// The `publish` job's YAML is the part most likely to be edited by
/// hand, and the edits that break it are the ones that only fail at
/// release time. These are the load-bearing structural facts, checked
/// against the real file.
#[test]
fn the_workflow_file_is_valid_yaml_with_the_expected_shape() {
    // A deliberately shallow check: the point is not to re-implement a
    // YAML parser but to catch a file that has been edited into
    // something structurally broken. `serde_yaml` is not a dependency
    // of the CLI crate, and adding one to assert on a workflow file
    // would be a heavier change than the problem warrants.
    assert!(
        PUBLISH_WORKFLOW.contains("\njobs:\n"),
        "the workflow must have a top-level jobs: block"
    );
    assert!(
        PUBLISH_WORKFLOW.contains("\n  verify:\n"),
        "the workflow must have a `verify` job"
    );
    assert!(
        PUBLISH_WORKFLOW.contains("\n  publish:\n"),
        "the workflow must have a `publish` job"
    );
}

/// The `verify` job must not publish anything.
///
/// It runs on every pull request, and a publish in a pull-request
/// context would upload whatever the PR's code says the crate is.
#[test]
fn the_verify_job_never_publishes() {
    let workflow = without_comments(PUBLISH_WORKFLOW);
    let verify_job = job_body(&workflow, "verify");

    assert!(
        verify_job.contains("--dry-run"),
        "the verify job must use --dry-run"
    );
    // Every `cargo publish` in the verify job must be a dry run. The
    // check is per-line because the CLI crate's command is a
    // backslash continuation across two lines.
    for line in verify_job.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("cargo publish") {
            assert!(
                trimmed.contains("--dry-run"),
                "the verify job's publish step must be a dry run: {trimmed}"
            );
        }
    }
}

/// Strips full-line YAML comments so a string check does not match
/// prose in a comment.
fn without_comments(workflow: &str) -> String {
    workflow
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The body of one job, from its `  <id>:` line to the next
/// two-space-indent `:` line.
///
/// No YAML parsing: a workflow's `jobs:` block is the only place where
/// a line at exactly two-space indent ends with `:`, so that shape is
/// a reliable job boundary.
fn job_body(workflow: &str, job_id: &str) -> String {
    let mut out = Vec::new();
    let mut inside = false;
    for line in workflow.lines() {
        let is_job_header = line.starts_with(&format!("  {job_id}:"));
        if is_job_header {
            inside = true;
            continue;
        }
        if inside {
            // A two-space-indent line ending in `:` starts the next job.
            if line.starts_with("  ") && !line.starts_with("   ") && line.trim_end().ends_with(':') {
                break;
            }
            out.push(line);
        }
    }
    out.join("\n")
}
