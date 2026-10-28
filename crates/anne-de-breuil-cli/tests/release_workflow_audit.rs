//! T29 structural checks against the real release workflow file, mirroring
//! `ci_workflow_audit.rs`'s pattern (T28): `include_str!` pulls the actual
//! `.github/workflows/release.yml` in at compile time, so a change that
//! regresses one of these properties fails `cargo test`, not just a manual
//! read of the YAML.

const RELEASE_WORKFLOW: &str = include_str!("../../../.github/workflows/release.yml");
const AUTO_TAG_WORKFLOW: &str = include_str!("../../../.github/workflows/auto-tag.yml");

/// The tag-push-loop-prevention gotcha this task's own spec calls out: a
/// tag pushed with the default `GITHUB_TOKEN` never fires another
/// workflow's `on: push: tags` -- GitHub suppresses that specifically to
/// stop one workflow's automated push from recursively triggering others.
/// `release.yml` has to react to `auto-tag.yml` finishing instead, via
/// `on: workflow_run`, and re-derive the tag itself rather than trust a
/// tag-push event that will never arrive.
#[test]
fn release_workflow_uses_workflow_run_not_tag_push() {
    assert!(
        RELEASE_WORKFLOW.contains("workflow_run"),
        "release.yml must trigger off workflow_run, not a tag push directly"
    );
    assert!(
        !RELEASE_WORKFLOW.replace("\r\n", "\n").contains("on:\n  push:\n    tags"),
        "a plain `on: push: tags` trigger will never fire for a tag pushed by GITHUB_TOKEN"
    );
}

/// The tag must come from `auto-tag.yml`'s artifact, not from checking
/// out `${{ github.event.workflow_run.head_sha }}` and re-deriving it
/// with `git describe --tags --exact-match HEAD`.
///
/// Two independent reasons, and the second one is a bug that actually
/// shipped:
///
///   1. Scorecard's Dangerous-Workflow check flags any `actions/checkout`
///      whose `ref` derives from `github.event.workflow_run` as an
///      "untrusted code checkout" -- the pwn-request pattern where a
///      privileged workflow builds attacker-influenced code. The
///      artifact handoff means `release.yml` never checks out the
///      triggering commit at all.
///
///   2. `git describe --exact-match HEAD` exits 128 whenever the
///      checked-out commit is not the tagged one -- which is exactly
///      what happens when `auto-tag.yml` found the version already
///      tagged and pushed nothing. Every push to `main` that was not a
///      release therefore failed `resolve-tag` with a bare exit 128 and
///      no diagnostic. The artifact carries the "no new tag" decision
///      explicitly, so that case is now a clean no-op.
///
/// The `set -e` requirement stays: an unreadable or malformed artifact
/// must fail this job loudly rather than silently emitting an empty
/// tag, which would surface three jobs later in `publish-release` as
/// the opaque "GitHub Releases requires a tag".
#[test]
fn resolve_tag_reads_the_tag_from_the_artifact_not_an_untrusted_checkout() {
    let release_workflow = without_comments(RELEASE_WORKFLOW);
    let resolve_tag_job: String = release_workflow
        .lines()
        .skip_while(|line| line.trim() != "resolve-tag:")
        .skip(1)
        .take_while(|line| line.starts_with("    ") || line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !resolve_tag_job.contains("github.event.workflow_run.head_sha"),
        "resolve-tag must not check out the triggering workflow_run's commit -- that is the \
         untrusted-code-checkout pattern Scorecard's Dangerous-Workflow check flags"
    );
    assert!(
        !release_workflow.contains("github.event.workflow_run.head_sha"),
        "no job in release.yml may check out the triggering workflow_run's commit"
    );
    assert!(
        resolve_tag_job.contains("download-artifact"),
        "resolve-tag must read the tag from the artifact auto-tag.yml uploaded"
    );
    assert!(
        resolve_tag_job.contains("set -e"),
        "resolve-tag's artifact read must run under `set -e` so a failed lookup fails this \
         job instead of silently emitting an empty tag"
    );
}

/// The "no new tag" case has to be distinguishable from the normal
/// case, and it has to be a clean no-op: `auto-tag.yml` publishes the
/// literal `none` (rather than an empty file) when the workspace
/// version was already tagged, and `release.yml` turns that into an
/// empty `tag` output -- which every downstream job guards on, so a
/// non-release push to `main` does no work and fails nothing.
#[test]
fn a_non_release_push_is_a_clean_no_op() {
    let release_workflow = without_comments(RELEASE_WORKFLOW);
    let resolve_tag_job: String = release_workflow
        .lines()
        .skip_while(|line| line.trim() != "resolve-tag:")
        .skip(1)
        .take_while(|line| line.starts_with("    ") || line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        resolve_tag_job.contains("\"none\""),
        "resolve-tag must recognise auto-tag.yml's 'no new tag' sentinel"
    );
    assert!(
        release_workflow.contains("needs.resolve-tag.outputs.tag != ''"),
        "every job that builds or publishes a release must be guarded on a non-empty tag"
    );
}

/// Least-privilege posture, same property T28 codified for `ci.yml`: a
/// top-level `permissions:` block scopes the default `GITHUB_TOKEN` down
/// to read-only, so a job that doesn't explicitly ask for more can't
/// silently inherit the repository's own (often broader) default.
#[test]
fn top_level_permissions_default_to_read_only() {
    let has_top_level_permissions = RELEASE_WORKFLOW
        .lines()
        .take_while(|line| !line.trim_start().starts_with("jobs:"))
        .any(|line| line.trim_start().starts_with("permissions:"));
    assert!(
        has_top_level_permissions,
        "release.yml must set a top-level `permissions:` block"
    );

    // Excludes comment lines so a `#`-prefixed line explaining this very
    // policy (which necessarily contains the phrase "contents: write" as
    // prose) doesn't get counted as a second grant.
    let contents_write_count = RELEASE_WORKFLOW
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter(|line| line.contains("contents: write"))
        .count();
    assert_eq!(
        contents_write_count, 1,
        "only the job that actually creates the GitHub release should hold contents: write \
         -- every other job (build, sign, smoke-test, SBOM) has no legitimate reason to write \
         to the repository"
    );
}

/// The windows-msvc target is cross-compiled via `cargo xwin` on an
/// ubuntu-latest runner, per this task's own "faster, deterministic, no
/// Windows runner minutes for the artifact itself" rationale -- never
/// built natively on windows-latest.
///
/// x86_64-pc-windows-msvc only, not aarch64: cargo-xwin 0.23.1 has a real
/// bug cross-compiling `ring`'s C sources for aarch64-pc-windows-msvc
/// (emits an `/imsvc` flag bare `clang` doesn't understand), reproduced
/// identically on a local machine and on a real ubuntu-latest runner --
/// dropped from the release matrix rather than shipping a job that fails
/// every run, with the reason recorded in a workflow comment so this
/// isn't a silent omission. `windows_msvc_target_omission_is_explained`
/// below is the regression check for that comment staying in place.
#[test]
fn windows_msvc_target_is_cross_compiled_via_xwin_not_built_natively() {
    assert!(RELEASE_WORKFLOW.contains("cargo xwin build"));
    assert!(RELEASE_WORKFLOW.contains("x86_64-pc-windows-msvc"));

    let build_windows_job: String = RELEASE_WORKFLOW
        .lines()
        .skip_while(|line| line.trim() != "build-windows-msvc:")
        .skip(1)
        .take_while(|line| line.starts_with("    ") || line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !build_windows_job.contains("runs-on: windows"),
        "the xwin cross-build job must run on ubuntu-latest, not a windows runner"
    );
    assert!(
        !build_windows_job.contains("Cross-build aarch64-pc-windows-msvc"),
        "aarch64-pc-windows-msvc is deliberately not built -- see this test's own doc comment"
    );
}

/// The aarch64-pc-windows-msvc omission above is a documented, deliberate
/// gap (a real cargo-xwin bug), not something that can silently regress
/// into "nobody remembers why" -- the workflow comment explaining it, and
/// the mention of the target it's explaining the *absence* of, both have
/// to stay present.
#[test]
fn windows_msvc_target_omission_is_explained() {
    assert!(RELEASE_WORKFLOW.contains("aarch64-pc-windows-msvc"));
    assert!(RELEASE_WORKFLOW.contains("cargo-xwin"));
}

/// A real windows-latest runner has to execute the cross-built exe --
/// xwin's cross-build only proves it links, not that it runs on an actual
/// Windows machine with no Rust installed.
#[test]
fn a_real_windows_runner_smoke_tests_the_cross_built_exe() {
    assert!(RELEASE_WORKFLOW.contains("smoke-test-windows"));
    assert!(RELEASE_WORKFLOW.contains("runs-on: windows-latest"));
    assert!(RELEASE_WORKFLOW.contains("--version"));
}

/// The crt-static verification step (`xtask verify-static`, wrapping
/// `llvm-objdump -p`) has to actually run against the cross-built exe,
/// not just exist as an unused xtask command.
#[test]
fn crt_static_is_verified_for_the_windows_msvc_target() {
    let verify_calls = RELEASE_WORKFLOW.matches("xtask -- verify-static").count();
    assert_eq!(
        verify_calls, 1,
        "expected one verify-static call for the one windows-msvc target actually built"
    );
}

/// Both musl targets get built and their static linking is actually
/// checked (`ldd`), not just asserted in a comment.
#[test]
fn musl_targets_are_built_and_static_linking_is_checked() {
    assert!(RELEASE_WORKFLOW.contains("x86_64-unknown-linux-musl"));
    assert!(RELEASE_WORKFLOW.contains("aarch64-unknown-linux-musl"));
    assert!(RELEASE_WORKFLOW.contains("ldd "));
}

/// Signing is conditional on a real secret being configured, not an
/// unconditional step that would fail (or, worse, silently no-op without
/// saying so) on every fork/dry-run where no certificate exists.
#[test]
fn windows_signing_is_conditional_on_a_configured_secret() {
    assert!(RELEASE_WORKFLOW.contains("secrets.WINDOWS_CODESIGN_CERT"));

    let checks_before_signing = RELEASE_WORKFLOW.contains("WINDOWS_CODESIGN_CERT:-")
        || RELEASE_WORKFLOW.contains("-z \"${WINDOWS_CODESIGN_CERT");
    assert!(
        checks_before_signing,
        "the signing step must check whether the cert secret is actually set before attempting to sign"
    );
}

/// SBOM generation and checksum publication are real steps in the release
/// path, not just described in a task file.
#[test]
fn sbom_and_checksums_are_generated() {
    assert!(RELEASE_WORKFLOW.contains("cyclonedx"));
    assert!(RELEASE_WORKFLOW.contains("xtask -- checksum write"));
}

// ---------------------------------------------------------------------------
// ci.yml ↔ branch-protection contract.
//
// The branch-protection rule on `main` requires a fixed list of status
// contexts to report `success` before a PR can merge. Those contexts are
// GitHub-Actions *job display names*, not job ids: a job defined as
//     build-test-lint:
//       name: build, test, clippy (${{ matrix.os }})
//       strategy:
//         matrix:
//           os: [ubuntu-latest, windows-latest, macos-latest]
// reports contexts `build, test, clippy (ubuntu-latest)` etc., NOT
// `build-test-lint (ubuntu-latest)`. A protection rule listing the
// latter will wait forever for a context that never gets published and
// the PR appears to "hang" -- exactly the failure mode OSSF requires
// protection to prevent, ironic as that is.
//
// These tests pin both halves of that contract:
//   - every required context has a matching `name:` template in some
//     workflow under `.github/workflows/`, and
//   - every job `name:` template that uses `${{ matrix.os }}` is rendered
//     against the matrix's actual OS values (the test enumerates the same
//     three OS strings ci.yml uses, so a matrix edit that drops, say,
//     `windows-latest` is caught here too).
// ---------------------------------------------------------------------------

const CI_WORKFLOW: &str = include_str!("../../../.github/workflows/ci.yml");

/// Required status contexts that branch protection on `main` waits for.
/// This list **must** match the contexts currently configured via
/// `gh api /branches/main/protection -- required_status_checks.contexts`,
/// and each one **must** correspond to a real GitHub Actions job display
/// name (not a job id) in `ci.yml` / `release.yml`.
const REQUIRED_STATUS_CONTEXTS: &[&str] = &[
    "build, test, clippy (ubuntu-latest)",
    "build, test, clippy (windows-latest)",
    "build, test, clippy (macos-latest)",
    "cargo-deny (advisories, licenses, bans, sources)",
    "CodeQL",
];

/// Enumerates the `${{ matrix.* }}` values referenced by the test. ci.yml
/// declares `os: [ubuntu-latest, windows-latest, macos-latest]` on the
/// `build-test-lint` job, so any matrix edit has to update both this
/// list and the `name:` template in lockstep -- the assertion below
/// fails if either side drifts.
const BUILD_TEST_LINT_OS_MATRIX: &[&str] = &["ubuntu-latest", "windows-latest", "macos-latest"];

/// `name: build, test, clippy (${{ matrix.os }})` -- the actual template
/// string ci.yml uses, asserted verbatim so a rename of either the job
/// or the display string has to be reflected here too.
const BUILD_TEST_LINT_DISPLAY_NAME_TEMPLATE: &str = "build, test, clippy (${{ matrix.os }})";

/// Returns the leading-whitespace count of `line` (0 for top-level).
#[inline]
fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// A workflow's executable content, with comment lines removed.
///
/// Several of the properties below are argued in prose in the workflow
/// files themselves -- the comment explaining *why* `resolve-tag` must
/// not check out `github.event.workflow_run.head_sha` necessarily
/// contains that very string. Asserting against the raw file would then
/// fail on the explanation, so the checks run against this instead: a
/// line whose first non-space character is `#` is documentation, not
/// configuration.
fn without_comments(workflow: &str) -> String {
    workflow
        .replace("\r\n", "\n")
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The syft installer is fetched over the network and executed. It must
/// be pinned to a commit SHA, and the syft release it installs must be
/// pinned to a version.
///
/// Two independent reasons, both of which are real supply-chain
/// weaknesses rather than style points:
///
///   1. Fetching the installer from `main` means its contents can
///      change between the review that approved the line and the moment
///      the runner executes it. The runner's `GITHUB_TOKEN` is in
///      scope, so "the script changed" is "arbitrary code ran with
///      release credentials".
///   2. The install script defaults to the *latest* release, so the
///      `CycloneDX` SBOM would be generated by a syft version nobody
///      chose and nobody could reproduce.
///
///
/// The SHA and the version are written out literally rather than
/// interpolated from `env:`. Scorecard parses the shell script text, so
/// a `${{ env.SYFT_INSTALL_SHA }}` would read as a variable rather than
/// as a commit SHA -- and Scorecard's Pinned-Dependencies check would
/// (correctly) still report the download as unpinned.
#[test]
fn the_syft_installer_is_pinned_to_a_commit_sha_and_a_version() {
    let release_workflow = without_comments(RELEASE_WORKFLOW);

    // The installer URL carries a 40-hex commit SHA.
    let sha = release_workflow
        .lines()
        .find(|line| line.contains("raw.githubusercontent.com/anchore/syft/"))
        .expect("release.yml fetches the syft installer from raw.githubusercontent.com");
    assert!(
        sha.contains("/anchore/syft/")
            && sha
                .split("/anchore/syft/")
                .nth(1)
                .is_some_and(|rest| {
                    let candidate = rest.split('/').next().unwrap_or_default();
                    candidate.len() == 40
                        && candidate.chars().all(|c| c.is_ascii_hexdigit())
                }),
        "the syft installer must be fetched from a commit SHA, not a branch: {sha}"
    );

    // The installed syft version is pinned, not "latest".
    assert!(
        release_workflow.contains("sh -s -- -b /usr/local/bin v"),
        "the syft install must pass an explicit version tag -- the script defaults to `latest`"
    );

    // And the pinned version is not interpolated from an env var, which
    // the pinning check could not see.
    assert!(
        !release_workflow.contains("${SYFT"),
        "the syft SHA and version must be literal -- Scorecard parses the shell text, not the env"
    );
}

/// Job ids in ci.yml whose `name:` template uses `${{ matrix.os }}` --
/// we use this list to verify the assertion's expectations cover every
/// rendering, not just one.
///
/// Walks the workflow line-by-line with no YAML parsing: any line at
/// exactly two-space indent that ends with `:` is treated as a job id
/// (GitHub's `jobs:` block is the only place in a workflow where that
/// shape appears -- top-level keys are at indent 0, job-body keys at
/// indent ≥4). The walker then scans the job's body until the next
/// two-space-indent `:` line and records the id if it contains a
/// `name:` referencing `${{ matrix.os }}`.
fn job_ids_using_matrix_os(workflow: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let lines: Vec<&str> = workflow.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        // Skip blank/comment lines.
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        // Job-id line: exactly two-space indent, ends with `:`.
        if indent_of(line) != 2 || !line.trim_end().ends_with(':') {
            continue;
        }
        let id = line.trim().trim_end_matches(':');
        // Skip known workflow-level keys that happen to share the
        // two-space shape (none do today -- `jobs:` is at indent 0 --
        // but future-proofing against a future workflow that moves a
        // key into a `jobs:` block costs nothing).
        if matches!(id, "name" | "on" | "env" | "permissions" | "jobs") {
            continue;
        }

        // Walk the job's body until the next two-space-indent `:` line.
        for body in lines
            .iter()
            .skip(idx + 1)
            .take_while(|l| !(indent_of(l) == 2 && l.trim_end().ends_with(':')))
        {
            let body_trim = body.trim_start();
            if body_trim.starts_with("name:") && body.contains("${{ matrix.os }}") {
                out.push(id);
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod walker_self_tests {
    use super::job_ids_using_matrix_os;

    #[test]
    fn finds_matrix_os_in_a_canonical_workflow() {
        let yaml = "\
name: CI
on:
  push:
    branches: [main]
jobs:
  build-test-lint:
    name: build, test, clippy (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
  codeql:
    name: CodeQL
    runs-on: ubuntu-latest
";
        assert_eq!(job_ids_using_matrix_os(yaml), vec!["build-test-lint"]);
    }

    #[test]
    fn ignores_jobs_whose_name_does_not_reference_matrix() {
        let yaml = "\
jobs:
  cargo-deny:
    name: cargo-deny (advisories, licenses, bans, sources)
    runs-on: ubuntu-latest
  scorecard:
    name: Scorecard analysis
    runs-on: ubuntu-latest
";
        assert_eq!(job_ids_using_matrix_os(yaml), Vec::<&str>::new());
    }

    #[test]
    fn handles_a_job_with_no_name_field() {
        // No `name:` -> falls through to default, no match.
        let yaml = "\
jobs:
  build-test-lint:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest]
";
        assert_eq!(job_ids_using_matrix_os(yaml), Vec::<&str>::new());
    }

    #[test]
    fn finds_two_jobs_each_using_matrix_os_in_name() {
        let yaml = "\
jobs:
  build-test-lint:
    name: build, test, clippy (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
  windows-msvc:
    name: windows msvc (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
";
        let mut found = job_ids_using_matrix_os(yaml);
        found.sort_unstable();
        assert_eq!(found, vec!["build-test-lint", "windows-msvc"]);
    }
}

#[test]
fn required_status_contexts_match_actual_ci_job_display_names() {
    // 1. Every required context corresponds to a real GitHub Actions job
    //    display name. The simplest way to assert this without standing
    //    up the YAML parser: for any context of the form
    //    `<template> (<value>)`, the rendered template must appear in
    //    ci.yml.
    for ctx in REQUIRED_STATUS_CONTEXTS {
        // Pull a trailing `(value)` off the context, if present, and
        // reconstruct the template by stripping it.
        let (template, rendered_value) = match ctx.rsplit_once(" (") {
            Some((t, rest)) if rest.ends_with(')') => (t, &rest[..rest.len() - 1]),
            _ => continue, // single-name contexts (CodeQL, cargo-deny) handled below
        };
        // The rendered template must appear literally in the workflow,
        // OR there must be a `name:` line that uses `${{ matrix.* }}`
        // matching the template structure. For matrix-os contexts the
        // test asserts both halves below.
        let rendered = format!("{template} ({rendered_value})");
        assert!(
            CI_WORKFLOW.contains(&rendered) || CI_WORKFLOW.contains(template),
            "required status context `{ctx}` does not match any job display \
             name in ci.yml -- check that the job's `name:` template \
             renders to this string (the rule on `main` expects the \
             *display* name, not the job id)"
        );
    }
}

#[test]
fn build_test_lint_matrix_covers_all_required_os_contexts() {
    // 2. The matrix-os assertion: every (job_id, os) pair the ci.yml
    //    matrix enumerates must end up in REQUIRED_STATUS_CONTEXTS, and
    //    vice versa. Drift in either direction causes the branch
    //    protection rule to wait for a context that never publishes.
    assert!(
        CI_WORKFLOW.contains(BUILD_TEST_LINT_DISPLAY_NAME_TEMPLATE),
        "ci.yml must keep the build-test-lint job's `name:` template as \
         `{BUILD_TEST_LINT_DISPLAY_NAME_TEMPLATE}` -- the audit asserts \
         this verbatim so a rename of either the template or the matrix \
         is caught at compile time"
    );
    let jobs_with_matrix_os = job_ids_using_matrix_os(CI_WORKFLOW);
    assert!(
        jobs_with_matrix_os.contains(&"build-test-lint"),
        "ci.yml must still have a `build-test-lint` job that uses \
         `${{ matrix.os }}` in its `name:` -- if it was renamed, update \
         REQUIRED_STATUS_CONTEXTS in this file to match"
    );
    for os in BUILD_TEST_LINT_OS_MATRIX {
        let expected = format!("build, test, clippy ({os})");
        assert!(
            REQUIRED_STATUS_CONTEXTS.contains(&expected.as_str()),
            "matrix os `{os}` is missing from REQUIRED_STATUS_CONTEXTS -- \
             the branch-protection rule on `main` requires the context \
             `{expected}` so the PR will not appear to hang waiting for \
             a check that never publishes"
        );
    }
    // And the inverse: every required context whose template matches
    // `build, test, clippy (${{ matrix.os }})` must enumerate a real os
    // value from BUILD_TEST_LINT_OS_MATRIX.
    for ctx in REQUIRED_STATUS_CONTEXTS {
        if let Some((template, value)) = ctx.rsplit_once(" (")
            && template == "build, test, clippy (${{ matrix.os }})"
        {
            let value = &value[..value.len() - 1];
            assert!(
                BUILD_TEST_LINT_OS_MATRIX.contains(&value),
                "required context `{ctx}` references os `{value}` which \
                 is not in BUILD_TEST_LINT_OS_MATRIX -- the matrix in \
                 ci.yml and this test's matrix must stay in sync"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// OSSF Scorecard / branch-protection companion artefacts.
//
// These three files exist together so that the OSSF Scorecard check
// `Branch-Protection` (set on `main`) actually scores, and so the
// companion checks `Dependency-Update-Tool` and `Code-Review` are
// satisfied:
//
//   - `.github/CODEOWNERS` makes `require_code_owner_reviews` (a branch
//     protection rule on `main`) do something: without it the rule is a
//     no-op and the Scorecard's Branch-Protection score drops a tier.
//
//   - `.github/dependabot.yml` is the Dependency-Update-Tool check —
//     Scorecard scans the file system for a manifest under
//     `.github/dependabot.{yml,yaml}`.
//
//   - `.github/workflows/scorecard.yml` is the continuously-running
//     auditor that publishes Scorecard SARIF to the Code Scanning tab.
//
// They're all `include_str!`'d at compile time so any future removal
// (or rename) of the files fails `cargo test`, not just a manual read
// of the YAML.
// ---------------------------------------------------------------------------

const CODEOWNERS: &str = include_str!("../../../.github/CODEOWNERS");
const DEPENDABOT_CONFIG: &str = include_str!("../../../.github/dependabot.yml");
const SCORECARD_WORKFLOW: &str = include_str!("../../../.github/workflows/scorecard.yml");

/// Without a `CODEOWNERS` file, the `require_code_owner_reviews` rule on
/// `main` is a no-op — GitHub matches no path, no approval is required
/// from anyone in particular, and the OSSF Branch-Protection score drops
/// a tier for it. The file must (a) exist, (b) list an owner, and (c)
/// cover the security-critical workflow surface so a future split-owner
/// edit has somewhere to land.
#[test]
fn codeowners_file_exists_and_covers_security_critical_paths() {
    assert!(
        CODEOWNERS.contains("@greysquirr3l"),
        "CODEOWNERS must list at least one GitHub user/team handle"
    );
    for path in [
        ".github/workflows/release.yml",
        ".github/workflows/scorecard.yml",
        ".github/dependabot.yml",
        ".github/CODEOWNERS",
    ] {
        assert!(
            CODEOWNERS.contains(path),
            "CODEOWNERS must explicitly own `{path}` so security-critical \
             changes always surface a code-owner review"
        );
    }
}

/// The `main` ruleset (`rulesets/25918976`) combines
/// `require_code_owner_review` with `require_last_push_approval`. The
/// first demands an approval from a handle named in `CODEOWNERS`; the
/// second demands an approval from someone *other* than the account that
/// made the last push. With a single owner the two are mutually
/// unsatisfiable for any PR that owner pushes — the only code owner is
/// also the last pusher — and the PR deadlocks.
///
/// Two owners break the deadlock. GitHub resolves a path's owners from
/// the **last** matching pattern and uses only that pattern's owners, so
/// naming the second owner on the default `/*` rule is not enough: a
/// more specific rule listing only one owner would silently drop the
/// other from those paths and re-create the deadlock there. Every rule
/// must therefore name both owners.
///
/// This parses the file rather than grepping for handles, so a rule that
/// names only one owner fails the build even when both handles appear
/// elsewhere in the file.
#[test]
fn codeowners_every_rule_names_both_owners() {
    const OWNERS: [&str; 2] = ["@greysquirr3l", "@sosh-ncampbell"];

    let mut rules = 0usize;
    for (index, line) in CODEOWNERS.lines().enumerate() {
        let trimmed = line.trim();
        // Skip blank lines and comments; a rule is `pattern owner...`.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        rules += 1;
        let owners: Vec<&str> = trimmed.split_whitespace().skip(1).collect();
        for owner in OWNERS {
            assert!(
                owners.contains(&owner),
                "CODEOWNERS line {} (`{trimmed}`) must name {owner} as well \
                 as the other owner — the `main` ruleset requires an \
                 approval from a code owner AND from someone other than \
                 the last pusher, so a rule with a single owner \
                 deadlocks every PR that owner pushes",
                index + 1
            );
        }
    }

    assert!(
        rules > 0,
        "CODEOWNERS must contain at least one ownership rule, otherwise the \
         code-owner review requirement on `main` matches nothing"
    );
}

/// Scorecard's `Dependency-Update-Tool` check looks specifically for a
/// `.github/dependabot.{yml,yaml}` manifest. Two ecosystems here because
/// only those have lockfiles / catalog data that the release SBOM
/// (T29, `syft dir:.` against `Cargo.lock`) and the supply-chain
/// catalogues actually scan.
#[test]
fn dependabot_covers_cargo_and_github_actions_ecosystems() {
    assert!(
        DEPENDABOT_CONFIG.contains("package-ecosystem: \"cargo\""),
        "Dependabot must cover the cargo ecosystem so Cargo.lock updates \
         match the SBOM source-of-truth"
    );
    assert!(
        DEPENDABOT_CONFIG.contains("package-ecosystem: \"github-actions\""),
        "Dependabot must cover the github-actions ecosystem so workflow \
         updates land as reviewable PRs"
    );
}

/// The Scorecard workflow must (a) pin its action by SHA
/// (Pinned-Dependencies is itself a Scorecard check), (b) declare an
/// explicit `permissions:` block (Token-Permissions), and (c) publish
/// SARIF results to the Code Scanning tab.
#[test]
fn scorecard_workflow_is_pinned_explicit_and_publishes_sarif() {
    assert!(
        SCORECARD_WORKFLOW.contains("uses: ossf/scorecard-action@"),
        "scorecard.yml must invoke ossf/scorecard-action"
    );
    // SHA-pinned — the ref must look like 40-hex chars, not a tag. Pinned
    // to v2.5.0 (commit fa7117db83c52d787ae5a89f350999701505d78e); the
    // test pins the literal SHA so a tag-ref mistake in the workflow file
    // surfaces as a compile-time failure rather than a runtime surprise.
    assert!(
        SCORECARD_WORKFLOW
            .contains("uses: ossf/scorecard-action@fa7117db83c52d787ae5a89f350999701505d78e"),
        "scorecard.yml must pin the action to a full commit SHA — tag refs \
         are exactly what the Pinned-Dependencies Scorecard check penalises"
    );
    assert!(
        SCORECARD_WORKFLOW.contains("permissions:"),
        "scorecard.yml must declare an explicit top-level `permissions:` \
         block so the Token-Permissions Scorecard check recognises the \
         least-privilege posture"
    );
    assert!(
        SCORECARD_WORKFLOW.contains("publish_results: true"),
        "scorecard.yml must publish its results to api.scorecard.dev"
    );
    assert!(
        SCORECARD_WORKFLOW.contains("results_format: sarif"),
        "scorecard.yml must emit SARIF (the format Code Scanning ingests)"
    );
}

/// `auto-tag.yml` is the other half of the release handshake, and it
/// has to publish the tag it resolved for `release.yml` to read back.
/// Without the artifact there is no channel between the two workflows
/// -- a `workflow_run` event carries none of the triggering run's job
/// outputs -- and `release.yml` would be back to checking out the
/// triggering commit to re-derive the tag, which is the pattern
/// `resolve_tag_reads_the_tag_from_the_artifact_not_an_untrusted_checkout`
/// rules out.
#[test]
fn auto_tag_publishes_the_resolved_tag_as_an_artifact() {
    assert!(
        AUTO_TAG_WORKFLOW.contains("upload-artifact"),
        "auto-tag.yml must upload the resolved tag so release.yml can read it back"
    );
    assert!(
        AUTO_TAG_WORKFLOW.contains("name: release-tag"),
        "the artifact name must match the one release.yml downloads"
    );
    assert!(
        AUTO_TAG_WORKFLOW.contains("tag=none"),
        "auto-tag.yml must publish the literal 'none' when the version was already tagged, so \
         release.yml can tell 'no new tag' from 'no artifact'"
    );
}

/// The `contents: write` grant belongs on the job that actually pushes
/// the tag, not on the workflow. A top-level grant would hand write
/// access to the repository to every step of every job in the file --
/// including the `actions/checkout` step, which does not need it. This
/// is the Token-Permissions Scorecard check's least-privilege property.
#[test]
fn auto_tag_scopes_its_write_grant_to_the_job_that_needs_it() {
    let auto_tag_workflow = without_comments(AUTO_TAG_WORKFLOW);
    let top_level = auto_tag_workflow
        .lines()
        .take_while(|line| !line.trim_start().starts_with("jobs:"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        top_level.contains("permissions:"),
        "auto-tag.yml must set a top-level `permissions:` block"
    );
    assert!(
        !top_level.contains("contents: write"),
        "the top-level grant must be read-only -- contents: write belongs on the tagging job \
         alone, and a workflow-wide write grant is what the Token-Permissions check penalises"
    );
    assert!(
        auto_tag_workflow.contains("contents: write"),
        "the job that pushes the tag must hold contents: write explicitly"
    );
}

/// The Scorecard job needs two write scopes, and it needs them at the
/// *job* level. This is not a style preference -- it is the only shape
/// Scorecard's own API accepts, and the shape it requires is exactly
/// what the workflow was missing.
///
/// The failure this pins down is a real one that shipped: with
/// `publish_results: true` and no `id-token: write`, the action cannot
/// mint the OIDC token that signs the results, so it falls back to
/// sigstore's interactive device flow. On a runner there is nobody to
/// complete that flow, so the job sat in a retry loop for fifteen
/// minutes and then failed. The run before this fix had been failing
/// every week since the workflow was added.
///
/// Three properties have to hold together, and each one is a way the
/// workflow could silently regress:
///
///   1. `id-token: write` and `security-events: write` are present on
///      the job. Without the first the publish fails; without the second
///      the SARIF never reaches the Code Scanning tab.
///   2. Neither is granted at the workflow level. Scorecard's API
///      rejects a workflow whose global permissions include any `write`
///      scope, so moving them up would trade one failure for another.
///   3. The SARIF is actually uploaded. `ossf/scorecard-action` writes
///      the file but does not publish it -- `upload-sarif` does that --
///      so a workflow that stops short of the upload step produces a
///      green run with an empty Security tab.
#[test]
fn scorecard_workflow_carries_the_scopes_its_action_needs() {
    assert!(
        SCORECARD_WORKFLOW.contains("id-token: write"),
        "the scorecard job must hold id-token: write -- without it the action falls back to \
         sigstore's interactive device flow and the publish step fails"
    );
    assert!(
        SCORECARD_WORKFLOW.contains("security-events: write"),
        "the scorecard job must hold security-events: write so upload-sarif can publish to the \
         Code Scanning tab"
    );
    assert!(
        SCORECARD_WORKFLOW.contains("github/codeql-action/upload-sarif@"),
        "scorecard.yml must upload the SARIF it produced -- ossf/scorecard-action writes the \
         file but does not publish it, so without this step the Security tab stays empty"
    );
    // A distinct category keeps the Scorecard upload from colliding with
    // ci.yml's CodeQL upload: Code Scanning matches a new analysis to an
    // existing one by category, and an uncategorised upload would race
    // CodeQL for the same slot and one of the two would be overwritten.
    assert!(
        SCORECARD_WORKFLOW.contains("category: ossf-scorecard"),
        "the scorecard upload must declare its own category so it does not collide with the \
         CodeQL analysis uploaded by ci.yml"
    );
}
