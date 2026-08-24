//! T29 structural checks against the real release workflow file, mirroring
//! `ci_workflow_audit.rs`'s pattern (T28): `include_str!` pulls the actual
//! `.github/workflows/release.yml` in at compile time, so a change that
//! regresses one of these properties fails `cargo test`, not just a manual
//! read of the YAML.

const RELEASE_WORKFLOW: &str = include_str!("../../../.github/workflows/release.yml");

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
        !RELEASE_WORKFLOW.contains("on:\n  push:\n    tags"),
        "a plain `on: push: tags` trigger will never fire for a tag pushed by GITHUB_TOKEN"
    );
}

/// `resolve-tag`'s `git describe --exact-match` genuinely can fail --
/// e.g. a real race hit during iteration, where the tag moved again
/// after this `workflow_run`'s own triggering commit but before this
/// job actually executed. Without `set -e`, a failing command
/// substitution inside `echo "tag=$(...)"` still produces a zero-exit
/// `echo` with an empty value, silently writing `tag=` to
/// `GITHUB_OUTPUT` -- confirmed on a real run, where it surfaced three
/// jobs later as `publish-release` failing with the opaque "GitHub
/// Releases requires a tag" instead of a clear failure at the source.
#[test]
fn resolve_tag_fails_loudly_instead_of_emitting_an_empty_tag() {
    let resolve_tag_job: String = RELEASE_WORKFLOW
        .lines()
        .skip_while(|line| line.trim() != "resolve-tag:")
        .skip(1)
        .take_while(|line| line.starts_with("    ") || line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        resolve_tag_job.contains("set -e"),
        "resolve-tag's `git describe` step must run under `set -e` so a failed lookup fails \
         this job instead of silently emitting an empty tag"
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
    // to v2.4.4 (commit 2d1146689b8cda280b9bc96326124645441f03bc, "Bump
    // action tag for v2.4.4 release #1688", annotated tag dated
    // 2026-07-23); the test pins the literal SHA so a tag-ref mistake in
    // the workflow file surfaces as a compile-time failure rather than a
    // runtime surprise.
    assert!(
        SCORECARD_WORKFLOW
            .contains("uses: ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc"),
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
        "scorecard.yml must publish SARIF to the Code Scanning tab"
    );
    assert!(
        SCORECARD_WORKFLOW.contains("results_format: sarif"),
        "scorecard.yml must emit SARIF (the format Code Scanning ingests)"
    );
}
