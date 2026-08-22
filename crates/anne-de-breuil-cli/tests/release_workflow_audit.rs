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
