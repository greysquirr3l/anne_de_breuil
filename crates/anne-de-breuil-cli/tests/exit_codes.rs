//! Exit codes are a contract (`cli::ExitCode`'s doc comment): 0 clean,
//! 1 operational error, 2 config/arg error, 3 drift detected. CI and RMM
//! tooling branch on these, so each one needs a real, reproducible
//! trigger — not just the value asserted in isolation from `cli.rs`'s own
//! unit test.
//!
//! The task sketch's own suggested triggers don't all match what this CLI
//! actually does yet: `scan --target unreachable.invalid` can't fire an
//! operational error today because `--target` isn't wired to a real
//! transport (T31) — it deliberately warns and exits clean rather than
//! silently scanning the local host instead of the host the operator
//! named. `diff` against a snapshot file that doesn't exist is a real,
//! deterministic operational failure available today, so that's the
//! trigger used here instead.

#[cfg(test)]
mod support;

#[test]
fn clean_exit_from_a_local_emit_json_scan() {
    support::anne_cmd()
        .args(["scan", "--emit-json"])
        .assert()
        .code(0);
}

#[test]
fn operational_error_when_a_diff_input_file_is_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let baseline = dir.path().join("does-not-exist-baseline.json");
    let current = dir.path().join("does-not-exist-current.json");

    support::anne_cmd()
        .arg("diff")
        .arg(&baseline)
        .arg(&current)
        .assert()
        .code(1);
}

#[test]
fn config_or_arg_error_for_an_invalid_strategy_value() {
    support::anne_cmd()
        .args(["scan", "--strategy", "bogus"])
        .assert()
        .code(2);
}

#[test]
fn config_or_arg_error_for_a_malformed_inventory_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("broken.toml");
    std::fs::write(&path, "this is not [[[ valid toml").expect("write fixture");

    support::anne_cmd()
        .arg("inventory")
        .arg("validate")
        .arg(&path)
        .assert()
        .code(2);
}

#[test]
fn drift_detected_exit_code_fires_above_the_fail_on_drift_threshold() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (baseline, current) = support::drift_snapshot_pair();
    let baseline_path = support::write_snapshot(dir.path(), "baseline.json", &baseline);
    let current_path = support::write_snapshot(dir.path(), "current.json", &current);

    support::anne_cmd()
        .arg("diff")
        .arg(&baseline_path)
        .arg(&current_path)
        .arg("--fail-on-drift")
        .arg("high")
        .assert()
        .code(3);
}

#[test]
fn identical_snapshots_never_fire_the_drift_exit_code() {
    // A snapshot diffed against itself has no entries at all, regardless
    // of the threshold — proves the drift exit code isn't just "diff ran
    // without an I/O error", it genuinely gates on `DriftReport::entries`.
    let dir = tempfile::tempdir().expect("tempdir");
    let snapshot = support::sample_snapshot();
    let baseline_path = support::write_snapshot(dir.path(), "baseline.json", &snapshot);
    let current_path = support::write_snapshot(dir.path(), "current.json", &snapshot);

    // Identical snapshots diff to nothing, so this must be clean regardless
    // of the threshold supplied.
    support::anne_cmd()
        .arg("diff")
        .arg(&baseline_path)
        .arg(&current_path)
        .arg("--fail-on-drift")
        .arg("low")
        .assert()
        .code(0);
}
