//! One substantive test per subcommand, beyond `--help` and the exit-code
//! contract — each of these actually exercises the handler's real work,
//! not just its argument parsing.

#[cfg(test)]
mod support;

use anne_de_breuil::domain::ScanSnapshot;

#[test]
fn scan_emit_json_produces_a_valid_snapshot() {
    let output = support::anne_cmd()
        .args(["scan", "--emit-json"])
        .output()
        .expect("anne scan --emit-json runs");
    assert!(output.status.success());
    let snapshot: ScanSnapshot =
        serde_json::from_slice(&output.stdout).expect("stdout is a valid ScanSnapshot");
    assert_eq!(snapshot.collector_version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn diff_reports_the_critical_endpoint_appeared_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (baseline, current) = support::drift_snapshot_pair();
    let baseline_path = support::write_snapshot(dir.path(), "baseline.json", &baseline);
    let current_path = support::write_snapshot(dir.path(), "current.json", &current);

    let output = support::anne_cmd()
        .arg("diff")
        .arg(&baseline_path)
        .arg(&current_path)
        .output()
        .expect("anne diff runs");

    // Exit code 3 (drift detected) for the default --fail-on-drift=high
    // threshold, and the printed JSON names the drift kind so a reader
    // isn't just trusting the exit code.
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("EndpointAppeared"),
        "expected the drift entry kind in stdout, got: {stdout}"
    );
}

#[test]
fn report_renders_a_snapshot_file_as_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let snapshot = support::sample_snapshot();
    let path = support::write_snapshot(dir.path(), "snapshot.json", &snapshot);

    let output = support::anne_cmd()
        .arg("report")
        .arg(&path)
        .output()
        .expect("anne report runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is valid JSON");
    assert!(
        value.get("hosts").is_some(),
        "expected a ReportModel-shaped object with a `hosts` field, got: {value}"
    );
}

#[test]
fn inventory_validate_accepts_a_well_formed_file() {
    support::anne_cmd()
        .arg("inventory")
        .arg("validate")
        .arg(support::valid_inventory_path())
        .assert()
        .code(0);
}

#[test]
fn version_prints_semver_and_a_git_sha() {
    let output = support::anne_cmd()
        .arg("version")
        .output()
        .expect("anne version runs");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "expected the crate version in output, got: {stdout}"
    );
    assert!(
        stdout.contains("git"),
        "expected the git SHA marker in output, got: {stdout}"
    );
}
