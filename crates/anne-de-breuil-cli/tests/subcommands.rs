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
fn report_format_csv_writes_a_header_row_with_the_host_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let snapshot = support::sample_snapshot();
    let path = support::write_snapshot(dir.path(), "snapshot.json", &snapshot);

    let output = support::anne_cmd()
        .arg("report")
        .arg(&path)
        .args(["--format", "csv"])
        .output()
        .expect("anne report --format csv runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("host_id,protocol,bind_address,port,"),
        "unexpected CSV header, got: {stdout}"
    );
    assert!(stdout.contains(&snapshot.host_id.to_string()));
}

#[test]
fn report_format_sarif_writes_a_valid_sarif_envelope() {
    let dir = tempfile::tempdir().expect("tempdir");
    let snapshot = support::sample_snapshot();
    let path = support::write_snapshot(dir.path(), "snapshot.json", &snapshot);

    let output = support::anne_cmd()
        .arg("report")
        .arg(&path)
        .args(["--format", "sarif"])
        .output()
        .expect("anne report --format sarif runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is valid SARIF JSON");
    assert_eq!(value["version"], "2.1.0");
    assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "anne-de-breuil");
}

#[test]
fn report_output_flag_writes_the_report_to_a_file_instead_of_stdout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let snapshot = support::sample_snapshot();
    let path = support::write_snapshot(dir.path(), "snapshot.json", &snapshot);
    let out_path = dir.path().join("out.json");

    let output = support::anne_cmd()
        .arg("report")
        .arg(&path)
        .args(["--output", out_path.to_str().expect("utf8 path")])
        .output()
        .expect("anne report --output runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "expected stdout to stay empty when --output is given"
    );
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out_path).expect("output file exists"))
            .expect("output file is valid JSON");
    assert!(value.get("hosts").is_some());
}

#[test]
fn report_format_html_renders_a_self_contained_document() {
    let dir = tempfile::tempdir().expect("tempdir");
    let snapshot = support::sample_snapshot();
    let path = support::write_snapshot(dir.path(), "snapshot.json", &snapshot);

    let output = support::anne_cmd()
        .arg("report")
        .arg(&path)
        .args(["--format", "html"])
        .output()
        .expect("anne report --format html runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let html = String::from_utf8_lossy(&output.stdout);
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("Content-Security-Policy"));
    assert!(html.contains("--paper: #f5f5f4"));
    assert!(html.contains("base64,"), "default --fonts is embed");
    for pattern in ["src=\"http", "href=\"http", "url(http"] {
        assert!(
            !html.contains(pattern),
            "found external reference {pattern}"
        );
    }
}

#[test]
fn report_format_html_fonts_system_omits_embedded_font_payload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let snapshot = support::sample_snapshot();
    let path = support::write_snapshot(dir.path(), "snapshot.json", &snapshot);

    let output = support::anne_cmd()
        .arg("report")
        .arg(&path)
        .args(["--format", "html", "--fonts", "system"])
        .output()
        .expect("anne report --format html --fonts system runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let html = String::from_utf8_lossy(&output.stdout);
    assert!(!html.contains("base64,"));
    assert!(!html.contains("@font-face"));
}

#[test]
fn report_split_writes_one_file_per_host_plus_an_index() {
    let dir = tempfile::tempdir().expect("tempdir");
    let snapshot = support::sample_snapshot();
    let path = support::write_snapshot(dir.path(), "snapshot.json", &snapshot);
    let split_dir = dir.path().join("split-out");

    let output = support::anne_cmd()
        .arg("report")
        .arg(&path)
        .args(["--format", "html"])
        .args(["--split", split_dir.to_str().expect("utf8 path")])
        .output()
        .expect("anne report --split runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "expected stdout to stay empty when --split is given"
    );

    let index = std::fs::read_to_string(split_dir.join("index.html")).expect("index.html exists");
    assert!(index.starts_with("<!doctype html>"));

    let host_file = std::fs::read_dir(&split_dir)
        .expect("split dir exists")
        .filter_map(Result::ok)
        .find(|entry| {
            entry.file_name().to_string_lossy().starts_with("host-")
                && entry.file_name().to_string_lossy().ends_with(".html")
        })
        .expect("one per-host file exists");
    let host_doc = std::fs::read_to_string(host_file.path()).expect("host file readable");
    assert!(host_doc.contains("class=\"host-section\""));
}

#[test]
fn report_split_rejects_a_non_html_format() {
    let dir = tempfile::tempdir().expect("tempdir");
    let snapshot = support::sample_snapshot();
    let path = support::write_snapshot(dir.path(), "snapshot.json", &snapshot);
    let split_dir = dir.path().join("split-out");

    let output = support::anne_cmd()
        .arg("report")
        .arg(&path)
        .args(["--format", "json"])
        .args(["--split", split_dir.to_str().expect("utf8 path")])
        .output()
        .expect("anne report --format json --split runs");

    assert_eq!(output.status.code(), Some(2), "expected ConfigOrArgError");
    assert!(!split_dir.exists(), "must not write anything on rejection");
}

#[test]
fn report_split_and_output_are_mutually_exclusive() {
    let output = support::anne_cmd()
        .args(["report", "some-target", "--format", "html"])
        .args(["--output", "out.html"])
        .args(["--split", "out-dir"])
        .output()
        .expect("anne report --output --split runs");

    assert!(
        !output.status.success(),
        "clap must reject --output combined with --split"
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
