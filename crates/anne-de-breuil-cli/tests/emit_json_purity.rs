//! `--emit-json` is the wire contract the remote transport parses stdout
//! against (see `application::scan`'s module doc) — a stray log line on
//! stdout there breaks every remote scan, not just this one invocation.
//! `RUST_LOG=trace` is the adversarial case: it's the log level most
//! likely to leak something onto the wrong stream if `observability::init`
//! were ever wired to the default writer instead of stderr.
//!
//! `serde_json::from_slice` already rejects trailing non-whitespace bytes
//! after the value it parses (it calls the deserializer's `end()` check
//! internally), so a bare `from_slice::<ScanSnapshot>` over the whole
//! captured stdout is sufficient to prove "exactly one value, nothing
//! else" — no need to hand-roll a `Deserializer` to check for leftovers.

#[cfg(test)]
mod support;

use anne_de_breuil::domain::ScanSnapshot;

#[test]
fn emit_json_stdout_is_pure_even_at_trace_level() {
    let output = support::anne_cmd()
        .args(["scan", "--emit-json"])
        .env("RUST_LOG", "trace")
        .output()
        .expect("anne scan --emit-json runs");

    assert!(
        output.status.success(),
        "expected a clean exit, got {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Result<ScanSnapshot, _> = serde_json::from_slice(&output.stdout);
    assert!(
        parsed.is_ok(),
        "stdout was not a bare ScanSnapshot with no leading/trailing noise: {} ({:?})",
        String::from_utf8_lossy(&output.stdout),
        parsed.err()
    );
}

#[test]
fn emit_json_stdout_is_pure_at_default_log_level_too() {
    let output = support::anne_cmd()
        .args(["scan", "--emit-json"])
        .output()
        .expect("anne scan --emit-json runs");

    assert!(output.status.success());
    let parsed: Result<ScanSnapshot, _> = serde_json::from_slice(&output.stdout);
    assert!(
        parsed.is_ok(),
        "stdout was not a bare ScanSnapshot: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
