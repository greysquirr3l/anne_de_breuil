//! Every subcommand must respond to `--help` successfully — clap gives
//! this for free from the `Subcommand` derive's doc comments, but it's
//! still worth pinning as a real test: a `#[command(subcommand)]` field
//! that's accidentally made non-exhaustive, or a doc-comment typo that
//! breaks clap's parser, would otherwise only surface at manual testing
//! time.

#[cfg(test)]
mod support;

use predicates::prelude::*;

#[test]
fn every_subcommand_has_help_text() {
    for sub in ["scan", "diff", "report", "inventory", "version", "update"] {
        support::anne_cmd().args([sub, "--help"]).assert().success();
    }
}

#[test]
fn scan_help_lists_the_redaction_flags() {
    for flag in [
        "--include-command-line",
        "--include-executable-path",
        "--include-service-path",
        "--include-disabled-firewall-rules",
    ] {
        support::anne_cmd()
            .args(["scan", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains(flag));
    }
}

#[test]
fn the_inventory_validate_subcommand_has_help_text() {
    support::anne_cmd()
        .args(["inventory", "validate", "--help"])
        .assert()
        .success();
}

#[test]
fn top_level_help_succeeds() {
    support::anne_cmd().arg("--help").assert().success();
}
