//! `anne --self-hash`: a bare, subcommand-less invocation mode.
//!
//! The pushed collector binary runs this remotely so
//! `SshTransport::run_and_collect`/`push_exec_collect_remove` can verify it
//! wasn't tampered with in transit before ever trusting its `--emit-json`
//! output.
//!
//! `RemoteCommand::new(remote_path.as_str(), ["--self-hash"])` — the exact
//! shape `run_and_collect` invokes — has no subcommand at all, just this
//! one flag. `Cli`'s `#[command(subcommand)] command: Command` field is
//! required, so this mode can never go through ordinary `Cli::parse()`;
//! `main` checks for it first, the same way some CLIs special-case
//! `--version` ahead of full argument parsing.

use anne_de_breuil::adapters::binary_hash::{self, BinaryHashError};

/// `true` if `args` (argv, including argv[0]) is exactly a bare
/// `--self-hash` invocation — the one shape `push_exec_collect_remove`
/// ever produces.
#[must_use]
pub fn is_self_hash_invocation(args: &[String]) -> bool {
    args.len() == 2 && args.get(1).map(String::as_str) == Some("--self-hash")
}

/// Hashes this process's own executable and prints the lowercase hex
/// digest to stdout, nothing else.
///
/// `run_and_collect` trims and string-compares this output verbatim
/// against the hash it computed locally, over the same binary, before
/// push.
///
/// # Errors
///
/// Returns [`BinaryHashError`] if the running executable can't be located
/// or read — a real, if extremely unlikely, error path; never a panic.
pub fn run() -> Result<(), BinaryHashError> {
    let (_path, hash) = binary_hash::locate_and_hash_current_exe()?;
    println!("{hash}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_self_hash_invocation;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn bare_self_hash_flag_is_recognised() {
        assert!(is_self_hash_invocation(&args(&["anne", "--self-hash"])));
    }

    #[test]
    fn self_hash_combined_with_anything_else_is_not_recognised() {
        // `push_exec_collect_remove` only ever invokes this exact bare
        // shape -- anything else falls through to ordinary clap parsing,
        // which will itself reject an unrecognised combination.
        assert!(!is_self_hash_invocation(&args(&[
            "anne",
            "--self-hash",
            "extra"
        ])));
        assert!(!is_self_hash_invocation(&args(&[
            "anne",
            "scan",
            "--self-hash"
        ])));
    }

    #[test]
    fn no_arguments_at_all_is_not_recognised() {
        assert!(!is_self_hash_invocation(&args(&["anne"])));
        assert!(!is_self_hash_invocation(&[]));
    }

    #[test]
    fn unrelated_flag_is_not_recognised() {
        assert!(!is_self_hash_invocation(&args(&["anne", "--version"])));
    }
}
