//! Table-driven coverage over `support::malformed_argument_table()`: every
//! row must make the process exit with *some* status code, never die by
//! panic/abort/signal. `status.code()` returns `None` on Unix only when
//! the process was killed by a signal (SIGSEGV, SIGABRT from a Rust
//! panic-as-abort profile, etc.) — a clean `std::process::exit`-style
//! termination, even for a deliberately rejected argument, always yields
//! `Some(_)`.

#[cfg(test)]
mod support;

#[test]
fn malformed_arguments_never_panic() {
    for args in support::malformed_argument_table() {
        let output = support::anne_cmd()
            .args(&args)
            .output()
            .unwrap_or_else(|e| panic!("failed to even spawn anne {args:?}: {e}"));

        assert!(
            output.status.code().is_some(),
            "anne {args:?} did not exit cleanly (status: {:?}); stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
