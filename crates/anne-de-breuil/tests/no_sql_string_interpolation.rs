//! T30's own regression check for the parameterised-query invariant T28
//! already established by reading `adapters/snapshot_store/sqlite.rs` in
//! full (see `docs/security-audit.md`'s A05:2025 section) — this pins the
//! same fact against the file's real source text so a future edit that
//! reintroduces string-built SQL fails a test, not just a re-read.
//!
//! Lives in this crate's own `tests/` directory, not inside
//! `sqlite.rs`'s own `#[cfg(test)] mod tests`, deliberately: a test that
//! `include_str!`s a file and greps it for a literal substring must not
//! live in that same file, or the search pattern's own string literal
//! (`"format!(\"SELECT"`) becomes a self-matching false positive.

#![cfg(feature = "store-sqlite")]

const SQLITE_ADAPTER_SOURCE: &str = include_str!("../src/adapters/snapshot_store/sqlite.rs");

#[test]
fn no_sql_string_interpolation_in_sqlite_adapter() {
    for verb in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
        let needle = format!("format!(\"{verb}");
        assert!(
            !SQLITE_ADAPTER_SOURCE.contains(&needle),
            "found string-built SQL: {needle}"
        );
    }
}
