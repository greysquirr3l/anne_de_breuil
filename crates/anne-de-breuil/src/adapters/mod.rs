//! Port implementations against the outside world (OS APIs, PowerShell,
//! SSH, `SQLite`, HTTP).
//!
//! All `unsafe` in this crate is confined to this module tree, wrapped in
//! a safe function and annotated with
//! `#[expect(unsafe_code, reason = "...")]`. Empty until the first
//! platform adapter lands (T05/T06/T07).
