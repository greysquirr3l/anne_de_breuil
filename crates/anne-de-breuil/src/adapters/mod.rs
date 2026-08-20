//! Port implementations against the outside world (OS APIs, PowerShell,
//! SSH, `SQLite`, HTTP).
//!
//! All `unsafe` in this crate is confined to this module tree, wrapped in
//! a safe function and annotated with
//! `#[expect(unsafe_code, reason = "...")]`. Otherwise empty until the
//! first platform adapter lands (T05/T06/T07) — [`config`] is the first
//! real adapter-boundary concern: parsing untrusted TOML/env input into
//! typed configuration value objects. [`fonts`] is the second: vendored
//! WOFF2 assets compiled in behind `report-html`, so a collector-only
//! build carries none of that payload.

pub mod config;

#[cfg(feature = "report-html")]
pub mod fonts;
