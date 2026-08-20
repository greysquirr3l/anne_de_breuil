//! Port implementations against the outside world (OS APIs, PowerShell,
//! SSH, `SQLite`, HTTP).
//!
//! All `unsafe` in this crate is confined to this module tree, wrapped in
//! a safe function and annotated with
//! `#[expect(unsafe_code, reason = "...")]`. [`config`] is the first
//! real adapter-boundary concern: parsing untrusted TOML/env input into
//! typed configuration value objects. [`fonts`] is the second: vendored
//! WOFF2 assets compiled in behind `report-html`, so a collector-only
//! build carries none of that payload. [`snapshot_store`] is the third:
//! filesystem and (behind `store-sqlite`) `SQLite` implementations of the
//! [`crate::application::SnapshotStore`] port. [`prober`] is the fourth:
//! [`crate::application::identify::Prober`] implemented against `reqwest`
//! — always compiled in, since probing is a runtime opt-in behind a future
//! `--probe` CLI flag, not a Cargo feature. [`powershell_collector`] is
//! the fifth: the primary Windows collection adapter, behind
//! `windows-collector` — a native Win32 fallback (T06) is expected to sit
//! alongside it under the same feature.

pub mod config;
pub mod prober;
pub mod snapshot_store;

#[cfg(feature = "report-html")]
pub mod fonts;

#[cfg(feature = "windows-collector")]
pub mod powershell_collector;
