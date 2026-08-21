//! CLI command handlers. Each subcommand has its own file; this module
//! just re-exports their `run` entry points so `crate::run` can dispatch.

pub mod diff;
pub mod inventory;
pub mod report;
pub mod scan;
pub mod self_hash;
pub mod version;
