//! Consumer-owned port traits.
//!
//! Each trait lives alongside the handler or use case that calls it, never
//! here as a shared grab-bag — this module only re-exports what individual
//! use-case modules declare. Empty until T04 (collector ports) and T14
//! (transport port) land.
