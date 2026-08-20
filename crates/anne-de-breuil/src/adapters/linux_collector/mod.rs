//! Linux collection adapter, behind `linux-collector`.
//!
//! One struct per port, one file per concern, matching this task's own
//! anti-godfile instruction, and the same pure-vs-platform split
//! [`super::windows_collector`] already established:
//!
//! - [`endpoints::LinuxEndpointSource`] — listening sockets, netlink
//!   `INET_DIAG` via `netstat2` first, falling back to parsing
//!   [`proc_net`]'s `/proc/net/{tcp,tcp6,udp,udp6}` when netlink itself
//!   fails.
//! - [`processes::LinuxProcessResolver`] — process metadata via `sysinfo`
//!   plus `/proc/<pid>/exe`; hosted services via [`services`] reading
//!   `/proc/<pid>/cgroup` and [`cgroup_unit`] extracting the systemd unit.
//! - [`firewall::LinuxFirewallPolicySource`] — nftables base-chain policy
//!   via a hand-driven `NETLINK_NETFILTER` socket; [`nft_wire`] owns the
//!   wire framing and the empty-vs-unreadable classification.
//! - [`signatures::LinuxSignatureVerifier`] — always
//!   [`crate::domain::SignatureStatus::NotApplicable`]; there is no Linux
//!   Authenticode equivalent (package-manager provenance is a documented
//!   future task, not this one).
//!
//! [`proc_net`], [`cgroup_unit`], and [`nft_wire`] are deliberately *not*
//! `#[cfg(target_os = "linux")]`-gated: each is pure text/byte parsing with
//! no platform API calls, so all three compile and run their fixture-driven
//! tests on any host, including the macOS machine this was written on --
//! this task's own instruction ("no root and no live kernel state
//! required"). Only [`endpoints`], [`processes`], [`services`],
//! [`firewall`], and [`signatures`] -- the files that actually open a
//! netlink socket, call `sysinfo`/`netstat2`, or read a real `/proc` tree
//! -- are `#[cfg(target_os = "linux")]`-gated.
//!
//! Zero `std::process::Command` anywhere in this module: no `systemctl`,
//! no `nft`, no `dpkg`/`rpm`. Every concern reads a kernel interface
//! (netlink, `/proc`) directly.
//!
//! # nftables library choice
//!
//! This task names `nftnl`/`rustables` as the expected libraries. Both
//! bind `libnftnl`, a native C library located via `pkg-config` at build
//! time; confirmed by trying it directly (`cargo build` against a
//! throwaway crate depending on `nftnl` fails in `nftnl-sys`'s build
//! script: `Package libnftnl was not found in the pkg-config search
//! path`), neither `libnftnl` nor a musl build of it exists on this dev
//! machine or its cross-compile toolchain, and there's no "bundled"/
//! "vendored" Cargo feature on either crate to build it from source the
//! way e.g. `rusqlite`'s `bundled` feature does for `SQLite`. Adding either
//! as a plain dependency breaks `cargo build` on macOS outright, which
//! fails this task's own "must not break the build" requirement before
//! even reaching Linux. `rustables` additionally ships GPL-3.0-or-later,
//! which doesn't fit this workspace's `MIT OR Apache-2.0` licensing.
//!
//! The mitigation is [`nft_wire`]: a small, hand-rolled, pure-Rust
//! `NETLINK_NETFILTER` client built on `netlink-sys` (already a proven
//! dependency in this workspace's cross-compile story -- `netstat2`'s own
//! Linux integration depends on the same `netlink-sys`/`netlink-packet-*`
//! family and already cross-compiles cleanly for `x86_64-unknown-linux-musl`
//! in this project). It decodes `NEWCHAIN` dump responses to
//! table/name/hook/policy (chain granularity), not full per-rule match
//! expressions -- decoding `NFTA_RULE_EXPRESSIONS`' deeply nested
//! attribute trees is materially more work and is left as a documented
//! `TODO(future task)` on [`nft_wire::nft_chain_to_raw_rule`] rather than
//! guessed at. This dev machine has no Linux kernel to validate the wire
//! decoding against real `NEWCHAIN` bytes; [`nft_wire`]'s module docs are
//! explicit about that, the same way [`super::windows_collector::firewall`]'s
//! docs already are about its own unverified WMI numeric encodings.

pub mod cgroup_unit;
pub mod nft_wire;
pub mod proc_net;

#[cfg(target_os = "linux")]
mod endpoints;
#[cfg(target_os = "linux")]
mod firewall;
#[cfg(target_os = "linux")]
mod processes;
#[cfg(target_os = "linux")]
mod services;
#[cfg(target_os = "linux")]
mod signatures;

#[cfg(target_os = "linux")]
pub use endpoints::LinuxEndpointSource;
#[cfg(target_os = "linux")]
pub use firewall::LinuxFirewallPolicySource;
#[cfg(target_os = "linux")]
pub use processes::LinuxProcessResolver;
#[cfg(target_os = "linux")]
pub use signatures::LinuxSignatureVerifier;

/// Bundles the four Linux collector adapters for one host.
#[cfg(target_os = "linux")]
pub struct LinuxCollectors {
    /// The listening-socket source for this run.
    pub endpoints: LinuxEndpointSource,
    /// The process resolver for this run.
    pub processes: LinuxProcessResolver,
    /// The firewall policy source for this run.
    pub firewall: LinuxFirewallPolicySource,
    /// The signature verifier for this run.
    pub signatures: LinuxSignatureVerifier,
}

#[cfg(target_os = "linux")]
impl LinuxCollectors {
    /// Builds every adapter with no state initialized yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            endpoints: LinuxEndpointSource::new(),
            processes: LinuxProcessResolver::new(),
            firewall: LinuxFirewallPolicySource::new(),
            signatures: LinuxSignatureVerifier::new(),
        }
    }
}

#[cfg(target_os = "linux")]
impl Default for LinuxCollectors {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds the Linux collector adapters for this host.
///
/// # Errors
///
/// Returns [`crate::application::collect::CollectError::UnsupportedPlatform`]
/// on any non-Linux host — macOS/other-platform collection is out of
/// scope for this phase, but must not break the build, so this factory
/// fails at runtime rather than the crate failing to compile off Linux.
#[cfg(target_os = "linux")]
pub const fn build() -> Result<LinuxCollectors, crate::application::collect::CollectError> {
    Ok(LinuxCollectors::new())
}

/// The off-Linux counterpart to the `#[cfg(target_os = "linux")]` [`build`] above.
///
/// Shares its name and error type so a caller can invoke either
/// unconditionally. [`core::convert::Infallible`] stands in for
/// [`LinuxCollectors`] as the success type rather than duplicating that
/// struct's definition for a platform that will never construct one.
#[cfg(not(target_os = "linux"))]
pub const fn build() -> Result<core::convert::Infallible, crate::application::collect::CollectError>
{
    Err(crate::application::collect::CollectError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn build_reports_unsupported_platform_off_linux() {
        let result = super::build();
        assert!(matches!(
            result,
            Err(crate::application::collect::CollectError::UnsupportedPlatform)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_succeeds_on_linux() {
        assert!(super::build().is_ok());
    }
}
