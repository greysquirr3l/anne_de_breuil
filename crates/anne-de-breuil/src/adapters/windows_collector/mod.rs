//! Native Win32 collection adapter: the fallback for hosts where
//! [`super::powershell_collector`] is absent, blocked by policy, or reduced
//! to Constrained Language Mode.
//!
//! Both adapters are expected to emit identical `Raw*` DTOs (T04's
//! [`crate::application::collect`] types) so a caller can swap between
//! them freely; [`tests::live_host_windows_collector_matches_powershell_collector`]
//! is the differential test that would catch the two drifting apart on a
//! real host.
//!
//! One struct per port, one file per concern, matching this task's own
//! anti-godfile instruction:
//!
//! - [`endpoints::NetstatEndpointSource`] — listening sockets via `netstat2`.
//! - [`processes::WindowsProcessResolver`] — process metadata via `sysinfo`,
//!   hosted services via [`services::enum_services_grouped_by_pid`].
//! - [`firewall::WmiFirewallPolicySource`] — firewall rules/profiles via WMI.
//! - [`signatures::WinTrustSignatureVerifier`] — Authenticode status via
//!   `WinVerifyTrust`, cached by path.
//!
//! [`firewall_join`] is deliberately *not* gated behind `#[cfg(windows)]`:
//! it is pure data transformation (WMI row DTOs plus the `InstanceID` join
//! and numeric-enum-to-domain-string mapping), so it compiles and runs its
//! fixture-driven tests on any host, including the macOS machine this was
//! written on. Only the files that actually call `wmi`/`netstat2`/`sysinfo`/
//! the `windows` crate's Win32 FFI are `#[cfg(windows)]`-gated; those crates
//! themselves compile fine as libraries on any host (`wmi` self-gates its
//! entire body behind `#![cfg(windows)]`; `windows` and `sysinfo` are
//! ordinary cross-platform dependencies already exercised that way by
//! `sysinfo` itself), so no `[target.'cfg(windows)'.dependencies]` split is
//! needed in this crate's `Cargo.toml` — the `#[cfg(windows)]` on the
//! *files that call them* is sufficient.
//!
//! All `unsafe` FFI (`EnumServicesStatusExW`, `WinVerifyTrust`) is confined
//! to [`services`] and [`signatures`] respectively, each wrapped in a safe
//! function annotated `#[expect(unsafe_code, reason = "...")]`. Neither
//! `netstat2` (which already keeps `GetExtendedTcpTable`/
//! `GetExtendedUdpTable` behind a safe API) nor `wmi`/`sysinfo` need any
//! `unsafe` of our own.
//!
//! # `ProcessAttribution` — not duplicated here
//!
//! This task's own code sketch shows a local `ProcessAttribution` enum
//! (`Attributed`/`ProcessGone`/`AmbiguousSharedSvchost`). It is
//! deliberately *not* introduced as a real type in this module:
//!
//! - **PID-vanished-between-calls** is already exactly what T04's
//!   [`crate::application::collect::ProcessAttribution::ProcessGone`]
//!   models, and the generic [`crate::application::collect::collect_endpoints`]
//!   algorithm already produces it whenever [`processes::WindowsProcessResolver::describe`]
//!   returns `None` for a pid `netstat2` reported. Because
//!   `collect_endpoints` always resolves endpoints *before* it resolves
//!   their owning processes, and this adapter's process snapshot is taken
//!   lazily on the first `describe` call, the real race the task describes
//!   (pid exits between the socket enumeration and the process query)
//!   falls straight out of that ordering with zero extra code.
//! - **Shared, unsplit `svchost.exe`** is represented by
//!   [`processes::WindowsProcessResolver::hosted_services`] returning every
//!   service [`services::enum_services_grouped_by_pid`] found under that
//!   pid, rather than guessing one. On a split-svchost host (Server 2016 or
//!   later, with more than 3.5 GB of RAM) that list is almost always one
//!   element; on an older or memory-constrained host sharing several
//!   services under one process it is several — and *that plurality is the
//!   ambiguity marker*. Introducing a second, adapter-local
//!   `ProcessAttribution`-shaped enum on top of the same `Vec<ServiceName>`
//!   the domain type already carries would be the
//!   duplicate-with-overlapping-meaning this task explicitly warns against
//!   (see T04's own note distinguishing its `ProcessAttribution` from T08's
//!   `Attribution`); returning the honest candidate list is not a guess,
//!   it is the fact.

pub mod firewall_join;

#[cfg(windows)]
mod endpoints;
#[cfg(windows)]
mod firewall;
#[cfg(windows)]
mod processes;
#[cfg(windows)]
mod services;
#[cfg(windows)]
mod signatures;

#[cfg(windows)]
pub use endpoints::NetstatEndpointSource;
#[cfg(windows)]
pub use firewall::WmiFirewallPolicySource;
#[cfg(windows)]
pub use processes::WindowsProcessResolver;
#[cfg(windows)]
pub use signatures::WinTrustSignatureVerifier;

#[cfg(windows)]
#[cfg(test)]
mod tests {
    use super::{
        NetstatEndpointSource, WinTrustSignatureVerifier, WindowsProcessResolver,
        WmiFirewallPolicySource,
    };
    use crate::application::collect::{CollectorSet, EndpointSource as _};

    /// Differential check: both collection adapters must agree on the
    /// listening-endpoint set of one real host. This never runs off
    /// Windows (the whole module is `#[cfg(windows)]`) and never runs
    /// without an operator opting in via `ANNE_LIVE_WINDOWS_TESTS`, since
    /// it needs a real host's `powershell.exe` and Win32 APIs, not a
    /// fixture.
    #[cfg_attr(not(windows), ignore)]
    #[tokio::test]
    async fn live_host_windows_collector_matches_powershell_collector() {
        if std::env::var("ANNE_LIVE_WINDOWS_TESTS").is_err() {
            return;
        }

        let ps = crate::adapters::powershell_collector::PowerShellCollector::new(
            std::time::Duration::from_secs(60),
        )
        .expect("embedded helper script writes to a temp file");
        let ps_endpoints = ps
            .listening_endpoints()
            .await
            .expect("live PowerShell collection");

        let endpoints = NetstatEndpointSource::new();
        let processes = WindowsProcessResolver::new();
        let firewall = WmiFirewallPolicySource::new();
        let signatures = WinTrustSignatureVerifier::new();
        let win32 = CollectorSet {
            endpoints: &endpoints,
            processes: &processes,
            firewall: &firewall,
            signatures: &signatures,
        };
        let win32_endpoints = win32
            .listening_endpoints()
            .await
            .expect("live Win32 collection");

        let mut ps_sorted = ps_endpoints;
        let mut win32_sorted = win32_endpoints;
        ps_sorted.sort_by(|a, b| {
            (a.protocol.as_str(), a.local_port).cmp(&(b.protocol.as_str(), b.local_port))
        });
        win32_sorted.sort_by(|a, b| {
            (a.protocol.as_str(), a.local_port).cmp(&(b.protocol.as_str(), b.local_port))
        });

        assert_eq!(
            ps_sorted
                .iter()
                .map(|e| (e.protocol.clone(), e.local_port))
                .collect::<Vec<_>>(),
            win32_sorted
                .iter()
                .map(|e| (e.protocol.clone(), e.local_port))
                .collect::<Vec<_>>(),
            "PowerShell and native Win32 collectors disagree on the listening-endpoint set"
        );
    }
}
