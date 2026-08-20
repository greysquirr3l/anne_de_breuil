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
//! `windows-collector`. [`windows_collector`] is the sixth: the native
//! Win32 fallback for hosts where PowerShell is absent, blocked by policy,
//! or reduced to Constrained Language Mode — behind `windows-collector`
//! *and* `#[cfg(windows)]`, since it calls `netstat2`/`sysinfo`/`wmi`/the
//! `windows` crate directly rather than shelling out. Only its pure,
//! platform-independent WMI-row-to-`Raw*`-DTO mapping
//! ([`windows_collector::firewall_join`]) compiles unconditionally, so it
//! can be fixture-tested on any host. [`linux_collector`] is the seventh:
//! the Linux collection adapter, behind `linux-collector`, following the
//! same split as `windows_collector` -- its parsing/classification logic
//! (`/proc/net` socket-table parsing, cgroup-to-systemd-unit extraction,
//! nftables netlink wire framing) compiles and is fixture-tested on any
//! host, while the concrete adapter structs that actually open sockets or
//! read `/proc` are `#[cfg(target_os = "linux")]`-gated. [`inventory`] is
//! the eighth: parsing an operator-authored TOML inventory file of remote
//! hosts into typed value objects, always compiled in since inventory
//! parsing has no platform dependency. [`tls_probe`] is the ninth: a
//! second [`crate::application::identify::Prober`] implementation, sibling
//! to [`prober::HttpProber`], that completes TLS handshakes and inspects
//! whatever certificate chain the target presents, including a chain that
//! fails ordinary validation — that's the finding, not a reason to abort.
//! Its non-validating `ClientConfig` is confined to a private submodule
//! unreachable from anywhere else in this tree; see that module's own doc
//! comment for the confinement mechanism and its enforcing test. [`ssh_transport`]
//! is the tenth: [`crate::application::remote::RemoteTransport`] implemented
//! over SSH via `russh`/`russh-sftp`, behind the `ssh` feature — opportunistic,
//! never assumed; a host with no working SSH demotes to `TargetStrategy::Probe`
//! rather than aborting the run.

pub mod config;
pub mod inventory;
pub mod prober;
pub mod snapshot_store;
pub mod tls_probe;

#[cfg(feature = "report-html")]
pub mod fonts;

#[cfg(feature = "windows-collector")]
pub mod powershell_collector;

#[cfg(feature = "windows-collector")]
pub mod windows_collector;

#[cfg(feature = "linux-collector")]
pub mod linux_collector;

#[cfg(feature = "ssh")]
pub mod ssh_transport;
