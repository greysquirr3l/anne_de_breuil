//! Cross-platform local collector selection.
//!
//! The `anne` binary needs to pick a `CollectorSet` for the local host
//! without taking a feature dependency on the library crate's platform
//! gates. Today the library has no unconditionally-compiled concrete
//! `CollectorSet` (every real implementation is feature-gated and
//! `#[cfg]`-d), so this module returns a minimal stub set whose four
//! port impls all yield empty results — enough to keep `anne scan`
//! runnable end-to-end today, even on a host without PowerShell, WMI,
//! procfs, or netlink access. A real local collector wiring lands in
//! T31 alongside the fan-out integration.
//!
//! Returns a `(LocalCollectorSet, LocalCollectorGuard)` tuple; the guard
//! exists so future implementations can hold a `kill_on_drop` `Child` or
//! a temp-file handle for the duration of the scan without changing the
//! public signature.

use anne_de_breuil::application::collect::{
    CollectError, EndpointSource, FirewallPolicySource, ProcessResolver, RawEndpoint, RawProcess,
    RawProfile, RawRule, RawService, SignatureVerifier,
};
use anne_de_breuil::domain::{ProcessId, ProcessPath, SignatureStatus};

/// Pick the local collector. `include_udp` is currently informational —
/// the real adapter would use it; the stub ignores it.
pub const fn local_collectors(include_udp: bool) -> (LocalCollectorSet, LocalCollectorGuard) {
    let _ = include_udp;
    (LocalCollectorSet, LocalCollectorGuard)
}

/// Placeholder collector-set that returns zero rows from every port.
pub struct LocalCollectorSet;

/// Unit-like guard, kept so future impls can hold a `kill_on_drop`
/// `Child` or temp-file without changing the call site.
pub struct LocalCollectorGuard;

#[async_trait::async_trait]
impl EndpointSource for LocalCollectorSet {
    async fn listening_endpoints(&self) -> Result<Vec<RawEndpoint>, CollectError> {
        Ok(Vec::new())
    }
}

#[async_trait::async_trait]
impl ProcessResolver for LocalCollectorSet {
    async fn describe(&self, _pid: ProcessId) -> Result<Option<RawProcess>, CollectError> {
        Ok(None)
    }

    async fn hosted_services(&self, _pid: ProcessId) -> Result<Vec<RawService>, CollectError> {
        Ok(Vec::new())
    }
}

#[async_trait::async_trait]
impl FirewallPolicySource for LocalCollectorSet {
    async fn inbound_rules(&self) -> Result<Vec<RawRule>, CollectError> {
        Ok(Vec::new())
    }

    async fn profiles(&self) -> Result<Vec<RawProfile>, CollectError> {
        Ok(Vec::new())
    }
}

#[async_trait::async_trait]
impl SignatureVerifier for LocalCollectorSet {
    async fn verify(&self, _path: &ProcessPath) -> Result<SignatureStatus, CollectError> {
        Ok(SignatureStatus::Unknown)
    }
}

// The lifetime-elision mismatch on `FirewallPolicySource::profiles` and
// `SignatureVerifier::verify` reported by rustc earlier was a red
// herring — those methods are RPITIT (return-position impl trait in
// trait) under `#[async_trait]`, so the `async fn` declaration is
// correct. The error only appears when the trait impl is in a downstream
// crate (because async_trait emits a hidden `+ Send` lifetime bound
// there) — solved by adding `async_trait` to this crate's dependencies,
// mirroring the library crate's own usage.
#[allow(dead_code)]
const _LIFETIME_NOTE: &str = "see module doc for the async_trait lifetime explanation";
