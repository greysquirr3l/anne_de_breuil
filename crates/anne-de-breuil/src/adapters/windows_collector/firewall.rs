//! [`WmiFirewallPolicySource`]: firewall rules and profiles via WMI,
//! `root/standardcimv2`'s `MSFT_NetFirewallRule`/`MSFT_NetFirewallProfile`
//! (and their filter classes).
//!
//! Deliberately not `INetFwPolicy2::Rules` -- that COM interface only
//! surfaces the local policy store, which on a domain-managed host misses
//! most rules (anything pushed by GPO). `Get-NetFirewallRule`'s own
//! default `-PolicyStore ActiveStore` view is exactly a plain WMI query
//! against this namespace; no extra store-selection ceremony is needed
//! once `INetFwPolicy2` is out of the picture.
//!
//! Every query below is one bulk `SELECT *` against one WMI class --
//! never a per-rule round trip, which on a domain controller with
//! thousands of GPO-delivered rules is the difference between seconds and
//! minutes. [`super::firewall_join`] owns the `InstanceID` joins and the raw
//! numeric-to-domain-string mapping; this file only queries and hands
//! rows to it.
//!
//! `wmi::WMIConnection` is `!Send` (COM apartment-affine), so a connection
//! is opened, used, and dropped entirely inside one `spawn_blocking`
//! closure per call -- it never crosses an `.await` point, and only the
//! `Send` result (`Vec<RawRule>`/`Vec<RawProfile>`) returns to async code.

use async_trait::async_trait;
use wmi::WMIConnection;

use super::firewall_join::{
    WmiApplicationFilter, WmiFirewallProfile, WmiFirewallRule, WmiPortFilter, WmiServiceFilter,
    assemble_rules, profiles_from_wmi,
};
use crate::application::collect::{CollectError, FirewallPolicySource, RawProfile, RawRule};

/// Queries the host's effective (`ActiveStore`) firewall policy through WMI.
#[derive(Debug, Default)]
pub struct WmiFirewallPolicySource;

impl WmiFirewallPolicySource {
    /// Builds a source with no state to initialize -- each call opens its
    /// own WMI connection.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl FirewallPolicySource for WmiFirewallPolicySource {
    async fn inbound_rules(&self) -> Result<Vec<RawRule>, CollectError> {
        tokio::task::spawn_blocking(query_inbound_rules)
            .await
            .map_err(|source| CollectError::Spawn(source.to_string()))?
    }

    async fn profiles(&self) -> Result<Vec<RawProfile>, CollectError> {
        tokio::task::spawn_blocking(query_profiles)
            .await
            .map_err(|source| CollectError::Spawn(source.to_string()))?
    }
}

fn connect() -> Result<WMIConnection, CollectError> {
    WMIConnection::with_namespace_path("ROOT\\StandardCimv2")
        .map_err(|source| CollectError::Spawn(source.to_string()))
}

fn query_inbound_rules() -> Result<Vec<RawRule>, CollectError> {
    let conn = connect()?;

    // `PolicyStoreSourceType != 2` (Dynamic) excludes rules created
    // transiently at runtime (e.g. by IPsec or an app installer) rather
    // than a durable policy decision a report should audit -- matching
    // this task's own code sketch. Direction is filtered in Rust below,
    // not in WQL, to stay symmetric with how the PowerShell adapter (T05)
    // filters `RawRule::direction` post-parse rather than trusting a raw
    // numeric literal in the query text.
    let rules: Vec<WmiFirewallRule> = conn
        .raw_query("SELECT * FROM MSFT_NetFirewallRule WHERE PolicyStoreSourceType != 2")
        .map_err(|source| CollectError::Parse(source.to_string()))?;
    let port_filters: Vec<WmiPortFilter> = conn
        .raw_query("SELECT * FROM MSFT_NetFirewallPortFilter")
        .map_err(|source| CollectError::Parse(source.to_string()))?;
    let app_filters: Vec<WmiApplicationFilter> = conn
        .raw_query("SELECT * FROM MSFT_NetFirewallApplicationFilter")
        .map_err(|source| CollectError::Parse(source.to_string()))?;
    let service_filters: Vec<WmiServiceFilter> = conn
        .raw_query("SELECT * FROM MSFT_NetFirewallServiceFilter")
        .map_err(|source| CollectError::Parse(source.to_string()))?;

    Ok(
        assemble_rules(rules, &port_filters, &app_filters, &service_filters)
            .into_iter()
            .filter(|rule| rule.direction.eq_ignore_ascii_case("inbound"))
            .collect(),
    )
}

fn query_profiles() -> Result<Vec<RawProfile>, CollectError> {
    let conn = connect()?;
    let profiles: Vec<WmiFirewallProfile> = conn
        .raw_query("SELECT * FROM MSFT_NetFirewallProfile")
        .map_err(|source| CollectError::Parse(source.to_string()))?;
    Ok(profiles_from_wmi(profiles))
}
