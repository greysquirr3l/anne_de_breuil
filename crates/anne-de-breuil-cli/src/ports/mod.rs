//! Binary-local port traits, if any use case is only ever driven from the
//! CLI (e.g. `ProgressReporter`, see T19).

/// `anne update`'s view of a GitHub-releases-shaped source.
///
/// Consumer-owned by [`crate::application::update`] -- the only caller --
/// rather than living beside
/// [`crate::adapters::github_release::GitHubReleaseSource`], matching this
/// workspace's "port traits live in the handler that calls them, never in
/// the adapter" rule.
///
/// Two methods, not one per GitHub endpoint: `release` covers both
/// "latest" (`tag: None`) and a specific version (`tag: Some("v0.1.0")`,
/// for `anne update --version`), and `download_asset` is the one other
/// network operation the handler needs (the matched platform binary, and
/// separately `SHA256SUMS.txt`, both are "download this asset").
#[async_trait::async_trait]
pub trait ReleaseSource: Send + Sync {
    /// Fetches release metadata: `tag: None` for the latest release,
    /// `tag: Some(tag)` for a specific tagged release (e.g. `"v0.1.0"`).
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the response isn't valid
    /// JSON, or (for `Some(tag)`) no release with that tag exists.
    async fn release(&self, tag: Option<&str>) -> anyhow::Result<ReleaseInfo>;

    /// Downloads `url` (a [`ReleaseAsset::download_url`] from a prior
    /// [`Self::release`] call) and returns its raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the server responds with
    /// a non-success status.
    async fn download_asset(&self, url: &str) -> anyhow::Result<Vec<u8>>;
}

/// The subset of a GitHub release's JSON this crate needs.
#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    /// The release's tag name, e.g. `"v0.2.0"`.
    pub tag_name: String,
    /// Every asset (binary, `SHA256SUMS.txt`, SBOM, ...) attached to this release.
    pub assets: Vec<ReleaseAsset>,
}

/// One file attached to a GitHub release.
#[derive(Debug, Clone)]
pub struct ReleaseAsset {
    /// The asset's file name, e.g. `"anne-x86_64-unknown-linux-musl"`.
    pub name: String,
    /// The URL [`ReleaseSource::download_asset`] fetches this asset from.
    pub download_url: String,
}
