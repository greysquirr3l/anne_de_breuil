//! [`GitHubReleaseSource`]: the [`ReleaseSource`] port implemented against
//! the real GitHub REST API.
//!
//! Unlike `anne_de_breuil::adapters::prober::HttpProber` (built to probe
//! *arbitrary, user-supplied* targets, where a redirect could be an SSRF
//! vector and is therefore disabled entirely), this client's target host
//! is fixed and trusted -- `api.github.com`, or whatever `api_base` a
//! caller constructs it with -- and GitHub's own release-asset download
//! URLs redirect to object storage as a matter of course, so this client
//! uses `reqwest`'s normal (bounded) redirect policy rather than
//! disabling it.

use serde::Deserialize;

use crate::ports::{ReleaseAsset, ReleaseInfo, ReleaseSource};

/// The real GitHub REST API's base URL.
///
/// `GitHubReleaseSource::new`'s `api_base` parameter defaults to this in
/// production; tests point it at a local fixture server instead, so no
/// test ever makes a real network call.
pub const GITHUB_API_BASE: &str = "https://api.github.com";

/// This repository's `owner/repo` slug, as GitHub's API addresses it.
/// Parsed from `Cargo.toml`'s `repository` field at compile time rather
/// than duplicated as a second literal that could drift from it.
pub fn owner_repo() -> anyhow::Result<String> {
    let repo_url = env!("CARGO_PKG_REPOSITORY");
    let slug = repo_url
        .strip_prefix("https://github.com/")
        .ok_or_else(|| anyhow::anyhow!("CARGO_PKG_REPOSITORY {repo_url} is not a github.com URL"))?
        .trim_end_matches('/');
    anyhow::ensure!(
        slug.matches('/').count() == 1,
        "CARGO_PKG_REPOSITORY {repo_url} doesn't look like https://github.com/<owner>/<repo>"
    );
    Ok(slug.to_owned())
}

/// [`ReleaseSource`] implementation against the real GitHub REST API.
pub struct GitHubReleaseSource {
    api_base: String,
    owner_repo: String,
    client: reqwest::Client,
}

/// The subset of GitHub's release JSON this crate deserializes.
#[derive(Debug, Deserialize)]
struct RawRelease {
    tag_name: String,
    assets: Vec<RawAsset>,
}

#[derive(Debug, Deserialize)]
struct RawAsset {
    name: String,
    browser_download_url: String,
}

impl From<RawRelease> for ReleaseInfo {
    fn from(raw: RawRelease) -> Self {
        Self {
            tag_name: raw.tag_name,
            assets: raw
                .assets
                .into_iter()
                .map(|asset| ReleaseAsset {
                    name: asset.name,
                    download_url: asset.browser_download_url,
                })
                .collect(),
        }
    }
}

impl GitHubReleaseSource {
    /// Builds a client against `api_base` (production: [`GITHUB_API_BASE`];
    /// tests: a local fixture server) for `owner_repo` (e.g.
    /// `"greysquirr3l/anne_de_breuil"`, see [`owner_repo`]).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying HTTP client cannot be
    /// constructed.
    pub fn new(api_base: String, owner_repo: String) -> anyhow::Result<Self> {
        let user_agent = format!("anne-de-breuil/{}", env!("CARGO_PKG_VERSION"));
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_mins(1))
            .user_agent(user_agent)
            .build()?;
        Ok(Self {
            api_base,
            owner_repo,
            client,
        })
    }
}

#[async_trait::async_trait]
impl ReleaseSource for GitHubReleaseSource {
    async fn release(&self, tag: Option<&str>) -> anyhow::Result<ReleaseInfo> {
        let url = tag.map_or_else(
            || format!("{}/repos/{}/releases/latest", self.api_base, self.owner_repo),
            |tag| {
                format!(
                    "{}/repos/{}/releases/tags/{tag}",
                    self.api_base, self.owner_repo
                )
            },
        );
        let response = self
            .client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .with_context_url(&url)?
            .error_for_status()
            .with_context_url(&url)?;
        let raw: RawRelease = response.json().await.with_context_url(&url)?;
        Ok(raw.into())
    }

    async fn download_asset(&self, url: &str) -> anyhow::Result<Vec<u8>> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .with_context_url(url)?
            .error_for_status()
            .with_context_url(url)?;
        Ok(response.bytes().await.with_context_url(url)?.to_vec())
    }
}

/// Small local extension trait so every fallible step above can attach
/// which URL it was talking to, without repeating
/// `.with_context(|| format!("... {url}"))` at each call site.
trait WithContextUrl<T> {
    fn with_context_url(self, url: &str) -> anyhow::Result<T>;
}

impl<T, E> WithContextUrl<T> for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn with_context_url(self, url: &str) -> anyhow::Result<T> {
        use anyhow::Context as _;
        self.with_context(|| format!("requesting {url}"))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    use super::{GitHubReleaseSource, ReleaseSource, owner_repo};

    #[test]
    fn owner_repo_parses_the_real_cargo_toml_repository_field() {
        // Pinned to the real value rather than a synthetic one -- this is
        // exactly the field `anne update` reads at runtime, so a test
        // double here would prove nothing about whether the real one is
        // still shaped the way this parser expects.
        assert_eq!(owner_repo().unwrap(), "greysquirr3l/anne_de_breuil");
    }

    /// Minimal blocking single-response HTTP/1.1 fixture -- no tokio
    /// runtime needed, since `#[tokio::test]` below only needs an async
    /// context for the `reqwest` client, not for the server side.
    fn respond_once(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn release_parses_a_real_shaped_github_response() {
        let body = r#"{
            "tag_name": "v0.2.0",
            "assets": [
                {"name": "anne-x86_64-unknown-linux-musl", "browser_download_url": "http://example.invalid/anne-x86_64-unknown-linux-musl"},
                {"name": "SHA256SUMS.txt", "browser_download_url": "http://example.invalid/SHA256SUMS.txt"}
            ]
        }"#;
        let base = respond_once(body);
        let source = GitHubReleaseSource::new(base, "owner/repo".to_owned()).unwrap();
        let release = source.release(None).await.unwrap();
        assert_eq!(release.tag_name, "v0.2.0");
        assert_eq!(release.assets.len(), 2);
        let first = release.assets.first().expect("two assets were parsed");
        assert_eq!(first.name, "anne-x86_64-unknown-linux-musl");
    }
}
