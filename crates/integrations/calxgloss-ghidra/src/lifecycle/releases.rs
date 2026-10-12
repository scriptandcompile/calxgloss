//! The GitHub releases API, as the bootstrap needs it.
//!
//! Both bootstrap artifacts come from GitHub releases, and the releases API
//! is the source of truth for *both* the download URL and the sha256 digest
//! (design §3.5: both repos expose `digest: "sha256:…"` directly on the
//! release asset). Every download is verified against that digest before it
//! is unzipped, so this module parses the digest rather than trusting a
//! side-channel checksum.
//!
//! The API base URL is a constructor input, not a constant: the integration
//! tests drive the whole bootstrap against a fake releases server, and an
//! optional token rides on every request for users hitting the anonymous
//! rate limit (`GHIDRA_MCP_GITHUB_TOKEN`).

use serde::Deserialize;
use std::path::Path;
use tracing::{debug, info};
use url::Url;

use crate::client::{GhidraError, Result, plugin_version_at_least};

/// The GhidraMCP extension repository (ADR-0001's pinned bridge).
pub const PLUGIN_REPO: &str = "bethington/ghidra-mcp";

/// The Ghidra repository.
pub const GHIDRA_REPO: &str = "NationalSecurityAgency/ghidra";

/// One release asset: the download URL plus the digest to verify it against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAsset {
    /// The asset file name, e.g. `GhidraMCP-6.0.0.zip`.
    pub name: String,
    /// Where to download it from.
    pub download_url: String,
    /// The sha256 digest as lowercase hex, when the API carries one. A
    /// missing digest means the download cannot be verified, which the
    /// bootstrap treats as a failure rather than a pass.
    pub sha256: Option<String>,
}

/// One GitHub release: its tag plus its assets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// The tag name, e.g. `v6.0.0` or `Ghidra_12.1.2_build`.
    pub tag: String,
    /// The release's assets.
    pub assets: Vec<ReleaseAsset>,
}

impl Release {
    /// The single extension zip of a GhidraMCP release.
    pub fn plugin_asset(&self) -> Option<&ReleaseAsset> {
        self.assets
            .iter()
            .find(|asset| asset.name.starts_with("GhidraMCP") && asset.name.ends_with(".zip"))
    }

    /// The single Ghidra zip of a Ghidra release.
    pub fn ghidra_asset(&self) -> Option<&ReleaseAsset> {
        self.assets
            .iter()
            .find(|asset| asset.name.starts_with("ghidra_") && asset.name.ends_with(".zip"))
    }
}

/// The GitHub API shape for a release asset. Unknown fields are ignored so
/// the API can grow without breaking the parse.
#[derive(Debug, Deserialize)]
struct ApiAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    digest: Option<String>,
}

/// The GitHub API shape for a release.
#[derive(Debug, Deserialize)]
struct ApiRelease {
    tag_name: String,
    #[serde(default)]
    assets: Vec<ApiAsset>,
}

impl From<ApiAsset> for ReleaseAsset {
    fn from(asset: ApiAsset) -> Self {
        // The API spells digests `sha256:<hex>`; anything else (a future
        // blake3, say) is not a digest this bootstrap can verify.
        let sha256 = asset
            .digest
            .as_deref()
            .and_then(|digest| digest.strip_prefix("sha256:"))
            .map(|hex| hex.trim().to_ascii_lowercase());
        Self {
            name: asset.name,
            download_url: asset.browser_download_url,
            sha256,
        }
    }
}

impl From<ApiRelease> for Release {
    fn from(release: ApiRelease) -> Self {
        Self {
            tag: release.tag_name,
            assets: release.assets.into_iter().map(ReleaseAsset::from).collect(),
        }
    }
}

/// What a progress reporter receives: bytes downloaded so far, and the total
/// size when the server names one.
type ProgressReporter = std::sync::Arc<dyn Fn(u64, Option<u64>) + Send + Sync>;

/// A minimal GitHub releases client.
#[derive(Clone)]
pub struct ReleasesApi {
    http: reqwest::Client,
    base: Url,
    token: Option<String>,
    progress: Option<ProgressReporter>,
}

impl std::fmt::Debug for ReleasesApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleasesApi")
            .field("base", &self.base)
            .field("token", &self.token.as_ref().map(|_| "<set>"))
            .field("progress", &self.progress.as_ref().map(|_| "<reporter>"))
            .finish()
    }
}

impl ReleasesApi {
    /// A client against `base` — `https://api.github.com` in production, a
    /// fake server in tests.
    ///
    /// # Errors
    ///
    /// Returns [`GhidraError::InvalidUrl`] if `base` is not a valid URL.
    pub fn new(base: &str) -> Result<Self> {
        let mut base = Url::parse(base)?;
        // Every path join below hangs off the base; a bare host comes back
        // with an empty path that would swallow the first segment.
        if base.path() == "" {
            base.set_path("/");
        }
        Ok(Self {
            http: reqwest::Client::new(),
            base,
            token: None,
            progress: None,
        })
    }

    /// Attach a GitHub token, for users hitting the anonymous rate limit.
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Report large-download progress to `reporter`: called every 32 MB with
    /// the bytes downloaded so far and the total size when the server names
    /// one — the ~570 MB Ghidra stream should never look like a hang.
    pub fn with_progress(
        mut self,
        reporter: impl Fn(u64, Option<u64>) + Send + Sync + 'static,
    ) -> Self {
        self.progress = Some(std::sync::Arc::new(reporter));
        self
    }

    /// The latest release of `repo` — the plugin-first entry point.
    pub async fn latest_release(&self, repo: &str) -> Result<Release> {
        let body = self.get(&format!("repos/{repo}/releases/latest")).await?;
        let release: ApiRelease =
            serde_json::from_value(body).map_err(|source| GhidraError::ReleasesApi {
                url: format!("repos/{repo}/releases/latest"),
                detail: source.to_string(),
            })?;
        Ok(release.into())
    }

    /// The release tagged exactly `tag`, or `None` when no such tag exists
    /// (a 404 is an ordinary answer here: the plugin's target Ghidra build
    /// may not use the `Ghidra_<ver>_build` tag spelling).
    pub async fn release_by_tag(&self, repo: &str, tag: &str) -> Result<Option<Release>> {
        let path = format!("repos/{repo}/releases/tags/{tag}");
        match self.try_get(&path).await? {
            None => Ok(None),
            Some(body) => {
                let release: ApiRelease =
                    serde_json::from_value(body).map_err(|source| GhidraError::ReleasesApi {
                        url: path,
                        detail: source.to_string(),
                    })?;
                Ok(Some(release.into()))
            }
        }
    }

    /// The release list of `repo`, newest first as the API returns it.
    pub async fn list_releases(&self, repo: &str) -> Result<Vec<Release>> {
        let body = self
            .get(&format!("repos/{repo}/releases?per_page=100"))
            .await?;
        let releases: Vec<ApiRelease> =
            serde_json::from_value(body).map_err(|source| GhidraError::ReleasesApi {
                url: format!("repos/{repo}/releases"),
                detail: source.to_string(),
            })?;
        Ok(releases.into_iter().map(Release::from).collect())
    }

    /// GET `path` (relative to the base) and require a JSON success body.
    async fn get(&self, path: &str) -> Result<serde_json::Value> {
        self.try_get(path)
            .await?
            .ok_or_else(|| GhidraError::ReleasesApi {
                url: path.to_string(),
                detail: "the API answered 404".to_string(),
            })
    }

    /// GET `path`; `None` on 404, an error on any other non-success status.
    async fn try_get(&self, path: &str) -> Result<Option<serde_json::Value>> {
        let url = self
            .base
            .join(path)
            .map_err(|source| GhidraError::ReleasesApi {
                url: path.to_string(),
                detail: source.to_string(),
            })?;
        let mut request = self
            .http
            .get(url.clone())
            .header("Accept", "application/vnd.github+json")
            .header(
                "User-Agent",
                concat!("calxgloss/", env!("CARGO_PKG_VERSION")),
            );
        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let response = request
            .send()
            .await
            .map_err(|source| GhidraError::ReleasesApi {
                url: url.to_string(),
                detail: source.to_string(),
            })?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            // GitHub's rate limits answer as 403 with the remaining budget
            // at zero (primary) or 429; the secondary limit answers 403 with
            // a `retry-after` instead. Either way the fix is a token or the
            // clock — a bare "HTTP 403" would hide that.
            let limited = status == reqwest::StatusCode::TOO_MANY_REQUESTS
                || (status == reqwest::StatusCode::FORBIDDEN
                    && (response
                        .headers()
                        .get("x-ratelimit-remaining")
                        .and_then(|value| value.to_str().ok())
                        == Some("0")
                        || response.headers().contains_key("retry-after")));
            if limited {
                return Err(GhidraError::RateLimited {
                    url: url.to_string(),
                    detail: format!("HTTP {status}"),
                });
            }
            return Err(GhidraError::ReleasesApi {
                url: url.to_string(),
                detail: format!("HTTP {status}"),
            });
        }
        let body = response
            .json()
            .await
            .map_err(|source| GhidraError::ReleasesApi {
                url: url.to_string(),
                detail: source.to_string(),
            })?;
        debug!(%url, "GitHub releases API answered");
        Ok(Some(body))
    }

    /// Stream `url` into `dest`, resuming a partial `.part` file over HTTP
    /// Range when one exists — a flaky connection must not refetch 570 MB.
    ///
    /// The caller verifies the digest afterwards; this function only moves
    /// bytes, so a completed download is not yet trusted.
    pub async fn download(&self, url: &str, dest: &Path) -> Result<()> {
        let existing = std::fs::metadata(dest).map(|meta| meta.len()).unwrap_or(0);
        let mut request = self.http.get(url).header(
            "User-Agent",
            concat!("calxgloss/", env!("CARGO_PKG_VERSION")),
        );
        if existing > 0 {
            request = request.header("Range", format!("bytes={existing}-"));
        }
        let mut response = request
            .send()
            .await
            .map_err(|source| GhidraError::ReleasesApi {
                url: url.to_string(),
                detail: source.to_string(),
            })?;
        let status = response.status();
        // A 206 continues the partial file; a plain 200 means the server
        // ignored the Range header, so the file starts over.
        let append = status == reqwest::StatusCode::PARTIAL_CONTENT;
        if !status.is_success() {
            return Err(GhidraError::ReleasesApi {
                url: url.to_string(),
                detail: format!("HTTP {status}"),
            });
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .append(append)
            .truncate(!append)
            .open(dest)
            .map_err(|source| GhidraError::BootstrapBlocked {
                reason: format!(
                    "the download could not be written to {}: {source}",
                    dest.display()
                ),
            })?;
        let mut downloaded = if append { existing } else { 0 };
        let mut last_report = downloaded;
        // The total the reporter sees: a 206's Content-Length is only the
        // remaining part, so the already-downloaded prefix counts toward it.
        let total = response
            .content_length()
            .map(|rest| if append { existing + rest } else { rest });
        while let Some(chunk) =
            response
                .chunk()
                .await
                .map_err(|source| GhidraError::ReleasesApi {
                    url: url.to_string(),
                    detail: source.to_string(),
                })?
        {
            std::io::Write::write_all(&mut file, &chunk).map_err(|_| {
                GhidraError::BootstrapBlocked {
                    reason: format!("the download could not be written to {}", dest.display()),
                }
            })?;
            downloaded += chunk.len() as u64;
            // Progress for a ~570 MB stream: a line every 32 MB, not a line
            // per chunk — in the log and to the reporter the CLI attached.
            if downloaded - last_report >= 32 * 1024 * 1024 {
                info!(url, downloaded, "Downloading Ghidra bootstrap artifact");
                if let Some(reporter) = &self.progress {
                    reporter(downloaded, total);
                }
                last_report = downloaded;
            }
        }
        info!(url, downloaded, "Download complete");
        if downloaded > last_report
            && let Some(reporter) = &self.progress
        {
            reporter(downloaded, total);
        }
        Ok(())
    }
}

/// The release tag Ghidra's repository uses for one build.
pub fn ghidra_tag(version: &str) -> String {
    format!("Ghidra_{version}_build")
}

/// The version a `Ghidra_<ver>_build` tag names, `None` for other tags.
pub fn version_from_tag(tag: &str) -> Option<&str> {
    tag.strip_prefix("Ghidra_")?.strip_suffix("_build")
}

/// The release whose Ghidra version is the nearest at-or-above `version`.
///
/// The exact-tag lookup is the first choice (design §3.5); this is its
/// fallback, and "nearest ≥" keeps a request from silently *down*grading to
/// an older build the plugin may not even support (a pinned request never
/// falls back here at all — it demands the exact build). Releases whose
/// tags do not name an orderable version are skipped.
pub fn nearest_release_at_least<'a>(releases: &'a [Release], version: &str) -> Option<&'a Release> {
    releases
        .iter()
        .filter(|release| {
            version_from_tag(&release.tag).is_some_and(|candidate| {
                super::install::parses_as_version(candidate)
                    && plugin_version_at_least(candidate, version)
            })
        })
        .min_by(|a, b| {
            let (va, vb) = (
                version_from_tag(&a.tag).unwrap_or_default(),
                version_from_tag(&b.tag).unwrap_or_default(),
            );
            compare_versions(va, vb)
        })
}

/// A total order over dotted-numeric versions, for "nearest ≥" selection.
pub(crate) fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |v: &str| -> Vec<u64> {
        v.split(['-', '+'])
            .next()
            .unwrap_or(v)
            .split('.')
            .filter_map(|part| part.parse::<u64>().ok())
            .collect()
    };
    let (pa, pb) = (parts(a), parts(b));
    for i in 0..pa.len().max(pb.len()) {
        match pa.get(i).unwrap_or(&0).cmp(pb.get(i).unwrap_or(&0)) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_parses_the_api_spelling_and_ignores_other_algorithms() {
        let asset = ReleaseAsset::from(ApiAsset {
            name: "GhidraMCP-6.0.0.zip".into(),
            browser_download_url: "https://example.invalid/a.zip".into(),
            digest: Some("sha256:AB12".into()),
        });
        assert_eq!(asset.sha256.as_deref(), Some("ab12"));
        let other = ApiAsset {
            name: "x.zip".into(),
            browser_download_url: "https://example.invalid/x.zip".into(),
            digest: Some("blake3:ff".into()),
        };
        assert_eq!(ReleaseAsset::from(other).sha256, None);
    }

    #[test]
    fn test_asset_pickers_follow_each_repos_naming() {
        let release = Release {
            tag: "v6.0.0".into(),
            assets: vec![
                ReleaseAsset {
                    name: "GhidraMCP-6.0.0.zip".into(),
                    download_url: "u".into(),
                    sha256: None,
                },
                ReleaseAsset {
                    name: "sha256sum.txt".into(),
                    download_url: "u".into(),
                    sha256: None,
                },
            ],
        };
        assert_eq!(
            release.plugin_asset().map(|a| &a.name),
            Some(&"GhidraMCP-6.0.0.zip".to_string())
        );

        let ghidra = Release {
            tag: "Ghidra_12.1.2_build".into(),
            assets: vec![ReleaseAsset {
                name: "ghidra_12.1.2_PUBLIC_20250603.zip".into(),
                download_url: "u".into(),
                sha256: None,
            }],
        };
        assert!(ghidra.ghidra_asset().is_some());
    }

    #[test]
    fn test_nearest_at_least_picks_the_smallest_candidate_not_the_newest() {
        // The plugin wants 12.1.2; the repo has 12.1.4 (newest, listed first)
        // and 12.1.3 — the nearest ≥ is 12.1.3, never a downgrade and never
        // an unrequested jump to the newest.
        let releases = sample_releases(&["12.1.4", "12.1.3", "12.1.1", "junk"]);
        let found = nearest_release_at_least(&releases, "12.1.2").expect("a candidate");
        assert_eq!(found.tag, "Ghidra_12.1.3_build");
    }

    #[test]
    fn test_exact_match_wins_over_a_higher_candidate() {
        let releases = sample_releases(&["12.1.4", "12.1.2"]);
        let found = nearest_release_at_least(&releases, "12.1.2").expect("a candidate");
        assert_eq!(found.tag, "Ghidra_12.1.2_build");
    }

    #[test]
    fn test_nothing_at_or_above_is_no_candidate() {
        let releases = sample_releases(&["12.1.1", "12.1.0"]);
        assert!(nearest_release_at_least(&releases, "12.1.2").is_none());
        assert!(nearest_release_at_least(&[], "12.1.2").is_none());
    }

    /// Releases tagged `Ghidra_<v>_build` for each version (junk included).
    fn sample_releases(versions: &[&str]) -> Vec<Release> {
        versions
            .iter()
            .map(|v| Release {
                tag: ghidra_tag(v),
                assets: vec![],
            })
            .collect()
    }

    #[test]
    fn test_tag_round_trip() {
        assert_eq!(ghidra_tag("12.1.2"), "Ghidra_12.1.2_build");
        assert_eq!(version_from_tag("Ghidra_12.1.2_build"), Some("12.1.2"));
        assert_eq!(version_from_tag("v6.0.0"), None);
    }
}
