//! The one vendored static asset the portal serves: htmx's runtime.
//!
//! Same reasoning as `adapters::fonts` for the standalone HTML report --
//! compiled in via `include_bytes!`, never fetched from a CDN at view
//! time, since this project's "no external resource fetch" rule applies
//! to every artifact it ships, not just the offline report. Provenance
//! and license: `THIRD_PARTY_LICENSES.md` at the repository root.

/// htmx 2.0.4's minified runtime, unmodified from upstream. `pub` rather
/// than `pub(crate)` -- the `assets` module itself is private to
/// `adapters::portal`, which already caps this item's real reach, so a
/// narrower marker here would be redundant.
pub const HTMX_JS: &[u8] = include_bytes!("../../../assets/vendor/htmx.min.js");

/// Recorded at vendor time; only the hash-verification test below reads
/// this, so it's `#[cfg(test)]`-only rather than a `dead_code` warning in
/// a normal build.
#[cfg(test)]
const HTMX_JS_SHA256_HEX: &str = "e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447";

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use sha2::{Digest as _, Sha256};

    use super::{HTMX_JS, HTMX_JS_SHA256_HEX};

    #[test]
    fn vendored_htmx_matches_recorded_hash() {
        let digest = Sha256::digest(HTMX_JS);
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            let _ = write!(hex, "{byte:02x}");
        }
        assert_eq!(hex, HTMX_JS_SHA256_HEX);
    }

    #[test]
    fn vendored_htmx_is_the_expected_library() {
        // Cheap sanity check that this is genuinely htmx and not an empty
        // or truncated file that happens to match some stale hash.
        let text = String::from_utf8_lossy(HTMX_JS);
        assert!(text.contains("htmx"));
    }
}
