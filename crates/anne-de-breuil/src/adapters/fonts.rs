//! Vendored OFL font subsets, compiled directly into the binary.
//!
//! Four faces only: Instrument Serif 400 (titles, italic callouts), Geist
//! 400 and 500 (labels, body), Geist Mono 400 (technical content). Raw
//! WOFF2 bytes are embedded via `include_bytes!` — never pre-encoded
//! base64, since that pays the 4/3 inflation in the binary as well as in
//! every report. The base64 `data:` URI is computed lazily, once per
//! process, the first time a report actually needs it, and reused for
//! every report rendered in the same run.
//!
//! Provenance and hashes: `assets/fonts/manifest.toml`. License texts:
//! `assets/fonts/OFL-instrument-serif.txt` and `assets/fonts/OFL-geist.txt`,
//! reproduced in full in `THIRD_PARTY_LICENSES.md` at the repository root.
//!
//! Gated behind `report-html` so a collector-only build carries none of
//! this payload onto a remote host — see
//! `collector_only_build_contains_zero_font_bytes` below for the test that
//! actually proves it.

use std::fmt::Write as _;
use std::sync::LazyLock;

use base64::Engine as _;
use sha2::{Digest, Sha256};

/// One vendored font face: raw WOFF2 bytes plus the SHA-256 recorded in
/// `assets/fonts/manifest.toml` at vendor time.
pub struct VendoredFont {
    pub bytes: &'static [u8],
    pub sha256_hex: &'static str,
}

pub const INSTRUMENT_SERIF_400: VendoredFont = VendoredFont {
    bytes: include_bytes!("../../assets/fonts/instrument-serif-400-latin.woff2"),
    sha256_hex: "8950eaf16fea21c002eab52108e59b6ee31a07175cb6b59515ba423ef2c83706",
};

pub const GEIST_400: VendoredFont = VendoredFont {
    bytes: include_bytes!("../../assets/fonts/geist-400-latin.woff2"),
    sha256_hex: "1984ecaa8efd8b35a5fdb2aa7a69f181039bca8ed8b5b84be099a886d1223729",
};

pub const GEIST_500: VendoredFont = VendoredFont {
    bytes: include_bytes!("../../assets/fonts/geist-500-latin.woff2"),
    sha256_hex: "3de688055adb2059fceb435628f4d9ebb6979a14a388cd9f94d3db44e7ee75f4",
};

pub const GEIST_MONO_400: VendoredFont = VendoredFont {
    bytes: include_bytes!("../../assets/fonts/geist-mono-400-latin.woff2"),
    sha256_hex: "e7d60c52619a9ac852d8b93d45e2bf27fc3b0e4ce2fe7a9de0914d05da6d3369",
};

/// All four vendored faces, for iteration — hash verification now, and
/// eventually the report renderer's `@font-face` block (T24).
pub const ALL_FONTS: [&VendoredFont; 4] = [
    &INSTRUMENT_SERIF_400,
    &GEIST_400,
    &GEIST_500,
    &GEIST_MONO_400,
];

pub static INSTRUMENT_SERIF_400_DATA_URI: LazyLock<String> =
    LazyLock::new(|| data_uri(&INSTRUMENT_SERIF_400));
pub static GEIST_400_DATA_URI: LazyLock<String> = LazyLock::new(|| data_uri(&GEIST_400));
pub static GEIST_500_DATA_URI: LazyLock<String> = LazyLock::new(|| data_uri(&GEIST_500));
pub static GEIST_MONO_400_DATA_URI: LazyLock<String> = LazyLock::new(|| data_uri(&GEIST_MONO_400));

fn data_uri(font: &VendoredFont) -> String {
    format!(
        "data:font/woff2;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(font.bytes)
    )
}

/// `true` iff `font.bytes` starts with the WOFF2 magic and its SHA-256
/// digest matches `font.sha256_hex`.
///
/// Deliberately returns a `bool` rather than `assert!`-ing: a corrupted
/// vendored asset must fail a `#[test]` at build/CI time, not panic a
/// production report run. Callers that need "fail loudly" wrap this in an
/// `assert!` themselves — see the test below.
#[must_use]
pub fn font_matches_manifest(font: &VendoredFont) -> bool {
    font.bytes.starts_with(b"wOF2") && sha256_hex(font.bytes) == font.sha256_hex
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::{ALL_FONTS, INSTRUMENT_SERIF_400, font_matches_manifest};

    #[test]
    fn every_vendored_font_matches_its_manifest_hash() {
        for font in ALL_FONTS {
            assert!(
                font_matches_manifest(font),
                "font with recorded sha256 {} failed magic/hash verification",
                font.sha256_hex
            );
        }
    }

    /// The hash check must be a real check, not a tautology — corrupting a
    /// single byte (or pairing correct bytes with the wrong recorded hash)
    /// has to actually fail.
    #[test]
    fn font_matches_manifest_rejects_a_hash_mismatch() {
        let mismatched = super::VendoredFont {
            bytes: INSTRUMENT_SERIF_400.bytes,
            sha256_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        };
        assert!(!font_matches_manifest(&mismatched));
    }

    #[test]
    fn font_matches_manifest_rejects_missing_woff2_magic() {
        let not_a_font = super::VendoredFont {
            bytes: b"not a woff2 payload at all",
            sha256_hex: INSTRUMENT_SERIF_400.sha256_hex,
        };
        assert!(!font_matches_manifest(&not_a_font));
    }

    #[test]
    fn data_uri_decodes_back_to_the_source_bytes() {
        use base64::Engine as _;

        let uri = &*super::INSTRUMENT_SERIF_400_DATA_URI;
        let prefix = "data:font/woff2;base64,";
        assert!(uri.starts_with(prefix));
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&uri[prefix.len()..])
            .expect("data URI payload must be valid base64");
        assert_eq!(decoded, INSTRUMENT_SERIF_400.bytes);
    }

    /// Renders a real report (`adapters::html_report`, T24) and extracts
    /// every `data:font/woff2;base64,...` URI actually present in the
    /// output, rather than trusting `data_uri_decodes_back_to_the_source_
    /// bytes` above (which only proves the constant is well-formed, not
    /// that the template interpolates it correctly).
    #[test]
    fn every_data_uri_in_rendered_report_decodes_to_woff2() {
        use core::str::FromStr as _;

        use base64::Engine as _;

        use crate::adapters::config::FontsMode;
        use crate::adapters::html_report;
        use crate::domain::bind_address::BindAddress;
        use crate::domain::endpoint::Endpoint;
        use crate::domain::ids::{HostId, ScanId};
        use crate::domain::port::Port;
        use crate::domain::process::ProcessPath;
        use crate::domain::protocol::Protocol;
        use crate::domain::publisher::SignatureStatus;
        use crate::domain::report_model::ReportModel;
        use crate::domain::snapshot::ScanSnapshot;
        use crate::domain::target_strategy::TargetStrategy;

        let endpoint = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").expect("valid ip"),
            Port::try_from(8443u16).expect("nonzero port"),
            None,
            Some(ProcessPath::from_str("/usr/sbin/sshd").expect("non-empty path")),
            vec![],
            SignatureStatus::Unknown,
            None,
        );
        let snapshot = ScanSnapshot::new(
            HostId::generate(),
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "test-fixture".to_owned(),
            vec![endpoint],
            vec![],
            vec![],
            TargetStrategy::LocalOnly,
        );
        let model = ReportModel::build(&[snapshot], None, true).expect("model builds");
        let html = html_report::render(&model, FontsMode::Embed).expect("renders");

        let prefix = "data:font/woff2;base64,";
        let mut decoded_count = 0usize;
        let mut rest = html.as_str();
        while let Some(start) = rest.find(prefix) {
            let after = rest.get(start + prefix.len()..).unwrap_or_default();
            let end = after.find('"').unwrap_or(after.len());
            let encoded = after.get(..end).unwrap_or_default();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .expect("data URI payload must be valid base64");
            assert!(
                decoded.starts_with(b"wOF2"),
                "decoded data URI payload does not start with the WOFF2 magic"
            );
            decoded_count += 1;
            rest = after.get(end..).unwrap_or_default();
        }
        assert_eq!(
            decoded_count, 4,
            "expected all four vendored faces to appear as data URIs in a real render"
        );
    }

    // `fonts_system_flag_emits_no_base64_or_font_face_block` (task T22
    // spec) now lives in `adapters::html_report::tests` — it needs a real
    // rendered artifact to inspect, which only exists once that module's
    // `render()` function does.

    // TODO(T25): once the SVG diagram generator and HTML templates exist,
    // add the codepoint-subset scan (`no_glyph_outside_subset_is_emitted_as_text`):
    // walk every template/SVG text node and assert each character is
    // either in the vendored Latin+digits+punctuation subset
    // (`xtask/src/vendor_fonts.rs::SUBSET_UNICODES`) or lives inside an SVG
    // `<path>`, never as a font-rendered text glyph (task T22 spec — status
    // marks, arrows, and box-drawing must be SVG paths, never glyphs).

    /// Builds `anne-de-breuil` *without* `report-html` into a scratch
    /// target dir and greps the resulting `.rlib` for the WOFF2 magic and
    /// for a long byte run pulled directly from a real vendored file, so a
    /// collector-only build is proven — not just asserted in prose — to
    /// carry zero font bytes.
    #[test]
    fn collector_only_build_contains_zero_font_bytes() {
        let workspace_root = workspace_root();
        let target_dir =
            std::env::temp_dir().join(format!("anne-font-audit-{}", std::process::id()));

        let output = Command::new(env!("CARGO"))
            .current_dir(&workspace_root)
            .arg("build")
            .arg("--locked")
            .arg("-p")
            .arg("anne-de-breuil")
            .arg("--lib")
            .arg("--no-default-features")
            .arg("--features")
            .arg("windows-collector,linux-collector")
            .arg("--message-format=json-render-diagnostics")
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .expect("spawning nested cargo build");
        assert!(
            output.status.success(),
            "nested cargo build (no report-html) failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let rlib_path = find_rlib_artifact(&output.stdout)
            .expect("cargo build output must report a compiler-artifact .rlib");
        let compiled = std::fs::read(&rlib_path).expect("reading compiled rlib");

        let fingerprint_len = 64usize.min(INSTRUMENT_SERIF_400.bytes.len());
        let fingerprint = INSTRUMENT_SERIF_400
            .bytes
            .get(..fingerprint_len)
            .expect("vendored font is at least 64 bytes");

        assert!(
            !contains_subsequence(&compiled, fingerprint),
            "collector-only build embeds vendored font bytes"
        );
        assert!(
            !contains_subsequence(&compiled, b"wOF2"),
            "collector-only build contains a WOFF2 magic-byte sequence"
        );

        std::fs::remove_dir_all(&target_dir).ok();
    }

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate manifest dir has a workspace root two levels up")
            .to_path_buf()
    }

    fn find_rlib_artifact(cargo_stdout: &[u8]) -> Option<PathBuf> {
        for line in String::from_utf8_lossy(cargo_stdout).lines() {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if value.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact")
            {
                continue;
            }
            let Some(filenames) = value.get("filenames").and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            for name in filenames {
                if let Some(path) = name.as_str()
                    && Path::new(path)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("rlib"))
                {
                    return Some(PathBuf::from(path));
                }
            }
        }
        None
    }

    fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }
}
