//! T28 security-audit: structural checks against the repository's own
//! checkout configuration.
//!
//! `.gitattributes` decides what lands on disk. It is easy to add a
//! file, change one, or delete the file, and have the repository keep
//! working perfectly on the machine that made the change -- because
//! `core.autocrlf` is unset on macOS and Linux and defaults to `true`
//! on Windows.
//!
//! That is not hypothetical. The workflow audit suites assert against
//! literal `"\n"` sequences in files they read with `include_str!`,
//! and they failed on the Windows CI runner because the checkout there
//! had CRLF endings. The assertions now normalise line endings
//! themselves, which is the defence that matters. These tests cover the
//! second layer: the repository-wide policy, so that the *next* test
//! someone writes against a repository file does not have to rediscover
//! this the hard way.

const GITATTRIBUTES: &str = include_str!("../../../.gitattributes");

/// Text files must be checked out with LF endings on every platform.
///
/// This is the setting that stops the class of bug above. `eol=lf`
/// forces LF in the working tree regardless of what
/// `core.autocrlf` says, so a Windows checkout produces the same bytes
/// as a Linux one.
#[test]
fn text_files_are_checked_out_with_lf_endings() {
    assert!(
        GITATTRIBUTES.contains("* text=auto eol=lf"),
        ".gitattributes must force LF endings in the working tree -- without it, \
         `core.autocrlf=true` (the Windows default) produces CRLF files and every \
         test that matches on a literal newline behaves differently per platform"
    );
}

/// Binary files must be declared binary.
///
/// `text=auto` already detects most binaries by content, but the
/// detection is a heuristic and the consequences of getting it wrong
/// are silent corruption. These two file kinds are worth stating:
///
///   * the fuzz seed is raw bytes from a captured netlink response. A
///     seed that changes by one byte is a fuzzer that quietly stops
///     reproducing the defect it was found for.
///   * the WOFF2 faces are embedded into the self-contained HTML
///     report with `include_bytes!`, so they must be byte-identical
///     everywhere the report is built.
#[test]
fn binary_files_are_declared_binary() {
    assert!(
        GITATTRIBUTES.contains("*.bin binary"),
        ".gitattributes must mark `*.bin` as binary -- the fuzz seed is raw netlink bytes"
    );
    assert!(
        GITATTRIBUTES.contains("*.woff2 binary"),
        ".gitattributes must mark `*.woff2` as binary -- the report fonts are embedded with include_bytes!"
    );
}

/// The tracked text files must not contain CRLF in the working tree.
///
/// This is the invariant the `.gitattributes` rule exists to protect,
/// asserted directly. It fails the moment something reintroduces CRLF
/// -- whether through a careless editor, a `core.autocrlf` set to
/// `true` on a contributor's machine, or a merge that brought in a
/// CRLF file from elsewhere.
#[test]
fn no_tracked_text_file_contains_crlf() {
    let offenders: Vec<&str> = TEXT_FILES
        .iter()
        .copied()
        .filter(|path| {
            let bytes = std::fs::read(repo_root().join(path)).unwrap_or_default();
            bytes.windows(2).any(|pair| pair == b"\r\n")
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "these tracked text files contain CRLF and will not match the `\\n` assertions \
         in the workflow audit suites on a Windows checkout: {offenders:?}"
    );
}

/// Text files whose exact bytes the test suites depend on.
///
/// Every one of these is read with `include_str!` by a test that
/// matches on a literal newline sequence.
const TEXT_FILES: &[&str] = &[
    ".github/workflows/auto-tag.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/publish-crate.yml",
    ".github/workflows/release.yml",
    ".github/workflows/scorecard.yml",
    "Cargo.toml",
    "rust-toolchain.toml",
];

/// The repository root, derived from this crate's manifest directory.
///
/// `CARGO_MANIFEST_DIR` is `<repo>/crates/anne-de-breuil-cli`.
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map_or_else(|| std::path::PathBuf::from("."), std::path::Path::to_path_buf)
}
