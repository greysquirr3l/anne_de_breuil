# anne-de-breuil developer & release tasks.
#
# Run `just` with no arguments to list everything below. Requires
# https://github.com/casey/just (`brew install just` / `cargo install just`).
#
# Mirrors, rather than replaces, the real CI/release pipeline
# (.github/workflows/{ci,release}.yml) -- every recipe here runs the exact
# same commands those workflows do, so `just ci` failing locally means CI
# would fail too, and `just release-*` produces byte-for-byte the same
# artifacts release.yml does. Nothing here uploads, tags, or publishes
# anything; that stays release.yml's job, triggered by auto-tag.yml on a
# push to main (see README.md's "Release artifacts" section).
#
# just's doc-comment convention: only the single comment line immediately
# above a recipe's `[group(...)]` attribute becomes its --list description
# -- longer rationale lives in its own comment block above that, separated
# by a blank line, so `just --list` stays scannable while the reasoning is
# still here for anyone reading the file directly.

set unstable := true

_default:
    @just --list

# ---------------------------------------------------------------------------

# Build the whole workspace with every feature.
[group('dev')]
build:
    cargo build --workspace --all-features

# Run the whole workspace's test suite with every feature.
[group('dev')]
test:
    cargo test --workspace --all-features

# Same clippy profile as the `cargo l` alias in .cargo/config.toml, which
# this project enforces in CI.

# Full clippy profile this project enforces in CI.
[group('dev')]
lint:
    cargo l

# No rustfmt.toml is committed, so this is whatever the pinned toolchain's
# rustfmt ships with, unconfigured.

# Format the workspace.
[group('dev')]
fmt:
    cargo fmt --all

# Check formatting without writing.
[group('dev')]
fmt-check:
    cargo fmt --all -- --check

# RUSTSEC advisory database check.
[group('dev')]
audit:
    cargo audit

# Advisory/license/ban/source checks per deny.toml.
[group('dev')]
deny:
    cargo deny check

# Run this before pushing, not after CI tells you it failed.

# Everything CI's build-test-lint job runs, in one shot.
[group('dev')]
ci: build test lint

# ---------------------------------------------------------------------------
# xtask wrappers -- see xtask/src/main.rs's own module doc for what each
# task does and does not do (none of them install anything).

# See README.md's "Fonts (report-html)" section for the one-time fonts-src/
# setup this depends on.

# Re-subset vendored fonts into crates/anne-de-breuil/assets/fonts/.
[group('xtask')]
vendor-fonts:
    cargo run -p xtask -- vendor-fonts

# Fail if a windows-msvc release exe imports a dynamic CRT DLL.
[group('xtask')]
verify-static exe:
    cargo run -p xtask -- verify-static {{ exe }}

# Write a SHA256SUMS.txt-format manifest covering the given artifacts.
[group('xtask')]
checksum-write manifest *artifacts:
    cargo run -p xtask -- checksum write {{ manifest }} {{ artifacts }}

# Re-hash every artifact a manifest names and fail on the first mismatch.
[group('xtask')]
checksum-verify manifest artifact_dir:
    cargo run -p xtask -- checksum verify {{ manifest }} {{ artifact_dir }}

# The exact two-step `cargo xwin build` + `verify-static` dance release.yml
# runs as separate CI steps, wrapped into one command. Requires cargo-xwin
# (`cargo install cargo-xwin`) and llvm-objdump already on PATH (on macOS:
# Xcode Command Line Tools, at /Library/Developer/CommandLineTools/usr/bin,
# not on PATH by default) -- never installs either itself.

# Cross-build + verify the release x86_64 Windows binary.
[group('xtask')]
build-windows:
    cargo run -p xtask -- build-windows

# ---------------------------------------------------------------------------

# Matches README.md's "Cross-compilation" section. Safe to re-run --
# rustup no-ops on an already-installed target.

# Add every cross target this project's toolchain expects.
[group('cross-compile')]
install-targets:
    rustup target add x86_64-pc-windows-msvc aarch64-pc-windows-msvc \
        x86_64-unknown-linux-musl aarch64-unknown-linux-musl

# Proves the cross-compile path works without a full cargo-xwin build.
# Requires cargo-xwin.

# Type-check (not link) the Windows target.
[group('cross-compile')]
xwin-check:
    cargo xwin check --target x86_64-pc-windows-msvc

# ---------------------------------------------------------------------------
# Local release build, mirroring release.yml's per-target steps into
# ./dist/ (gitignored). Not a substitute for a real release: no signing, no
# SBOM (both need tools/secrets release.yml's CI runners provide, not
# something this Justfile should silently install), and no publish step --
# see auto-tag.yml/release.yml for what actually ships a tagged release.

# Windows x86_64: cross-build via xtask, stage into dist/.
[group('release')]
release-windows: build-windows
    mkdir -p dist
    cp target/x86_64-pc-windows-msvc/release/anne.exe dist/anne-x86_64-pc-windows-msvc.exe

# Requires a real x86_64-linux-musl-gcc cross toolchain already on PATH
# plus rust-lld as the linker -- release.yml fetches its own from this
# repo's musl-cross-mirror release (see that workflow's own comments for
# exactly why, and where from). Never installs a toolchain itself; fails
# loudly if x86_64-linux-musl-gcc isn't found.

# Linux musl x86_64: cross-build, stage into dist/.
[group('release')]
release-musl-x86_64:
    #!/usr/bin/env bash
    set -euo pipefail
    host_triple=$(rustc -vV | sed -n 's/^host: //p')
    rust_lld="$(rustc --print sysroot)/lib/rustlib/${host_triple}/bin/rust-lld"
    CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc \
      RUSTFLAGS="-C linker=${rust_lld} -C linker-flavor=ld.lld" \
      cargo build --release --target x86_64-unknown-linux-musl -p anne-de-breuil-cli
    mkdir -p dist
    cp target/x86_64-unknown-linux-musl/release/anne dist/anne-x86_64-unknown-linux-musl

# Same prerequisites as release-musl-x86_64, for aarch64-linux-musl-gcc.

# Linux musl aarch64: cross-build, stage into dist/.
[group('release')]
release-musl-aarch64:
    #!/usr/bin/env bash
    set -euo pipefail
    host_triple=$(rustc -vV | sed -n 's/^host: //p')
    rust_lld="$(rustc --print sysroot)/lib/rustlib/${host_triple}/bin/rust-lld"
    CC_aarch64_unknown_linux_musl=aarch64-linux-musl-gcc \
      RUSTFLAGS="-C linker=${rust_lld} -C linker-flavor=ld.lld" \
      cargo build --release --target aarch64-unknown-linux-musl -p anne-de-breuil-cli
    mkdir -p dist
    cp target/aarch64-unknown-linux-musl/release/anne dist/anne-aarch64-unknown-linux-musl

# Only the Windows leg builds without extra local toolchain setup. Run the
# two release-musl-* recipes yourself once their cross-gcc toolchains are
# in place.

# Build every target that doesn't need extra local toolchain setup.
[group('release')]
release-all: release-windows
    @echo "Windows build staged in dist/. musl targets need their cross-gcc"
    @echo "toolchains on PATH first -- see those recipes' own comments, then run:"
    @echo "  just release-musl-x86_64"
    @echo "  just release-musl-aarch64"

# SHA-256-checksum every artifact currently staged in dist/.
[group('release')]
release-checksums:
    #!/usr/bin/env bash
    set -euo pipefail
    artifacts=(dist/*)
    cargo run -p xtask -- checksum write dist/SHA256SUMS.txt "${artifacts[@]}"

# Updates Cargo.toml's [workspace.package].version and the anne-de-breuil
# path-dependency's own version pin, then refreshes Cargo.lock.
# Deliberately does NOT touch CHANGELOG.md -- moving [Unreleased] into a
# dated section is a judgment call (what actually shipped, what didn't)
# this recipe shouldn't make for you. `perl -pi` rather than `sed -i`:
# GNU and BSD sed disagree on -i's argument requirement, perl's doesn't.

# Bump the workspace version everywhere it's pinned.
[group('release')]
bump-version version:
    perl -pi -e 's/^version = "\d+\.\d+\.\d+"/version = "{{ version }}"/' Cargo.toml
    perl -pi -e 's/(anne-de-breuil", version = ")\d+\.\d+\.\d+(")/${1}{{ version }}${2}/' Cargo.toml
    cargo build --workspace --all-features
    @echo "Bumped to {{ version }}. Now: update CHANGELOG.md ([Unreleased] -> [{{ version }}] -- YYYY-MM-DD), then commit."

# ---------------------------------------------------------------------------

# Remove build artifacts, including dist/.
[group('housekeeping')]
clean:
    cargo clean
    rm -rf dist

# Print the build version the workspace would currently produce.
[group('housekeeping')]
version:
    @cargo run -p anne-de-breuil-cli --bin anne -- version
