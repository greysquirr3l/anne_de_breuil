# anne-de-breuil

Enumerates the listening-port surface of a host and correlates each endpoint
with its owning process, hosted services, binary signature, and the
effective host firewall policy that governs it.

Runs against the local machine or fans out over SSH to an inventory of
remote hosts, pushing a static collector, executing it, retrieving a signed
JSON snapshot, and removing the artifact. Snapshots are content-addressed
and diffable, so a baseline scan and a rescan produce a drift report rather
than a wall of noise.

Output targets are JSON, CSV, SARIF, and a self-contained HTML5 report with
server-rendered SVG diagrams, no external assets, and no network fetches at
view time.

## Layout

Two crates under `crates/`:

- `anne-de-breuil` — library crate. Hexagonal layout under `src/`:
  `domain/` (pure logic, no I/O), `ports/` (consumer-owned trait
  boundaries), `application/` (use-case orchestration), `adapters/`
  (implementations against the OS, PowerShell, SSH, SQLite, HTTP).
- `anne-de-breuil-cli` — binary crate, ships the `anne` executable. Same
  four-module layout for CLI-local glue.

## Toolchain

Pinned exactly to Rust 1.97.1 via `rust-toolchain.toml`. Never let this
float to bare 1.97.0 — that release has a known LLVM miscompilation
(rust-lang/rust#159035) fixed in the 1.97.1 patch.

## Build, test, lint

```bash
cargo build --workspace --all-features
cargo test --workspace --all-features
cargo l   # alias for the full clippy profile, see .cargo/config.toml
cargo audit
cargo deny check
```

`cargo l` runs clippy with `clippy::all`, `pedantic`, `nursery`, `cargo`,
and `perf` enabled, a small allow-list for lints that are too noisy to be
useful project-wide, and a deny-list (`unwrap_used`, `expect_used`,
`panic`, `indexing_slicing`, `cast_ptr_alignment`, `suspicious`) that turns
"never `.unwrap()`/`.expect()`/panicking index outside tests" into a
mechanically enforced rule instead of a review convention.

CI enforces `-D warnings` via `CARGO_BUILD_WARNINGS=deny` (stable as of
1.97), not by injecting `-D warnings` into `RUSTFLAGS` — `RUSTFLAGS`
changes bust the build cache between local and CI runs.

## Cross-compilation

Local development happens on macOS. The pinned toolchain carries four
extra targets so Windows- and Linux-specific adapter work can be
type-checked without a VM in the loop:

```bash
rustup target add x86_64-pc-windows-msvc aarch64-pc-windows-msvc \
  x86_64-unknown-linux-musl aarch64-unknown-linux-musl
```

The `-musl` targets link with `rustc`'s bundled musl support directly.
The `-msvc` targets need the Windows SDK and MSVC import libraries, which
[`cargo-xwin`](https://github.com/rust-cross/cargo-xwin) downloads on
first use — no Windows install or VM required:

```bash
cargo install cargo-xwin
cargo xwin check --target x86_64-pc-windows-msvc
```

This proves the cross-compile path works before any Windows-specific code
exists, and lets `windows-collector`/`powershell-collector` work (T05/T06)
be iterated on from macOS or Linux.

The native 3-OS CI matrix (ubuntu-latest, windows-latest, macos-latest) is
separate from this cross-compiled path — it exists to actually exercise
`#[cfg(windows)]`/`#[cfg(unix)]` code natively, not to replace it. The
cross-compiled release build path is covered by the packaging/release task.

## Supply chain

`deny.toml` configures `cargo-deny` for advisory, license, ban, and source
checks. `cargo audit` covers the RUSTSEC advisory database independently.
