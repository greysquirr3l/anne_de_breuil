//! Repository-local developer tasks, invoked as `cargo run -p xtask -- <task>`.
//!
//! Never fetches anything over the network — every task here operates only
//! on files already present in the working tree or produced by an earlier
//! build step in the same CI job.

mod checksum;
mod vendor_fonts;
mod verify_static;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let task = args.next();
    match task.as_deref() {
        Some("vendor-fonts") => vendor_fonts::run(),
        Some("verify-static") => verify_static::run(args),
        Some("checksum") => checksum::run(args),
        Some(other) => anyhow::bail!(
            "unknown xtask `{other}` — known tasks: vendor-fonts, verify-static, checksum"
        ),
        None => anyhow::bail!(
            "usage: cargo run -p xtask -- <task>\n  \
             vendor-fonts    re-subset fonts-src/ into crates/anne-de-breuil/assets/fonts/\n  \
             verify-static   fail if a windows-msvc exe imports a dynamic CRT DLL\n  \
             checksum        write/verify a SHA256SUMS.txt release manifest"
        ),
    }
}
