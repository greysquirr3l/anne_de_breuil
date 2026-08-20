//! Repository-local developer tasks, invoked as `cargo run -p xtask -- <task>`.
//!
//! Never fetches anything over the network — every task here operates only
//! on files already present in the working tree.

mod vendor_fonts;

fn main() -> anyhow::Result<()> {
    let task = std::env::args().nth(1);
    match task.as_deref() {
        Some("vendor-fonts") => vendor_fonts::run(),
        Some(other) => anyhow::bail!("unknown xtask `{other}` — known tasks: vendor-fonts"),
        None => anyhow::bail!(
            "usage: cargo run -p xtask -- <task>\n  vendor-fonts  re-subset fonts-src/ into crates/anne-de-breuil/assets/fonts/"
        ),
    }
}
