#![deny(dead_code_pub_in_binary)]

//! Binary entry point. Subcommand wiring (scan, diff, report, inventory,
//! version) lands in T18; this is the workspace-scaffold stub.

mod adapters;
mod application;
mod domain;
mod ports;

const fn main() {}

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_matches_package() {
        assert_eq!(env!("CARGO_PKG_NAME"), "anne-de-breuil-cli");
    }
}
