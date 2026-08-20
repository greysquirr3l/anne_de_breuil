//! Domain, port, application, and adapter layers for host listening-port
//! surface enumeration.
//!
//! See the crate-level modules for the hexagonal architecture boundaries:
//! `domain` holds pure logic, `ports` declares consumer-owned trait
//! boundaries, `application` wires use cases, and `adapters` implements
//! ports against the outside world.

pub mod adapters;
pub mod application;
pub mod domain;
pub mod ports;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_matches_package() {
        assert_eq!(env!("CARGO_PKG_NAME"), "anne-de-breuil");
    }
}
