//! Inventory: TOML-parsed remote host definitions.
//!
//! This is the adapter-boundary parse of untrusted TOML input — untrusted
//! not because it's malicious in the usual adversarial sense, but because
//! it's operator-authored and can be malformed. [`parse_inventory`] is the
//! one place that input crosses into typed value objects; nothing past this
//! boundary should ever see a raw, unvalidated inventory field. Unlike
//! `adapters::config::AnneConfig`, this has no env-var overrides or
//! defaults-layering concern, so it's a plain `toml::from_str` rather than
//! a `figment` stack.

use std::path::PathBuf;

use crate::domain::{HostAddress, HostId, Port};

/// One host in the inventory file.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryHost {
    /// Stable identifier for this host, unchanged across rescans.
    pub host_id: HostId,
    /// The host's address: an IP address or a hostname.
    pub address: HostAddress,
    /// The port the remote transport connects on.
    pub port: Port,
    /// How to authenticate to this host.
    pub auth: AuthMethod,
    /// An optional jump/bastion host the connection is routed through.
    #[serde(default)]
    pub jump: Option<HostAddress>,
    /// Free-form labels for grouping or filtering hosts in a report.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// How to authenticate to a remote host.
///
/// Deliberately has no `Password` variant, and none will ever be added:
/// this inventory file is meant to be readable, diffable, and safe to
/// commit to source control, and a password is secret material that has no
/// business living in a file like that. Every variant here names a
/// *reference* to a credential that lives elsewhere — an already-running
/// SSH agent, a key file on disk, or an OS keyring entry — never the
/// credential itself. Enforced structurally by the variant set, not just by
/// this doc comment: there is nowhere in this enum a secret could go.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum AuthMethod {
    /// Authenticate using whatever identity an already-running SSH agent offers.
    Agent,
    /// Authenticate with the private key file at this path.
    KeyFile(PathBuf),
    /// Authenticate with a private key looked up by name in the OS keyring.
    KeyFromKeyring(String),
}

/// The full contents of one inventory file.
///
/// A TOML document is always a table at its root, never a bare sequence, so
/// a file of hosts is represented as `[[host]]` array-of-tables entries
/// under one key rather than a top-level array. This wrapper exists only to
/// receive that shape; [`parse_inventory`] unwraps it immediately; nothing
/// outside this module ever sees it.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryFile {
    #[serde(default)]
    host: Vec<InventoryHost>,
}

/// Failure parsing an inventory file.
#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    /// The input was not valid TOML, named a field this module does not
    /// recognise, or omitted a required field.
    #[error("inventory file is not valid TOML: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Parses the full contents of an inventory file into its typed hosts.
///
/// Expects zero or more `[[host]]` array-of-tables entries; each is parsed
/// into an [`InventoryHost`], rejecting any field this module does not
/// recognise.
///
/// # Errors
///
/// Returns [`InventoryError`] if `contents` is not valid TOML, names an
/// unrecognised field, or omits a required field.
pub fn parse_inventory(contents: &str) -> Result<Vec<InventoryHost>, InventoryError> {
    let file: InventoryFile = toml::from_str(contents)?;
    Ok(file.host)
}

#[cfg(test)]
mod tests {
    use super::{AuthMethod, InventoryHost, parse_inventory};

    #[test]
    fn valid_inventory_parses() {
        // The task's own test spec calls `toml::from_str::<Vec<InventoryHost>>`
        // directly on the file's raw contents. That can never succeed against
        // real TOML: a TOML document is always a table at its root, never a
        // bare sequence, so deserializing straight into a `Vec<T>` fails with
        // "invalid type: map, expected a sequence" no matter what the table
        // contains (verified empirically before writing this test). The
        // fixture below uses `[[host]]` array-of-tables entries instead, and
        // this test goes through `parse_inventory`, the module's real
        // boundary function, which un-wraps that one level of nesting —
        // the same three-hosts assertion the spec asked for.
        let toml = include_str!("../../fixtures/inventory/valid.toml");
        let inventory = parse_inventory(toml).unwrap();
        assert_eq!(inventory.len(), 3);

        assert!(matches!(inventory[0].auth, AuthMethod::Agent));
        assert!(matches!(inventory[1].auth, AuthMethod::KeyFile(_)));
        assert!(matches!(inventory[2].auth, AuthMethod::KeyFromKeyring(_)));
        assert!(inventory[1].jump.is_some());
        assert!(!inventory[0].tags.is_empty());
    }

    #[test]
    fn unknown_field_is_rejected() {
        let toml = include_str!("../../fixtures/inventory/unknown_field.toml");
        assert!(parse_inventory(toml).is_err());
    }

    #[test]
    fn password_field_is_rejected_with_clear_error() {
        let toml = r#"
            host_id = "11111111-1111-1111-1111-111111111111"
            address = "10.0.0.5"
            port = 22
            auth = "agent"
            password = "hunter2"
        "#;
        let err = toml::from_str::<InventoryHost>(toml).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }
}
