//! Layered configuration: built-in defaults, an operator TOML file, then
//! `ANNE_`-prefixed environment overrides, each layer overriding the last.
//!
//! This is the adapter-boundary parse of untrusted TOML/env input:
//! [`AnneConfig::load`] is the one place that input crosses into typed
//! value objects. Nothing past this boundary should ever see a raw,
//! unvalidated `String` standing in for a config value.
//!
//! Env overrides use `__` (double underscore) as the section separator —
//! e.g. `ANNE_REMOTE__CONCURRENCY`, never `ANNE_REMOTE_CONCURRENCY` — so a
//! single-underscore `ANNE_`-prefixed variable used for something else
//! entirely (an operational knob like `ANNE_LOG_FORMAT`) never gets
//! misread as a config path segment and rejected by `deny_unknown_fields`.
//! `__` alone doesn't close every gap, though: *any* `ANNE_`-prefixed
//! variable that happens to be set, with no `__` in it at all, still lands
//! as a single unrecognised top-level key and fails the whole load —
//! `ANNE_LOG_FORMAT` genuinely does this today (T18's finding, still
//! unfixed — read directly via `std::env::var` in `main.rs`, not renamed
//! out of the prefix). A build-time git SHA constant used to collide the
//! same way (`cargo:rustc-env` sets a real process env var for `cargo
//! test`/`cargo run`, not just a compile-time one — T31 traced this down
//! empirically after `--config` wiring made `load` actually get called for
//! the first time); it was renamed outside the `ANNE_` prefix entirely
//! (`anne-de-breuil-cli/build.rs`'s `ENV_KEY`) since it has no user-facing
//! reason to live under that prefix at all, unlike `ANNE_LOG_FORMAT`.

mod error;
mod portal;
mod remote;
mod report;
mod scan;
mod store;

use std::path::Path;

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};

pub use error::ConfigError;
pub use portal::{PortalConfig, PortalTokenConfig};
pub use remote::RemoteConfig;
pub use report::{FontsMode, ReportConfig, ReportFormat, Theme};
pub use scan::ScanConfig;
pub use store::{StoreBackend, StoreConfig};

/// The reference configuration shipped with the crate.
///
/// Not consulted by [`AnneConfig::load`] — [`ScanConfig`], [`RemoteConfig`],
/// and [`ReportConfig`] each carry their own [`Default`] impl, and that is
/// what `load` actually layers under the operator's file. This asset is the
/// starter file an operator copies to build their own `anne.toml`; nothing
/// in the crate reads it at runtime.
pub const DEFAULT_CONFIG_TEMPLATE: &str = include_str!("../../../assets/anne.default.toml");

/// The full, validated application configuration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnneConfig {
    /// Local endpoint collection settings.
    pub scan: ScanConfig,
    /// SSH fan-out settings.
    pub remote: RemoteConfig,
    /// Report generation settings.
    pub report: ReportConfig,
    /// Snapshot persistence settings; has no built-in default, see [`StoreConfig`].
    pub store: StoreConfig,
    /// `portal` feature settings; defaults to zero tokens (deny-all), see [`PortalConfig`].
    #[serde(default)]
    pub portal: PortalConfig,
}

impl AnneConfig {
    /// Loads configuration by layering built-in defaults, `path`, then
    /// `ANNE_`-prefixed environment variables, each overriding the last.
    ///
    /// `path` need not exist: a missing file simply contributes no values,
    /// so callers can point at an optional user config path. `[store]` has
    /// no built-in default, so it must be supplied by `path` or the
    /// environment or loading fails, naming the missing field (e.g.
    /// `store.backend`) and the file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if any layer fails to parse, a required
    /// field is missing, or an unrecognised field is present.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Figment::new()
            .merge(Serialized::default("scan", ScanConfig::default()))
            .merge(Serialized::default("remote", RemoteConfig::default()))
            .merge(Serialized::default("report", ReportConfig::default()))
            .merge(Serialized::default("portal", PortalConfig::default()))
            .merge(Toml::file(path))
            .merge(Env::prefixed("ANNE_").split("__"))
            .extract()
            .map_err(|source| ConfigError::new(path, source))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    /// Serializes tests that mutate process-global environment state so
    /// they can't interleave under the default parallel test runner.
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    /// Writes `contents` to a fresh temp directory as a file literally
    /// named `anne.toml`, so error-message assertions can check for that
    /// filename without caring where the OS temp directory lives.
    fn fixture_path(contents: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("anne-config-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("anne.toml");
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// A fully valid config: every section deserializes cleanly, either
    /// from the explicit values here or from the built-in section
    /// defaults for whatever's omitted.
    const VALID_CONFIG: &str = r#"
        [scan]
        include_udp = true

        [remote]
        concurrency = 4

        [report]
        theme = "Dark"

        [store]
        backend = "FileSystem"
        path = "./data"
    "#;

    #[test]
    fn loads_a_complete_config_into_typed_values() {
        // `AnneConfig::load` reads process-global ANNE_-prefixed env vars,
        // so every test that calls it — not just ones that set vars —
        // must be serialized against tests that do.
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let path = fixture_path(VALID_CONFIG);
        let config = AnneConfig::load(&path).unwrap();

        assert!(config.scan.include_udp);
        assert_eq!(config.remote.concurrency, 4);
        assert_eq!(config.report.theme, Theme::Dark);
        assert_eq!(config.store.backend, StoreBackend::FileSystem);
        // Sections/fields left unset in the file still get typed defaults.
        assert!(!config.scan.skip_signature);
        assert!(!config.remote.accept_new);
    }

    #[test]
    fn env_var_overrides_file_value() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let path = fixture_path(VALID_CONFIG);

        // SAFETY: serialized by `env_lock`; no other test reads or writes
        // ANNE_REMOTE__CONCURRENCY concurrently.
        unsafe {
            std::env::set_var("ANNE_REMOTE__CONCURRENCY", "16");
        }
        let result = AnneConfig::load(&path);
        unsafe {
            std::env::remove_var("ANNE_REMOTE__CONCURRENCY");
        }

        assert_eq!(result.unwrap().remote.concurrency, 16);
    }

    #[test]
    fn missing_required_field_names_the_field_and_file() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let path = fixture_path(
            r#"
            [store]
            path = "./data"
            "#,
        );

        let err = AnneConfig::load(&path).unwrap_err();
        let message = err.to_string();

        assert!(message.contains("store.backend"), "{message}");
        assert!(message.contains("anne.toml"), "{message}");
    }

    #[test]
    fn password_field_in_config_is_rejected() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let path = fixture_path(
            r#"
            [remote]
            concurrency = 4
            password = "hunter2"

            [store]
            backend = "FileSystem"
            path = "./data"
            "#,
        );

        let err = AnneConfig::load(&path).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("unknown field"));
    }

    #[test]
    fn shipped_default_config_has_no_secrets_or_inventory() {
        assert!(!DEFAULT_CONFIG_TEMPLATE.to_lowercase().contains("password"));
        assert!(!DEFAULT_CONFIG_TEMPLATE.contains("[[inventory"));
    }

    #[test]
    fn missing_file_still_loads_from_defaults_when_store_is_supplied_by_env() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let missing =
            std::env::temp_dir().join(format!("anne-config-test-{}", uuid::Uuid::new_v4()));

        // SAFETY: serialized by `env_lock`; no other test touches these
        // ANNE_STORE_* vars concurrently.
        unsafe {
            std::env::set_var("ANNE_STORE__BACKEND", "Sqlite");
            std::env::set_var("ANNE_STORE__PATH", "/tmp/anne.sqlite");
        }
        let result = AnneConfig::load(&missing);
        unsafe {
            std::env::remove_var("ANNE_STORE__BACKEND");
            std::env::remove_var("ANNE_STORE__PATH");
        }

        let config = result.unwrap();
        assert_eq!(config.store.backend, StoreBackend::Sqlite);
        assert_eq!(
            config.remote.concurrency,
            RemoteConfig::default().concurrency
        );
    }
}
