//! [`ConfigError`]: the single error surface for [`super::AnneConfig::load`].

use std::path::{Path, PathBuf};

use figment::error::Kind;

/// Failure loading or validating [`super::AnneConfig`].
///
/// Wraps the underlying `figment` layering/deserialization failure (missing
/// field, unknown field, type mismatch) together with the path the caller
/// asked to load, so one error message names both the offending field —
/// dotted, e.g. `store.backend` — and the file it was (or should have
/// been) declared in.
#[derive(Debug, thiserror::Error)]
#[error("failed to load config from {}: {message}", path.display())]
pub struct ConfigError {
    /// The path passed to [`super::AnneConfig::load`].
    pub path: PathBuf,
    message: String,
    /// The underlying `figment` layering/deserialization failure. Boxed:
    /// `figment::Error` is large (it carries a chain of prior errors), and
    /// an oversized `Err` variant bloats every `Result<T, ConfigError>`
    /// return slot regardless of whether loading fails.
    #[source]
    source: Box<figment::Error>,
}

impl ConfigError {
    pub(super) fn new(path: &Path, source: figment::Error) -> Self {
        Self {
            path: path.to_path_buf(),
            message: describe(&source),
            source: Box::new(source),
        }
    }
}

/// Figment reports a missing field's location as the path to its *parent*
/// table (the field itself was never visited, since it's absent) — e.g.
/// `store` rather than `store.backend`. Re-derive the full dotted path so
/// the error names the exact field an operator needs to set.
fn describe(error: &figment::Error) -> String {
    match &error.kind {
        Kind::MissingField(field) => {
            let mut segments = error.path.clone();
            segments.push(field.to_string());
            format!("missing field `{}`", segments.join("."))
        }
        kind => kind.to_string(),
    }
}
