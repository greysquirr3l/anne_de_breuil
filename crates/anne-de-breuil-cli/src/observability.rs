//! Structured logging wired exclusively to stderr.

use std::io::stderr;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoggingFormat {
    #[default]
    Pretty,
    Json,
}

/// Initialise the global tracing subscriber. Idempotent — repeated calls
/// are no-ops without re-installing the subscriber.
///
/// `tracing_subscriber`'s `try_init` returns the raw `dyn Error` from the
/// underlying `set_global_default` call, which surfaces "default subscriber
/// already set" as a plain `Box<dyn Error + Send + Sync>` carrying a
/// `tracing::subscriber::SetGlobalDefaultError`. We swallow that outcome
/// so callers can call `init` defensively without worrying about ordering
/// (the library crate's own tests, for example, install their own
/// subscriber before pulling in the binary).
pub fn init(format: LoggingFormat) {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let builder = fmt()
        .with_env_filter(env_filter)
        .with_writer(stderr)
        .with_target(false)
        .with_ansi(false);

    let _ = match format {
        LoggingFormat::Pretty => builder.try_init(),
        LoggingFormat::Json => builder.json().try_init(),
    };
}
