//! clap derive surface for the `anne` binary.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Exit codes are a contract — documented in `--help` and the README so
/// CI and RMM tooling can branch on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// The command completed successfully.
    Clean = 0,
    /// Operational failure: collector couldn't talk to the host, snapshot
    /// couldn't be persisted, etc.
    OperationalError = 1,
    /// Bad configuration or bad arguments: missing required config field,
    /// unparseable inventory, unknown `--strategy` value, etc.
    ConfigOrArgError = 2,
    /// `diff` was run with `--fail-on-drift` and drift was detected above
    /// the configured severity threshold.
    DriftDetected = 3,
}

impl ExitCode {}

/// `--strategy` value: forces the collection tier for `scan` when the
/// operator already knows what the environment allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum StrategyArg {
    Auto,
    Execute,
    Probe,
    LocalOnly,
}

#[derive(Debug, Parser)]
#[command(
    name = "anne",
    version,
    about = "Enumerate a host's listening-port surface and correlate each endpoint with its owning process, hosted services, and firewall policy.",
    long_about = None,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Collect a fresh snapshot from a local host or an inventory of remote hosts.
    Scan(ScanArgs),
    /// Compare two snapshots and report drift.
    Diff {
        baseline: PathBuf,
        current: PathBuf,
        #[arg(long, value_enum, default_value_t = SeverityArg::High)]
        fail_on_drift: SeverityArg,
    },
    /// Render a stored snapshot as a report (JSON/CSV/SARIF/HTML).
    Report {
        target: String,
        /// Which machine format to render.
        #[arg(long, value_enum, default_value_t = ReportFormatArg::Json)]
        format: ReportFormatArg,
        /// Write the rendered report to this path instead of stdout.
        #[arg(long, value_name = "PATH", conflicts_with = "split")]
        output: Option<PathBuf>,
        /// Where the HTML report's fonts come from. Ignored for every
        /// other `--format`.
        #[arg(long, value_enum, default_value_t = FontsModeArg::Embed)]
        fonts: FontsModeArg,
        /// Emit one HTML file per host plus a lightweight index, instead
        /// of a single document. Only valid with `--format html`; takes
        /// the output directory (created if it doesn't exist) in place of
        /// `--output`.
        #[arg(long, value_name = "DIR", conflicts_with = "output")]
        split: Option<PathBuf>,
    },
    /// Validate an inventory file without scanning.
    Inventory {
        #[command(subcommand)]
        action: InventoryAction,
    },
    /// Print the build version (semver + git SHA) and exit.
    Version,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for anne_de_breuil::domain::Severity {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Low => Self::Low,
            SeverityArg::Medium => Self::Medium,
            SeverityArg::High => Self::High,
            SeverityArg::Critical => Self::Critical,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum InventoryAction {
    /// Parse `path` as an inventory TOML file and report any validation errors.
    Validate { path: PathBuf },
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    #[arg(long, conflicts_with = "inventory", value_name = "HOST")]
    pub target: Option<String>,

    #[arg(long, conflicts_with = "target", value_name = "FILE")]
    pub inventory: Option<PathBuf>,

    #[arg(long)]
    pub include_udp: bool,

    #[arg(long)]
    pub include_loopback: bool,

    #[arg(long)]
    pub skip_signature: bool,

    /// Include process command lines in the snapshot. Off by default --
    /// command lines routinely carry credentials, connection strings, and
    /// tokens.
    #[arg(long)]
    pub include_command_line: bool,

    /// Include process executable paths in the snapshot. Off by default --
    /// install paths can leak customer names and sensitive directory
    /// layouts.
    #[arg(long)]
    pub include_executable_path: bool,

    /// Include hosted-service `PathName` values (systemd `ExecStart=` / the
    /// Windows service `PathName`) in the snapshot. Off by default -- these
    /// can carry arguments and embedded secrets.
    #[arg(long)]
    pub include_service_path: bool,

    /// Include firewall rules that are present but disabled. Off by
    /// default -- disabled rules don't shape connectivity, but their
    /// program/service filter strings can still leak.
    #[arg(long)]
    pub include_disabled_firewall_rules: bool,

    #[arg(long, value_enum)]
    pub policy_store: Option<PolicyStoreArg>,

    #[arg(long, value_enum, default_value_t = StrategyArg::Auto)]
    pub strategy: StrategyArg,

    /// Enable active identification (makes outbound connections to the target).
    #[arg(long)]
    pub probe: bool,

    #[arg(long, value_name = "PORT_OR_CIDR")]
    pub probe_exclude: Vec<String>,

    #[arg(long, value_name = "DURATION")]
    pub probe_timeout: Option<String>,

    #[arg(long, value_name = "RPS")]
    pub probe_rate: Option<u32>,

    #[arg(long, value_name = "PATH")]
    pub store: Option<PathBuf>,

    /// Emit a bare `ScanSnapshot` to stdout — for the on-host collector mode.
    #[arg(long)]
    pub emit_json: bool,

    /// Loads `anne_de_breuil::adapters::config::AnneConfig` from this path
    /// and layers its `[scan]`/`[remote]`/`[store]` sections under whatever
    /// flags were also passed — see `application::scan::resolve_config`.
    /// Omitted entirely: every section falls back to its own built-in
    /// `Default`, exactly as before this flag existed (`[store]` has no
    /// `Default`, so `AnneConfig::load` is only ever called when this flag
    /// is actually given — see `resolve_config`'s doc comment for why).
    ///
    /// `ANNE_LOG_FORMAT` (read directly via `std::env::var` in `main.rs`,
    /// never through `AnneConfig`) still isn't renamed out of the `ANNE_`
    /// prefix (a pre-existing, unrelated collision `AnneConfig::load` would
    /// hit if that var happens to be set — see the T18 learning in
    /// `PROGRESS.md`); this flag's own wiring doesn't touch that.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

/// `--format` value for `anne report`.
///
/// Mirrors `anne_de_breuil::adapters::config::ReportFormat` variant-for-
/// variant (same pattern as [`PolicyStoreArg`]/[`SeverityArg`] below).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormatArg {
    Json,
    Csv,
    Sarif,
    Html,
}

impl From<ReportFormatArg> for anne_de_breuil::adapters::config::ReportFormat {
    fn from(value: ReportFormatArg) -> Self {
        match value {
            ReportFormatArg::Json => Self::Json,
            ReportFormatArg::Csv => Self::Csv,
            ReportFormatArg::Sarif => Self::Sarif,
            ReportFormatArg::Html => Self::Html,
        }
    }
}

/// `--fonts` value for `anne report --format html`.
///
/// Mirrors `anne_de_breuil::adapters::config::FontsMode` variant-for-
/// variant, same pattern as [`ReportFormatArg`] above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FontsModeArg {
    Embed,
    System,
}

impl From<FontsModeArg> for anne_de_breuil::adapters::config::FontsMode {
    fn from(value: FontsModeArg) -> Self {
        match value {
            FontsModeArg::Embed => Self::Embed,
            FontsModeArg::System => Self::System,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PolicyStoreArg {
    Local,
    Group,
    Dynamic,
    Static,
}

impl From<PolicyStoreArg> for anne_de_breuil::domain::PolicyStore {
    fn from(value: PolicyStoreArg) -> Self {
        match value {
            PolicyStoreArg::Local => Self::Local,
            PolicyStoreArg::Group => Self::GroupPolicy,
            PolicyStoreArg::Dynamic => Self::Dynamic,
            PolicyStoreArg::Static => Self::Static,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_numeric_values_match_contract() {
        // The discriminants come from the explicit `= N` assignments on the
        // `#[repr(i32)]` enum above; this test pins them so a future edit to
        // the enum can't silently change the exit-code contract that RMM
        // tooling and CI branch on.
        assert_eq!(ExitCode::Clean as i32, 0);
        assert_eq!(ExitCode::OperationalError as i32, 1);
        assert_eq!(ExitCode::ConfigOrArgError as i32, 2);
        assert_eq!(ExitCode::DriftDetected as i32, 3);
    }

    #[test]
    fn severity_arg_converts_to_domain_severity() {
        assert_eq!(
            anne_de_breuil::domain::Severity::from(SeverityArg::Low),
            anne_de_breuil::domain::Severity::Low
        );
        assert_eq!(
            anne_de_breuil::domain::Severity::from(SeverityArg::Critical),
            anne_de_breuil::domain::Severity::Critical
        );
    }

    #[test]
    fn report_format_arg_converts_to_config_report_format() {
        use anne_de_breuil::adapters::config::ReportFormat;

        assert_eq!(
            ReportFormat::from(ReportFormatArg::Json),
            ReportFormat::Json
        );
        assert_eq!(ReportFormat::from(ReportFormatArg::Csv), ReportFormat::Csv);
        assert_eq!(
            ReportFormat::from(ReportFormatArg::Sarif),
            ReportFormat::Sarif
        );
        assert_eq!(
            ReportFormat::from(ReportFormatArg::Html),
            ReportFormat::Html
        );
    }

    #[test]
    fn fonts_mode_arg_converts_to_config_fonts_mode() {
        use anne_de_breuil::adapters::config::FontsMode;

        assert_eq!(FontsMode::from(FontsModeArg::Embed), FontsMode::Embed);
        assert_eq!(FontsMode::from(FontsModeArg::System), FontsMode::System);
    }
}
