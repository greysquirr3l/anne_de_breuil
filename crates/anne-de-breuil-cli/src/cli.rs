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
    /// Render a stored snapshot as a report (HTML/JSON/CSV/SARIF; T21 wires formats).
    Report { target: String },
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

    // TODO(T31): wire this into `anne_de_breuil::adapters::config::AnneConfig::load`
    // alongside the rest of the local-collector integration. Two things need
    // to happen together, not separately, when that lands: (1) `scan_local`
    // needs to actually read the loaded `ScanConfig` instead of the
    // `LocalCollectorSet` stub it uses today, and (2) `ANNE_LOG_FORMAT` (read
    // directly via `std::env::var` in `main.rs`, never through `AnneConfig`)
    // needs to be renamed outside the `ANNE_` prefix first — confirmed by a
    // scratch build against the real `AnneConfig::load` that a bare
    // `ANNE_LOG_FORMAT` in the process environment fails as an unknown
    // top-level field (`log_format`) even under the `__`-section-separator
    // fix, because it has no `__` in it to split on and lands as a
    // single-segment top-level key. Left unwired here rather than papered
    // over, since fixing only one half would either silently ignore
    // `--config` or reintroduce the exact env-var collision already fixed
    // once for `ANNE_CLI_GIT_HASH`.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
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
}
