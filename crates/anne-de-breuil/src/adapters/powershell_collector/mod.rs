//! [`PowerShellCollector`]: the primary Windows collection adapter.
//!
//! Runs one embedded, `CLM`-safe helper script (`assets/collect.ps1`)
//! through `powershell.exe -NoProfile -NonInteractive -File`, reads its
//! JSON output back from a file the script writes itself, and implements
//! all four [`crate::application::collect`] ports against the one parsed
//! payload. The native Win32 adapter (T06) is the fallback for hosts
//! where this path isn't available; both are expected to produce
//! identical `Raw*` DTOs so a caller can swap between them freely.
//!
//! Security posture, non-negotiable per the task this module implements:
//! never `-EncodedCommand` (a base64 UTF-16LE command line is one of the
//! strongest EDR heuristics for malicious PowerShell), and never
//! `-ExecutionPolicy Bypass` by default (only behind
//! [`PowerShellCollector::with_execution_policy_bypass`], with a logged
//! warning every time it's used). [`payload`] is the pure,
//! platform-independent JSON-parsing half of this adapter — it has no
//! `#[cfg(windows)]` anywhere and runs on any host, which is how its
//! tests validate real fixture payloads without a Windows machine.

mod payload;

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::Command;
use tokio::sync::Mutex as AsyncMutex;

use self::payload::{LanguageMode, PowerShellPayload, parse_payload, strip_bom};
use crate::application::collect::{
    CollectError, EndpointSource, FirewallPolicySource, ProcessResolver, RawEndpoint, RawProcess,
    RawProfile, RawRule, RawService, SignatureVerifier,
};
use crate::domain::{ProcessId, ProcessPath, SignatureStatus};

const HELPER_SCRIPT: &str = include_str!("../../../assets/collect.ps1");

/// How the child process is invoked.
///
/// Production code only ever builds [`Backend::PowerShell`]. The
/// `#[cfg(test)]` [`Backend::Fixed`] variant exists solely so
/// [`PowerShellCollector::for_test_with_sleep_script`] can prove the
/// timeout-and-kill mechanism against a real, cross-platform-available
/// slow process (`sleep`) without requiring `powershell.exe` to exist on
/// the machine running the test.
enum Backend {
    PowerShell {
        script_path: PathBuf,
        execution_policy_bypass: bool,
    },
    #[cfg(test)]
    Fixed {
        program: std::ffi::OsString,
        args: Vec<std::ffi::OsString>,
    },
}

impl Backend {
    fn command(&self, out_path: &std::path::Path) -> Command {
        match self {
            Self::PowerShell {
                script_path,
                execution_policy_bypass,
            } => {
                let mut cmd = Command::new("powershell.exe");
                cmd.arg("-NoProfile").arg("-NonInteractive");
                if *execution_policy_bypass {
                    eprintln!(
                        "warning: PowerShellCollector is running with -ExecutionPolicy Bypass; \
                         the signed helper script should run under the host's own execution \
                         policy. This opt-in fallback is only intended for hosts where that \
                         genuinely fails."
                    );
                    cmd.arg("-ExecutionPolicy").arg("Bypass");
                }
                cmd.arg("-File")
                    .arg(script_path)
                    .arg("-OutputPath")
                    .arg(out_path);
                cmd
            }
            #[cfg(test)]
            Self::Fixed { program, args } => {
                let mut cmd = Command::new(program);
                cmd.args(args);
                cmd
            }
        }
    }
}

/// Collects the Windows listening-port surface through the embedded
/// PowerShell helper script.
///
/// One instance is expected to serve all four collector ports for a
/// single scan of a single host: the first port method called runs the
/// script and parses its output; every later call on the same instance
/// reuses that parsed payload rather than re-invoking PowerShell, so a
/// `CollectorSet` built over one `&PowerShellCollector` reflects one
/// consistent point-in-time snapshot instead of four independent ones.
pub struct PowerShellCollector {
    backend: Backend,
    timeout: Duration,
    child_running: Arc<AtomicBool>,
    cached: AsyncMutex<Option<Arc<PowerShellPayload>>>,
}

impl PowerShellCollector {
    /// Writes the embedded helper script to a fresh temp file and builds a
    /// collector that runs it under the host's own execution policy.
    ///
    /// `timeout` bounds the child process; a hung `powershell.exe` is
    /// killed and reaped before this returns `Err(CollectError::Timeout)`,
    /// never left running.
    ///
    /// # Errors
    ///
    /// Returns [`CollectError::Spawn`] if the embedded script cannot be
    /// written to a temp file.
    pub fn new(timeout: Duration) -> Result<Self, CollectError> {
        let script_path = write_embedded_script()?;
        Ok(Self {
            backend: Backend::PowerShell {
                script_path,
                execution_policy_bypass: false,
            },
            timeout,
            child_running: Arc::new(AtomicBool::new(false)),
            cached: AsyncMutex::new(None),
        })
    }

    /// Builds a collector that passes `-ExecutionPolicy Bypass` to every
    /// invocation, logging a warning each time it runs.
    ///
    /// This must never be the default path — see the module docs. It
    /// exists for the rare host where the signed script genuinely cannot
    /// run under the configured execution policy and an operator has
    /// explicitly chosen to accept the risk.
    ///
    /// # Errors
    ///
    /// Returns [`CollectError::Spawn`] if the embedded script cannot be
    /// written to a temp file.
    pub fn with_execution_policy_bypass(timeout: Duration) -> Result<Self, CollectError> {
        let script_path = write_embedded_script()?;
        Ok(Self {
            backend: Backend::PowerShell {
                script_path,
                execution_policy_bypass: true,
            },
            timeout,
            child_running: Arc::new(AtomicBool::new(false)),
            cached: AsyncMutex::new(None),
        })
    }

    /// Builds a collector that spawns `sleep <secs>` instead of
    /// `powershell.exe`, so the timeout-and-kill mechanism can be tested
    /// with a real child process on any Unix host — no PowerShell
    /// required.
    #[cfg(test)]
    fn for_test_with_sleep_script(timeout: Duration) -> Self {
        Self {
            backend: Backend::Fixed {
                program: "sleep".into(),
                args: vec!["5".into()],
            },
            timeout,
            child_running: Arc::new(AtomicBool::new(false)),
            cached: AsyncMutex::new(None),
        }
    }

    /// `true` if the most recently spawned child has not yet been
    /// confirmed exited.
    #[cfg(test)]
    fn child_still_running(&self) -> bool {
        self.child_running.load(Ordering::SeqCst)
    }

    async fn run_script(&self) -> Result<Vec<u8>, CollectError> {
        let out_path = std::env::temp_dir().join(format!("anne-{}.json", uuid::Uuid::new_v4()));

        let mut child = self
            .backend
            .command(&out_path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|source| CollectError::Spawn(source.to_string()))?;

        self.child_running.store(true, Ordering::SeqCst);

        let status = match tokio::time::timeout(self.timeout, child.wait()).await {
            Ok(wait_result) => {
                self.child_running.store(false, Ordering::SeqCst);
                wait_result.map_err(|source| CollectError::Spawn(source.to_string()))?
            }
            Err(_elapsed) => {
                // `kill_on_drop(true)` above only fires once `child` is
                // dropped, which happens too late for a caller to observe
                // deterministically. Kill and reap explicitly here so a
                // hung PowerShell process is provably gone by the time
                // this function returns, not merely scheduled to be gone
                // eventually.
                let _ = child.kill().await;
                let _ = child.wait().await;
                self.child_running.store(false, Ordering::SeqCst);
                return Err(CollectError::Timeout(self.timeout));
            }
        };

        if !status.success() {
            return Err(CollectError::Spawn(format!(
                "powershell exited with {status}"
            )));
        }

        let bytes = tokio::fs::read(&out_path)
            .await
            .map_err(|source| CollectError::Parse(source.to_string()))?;
        let _ = tokio::fs::remove_file(&out_path).await;
        Ok(strip_bom(bytes))
    }

    /// The `PSLanguageMode` the helper script observed on its most recent
    /// successful run, or `None` if no collection has completed yet.
    ///
    /// A caller assembling a report should surface this:
    /// [`LanguageMode::Constrained`] means the collected data (firewall
    /// policy especially — see the module docs) reflects whatever a
    /// locked-down host's module allowlist permitted, not necessarily
    /// everything the script asks for.
    pub async fn language_mode(&self) -> Option<LanguageMode> {
        self.cached
            .lock()
            .await
            .as_ref()
            .map(|payload| payload.language_mode)
    }

    async fn payload(&self) -> Result<Arc<PowerShellPayload>, CollectError> {
        // The lock is only ever held for the quick check-and-store, never
        // across `run_script`'s process spawn/wait -- that can legitimately
        // take up to `self.timeout`, and no other port method should be
        // blocked waiting on this instance's mutex for that long.
        {
            let cached = self.cached.lock().await;
            if let Some(payload) = &*cached {
                return Ok(Arc::clone(payload));
            }
        }

        let bytes = self.run_script().await?;
        let parsed = Arc::new(parse_payload(&bytes)?);

        let winner = {
            let mut cached = self.cached.lock().await;
            // If another caller's collection landed first while this one
            // ran, `get_or_insert_with` keeps that existing payload instead
            // of clobbering it, so every port method a caller drives
            // against this instance still agrees on one snapshot.
            Arc::clone(cached.get_or_insert_with(|| parsed))
        };
        Ok(winner)
    }
}

fn write_embedded_script() -> Result<PathBuf, CollectError> {
    let path = std::env::temp_dir().join(format!("anne-collect-{}.ps1", uuid::Uuid::new_v4()));
    std::fs::write(&path, HELPER_SCRIPT)
        .map_err(|source| CollectError::Spawn(source.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

#[async_trait]
impl EndpointSource for PowerShellCollector {
    async fn listening_endpoints(&self) -> Result<Vec<RawEndpoint>, CollectError> {
        let payload = self.payload().await?;
        let mut endpoints = payload.tcp_endpoints.clone();
        endpoints.extend(payload.udp_endpoints.clone());
        Ok(endpoints)
    }
}

#[async_trait]
impl ProcessResolver for PowerShellCollector {
    async fn describe(&self, pid: ProcessId) -> Result<Option<RawProcess>, CollectError> {
        let payload = self.payload().await?;
        Ok(payload
            .processes
            .iter()
            .find(|process| process.pid == pid.get())
            .cloned())
    }

    async fn hosted_services(&self, pid: ProcessId) -> Result<Vec<RawService>, CollectError> {
        let payload = self.payload().await?;
        Ok(payload
            .services
            .iter()
            .filter(|hosted| hosted.process_id == pid.get())
            .map(|hosted| hosted.service.clone())
            .collect())
    }
}

#[async_trait]
impl FirewallPolicySource for PowerShellCollector {
    async fn inbound_rules(&self) -> Result<Vec<RawRule>, CollectError> {
        let payload = self.payload().await?;
        Ok(payload
            .firewall_rules
            .iter()
            .filter(|rule| rule.direction.eq_ignore_ascii_case("inbound"))
            .cloned()
            .collect())
    }

    async fn profiles(&self) -> Result<Vec<RawProfile>, CollectError> {
        let payload = self.payload().await?;
        Ok(payload.firewall_profiles.clone())
    }
}

#[async_trait]
impl SignatureVerifier for PowerShellCollector {
    // TODO(T06): Authenticode verification (`Get-AuthenticodeSignature` or
    // native `WinVerifyTrust`) is real capability this collection path
    // has cheap access to, but it's a per-path, not a bulk-collected,
    // query -- wiring it in belongs with the native adapter's signature
    // handling, not invented ad hoc here against an untested code path.
    async fn verify(&self, _path: &ProcessPath) -> Result<SignatureStatus, CollectError> {
        Ok(SignatureStatus::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::PowerShellCollector;
    use crate::application::collect::CollectError;

    #[tokio::test]
    #[cfg(unix)]
    async fn hung_child_is_killed_at_timeout() {
        let collector = PowerShellCollector::for_test_with_sleep_script(Duration::from_millis(50));

        let err = collector.run_script().await.unwrap_err();

        assert!(matches!(err, CollectError::Timeout(_)));
        assert!(!collector.child_still_running());
    }

    #[test]
    fn script_never_uses_encoded_command() {
        assert!(!super::HELPER_SCRIPT.contains("EncodedCommand"));
    }

    #[test]
    fn execution_policy_bypass_defaults_to_off() {
        let backend = super::Backend::PowerShell {
            script_path: std::path::PathBuf::from("/tmp/does-not-matter.ps1"),
            execution_policy_bypass: false,
        };
        let cmd = backend.command(std::path::Path::new("/tmp/out.json"));
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(!args.iter().any(|a| a == "Bypass"));
    }

    #[test]
    fn execution_policy_bypass_opt_in_adds_the_flag() {
        let backend = super::Backend::PowerShell {
            script_path: std::path::PathBuf::from("/tmp/does-not-matter.ps1"),
            execution_policy_bypass: true,
        };
        let cmd = backend.command(std::path::Path::new("/tmp/out.json"));
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|a| a == "Bypass"));
    }
}
