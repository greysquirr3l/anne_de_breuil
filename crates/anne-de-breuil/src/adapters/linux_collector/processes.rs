//! [`LinuxProcessResolver`]: process metadata via `sysinfo`, resolved
//! executable path via `/proc/<pid>/exe`, hosted services via
//! [`super::services::hosted_services_for_pid`].
//!
//! The `sysinfo::System` snapshot is taken lazily on the first call and
//! cached for this resolver's lifetime, the same pattern
//! [`super::super::windows_collector::processes::WindowsProcessResolver`]
//! uses -- and for the same reason: [`crate::application::collect::collect_endpoints`]
//! always resolves every endpoint before asking about any owning process,
//! so this snapshot is necessarily taken after the socket table was read,
//! which is the race window `ProcessAttribution::ProcessGone` models.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use sysinfo::System;
use tokio::sync::Mutex as AsyncMutex;

use super::services::hosted_services_for_pid;
use crate::application::collect::{
    CollectError, ProcessResolver, RawProcess, RawService, RedactionPolicy,
};
use crate::domain::ProcessId;

/// Resolves processes via `sysinfo`, enriching each with `/proc/<pid>/exe`'s
/// resolved target; caches the snapshot after its first successful query.
pub struct LinuxProcessResolver {
    processes: AsyncMutex<Option<Arc<HashMap<u32, RawProcess>>>>,
    redaction: RedactionPolicy,
}

impl LinuxProcessResolver {
    /// Builds a resolver with nothing cached yet -- the first
    /// [`ProcessResolver::describe`] call populates its snapshot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            processes: AsyncMutex::const_new(None),
            redaction: RedactionPolicy::default(),
        }
    }

    /// Builds a resolver that opts in to one or more sensitive-field
    /// categories via the [`RedactionPolicy`]. Mirrors
    /// `PowerShellCollector::with_redaction_policy` so the same flag on
    /// both platforms produces a snapshot with the same omission
    /// semantics — `include_command_line = false` means
    /// `RawProcess.command_line == None` on Windows _and_ Linux.
    #[must_use]
    pub fn with_redaction_policy(mut self, redaction: RedactionPolicy) -> Self {
        self.redaction = redaction;
        self
    }

    async fn process_snapshot(&self) -> Result<Arc<HashMap<u32, RawProcess>>, CollectError> {
        {
            let cached = self.processes.lock().await;
            if let Some(map) = &*cached {
                return Ok(Arc::clone(map));
            }
        }

        let redaction = self.redaction;
        let map = tokio::task::spawn_blocking(move || build_process_map(redaction))
            .await
            .map_err(|source| CollectError::Parse(source.to_string()))?;
        let map = Arc::new(map);

        let mut cached = self.processes.lock().await;
        Ok(Arc::clone(cached.get_or_insert_with(|| map)))
    }
}

impl Default for LinuxProcessResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProcessResolver for LinuxProcessResolver {
    async fn describe(&self, pid: ProcessId) -> Result<Option<RawProcess>, CollectError> {
        let snapshot = self.process_snapshot().await?;
        Ok(snapshot.get(&pid.get()).cloned())
    }

    async fn hosted_services(&self, pid: ProcessId) -> Result<Vec<RawService>, CollectError> {
        let raw_pid = pid.get();
        tokio::task::spawn_blocking(move || hosted_services_for_pid(raw_pid))
            .await
            .map_err(|source| CollectError::Parse(source.to_string()))?
    }
}

fn build_process_map(redaction: RedactionPolicy) -> HashMap<u32, RawProcess> {
    let system = System::new_all();
    system
        .processes()
        .iter()
        .map(|(pid, process)| {
            let raw_pid = pid.as_u32();
            let path = if redaction.include_executable_path {
                resolved_exe_path(raw_pid)
                    .or_else(|| process.exe().map(|exe| exe.display().to_string()))
            } else {
                None
            };
            let command_line = if redaction.include_command_line {
                command_line_of(process)
            } else {
                None
            };
            (
                raw_pid,
                RawProcess {
                    pid: raw_pid,
                    path,
                    command_line,
                },
            )
        })
        .collect()
}

/// Reads `/proc/<pid>/exe`'s symlink target directly, per this task's own
/// instruction, rather than trusting only `sysinfo`'s resolution --
/// `sysinfo` itself reads the same symlink internally, but doing it here
/// too gives an honest fallback to `sysinfo`'s answer (rather than a
/// silent `None`) when the caller lacks permission to read another user's
/// `/proc/<pid>/exe`.
fn resolved_exe_path(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|target| target.display().to_string())
}

fn command_line_of(process: &sysinfo::Process) -> Option<String> {
    let args = process.cmd();
    if args.is_empty() {
        return None;
    }
    Some(
        args.iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" "),
    )
}
