//! [`WindowsProcessResolver`]: process metadata via `sysinfo`, hosted
//! services via [`super::services::enum_services_grouped_by_pid`].
//!
//! Both the `sysinfo::System` snapshot and the service-to-pid grouping are
//! taken lazily, on the first call that needs them, and cached for this
//! resolver's lifetime — the same pattern
//! [`crate::adapters::powershell_collector::PowerShellCollector::payload`]
//! already uses. Because [`crate::application::collect::collect_endpoints`]
//! always resolves every endpoint before asking about any of their owning
//! processes, this snapshot is necessarily taken *after* `netstat2` ran,
//! which is exactly the race window T04's `ProcessGone` models: a pid
//! observed in the socket table can legitimately have exited by the time
//! this snapshot is taken. `describe` returning `None` for that pid is
//! what the generic collection handler already turns into
//! `ProcessAttribution::ProcessGone` — no adapter-local marker is needed
//! here for that case (see the module docs on `super` for the full
//! reconciliation).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use sysinfo::System;
use tokio::sync::Mutex as AsyncMutex;

use super::services::enum_services_grouped_by_pid;
use crate::application::collect::{CollectError, ProcessResolver, RawProcess, RawService};
use crate::domain::ProcessId;

/// PID → every service `EnumServicesStatusExW` reported running under it.
type ServicesByPid = HashMap<u32, Vec<RawService>>;

/// Resolves processes via `sysinfo` and hosted services via
/// `EnumServicesStatusExW`, each cached after their first successful query.
pub struct WindowsProcessResolver {
    processes: AsyncMutex<Option<Arc<HashMap<u32, RawProcess>>>>,
    services_by_pid: AsyncMutex<Option<Arc<ServicesByPid>>>,
}

impl WindowsProcessResolver {
    /// Builds a resolver with nothing cached yet — the first
    /// [`ProcessResolver::describe`] or
    /// [`ProcessResolver::hosted_services`] call populates its snapshot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            processes: AsyncMutex::const_new(None),
            services_by_pid: AsyncMutex::const_new(None),
        }
    }

    async fn process_snapshot(&self) -> Result<Arc<HashMap<u32, RawProcess>>, CollectError> {
        {
            let cached = self.processes.lock().await;
            if let Some(map) = &*cached {
                return Ok(Arc::clone(map));
            }
        }

        let map = tokio::task::spawn_blocking(build_process_map)
            .await
            .map_err(|source| CollectError::Parse(source.to_string()))?;
        let map = Arc::new(map);

        let mut cached = self.processes.lock().await;
        Ok(Arc::clone(cached.get_or_insert_with(|| map)))
    }

    async fn services_snapshot(&self) -> Result<Arc<ServicesByPid>, CollectError> {
        {
            let cached = self.services_by_pid.lock().await;
            if let Some(map) = &*cached {
                return Ok(Arc::clone(map));
            }
        }

        let map = tokio::task::spawn_blocking(enum_services_grouped_by_pid)
            .await
            .map_err(|source| CollectError::Parse(source.to_string()))??;
        let map = Arc::new(map);

        let mut cached = self.services_by_pid.lock().await;
        Ok(Arc::clone(cached.get_or_insert_with(|| map)))
    }
}

impl Default for WindowsProcessResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProcessResolver for WindowsProcessResolver {
    async fn describe(&self, pid: ProcessId) -> Result<Option<RawProcess>, CollectError> {
        let snapshot = self.process_snapshot().await?;
        Ok(snapshot.get(&pid.get()).cloned())
    }

    async fn hosted_services(&self, pid: ProcessId) -> Result<Vec<RawService>, CollectError> {
        let snapshot = self.services_snapshot().await?;
        // Every entry under this pid is returned, not just the first —
        // see the module docs: a shared, unsplit `svchost.exe` hosting
        // several services is exactly this case, and the honest answer is
        // every candidate, not a guess at one.
        Ok(snapshot.get(&pid.get()).cloned().unwrap_or_default())
    }
}

fn build_process_map() -> HashMap<u32, RawProcess> {
    let system = System::new_all();
    system
        .processes()
        .iter()
        .map(|(pid, process)| {
            let raw_pid = pid.as_u32();
            let path = process.exe().map(|exe| exe.display().to_string());
            let command_line = command_line_of(process);
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
