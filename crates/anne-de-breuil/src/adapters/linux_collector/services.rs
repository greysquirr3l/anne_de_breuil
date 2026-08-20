//! `/proc/<pid>/cgroup` reading -- the only I/O in the systemd-unit
//! attribution path; [`super::cgroup_unit`] owns the actual text parsing.

use crate::application::collect::{CollectError, RawService};

use super::cgroup_unit::extract_systemd_unit_from_cgroup;

/// Reads `pid`'s cgroup path and maps it to the systemd unit hosting it,
/// if any.
///
/// A process that exited between being resolved by [`super::processes`]
/// and this call running is reported as "hosts no services" (`Ok(vec![])`),
/// not an error -- the same race
/// [`crate::application::collect::ProcessAttribution::ProcessGone`] already
/// exists to model at the endpoint level; a service-lookup race on an
/// already-resolved process isn't a distinct failure worth surfacing
/// separately.
pub(super) fn hosted_services_for_pid(pid: u32) -> Result<Vec<RawService>, CollectError> {
    let contents = match std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(CollectError::Parse(err.to_string())),
    };

    Ok(extract_systemd_unit_from_cgroup(&contents)
        .into_iter()
        .map(|name| RawService {
            display_name: name.clone(),
            name,
        })
        .collect())
}
