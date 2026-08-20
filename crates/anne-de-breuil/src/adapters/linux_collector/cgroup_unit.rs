//! Pure `/proc/<pid>/cgroup` parsing: recovers the systemd unit (if any)
//! that owns a process from its cgroup path, without shelling out to `systemctl`.
//!
//! No `#[cfg(target_os = "linux")]`: this operates on already-read text, so
//! it compiles and its tests run on any host.
//!
//! A `/proc/<pid>/cgroup` line is `hierarchy-id:controller-list:path`. On
//! cgroup v2 (unified) there is exactly one line, `0::/path`; on cgroup v1
//! or hybrid systems there are several, one per controller, and the
//! `name=systemd` (or unified `0::`) line is the one whose path carries
//! systemd unit names. A process's cgroup path can nest a scope or slice
//! inside its owning service (e.g. `/system.slice/foo.service/some.scope`)
//! -- the closest `.service` segment to the leaf, not the first one from
//! the root, is the process's actual owning unit, so this walks path
//! segments from the end.

/// Extracts the systemd service unit name owning a process from the full
/// text of its `/proc/<pid>/cgroup` file.
///
/// Returns `None` if no line's path contains a `.service` segment (e.g. a
/// kernel thread, or a process systemd never spawned).
#[must_use]
pub fn extract_systemd_unit_from_cgroup(contents: &str) -> Option<String> {
    contents.lines().find_map(extract_from_cgroup_line)
}

fn extract_from_cgroup_line(line: &str) -> Option<String> {
    let path = line.splitn(3, ':').nth(2)?;
    path.split('/')
        .rev()
        .find(|segment| segment.ends_with(".service"))
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::extract_systemd_unit_from_cgroup;

    #[test]
    fn cgroup_v2_unified_line_yields_service_name() {
        let contents = "0::/system.slice/sshd.service\n";
        assert_eq!(
            extract_systemd_unit_from_cgroup(contents).as_deref(),
            Some("sshd.service")
        );
    }

    #[test]
    fn cgroup_v1_hybrid_uses_name_equals_systemd_line() {
        let contents = "\
12:pids:/system.slice/nginx.service
11:cpu,cpuacct:/system.slice/nginx.service
1:name=systemd:/system.slice/nginx.service
0::/system.slice/nginx.service
";
        assert_eq!(
            extract_systemd_unit_from_cgroup(contents).as_deref(),
            Some("nginx.service")
        );
    }

    #[test]
    fn nested_scope_under_a_service_still_resolves_to_the_service() {
        let contents = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-foo.scope\n";
        assert_eq!(
            extract_systemd_unit_from_cgroup(contents).as_deref(),
            Some("user@1000.service")
        );
    }

    #[test]
    fn process_with_no_service_unit_yields_none() {
        let contents = "0::/init.scope\n";
        assert_eq!(extract_systemd_unit_from_cgroup(contents), None);
    }

    #[test]
    fn root_cgroup_yields_none() {
        assert_eq!(extract_systemd_unit_from_cgroup("0::/\n"), None);
    }

    #[test]
    fn empty_contents_yields_none() {
        assert_eq!(extract_systemd_unit_from_cgroup(""), None);
    }
}
