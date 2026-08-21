//! T31's real end-to-end proof for the production `HostScanner`: a
//! locally-spawned OpenSSH `sshd`, a real inventory file, a real `--config`
//! file, and the actual built `anne` binary run as a subprocess via
//! `assert_cmd` — no mock transport, no fixture collector script.
//!
//! `anne scan --inventory <file> --config <file>` connects to `127.0.0.1`
//! as the invoking OS user, pushes *itself* (`std::env::current_exe()`
//! inside that subprocess resolves to the real `anne` binary on disk) over
//! SFTP, runs the pushed copy with `--self-hash` then `scan --emit-json`,
//! and persists the resulting snapshot — every step genuinely exercised,
//! not mocked. This mirrors `SshdFixture` in
//! `anne-de-breuil/src/adapters/ssh_transport/tests.rs` (same rationale: a
//! real local `sshd` is simpler than a container and still speaks the real
//! protocol end to end); this crate can't reuse that fixture directly since
//! it's private to the library crate's own test module, so this is a
//! deliberately small, standalone equivalent, not a second harness design.

#[cfg(test)]
mod support;

// Everything below (fixture + the test itself) lives inside one
// `#[cfg(test)]` module rather than as bare top-level items in this file --
// clippy's `allow-*-in-tests` config (`clippy.toml`) only recognises code
// as test code when it's lexically nested under a `#[cfg(test)]` item, not
// merely because Cargo only ever compiles a `tests/*.rs` binary under the
// test profile. `tests/support/mod.rs`'s own doc comment documents the
// same gotcha for the identical reason.
#[cfg(test)]
mod scenario {
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    use crate::support;

    struct SshdFixture {
        child: Child,
        port: u16,
        dir: tempfile::TempDir,
        client_key_path: PathBuf,
        user: String,
    }

    impl SshdFixture {
        fn spawn() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let host_key_path = dir.path().join("host_key");
            let client_key_path = dir.path().join("client_key");
            run_ssh_keygen(&host_key_path);
            run_ssh_keygen(&client_key_path);

            let client_pub = std::fs::read_to_string(dir.path().join("client_key.pub"))
                .expect("read client pubkey");
            std::fs::write(dir.path().join("authorized_keys"), &client_pub)
                .expect("write authorized_keys");
            let mut perms = std::fs::metadata(&host_key_path)
                .expect("stat host key")
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&host_key_path, perms).expect("chmod host key");

            let port = free_local_port();
            let config_path = dir.path().join("sshd_config");
            std::fs::write(
                &config_path,
                format!(
                    "Port {port}\n\
                     ListenAddress 127.0.0.1\n\
                     HostKey {host_key}\n\
                     AuthorizedKeysFile {authorized_keys}\n\
                     PidFile {pid_file}\n\
                     UsePAM no\n\
                     PasswordAuthentication no\n\
                     KbdInteractiveAuthentication no\n\
                     PubkeyAuthentication yes\n\
                     StrictModes no\n\
                     Subsystem sftp internal-sftp\n\
                     LogLevel ERROR\n",
                    host_key = host_key_path.display(),
                    authorized_keys = dir.path().join("authorized_keys").display(),
                    pid_file = dir.path().join("sshd.pid").display(),
                ),
            )
            .expect("write sshd_config");

            let child = Command::new("/usr/sbin/sshd")
                .args(["-f", config_path.to_str().expect("utf8 path"), "-D", "-e"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn sshd -- this test requires a system sshd at /usr/sbin/sshd");

            wait_for_port(port);

            Self {
                child,
                port,
                dir,
                client_key_path,
                user: current_user(),
            }
        }

        fn known_hosts_file(&self) -> PathBuf {
            let host_pub = std::fs::read_to_string(self.dir.path().join("host_key.pub"))
                .expect("read host key");
            let line = format!("[127.0.0.1]:{} {}", self.port, host_pub.trim());
            let path = self.dir.path().join("known_hosts");
            std::fs::write(&path, line).expect("write known_hosts");
            path
        }
    }

    impl Drop for SshdFixture {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn run_ssh_keygen(key_path: &Path) {
        let status = Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                key_path.to_str().expect("utf8 path"),
                "-q",
            ])
            .status()
            .expect("run ssh-keygen -- this test requires ssh-keygen on PATH");
        assert!(
            status.success(),
            "ssh-keygen failed for {}",
            key_path.display()
        );
    }

    fn free_local_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        listener.local_addr().expect("local_addr").port()
    }

    fn wait_for_port(port: u16) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("sshd did not start listening on 127.0.0.1:{port} in time");
    }

    fn current_user() -> String {
        std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .expect("USER or LOGNAME must be set to run this test")
    }

    #[test]
    fn scan_inventory_against_a_real_sshd_pushes_and_runs_the_real_anne_binary() {
        let sshd = SshdFixture::spawn();
        let work_dir = tempfile::tempdir().expect("tempdir");

        let inventory_path = work_dir.path().join("inventory.toml");
        std::fs::write(
            &inventory_path,
            format!(
                "[[host]]\n\
                 host_id = \"cccccccc-cccc-cccc-cccc-cccccccccccc\"\n\
                 address = \"127.0.0.1\"\n\
                 port = {port}\n\
                 user = \"{user}\"\n\
                 auth = {{ key_file = \"{key_path}\" }}\n",
                port = sshd.port,
                user = sshd.user,
                key_path = sshd.client_key_path.display(),
            ),
        )
        .expect("write inventory");

        let store_path = work_dir.path().join("store");
        let config_path = work_dir.path().join("anne.toml");
        std::fs::write(
            &config_path,
            format!(
                "[remote]\n\
                 concurrency = 1\n\
                 timeout = \"60s\"\n\
                 known_hosts = \"{known_hosts}\"\n\
                 accept_new = false\n\
                 \n\
                 [store]\n\
                 backend = \"FileSystem\"\n\
                 path = \"{store_path}\"\n",
                known_hosts = sshd.known_hosts_file().display(),
                store_path = store_path.display(),
            ),
        )
        .expect("write config");

        let output = support::anne_cmd()
            .args(["scan", "--inventory"])
            .arg(&inventory_path)
            .arg("--config")
            .arg(&config_path)
            .output()
            .expect("anne scan --inventory runs");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "expected a clean exit; stdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains("scanned") && stdout.contains("Execute"),
            "expected an Execute-tier summary line, got stdout: {stdout}\nstderr: {stderr}"
        );

        // The real proof this test exists for: a snapshot file genuinely
        // landed in the configured store, not just a clean exit code.
        let entries: Vec<_> = std::fs::read_dir(&store_path)
            .expect("store directory exists")
            .filter_map(Result::ok)
            .collect();
        assert!(
            !entries.is_empty(),
            "expected at least one persisted snapshot file under {}",
            store_path.display()
        );
    }
}
