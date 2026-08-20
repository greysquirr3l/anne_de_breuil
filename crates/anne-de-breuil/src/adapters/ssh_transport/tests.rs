//! Integration tests against a real, locally-spawned OpenSSH `sshd`.
//!
//! # Fixture strategy
//!
//! The task called for a containerised sshd fixture, with a locally-spawned
//! one as an acceptable substitute. This machine has both Docker and a
//! system `sshd`/`ssh-keygen` available. A locally-spawned `sshd` was
//! chosen over a Docker container for these tests specifically because:
//!
//! - It's genuinely simpler: no image build/pull, no container networking
//!   (port publishing, waiting for the container's network namespace to be
//!   ready), no extra CI dependency beyond what's already on this host.
//! - It's still a *real* sshd speaking the real protocol end to end --
//!   these tests exercise actual TCP, actual SSH key exchange, actual host
//!   key verification, actual SFTP, actual exec channels. Nothing here is
//!   mocked at the protocol level.
//! - It was verified interactively before writing any test code: a
//!   throwaway `sshd` bound to a high port, with a generated ed25519 host
//!   key and a generated ed25519 client key in `authorized_keys`, accepted
//!   a real `ssh`-client connection and ran a command
//!   (`command not found` is unrelated -- the point was proving key auth
//!   and command execution both worked, which they did).
//!
//! Each test that needs a live sshd spawns its own via [`SshdFixture::spawn`]
//! rather than sharing one across the module, so a failure in one test's
//! session can't leave a later test's fixture in a bad state.
//!
//! The two host-key-verification tests
//! (`unknown_host_key_fails_closed_by_default` /
//! `unknown_host_key_succeeds_with_accept_new`) live in `known_hosts.rs`
//! instead of here: [`known_hosts::verify_host_key`] is pure, synchronous
//! logic with no session or network involved, so they run unconditionally
//! as plain `#[test]`s with no sshd dependency at all -- see that module.

use std::io::Write as _;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::Mutex as AsyncMutex;

use super::{DEFAULT_MAX_OUTPUT_BYTES, KnownHosts, SshTransport};
use crate::adapters::inventory::AuthMethod;
use crate::application::remote::{RemoteCommand, RemoteTransport as _, TransportError};
use crate::domain::{HostId, ScanId, ScanSnapshot, TargetStrategy};

/// A throwaway, locally-spawned `sshd` bound to `127.0.0.1` on a free port,
/// with a fresh ed25519 host key and a fresh ed25519 client key authorized
/// for the current OS user. Torn down on `Drop`.
struct SshdFixture {
    child: Child,
    port: u16,
    #[expect(dead_code, reason = "kept alive for its Drop -- the sshd config, keys, and \
                                    authorized_keys file must outlive the child process")]
    work_dir: TempDir,
    client_key_path: PathBuf,
    known_hosts: Arc<KnownHosts>,
    user: String,
}

impl SshdFixture {
    fn spawn() -> Self {
        let work_dir = tempfile::tempdir().expect("create fixture temp dir");
        let dir = work_dir.path();

        let host_key_path = dir.join("host_key");
        let client_key_path = dir.join("client_key");
        run_ssh_keygen(&host_key_path);
        run_ssh_keygen(&client_key_path);

        let client_pub =
            std::fs::read_to_string(dir.join("client_key.pub")).expect("read client pubkey");
        std::fs::write(dir.join("authorized_keys"), &client_pub).expect("write authorized_keys");
        let mut perms = std::fs::metadata(&host_key_path).expect("stat host key").permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&host_key_path, perms).expect("chmod host key");

        let port = free_local_port();
        let config_path = dir.join("sshd_config");
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
                authorized_keys = dir.join("authorized_keys").display(),
                pid_file = dir.join("sshd.pid").display(),
            ),
        )
        .expect("write sshd_config");

        let child = Command::new("/usr/sbin/sshd")
            .args(["-f", config_path.to_str().expect("utf8 path"), "-D", "-e"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sshd -- this fixture requires a system sshd at /usr/sbin/sshd");

        wait_for_port(port);

        let host_pub =
            std::fs::read_to_string(dir.join("host_key.pub")).expect("read host pubkey");
        let known_hosts_line = format!("[127.0.0.1]:{port} {}", host_pub.trim());
        let known_hosts = Arc::new(KnownHosts::parse(&known_hosts_line));

        Self {
            child,
            port,
            work_dir,
            client_key_path,
            known_hosts,
            user: current_user(),
        }
    }

    const fn port(&self) -> u16 {
        self.port
    }

    fn auth(&self) -> AuthMethod {
        AuthMethod::KeyFile(self.client_key_path.clone())
    }

    async fn connect(&self) -> Result<Arc<SshTransport>, TransportError> {
        SshTransport::connect(
            "127.0.0.1",
            self.port,
            &self.user,
            &self.auth(),
            Arc::clone(&self.known_hosts),
            false,
            DEFAULT_MAX_OUTPUT_BYTES,
        )
        .await
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
        .expect("run ssh-keygen -- this fixture requires ssh-keygen on PATH");
    assert!(status.success(), "ssh-keygen failed for {key_path:?}");
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
        .expect("USER or LOGNAME must be set to run these fixture tests")
}

/// A fixture "collector" standing in for the real one T18 will build. Its
/// `--self-hash` and `--emit-json` behaviour is baked in at write time
/// (not read from the environment/argv at run time) so the SSH-side
/// plumbing under test -- push, hash compare, exec, JSON decode, cleanup --
/// is exercised against known-good, known-bad inputs without needing the
/// real collector binary this task doesn't own.
fn write_fixture_collector(dir: &Path, self_hash: &str, snapshot: &ScanSnapshot) -> PathBuf {
    let json = serde_json::to_string(snapshot).expect("serialize fixture snapshot");
    let script_path = dir.join("fixture-collector.sh");
    let mut file = std::fs::File::create(&script_path).expect("create fixture collector");
    write!(
        file,
        "#!/bin/sh\n\
         if [ \"$1\" = \"--self-hash\" ]; then\n\
         printf '%s' '{self_hash}'\n\
         elif [ \"$1\" = \"--emit-json\" ]; then\n\
         cat <<'ANNE_FIXTURE_EOF'\n\
         {json}\n\
         ANNE_FIXTURE_EOF\n\
         fi\n"
    )
    .expect("write fixture collector script");
    let mut perms = std::fs::metadata(&script_path)
        .expect("stat fixture collector")
        .permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(&script_path, perms).expect("chmod fixture collector");
    script_path
}

fn sample_snapshot() -> ScanSnapshot {
    ScanSnapshot::new(
        HostId::generate(),
        ScanId::generate(),
        time::OffsetDateTime::UNIX_EPOCH,
        "fixture-1.0.0".to_owned(),
        vec![],
        vec![],
        vec![],
        TargetStrategy::Execute,
    )
}

/// Every test in this module that counts `anne-collector-*` entries under
/// the *shared, real* `/tmp` directory (there is exactly one `/tmp` on the
/// machine running these tests, unlike the sshd fixture, which each test
/// gets its own instance of) must hold this lock for the duration of its
/// push/cleanup so Rust's default parallel test execution can't interleave
/// two tests' pushes and make one test's artifact look like a leak in
/// another's before/after count.
static TMP_ARTIFACT_LOCK: LazyLock<AsyncMutex<()>> = LazyLock::new(|| AsyncMutex::new(()));

/// Counts files under `/tmp` whose name starts with the prefix
/// [`crate::application::remote::RemotePath::random_under_temp`] uses, as a
/// leak detector: any test that pushes an artifact and is supposed to clean
/// it up should leave this count unchanged from before the call.
fn anne_artifact_count_in_tmp() -> usize {
    std::fs::read_dir("/tmp").map_or(0, |entries| {
        entries
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("anne-collector-"))
            })
            .count()
    })
}

#[tokio::test]
async fn push_exec_collect_remove_round_trip() {
    let _lock = TMP_ARTIFACT_LOCK.lock().await;
    let sshd = SshdFixture::spawn();
    let transport = sshd.connect().await.expect("connect to fixture sshd");

    let expected_snapshot = sample_snapshot();
    let collector = write_fixture_collector(
        std::env::temp_dir().as_path(),
        "fixture-hash-abc123",
        &expected_snapshot,
    );

    let snapshot = transport
        .push_exec_collect_remove(&collector, "fixture-hash-abc123")
        .await
        .expect("push_exec_collect_remove should succeed against the fixture collector");

    assert_eq!(snapshot.host_id, expected_snapshot.host_id);
    assert_eq!(snapshot.scan_id, expected_snapshot.scan_id);

    let _ = std::fs::remove_file(&collector);
}

#[tokio::test]
async fn remote_artifact_removed_after_forced_mid_exec_failure() {
    let _lock = TMP_ARTIFACT_LOCK.lock().await;
    let sshd = SshdFixture::spawn();
    let transport = sshd.connect().await.expect("connect to fixture sshd");

    let expected_snapshot = sample_snapshot();
    let collector = write_fixture_collector(
        std::env::temp_dir().as_path(),
        "fixture-hash-abc123",
        &expected_snapshot,
    );

    let before = anne_artifact_count_in_tmp();

    // The fixture collector always reports "fixture-hash-abc123"; passing a
    // different expected hash here forces `IntegrityMismatch` after the
    // artifact has already been pushed -- exactly the "failure mid-exec,
    // after push" scenario this test exists to cover.
    let err = transport
        .push_exec_collect_remove(&collector, "a-completely-different-hash")
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::IntegrityMismatch));

    let after = anne_artifact_count_in_tmp();
    assert_eq!(
        before, after,
        "the pushed artifact must be removed even though the run failed mid-exec"
    );

    let _ = std::fs::remove_file(&collector);
}

#[tokio::test]
async fn stdout_exceeding_cap_is_truncated_with_error() {
    let sshd = SshdFixture::spawn();
    let capped_transport = SshTransport::connect(
        "127.0.0.1",
        sshd.port(),
        &sshd.user,
        &sshd.auth(),
        Arc::clone(&sshd.known_hosts),
        false,
        1024,
    )
    .await
    .expect("connect to fixture sshd with a small output cap");

    let err = capped_transport
        .exec(&RemoteCommand::new("cat", ["/dev/zero"]))
        .await
        .unwrap_err();

    assert!(matches!(err, TransportError::OutputCapExceeded));
}

/// Exercises `RemoteArtifactGuard`'s `Drop` path directly (rather than the
/// explicitly-`.await`ed `remove_now` path the two tests above go through),
/// proving the fire-and-forget spawn described in the module doc actually
/// removes the artifact when given a moment to run. A short sleep after
/// dropping the guard is inherent to testing a detached background task
/// and is the one part of this suite that's a timing assumption rather
/// than a hard guarantee -- see the module doc's cleanup-guard section for
/// why `Drop` can't offer more than that.
#[tokio::test]
async fn drop_without_explicit_remove_now_still_cleans_up() {
    let _lock = TMP_ARTIFACT_LOCK.lock().await;
    let sshd = SshdFixture::spawn();
    let transport = sshd.connect().await.expect("connect to fixture sshd");
    let remote_path = crate::application::remote::RemotePath::random_under_temp();

    let local_file = std::env::temp_dir().join("anne-drop-guard-fixture.txt");
    std::fs::write(&local_file, b"drop-guard-fixture").expect("write local fixture file");
    transport
        .push(&local_file, &remote_path)
        .await
        .expect("push fixture file");
    let _ = std::fs::remove_file(&local_file);

    {
        let _guard = super::RemoteArtifactGuard::new(Arc::clone(&transport), remote_path.clone());
        // Guard drops here without `remove_now` ever being called.
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    // A second remove of an already-removed path fails -- proving the
    // Drop-spawned cleanup got there first, not that no cleanup ran at all.
    let result = transport.remove(&remote_path).await;
    assert!(
        result.is_err(),
        "removing an already-removed path should fail, proving Drop's spawned cleanup ran first"
    );
}
