//! [`ClientHandler`]: the `russh` session callback object, and
//! [`authenticate`]: the auth-order dispatch this task's own spec pins down
//! -- ssh-agent, then a key file, then the OS keyring, never a password.
//!
//! `authenticate` tries exactly the method named by the caller's
//! [`AuthMethod`] rather than silently cascading through all three: an
//! operator who configured `KeyFile` for a host asked for that key,
//! specifically, to be the credential offered; falling back to whatever the
//! ambient ssh-agent happens to hold would authenticate as an identity the
//! operator didn't choose for this host. Cascading fallback, if ever
//! wanted, belongs one layer up (the inventory/orchestrator), as a
//! sequence of distinct `AuthMethod`s to try -- not hidden inside this
//! adapter.

use std::path::Path;
use std::sync::Arc;

use russh::client::{AuthResult, Handle, Handler};
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::keys::{PrivateKeyWithHashAlg, PublicKey};

use crate::adapters::inventory::AuthMethod;
use crate::application::remote::TransportError;

use super::known_hosts::{KnownHosts, verify_host_key};

/// The service name credentials are namespaced under in the OS keyring --
/// distinct from any other application that might share the same keyring
/// backend on this machine.
const KEYRING_SERVICE: &str = "anne-de-breuil-ssh";

/// The `russh::client::Handler` this transport hands to every session.
///
/// Owns the [`KnownHosts`] book and `accept_new` flag for exactly one
/// connection attempt; [`Handler::check_server_key`] is the single call
/// site where those two things and the offered key come together.
pub(super) struct ClientHandler {
    host_label: String,
    known_hosts: Arc<KnownHosts>,
    accept_new: bool,
}

impl ClientHandler {
    pub(super) const fn new(
        host_label: String,
        known_hosts: Arc<KnownHosts>,
        accept_new: bool,
    ) -> Self {
        Self {
            host_label,
            known_hosts,
            accept_new,
        }
    }
}

impl Handler for ClientHandler {
    type Error = TransportError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        verify_host_key(
            &self.known_hosts,
            &self.host_label,
            server_public_key,
            self.accept_new,
        )?;
        Ok(true)
    }
}

/// Formats the label host key entries are matched against: OpenSSH's own
/// `known_hosts` convention omits the port for the default 22 and uses
/// `[host]:port` otherwise.
pub(super) fn host_label(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    }
}

/// Authenticates `user` on an already-handshaken session using exactly the
/// method `auth` names.
///
/// # Errors
///
/// Returns [`TransportError::Connect`] if the chosen method has no usable
/// credential (no agent running, no identities offered, key file unreadable
/// or undecodable, keyring entry missing) or if the server rejects every
/// identity offered through it.
pub(super) async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    auth: &AuthMethod,
) -> Result<(), TransportError> {
    let result = match auth {
        AuthMethod::Agent => authenticate_via_agent(handle, user).await?,
        AuthMethod::KeyFile(path) => authenticate_via_key_material(handle, user, path).await?,
        AuthMethod::KeyFromKeyring(name) => authenticate_via_keyring(handle, user, name).await?,
    };
    if result.success() {
        Ok(())
    } else {
        Err(TransportError::Connect(format!(
            "server rejected {auth:?} authentication for user {user:?}"
        )))
    }
}

/// Offers every identity the running ssh-agent holds, in the order the
/// agent returns them, stopping at the first one the server accepts.
///
/// This is the only auth path that talks to *this* (the orchestrator's own)
/// machine's ssh-agent -- never the target host's.
async fn authenticate_via_agent(
    handle: &mut Handle<ClientHandler>,
    user: &str,
) -> Result<AuthResult, TransportError> {
    let mut agent = AgentClient::connect_env()
        .await
        .map_err(|err| TransportError::Connect(format!("connecting to ssh-agent: {err}")))?;
    let identities = agent
        .request_identities()
        .await
        .map_err(|err| TransportError::Connect(format!("listing ssh-agent identities: {err}")))?;

    let mut last_failure = AuthResult::Failure {
        remaining_methods: russh::MethodSet::empty(),
        partial_success: false,
    };
    for identity in identities {
        let AgentIdentity::PublicKey { key, .. } = identity else {
            continue; // certificate identities aren't this task's scope
        };
        let hash_alg = handle
            .best_supported_rsa_hash()
            .await
            .map_err(TransportError::from)?
            .flatten();
        let result = handle
            .authenticate_publickey_with(user, key, hash_alg, &mut agent)
            .await
            .map_err(|err| TransportError::Connect(format!("ssh-agent signing failed: {err}")))?;
        if result.success() {
            return Ok(result);
        }
        last_failure = result;
    }
    Ok(last_failure)
}

/// Authenticates with the private key material in `secret`, already
/// decoded from a key file or a keyring entry.
async fn authenticate_with_decoded_key(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    private_key: russh::keys::PrivateKey,
) -> Result<AuthResult, TransportError> {
    let hash_alg = handle
        .best_supported_rsa_hash()
        .await
        .map_err(TransportError::from)?
        .flatten();
    let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(private_key), hash_alg);
    handle
        .authenticate_publickey(user, key_with_hash)
        .await
        .map_err(TransportError::from)
}

/// Loads and decodes the unencrypted private key file at `path`.
///
/// Passphrase-protected key files are out of this task's scope -- there is
/// no interactive prompt in a fleet-scanning orchestrator, and prompting is
/// exactly the kind of ambient side channel this adapter avoids elsewhere
/// (never a secret on argv, never a password method). An operator with an
/// encrypted key should register it with ssh-agent instead, which this
/// adapter tries first.
async fn authenticate_via_key_material(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    path: &Path,
) -> Result<AuthResult, TransportError> {
    let private_key = russh::keys::load_secret_key(path, None).map_err(|err| {
        TransportError::Connect(format!("loading key file {}: {err}", path.display()))
    })?;
    authenticate_with_decoded_key(handle, user, private_key).await
}

/// Authenticates with a private key stored under `entry_name` in the OS
/// keyring of the machine running this orchestrator.
///
/// Backend choice is deliberately the native per-OS credential store
/// (macOS Keychain via `apple-native`, Windows Credential Manager via
/// `windows-native`, the Linux kernel keyring via `linux-native`) rather
/// than the freedesktop Secret Service over D-Bus: Secret Service needs
/// either `libdbus` (breaking the musl static-linking story this crate
/// otherwise keeps pure-Rust) or a full async D-Bus session handshake, for
/// a credential store that may not even be running on a headless box this
/// orchestrator is launched from. The kernel keyring has a real, documented
/// trade-off in exchange -- entries typically don't outlive the user
/// session that created them -- which is a reasonable one for a third
/// fallback behind ssh-agent and a key file.
async fn authenticate_via_keyring(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    entry_name: &str,
) -> Result<AuthResult, TransportError> {
    let entry_name_owned = entry_name.to_owned();
    let secret = tokio::task::spawn_blocking(move || {
        keyring::Entry::new(KEYRING_SERVICE, &entry_name_owned)
            .and_then(|entry| entry.get_password())
    })
    .await
    .map_err(|err| TransportError::Connect(format!("OS keyring lookup task panicked: {err}")))?
    .map_err(|err| {
        TransportError::Connect(format!("reading OS keyring entry {entry_name:?}: {err}"))
    })?;

    let private_key = russh::keys::decode_secret_key(&secret, None).map_err(|err| {
        TransportError::Connect(format!(
            "decoding key from keyring entry {entry_name:?}: {err}"
        ))
    })?;
    authenticate_with_decoded_key(handle, user, private_key).await
}
