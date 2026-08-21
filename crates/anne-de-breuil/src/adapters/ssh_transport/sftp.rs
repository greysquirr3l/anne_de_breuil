//! SFTP push and remove against an established `russh` session.
//!
//! Both open a fresh SFTP subsystem channel rather than sharing one across
//! calls: [`RemoteTransport`](crate::application::remote::RemoteTransport)
//! methods each take `&self`, and a `russh_sftp::client::SftpSession` isn't
//! meant to be driven concurrently from multiple callers, so a
//! channel-per-call keeps every call independent at the cost of one extra
//! subsystem request -- negligible next to the network round trip a remote
//! push/remove already pays.

use std::path::Path;

use russh::client::Handle;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use tokio::io::AsyncWriteExt as _;

use crate::application::remote::{RemotePath, TransportError};

use super::handler::ClientHandler;

/// Mode bits for a pushed collector artifact: owner read/write/execute,
/// nothing for group or other. Set at file-creation time via the SFTP
/// `attrs` the server applies atomically to the new file, not as a
/// follow-up `chmod` an interrupted push could skip.
const PUSHED_ARTIFACT_MODE: u32 = 0o700;

async fn open_sftp(handle: &Handle<ClientHandler>) -> Result<SftpSession, TransportError> {
    let channel = handle.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;
    SftpSession::new(channel.into_stream())
        .await
        .map_err(TransportError::from)
}

/// Copies `local`'s contents to `remote`, creating it mode 0700.
///
/// # Errors
///
/// Returns [`TransportError`] if the local file can't be read or the
/// transfer fails.
pub(super) async fn push(
    handle: &Handle<ClientHandler>,
    local: &Path,
    remote: &RemotePath,
) -> Result<(), TransportError> {
    let bytes = tokio::fs::read(local)
        .await
        .map_err(|err| TransportError::Transfer(format!("reading {}: {err}", local.display())))?;

    let sftp = open_sftp(handle).await?;
    let attrs = FileAttributes {
        permissions: Some(PUSHED_ARTIFACT_MODE),
        ..FileAttributes::empty()
    };
    let mut file = sftp
        .open_with_flags_and_attributes(
            remote.as_str(),
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            attrs,
        )
        .await?;
    file.write_all(&bytes)
        .await
        .map_err(|err| TransportError::Transfer(format!("writing {}: {err}", remote.as_str())))?;
    file.shutdown()
        .await
        .map_err(|err| TransportError::Transfer(format!("closing {}: {err}", remote.as_str())))?;
    Ok(())
}

/// Deletes the file at `remote`.
///
/// # Errors
///
/// Returns [`TransportError`] if the SFTP session or the removal fails.
pub(super) async fn remove(
    handle: &Handle<ClientHandler>,
    remote: &RemotePath,
) -> Result<(), TransportError> {
    let sftp = open_sftp(handle).await?;
    sftp.remove_file(remote.as_str()).await?;
    Ok(())
}
