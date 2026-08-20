//! `exec()` against an established `russh` session, with output capture
//! bounded by an explicit byte cap enforced during the read itself.
//!
//! The SSH "exec" channel request (RFC 4254 6.5) carries exactly one
//! string, executed by the remote user's shell -- there is no argv-array
//! wire format to hand [`RemoteCommand`]'s already-split arguments to
//! directly. [`command_line`] closes that gap with POSIX single-quoting:
//! every argument is wrapped in `'...'` with embedded quotes escaped as
//! `'\''`, so nothing in an argument's *content* can ever terminate its
//! quoting early and inject additional shell syntax. That preserves
//! [`RemoteCommand`]'s no-injection guarantee at the point it actually
//! matters (this call site), even though the wire format itself has no
//! choice but to be a shell string.

use std::time::Instant;

use russh::ChannelMsg;
use russh::client::Handle;

use crate::application::remote::{ExecOutput, RemoteCommand, TransportError};

use super::handler::ClientHandler;

/// The SSH extended-data type code for stderr (RFC 4254 5.2).
const SSH_EXTENDED_DATA_STDERR: u32 = 1;

fn shell_quote(arg: &str) -> String {
    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn command_line(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Appends `chunk` to `buf` if doing so would not exceed `cap`, otherwise
/// leaves `buf` untouched and reports the overflow. Never extends `buf`
/// past `cap`, even transiently -- the check happens before the append,
/// not after.
fn append_capped(buf: &mut Vec<u8>, chunk: &[u8], cap: usize) -> Result<(), TransportError> {
    if buf.len().saturating_add(chunk.len()) > cap {
        return Err(TransportError::OutputCapExceeded);
    }
    buf.extend_from_slice(chunk);
    Ok(())
}

/// Runs `cmd` on the session behind `handle`, capturing stdout and stderr
/// up to `max_output_bytes` each.
///
/// # Errors
///
/// Returns [`TransportError::OutputCapExceeded`] the moment either stream
/// would exceed `max_output_bytes` -- the command's remaining output is
/// never read to completion in that case, so a command like `cat
/// /dev/zero` can't be waited out. Returns [`TransportError::Exec`] if the
/// channel closes without ever reporting an exit status.
pub(super) async fn exec(
    handle: &Handle<ClientHandler>,
    cmd: &RemoteCommand,
    max_output_bytes: usize,
) -> Result<ExecOutput, TransportError> {
    let started = Instant::now();
    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, command_line(cmd.argv())).await?;

    let mut stdout = Vec::with_capacity(max_output_bytes.min(8192));
    let mut stderr = Vec::new();
    let mut exit_status = None;

    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => append_capped(&mut stdout, &data, max_output_bytes)?,
            ChannelMsg::ExtendedData {
                data,
                ext: SSH_EXTENDED_DATA_STDERR,
            } => append_capped(&mut stderr, &data, max_output_bytes)?,
            ChannelMsg::ExitStatus { exit_status: status } => exit_status = Some(status),
            // `Eof` only means the remote side is done sending data on
            // this channel -- the exit-status request and the final
            // `Close` can (and per RFC 4254 typically do) arrive after it,
            // so only `Close` (or `wait()` returning `None`) ends the loop.
            ChannelMsg::Close => break,
            _ => {}
        }
    }

    let status = exit_status.ok_or_else(|| {
        TransportError::Exec("channel closed before an exit status was received".to_owned())
    })?;

    Ok(ExecOutput {
        status: i32::try_from(status).unwrap_or(i32::MAX),
        stdout,
        stderr,
        duration: started.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::{command_line, shell_quote};

    #[test]
    fn plain_arguments_are_wrapped_without_escaping() {
        assert_eq!(shell_quote("--emit-json"), "'--emit-json'");
    }

    #[test]
    fn embedded_single_quotes_cannot_break_out_of_quoting() {
        let hostile = "'; rm -rf /; echo '";
        let quoted = shell_quote(hostile);
        // The quoted form must never contain an unescaped `'` that isn't
        // part of the `'\''` escape sequence -- i.e. every `'` in the
        // output is immediately followed by `\''` or is the opening/closing
        // quote. A crude but effective check: replacing every `'\''`
        // escape leaves no bare `'` except the two boundary quotes.
        let interior = quoted
            .strip_prefix('\'')
            .and_then(|s| s.strip_suffix('\''))
            .unwrap_or(&quoted);
        let de_escaped = interior.replace("'\\''", "");
        assert!(!de_escaped.contains('\''));
    }

    #[test]
    fn command_line_joins_quoted_argv_with_spaces() {
        let argv = vec!["anne-collector".to_owned(), "--emit-json".to_owned()];
        assert_eq!(command_line(&argv), "'anne-collector' '--emit-json'");
    }
}
