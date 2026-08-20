//! [`enum_services_grouped_by_pid`]: PID-to-hosted-service mapping via
//! `EnumServicesStatusExW`.
//!
//! This is the only `unsafe` in this module tree besides [`super::signatures`]
//! — confined to this file, wrapped in the safe functions below, per the
//! project's unsafe-confinement rule.
//!
//! A single, unsplit `svchost.exe` process legitimately hosts more than one
//! service (pre-Server-2016, or a host under 3.5 GB RAM). This function
//! makes no attempt to guess which service inside a shared host owns any
//! particular socket — it groups every running `SERVICE_WIN32` service by
//! its `dwProcessId`, and a pid with more than one entry in the resulting
//! map *is* the ambiguity: [`super::processes::WindowsProcessResolver::hosted_services`]
//! returns the whole group rather than picking one, so a report reader
//! sees every candidate instead of a silently wrong single answer.

use std::collections::HashMap;

use windows::Win32::Foundation::ERROR_MORE_DATA;
use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
    SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL,
    SERVICE_WIN32,
};
use windows::core::{HRESULT, PCWSTR};

use crate::application::collect::{CollectError, RawService};

/// Queries every running Win32 service on the local host and groups the
/// results by owning pid.
///
/// Opens the Service Control Manager with `SC_MANAGER_ENUMERATE_SERVICE`
/// (read-only enumeration, no configuration or control rights), enumerates
/// with `EnumServicesStatusExW` using the standard two-pass
/// size-then-fetch pattern, and closes the SCM handle before returning on
/// every path — no handle is ever leaked on an error.
///
/// # Errors
///
/// Returns [`CollectError::Spawn`] if the SCM cannot be opened, or
/// [`CollectError::Parse`] if enumeration itself fails after a
/// correctly-sized buffer was allocated.
#[expect(
    unsafe_code,
    reason = "OpenSCManagerW/CloseServiceHandle are raw Win32 FFI with no safe wrapper upstream; confined to this function per the project's unsafe-confinement rule"
)]
pub(super) fn enum_services_grouped_by_pid() -> Result<HashMap<u32, Vec<RawService>>, CollectError>
{
    // SAFETY: `OpenSCManagerW(None, None, ...)` opens the SCM on the local
    // machine's default database; both `None` arguments are valid per the
    // Win32 contract (machine name/database name default to local/active).
    let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE) }
        .map_err(|source| CollectError::Spawn(source.to_string()))?;

    let result = enumerate(scm);

    // SAFETY: `scm` was just returned by the successful `OpenSCManagerW`
    // above, is used only here, and is closed exactly once regardless of
    // whether enumeration succeeded.
    unsafe {
        let _ = CloseServiceHandle(scm);
    }

    result
}

#[expect(
    unsafe_code,
    reason = "EnumServicesStatusExW's buffer-sizing and record-layout contract requires raw pointer arithmetic with no safe wrapper upstream"
)]
fn enumerate(scm: SC_HANDLE) -> Result<HashMap<u32, Vec<RawService>>, CollectError> {
    let mut bytes_needed: u32 = 0;
    let mut services_returned: u32 = 0;

    // First pass: an empty buffer, purely to learn the required size. This
    // call is expected to fail with `ERROR_MORE_DATA`.
    // SAFETY: `lpservices: None` and `pcbbytesneeded`/`lpservicesreturned`
    // point at valid, live `u32` locals for the duration of the call.
    let sizing = unsafe {
        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &raw mut bytes_needed,
            &raw mut services_returned,
            None,
            PCWSTR::null(),
        )
    };
    if let Err(source) = sizing
        && source.code() != HRESULT::from_win32(ERROR_MORE_DATA.0)
    {
        return Err(CollectError::Parse(source.to_string()));
    }
    if bytes_needed == 0 {
        return Ok(HashMap::new());
    }

    // `EnumServicesStatusExW` packs an array of `ENUM_SERVICE_STATUS_PROCESSW`
    // records into the buffer, and that struct needs pointer (8-byte)
    // alignment on x86_64 -- a plain `Vec<u8>` only guarantees 1-byte
    // alignment, so the backing storage is a `Vec<u64>` instead, sized in
    // 8-byte words and viewed as bytes only for the call itself.
    let byte_len = bytes_needed as usize;
    let word_len = byte_len.div_ceil(8);
    let mut buffer: Vec<u64> = vec![0u64; word_len];
    let mut resume_handle: u32 = 0;

    // SAFETY: `buffer` holds `word_len * 8 >= byte_len` bytes of writable
    // storage; a `u8` view has no alignment requirement stricter than
    // `u64`'s, so reinterpreting it as `&mut [u8]` of length `byte_len` is
    // valid, and it stays alive for the duration of the call below.
    let byte_view =
        unsafe { core::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), byte_len) };

    // SAFETY: `byte_view` is sized exactly to `bytes_needed` from the
    // sizing call above; `EnumServicesStatusExW` writes at most that many
    // bytes and reports the actual record count in `services_returned`.
    unsafe {
        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(byte_view),
            &raw mut bytes_needed,
            &raw mut services_returned,
            Some(&raw mut resume_handle),
            PCWSTR::null(),
        )
    }
    .map_err(|source| CollectError::Parse(source.to_string()))?;

    // SAFETY: the buffer was just filled by the call above with exactly
    // `services_returned` contiguous `ENUM_SERVICE_STATUS_PROCESSW`
    // records, per the documented `EnumServicesStatusExW` output layout;
    // `buffer`'s `u64` storage satisfies that struct's alignment.
    let records = unsafe {
        core::slice::from_raw_parts(
            buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
            services_returned as usize,
        )
    };

    let mut grouped: HashMap<u32, Vec<RawService>> = HashMap::new();
    for record in records {
        // SAFETY: `lpServiceName`/`lpDisplayName` are non-null,
        // null-terminated wide strings pointing into `buffer`, which is
        // still alive for the duration of this loop.
        let name = unsafe { record.lpServiceName.to_string() }
            .map_err(|source| CollectError::Parse(source.to_string()))?;
        let display_name = unsafe { record.lpDisplayName.to_string() }
            .map_err(|source| CollectError::Parse(source.to_string()))?;
        let pid = record.ServiceStatusProcess.dwProcessId;

        grouped
            .entry(pid)
            .or_default()
            .push(RawService { name, display_name });
    }

    Ok(grouped)
}
