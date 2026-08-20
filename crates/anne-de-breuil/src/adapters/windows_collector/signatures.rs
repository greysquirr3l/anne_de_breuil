//! [`WinTrustSignatureVerifier`]: Authenticode status via `WinVerifyTrust`.
//!
//! Results are cached by path: the same binary backs every process it owns, and a busy host can have
//! dozens of listening endpoints resolve to a handful of binaries (a
//! handful of `w3wp.exe` app pool workers, one `sshd.exe`, etc.) — caching
//! by path avoids re-running the trust provider chain for each one.
//!
//! `WinVerifyTrust` alone answers "is this file's Authenticode signature
//! valid," not "who signed it." Recovering the signer's subject name for
//! [`SignatureStatus::Signed`] requires walking `WinTrust`'s own opaque
//! provider-data chain (`WTHelperProvDataFromStateData` →
//! `WTHelperGetProvSignerFromChain` → the signer's leaf certificate →
//! `CertGetNameStringW`) — this is the deepest unsafe pointer-chasing in
//! this module tree, confined to [`publisher_name_from_state`], and it is
//! exactly the kind of platform-API assumption
//! [`super::tests::live_host_windows_collector_matches_powershell_collector`]
//! exists to catch if wrong on a real host, since this crate has no
//! Windows machine to verify it against directly.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::Cryptography::{CERT_CONTEXT, CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::core::{HSTRING, PCWSTR};

use crate::application::collect::{CollectError, SignatureVerifier};
use crate::domain::{ProcessPath, PublisherName, SignatureStatus};

/// Verifies Authenticode signatures via `WinVerifyTrust`, caching results
/// by path for this verifier's lifetime.
pub struct WinTrustSignatureVerifier {
    cache: Mutex<HashMap<String, SignatureStatus>>,
}

impl WinTrustSignatureVerifier {
    /// Builds a verifier with an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for WinTrustSignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SignatureVerifier for WinTrustSignatureVerifier {
    async fn verify(&self, path: &ProcessPath) -> Result<SignatureStatus, CollectError> {
        let key = path.as_str().to_owned();

        {
            let cache = self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(status) = cache.get(&key) {
                return Ok(status.clone());
            }
        }

        let query_path = key.clone();
        let status = tokio::task::spawn_blocking(move || verify_file(&query_path))
            .await
            .map_err(|source| CollectError::Parse(source.to_string()))?;

        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(key)
            .or_insert_with(|| status.clone());
        Ok(status)
    }
}

#[expect(
    unsafe_code,
    reason = "WinVerifyTrust is raw Win32 FFI with no safe wrapper upstream; confined to this function per the project's unsafe-confinement rule"
)]
fn verify_file(path: &str) -> SignatureStatus {
    let wide_path = HSTRING::from(path);

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: u32::try_from(core::mem::size_of::<WINTRUST_FILE_INFO>()).unwrap_or_default(),
        pcwszFilePath: PCWSTR::from_raw(wide_path.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: core::ptr::null_mut(),
    };

    let mut data = WINTRUST_DATA {
        cbStruct: u32::try_from(core::mem::size_of::<WINTRUST_DATA>()).unwrap_or_default(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };
    data.Anonymous.pFile = &raw mut file_info;

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // SAFETY: `file_info` and `data` are live, stack-allocated locals for
    // the duration of this call; `data.Anonymous.pFile` points at
    // `file_info`, which outlives the call by construction. `wide_path`
    // (and the null-terminated buffer `pcwszFilePath` points into) also
    // outlives the call.
    let verify_result =
        unsafe { WinVerifyTrust(HWND::default(), &raw mut action, (&raw mut data).cast()) };

    let status = if verify_result == 0 {
        // A zero return means verification succeeded, so
        // `data.hWVTStateData` is the valid state handle the call above
        // produced; `publisher_name_from_state` is itself a safe function
        // that confines its own unsafe internally.
        let publisher = publisher_name_from_state(data.hWVTStateData);
        publisher.map_or(SignatureStatus::Unknown, SignatureStatus::Signed)
    } else {
        SignatureStatus::Unsigned
    };

    // `WTD_STATEACTION_CLOSE` releases the trust-provider state
    // `WTD_STATEACTION_VERIFY` allocated above -- required on every path,
    // successful or not, or the state leaks for the process's lifetime.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: same struct as the verify call above, now requesting the
    // state it opened be closed.
    unsafe {
        let _ = WinVerifyTrust(HWND::default(), &raw mut action, (&raw mut data).cast());
    }

    status
}

/// Walks `WinTrust`'s provider-data chain to recover the signer's subject
/// name for a file `WinVerifyTrust` just confirmed as trusted.
///
/// Returns `None` if any step of the chain is unexpectedly empty (no
/// provider data, no signer, no certificate, or the name comes back
/// blank) -- a signed-but-unnamed result is reported as
/// [`SignatureStatus::Unknown`], never fabricated.
#[expect(
    unsafe_code,
    reason = "walks WinTrust's opaque CRYPT_PROVIDER_DATA/CRYPT_PROVIDER_SGNR chain, which has no safe wrapper upstream; confined to this function per the project's unsafe-confinement rule"
)]
fn publisher_name_from_state(state: HANDLE) -> Option<PublisherName> {
    // SAFETY: `state` is the handle a successful `WinVerifyTrust` call
    // just produced for this thread; `WTHelperProvDataFromStateData` is
    // the documented way to recover its provider data.
    let provider_data = unsafe { WTHelperProvDataFromStateData(state) };
    if provider_data.is_null() {
        return None;
    }

    // SAFETY: `provider_data` was just checked non-null and came from the
    // state produced above.
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider_data, 0, false, 0) };
    if signer.is_null() {
        return None;
    }

    // SAFETY: `signer` was just checked non-null; `csCertChain`/
    // `pasCertChain` describe the certificate chain WinTrust built for it.
    let (cert_chain, cert_count) = unsafe { ((*signer).pasCertChain, (*signer).csCertChain) };
    if cert_chain.is_null() || cert_count == 0 {
        return None;
    }

    // Chain index 0 is the end-entity (leaf/signer) certificate, per the
    // documented `CRYPT_PROVIDER_SGNR.pasCertChain` ordering.
    // SAFETY: `cert_count > 0` was just checked, so index 0 is in bounds.
    let leaf_cert: *const CERT_CONTEXT = unsafe { (*cert_chain).pCert };
    if leaf_cert.is_null() {
        return None;
    }

    let mut name_buf = [0u16; 256];
    // SAFETY: `leaf_cert` is a non-null certificate pointer from the chain
    // above; `name_buf` is a live, correctly sized local buffer for the
    // duration of the call.
    let len = unsafe {
        CertGetNameStringW(
            leaf_cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name_buf),
        )
    };
    // `len` includes the trailing NUL; `<= 1` means an empty or failed lookup.
    if len <= 1 {
        return None;
    }
    let name_wide = name_buf.get(..(len as usize).saturating_sub(1))?;
    let text = String::from_utf16_lossy(name_wide);
    PublisherName::try_from(text).ok()
}
