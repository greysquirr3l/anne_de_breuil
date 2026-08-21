//! Strict, fail-closed SSH host key verification.
//!
//! [`verify_host_key`] is a pure function deliberately kept free of any
//! network or session state, so it can be exercised by a plain unit test
//! with no sshd fixture involved -- host key verification is the one piece
//! of this transport where an accidental "verified" on the wrong branch is
//! a MITM primitive, so the logic that decides it stays small enough to
//! read in one sitting and stays covered without needing a live connection.
//!
//! [`KnownHosts`] uses interior mutability (`Mutex`, not `RefCell`, since
//! [`crate::adapters::ssh_transport::SshTransport`] must stay `Send + Sync`)
//! so that accepting a new host key can happen through a `&KnownHosts`
//! shared reference. That acceptance is held only in memory for the
//! lifetime of this value -- there is no method anywhere on this type that
//! writes to a `known_hosts` file. Persisting an accepted key back to disk,
//! if a caller ever wants that, is a deliberately separate concern this
//! module does not implement, so "opt in to trusting this key for this
//! run" can never silently turn into "opt in forever" as a side effect.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use hmac::{Hmac, Mac};
use russh::keys::PublicKey;
use russh::keys::ssh_key::known_hosts::{Entry, HostPatterns};
use sha1::Sha1;

use crate::application::remote::TransportError;

/// The result of comparing an offered host key against a [`KnownHosts`] book.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyStatus {
    /// The host has an entry in the book whose key matches exactly.
    Known,
    /// The host has no entry in the book at all.
    Unknown,
    /// The host has an entry in the book, but its key differs from the one
    /// offered -- the fingerprint on file rotated, or something is
    /// impersonating this host.
    Changed,
}

/// An in-memory book of host-to-public-key associations.
///
/// Built once per connection attempt from a parsed `known_hosts` file (or
/// [`KnownHosts::empty`] when the caller has none), and optionally grown at
/// runtime by [`verify_host_key`] when the caller opts into accepting new
/// keys. See the module doc for why growth here never touches disk.
#[derive(Debug, Default)]
pub struct KnownHosts {
    file_entries: Vec<Entry>,
    accepted: Mutex<Vec<(String, PublicKey)>>,
}

impl KnownHosts {
    /// A book with no entries at all -- every host is [`HostKeyStatus::Unknown`]
    /// until accepted.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parses OpenSSH `known_hosts`-formatted text into a book.
    ///
    /// Lines that don't parse (comments, blank lines, or genuinely
    /// malformed entries) are skipped rather than treated as a hard
    /// failure, matching how OpenSSH's own client tolerates a `known_hosts`
    /// file it didn't write byte-for-byte itself.
    #[must_use]
    pub fn parse(contents: &str) -> Self {
        let file_entries = russh::keys::ssh_key::known_hosts::KnownHosts::new(contents)
            .filter_map(Result::ok)
            .collect();
        Self {
            file_entries,
            accepted: Mutex::new(Vec::new()),
        }
    }

    /// Reads and parses a `known_hosts` file from disk.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Connect`] if the file cannot be read.
    pub fn load_file(path: &Path) -> Result<Self, TransportError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|err| TransportError::Connect(format!("reading {}: {err}", path.display())))?;
        Ok(Self::parse(&contents))
    }

    /// Looks up `host`'s status against `key`.
    ///
    /// Scans every entry whose host pattern matches `host`: an exact key
    /// match anywhere in that set is [`HostKeyStatus::Known`]; a pattern
    /// match with no exact key match is [`HostKeyStatus::Changed`] (some
    /// other key was recorded for this host); no pattern match at all is
    /// [`HostKeyStatus::Unknown`].
    fn lookup(&self, host: &str, key: &PublicKey) -> HostKeyStatus {
        let mut host_has_any_entry = false;

        for entry in &self.file_entries {
            if host_pattern_matches(entry.host_patterns(), host) {
                host_has_any_entry = true;
                // Compare key material only, not the whole `PublicKey`:
                // `PublicKey`'s `PartialEq` also compares the `comment`
                // field (e.g. `user@host`, written by `ssh-keygen`), which
                // a key offered live over the wire during key exchange
                // never carries -- comparing full structs would make an
                // otherwise-identical key look "changed" purely because a
                // known_hosts file happens to have a comment on it.
                if entry.public_key().key_data() == key.key_data() {
                    return HostKeyStatus::Known;
                }
            }
        }

        {
            let accepted = self.accepted.lock().unwrap_or_else(PoisonError::into_inner);
            for (accepted_host, accepted_key) in accepted.iter() {
                if accepted_host == host {
                    host_has_any_entry = true;
                    if accepted_key.key_data() == key.key_data() {
                        return HostKeyStatus::Known;
                    }
                }
            }
        }

        if host_has_any_entry {
            HostKeyStatus::Changed
        } else {
            HostKeyStatus::Unknown
        }
    }

    /// Records `host`/`key` as accepted for the remainder of this book's
    /// lifetime. In-memory only -- see the module doc.
    fn record(&self, host: &str, key: &PublicKey) {
        self.accepted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((host.to_owned(), key.clone()));
    }
}

/// `true` if any pattern in `patterns` matches `host`.
///
/// A leading `!` on a plain pattern negates it: if a negated pattern
/// matches, the whole entry is rejected outright regardless of any other
/// pattern in the same list, mirroring OpenSSH's own short-circuit
/// semantics for negated host patterns.
fn host_pattern_matches(patterns: &HostPatterns, host: &str) -> bool {
    match patterns {
        HostPatterns::Patterns(list) => {
            let mut matched = false;
            for raw in list {
                let (negate, pattern) = raw
                    .strip_prefix('!')
                    .map_or((false, raw.as_str()), |rest| (true, rest));
                if glob_match(pattern, host) {
                    if negate {
                        return false;
                    }
                    matched = true;
                }
            }
            matched
        }
        HostPatterns::HashedName { salt, hash } => hashed_match(salt, hash, host),
    }
}

/// Checks a `|1|salt|hash`-style hashed hostname entry: OpenSSH computes
/// `HMAC-SHA1(salt, hostname)` and stores the salt alongside the digest, so
/// the file never names the host in plaintext.
fn hashed_match(salt: &[u8], hash: &[u8; 20], host: &str) -> bool {
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(salt) else {
        return false;
    };
    mac.update(host.as_bytes());
    mac.finalize().into_bytes().as_slice() == hash.as_slice()
}

/// Minimal `fnmatch`-style glob: `*` matches any run of characters
/// (including none), `?` matches exactly one, everything else must match
/// literally. Deliberately case-sensitive -- see the module doc for why
/// under-matching is the safe direction for a security-relevant lookup.
fn glob_match(pattern: &str, text: &str) -> bool {
    glob_match_bytes(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_bytes(pattern: &[u8], text: &[u8]) -> bool {
    match (pattern.first(), text.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            let rest = pattern.get(1..).unwrap_or_default();
            glob_match_bytes(rest, text)
                || (!text.is_empty()
                    && glob_match_bytes(pattern, text.get(1..).unwrap_or_default()))
        }
        (Some(b'?'), Some(_)) => glob_match_bytes(
            pattern.get(1..).unwrap_or_default(),
            text.get(1..).unwrap_or_default(),
        ),
        (Some(pat_byte), Some(text_byte)) if pat_byte == text_byte => glob_match_bytes(
            pattern.get(1..).unwrap_or_default(),
            text.get(1..).unwrap_or_default(),
        ),
        _ => false,
    }
}

/// Verifies `key` against `known_hosts` for `host`, failing closed.
///
/// The only way this returns `Ok` for a host with no prior entry is
/// `accept_new == true`; a host whose *recorded* key differs from `key`
/// always errors, regardless of `accept_new` -- that flag exists for
/// genuinely new hosts, never to paper over a rotated or spoofed key on one
/// already known.
///
/// # Errors
///
/// Returns [`TransportError::UnknownHostKey`] for an unrecognised host with
/// `accept_new == false`, or [`TransportError::HostKeyChanged`] for a host
/// whose recorded key doesn't match.
pub fn verify_host_key(
    known_hosts: &KnownHosts,
    host: &str,
    key: &PublicKey,
    accept_new: bool,
) -> Result<(), TransportError> {
    match known_hosts.lookup(host, key) {
        HostKeyStatus::Known => Ok(()),
        HostKeyStatus::Unknown if accept_new => {
            known_hosts.record(host, key);
            Ok(())
        }
        HostKeyStatus::Unknown => Err(TransportError::UnknownHostKey {
            fingerprint: key.fingerprint(russh::keys::HashAlg::Sha256).to_string(),
        }),
        HostKeyStatus::Changed => Err(TransportError::HostKeyChanged),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use russh::keys::PublicKey;
    use russh::keys::ssh_key::public::Ed25519PublicKey;

    use super::{KnownHosts, TransportError, verify_host_key};

    /// Builds a structurally-valid but not cryptographically meaningful
    /// Ed25519 public key, distinct from every other key this function has
    /// returned in the same test run. This is pure host-key-comparison
    /// logic under test, never a real handshake or signature -- these
    /// fixture keys never need to correspond to a private key anyone
    /// holds, only to compare unequal to each other and round-trip through
    /// OpenSSH text encoding.
    fn test_key() -> PublicKey {
        static COUNTER: AtomicU32 = AtomicU32::new(1);
        let seed = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&seed.to_le_bytes());
        PublicKey::from(Ed25519PublicKey(bytes))
    }

    #[test]
    fn unknown_host_key_fails_closed_by_default() {
        let known_hosts = KnownHosts::empty();
        let err = verify_host_key(&known_hosts, "10.0.0.9", &test_key(), false).unwrap_err();
        assert!(matches!(err, TransportError::UnknownHostKey { .. }));
    }

    #[test]
    fn unknown_host_key_succeeds_with_accept_new() {
        let known_hosts = KnownHosts::empty();
        assert!(verify_host_key(&known_hosts, "10.0.0.9", &test_key(), true).is_ok());
    }

    #[test]
    fn accepted_new_key_is_then_known_without_reaccepting() {
        let known_hosts = KnownHosts::empty();
        let key = test_key();
        assert!(verify_host_key(&known_hosts, "10.0.0.9", &key, true).is_ok());
        // Second call for the same host+key, accept_new now false: must
        // still succeed, proving acceptance was actually recorded rather
        // than only checked-and-discarded.
        assert!(verify_host_key(&known_hosts, "10.0.0.9", &key, false).is_ok());
    }

    #[test]
    fn a_different_key_for_an_already_accepted_host_is_changed_not_unknown() {
        let known_hosts = KnownHosts::empty();
        let first = test_key();
        let second = test_key();
        assert!(verify_host_key(&known_hosts, "10.0.0.9", &first, true).is_ok());

        let err = verify_host_key(&known_hosts, "10.0.0.9", &second, true).unwrap_err();
        assert!(matches!(err, TransportError::HostKeyChanged));
    }

    #[test]
    fn known_key_from_a_parsed_known_hosts_file_is_accepted() {
        let key = test_key();
        let openssh_line = format!("build-host {}", key.to_openssh().unwrap());
        let known_hosts = KnownHosts::parse(&openssh_line);

        assert!(verify_host_key(&known_hosts, "build-host", &key, false).is_ok());
    }

    #[test]
    fn a_key_differing_from_the_parsed_file_entry_is_changed() {
        let recorded = test_key();
        let offered = test_key();
        let openssh_line = format!("build-host {}", recorded.to_openssh().unwrap());
        let known_hosts = KnownHosts::parse(&openssh_line);

        let err = verify_host_key(&known_hosts, "build-host", &offered, false).unwrap_err();
        assert!(matches!(err, TransportError::HostKeyChanged));
    }

    #[test]
    fn a_host_absent_from_the_parsed_file_is_unknown() {
        let recorded = test_key();
        let openssh_line = format!("some-other-host {}", recorded.to_openssh().unwrap());
        let known_hosts = KnownHosts::parse(&openssh_line);

        let err = verify_host_key(&known_hosts, "build-host", &recorded, false).unwrap_err();
        assert!(matches!(err, TransportError::UnknownHostKey { .. }));
    }

    #[test]
    fn glob_wildcard_pattern_matches_a_subdomain_style_host() {
        use super::glob_match;
        assert!(glob_match("10.0.0.*", "10.0.0.9"));
        assert!(!glob_match("10.0.0.*", "10.0.1.9"));
        assert!(glob_match("*.internal", "db1.internal"));
    }

    #[test]
    fn negated_pattern_rejects_even_when_another_pattern_matches() {
        use super::host_pattern_matches;
        use russh::keys::ssh_key::known_hosts::HostPatterns;

        let patterns = HostPatterns::Patterns(vec!["10.0.0.*".to_owned(), "!10.0.0.9".to_owned()]);
        assert!(!host_pattern_matches(&patterns, "10.0.0.9"));
        assert!(host_pattern_matches(&patterns, "10.0.0.5"));
    }
}
