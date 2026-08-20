//! Small identifier newtypes: opaque, `Copy`, and cheap to pass by value.
//!
//! Every identifier here wraps `Copy` data (`u32` or [`uuid::Uuid`]), so
//! there is no ownership reason to make an 8-16 byte handle move-only.

use crate::domain::error::DomainError;

macro_rules! uuid_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            serde::Serialize,
            serde::Deserialize,
        )]
        pub struct $name(uuid::Uuid);

        impl $name {
            /// Mints a fresh random identifier.
            ///
            /// Uses `uuid`'s v4 generator, which draws from the OS CSPRNG —
            /// appropriate for an opaque identifier, not a value that needs
            /// to withstand adversarial prediction of a secret.
            #[must_use]
            pub fn generate() -> Self {
                Self(uuid::Uuid::new_v4())
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> uuid::Uuid {
                self.0
            }
        }

        impl core::str::FromStr for $name {
            type Err = DomainError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                uuid::Uuid::parse_str(s.trim()).map(Self).map_err(|source| {
                    DomainError::InvalidUuid {
                        field: stringify!($name),
                        source,
                    }
                })
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

uuid_id!(
    ScanId,
    "Identifies one scan run, unique per invocation of the collector."
);
uuid_id!(
    HostId,
    "Identifies one host in the inventory, stable across rescans."
);
uuid_id!(
    IdempotencyKey,
    "Deduplicates retried collector pushes so a retry never double-applies."
);
uuid_id!(
    RuleId,
    "Identifies one firewall rule, synthesised by the collecting adapter if the platform has no native rule GUID."
);

/// An operating-system process identifier.
///
/// Zero is rejected: no live process is ever addressable at pid 0 on the
/// platforms this tool targets.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ProcessId(u32);

impl ProcessId {
    /// Returns the underlying pid.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for ProcessId {
    type Error = DomainError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 0 {
            return Err(DomainError::InvalidProcessId(value));
        }
        Ok(Self(value))
    }
}

impl core::fmt::Display for ProcessId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_id_rejects_zero() {
        assert!(ProcessId::try_from(0).is_err());
    }

    #[test]
    fn process_id_accepts_nonzero() {
        assert_eq!(ProcessId::try_from(4).unwrap().get(), 4);
    }

    #[test]
    fn scan_id_roundtrips_through_string() {
        let id = ScanId::generate();
        let printed = id.to_string();
        let parsed: ScanId = printed.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn scan_id_rejects_malformed_uuid() {
        assert!("not-a-uuid".parse::<ScanId>().is_err());
    }

    #[test]
    fn host_id_and_rule_id_roundtrip_through_string() {
        let host = HostId::generate();
        let rule = RuleId::generate();
        assert_eq!(host.to_string().parse::<HostId>().unwrap(), host);
        assert_eq!(rule.to_string().parse::<RuleId>().unwrap(), rule);
    }
}
