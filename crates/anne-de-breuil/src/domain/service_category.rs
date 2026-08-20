//! [`ServiceCategory`]: a coarse grouping for a [`crate::domain::ServiceIdentity`].

/// A coarse category for a hosted service, used for grouping and reporting.
///
/// Deliberately small and non-exhaustive-forever — this is a display/report
/// grouping, not a taxonomy the domain reasons about structurally. New
/// variants can be added as fingerprinting (T11) broadens coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ServiceCategory {
    /// HTTP/HTTPS servers and reverse proxies.
    WebServer,
    /// Relational and non-relational database engines.
    Database,
    /// Interactive remote-access protocols (SSH, RDP, VNC, Telnet).
    RemoteAccess,
    /// File and object sharing (SMB, NFS, FTP).
    FileSharing,
    /// Message brokers and queues.
    Messaging,
    /// Metrics, logging, and health-check endpoints.
    Monitoring,
    /// DNS resolvers and authoritative servers.
    Dns,
    /// SMTP/IMAP/POP3 and related mail protocols.
    Mail,
    /// Anything not covered by a more specific category, including a bare
    /// registry match where the category cannot be inferred from the port
    /// number alone.
    Other,
}
