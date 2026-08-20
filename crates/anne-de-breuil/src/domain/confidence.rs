//! [`Confidence`]: how strongly a [`crate::domain::ServiceIdentity`] is believed.

/// How strongly a service identification is believed, weakest first.
///
/// Declaration order is derivation order for [`Ord`] — `Assigned` is the
/// weakest tier and `Confirmed` the strongest, so `Confidence::Assigned <
/// Confidence::Confirmed` holds without a hand-written comparator.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Confidence {
    /// A registry number match only — nothing about the responder was observed.
    Assigned,
    /// A weak or generic banner matched.
    Heuristic,
    /// A protocol-specific response matched.
    Probable,
    /// The service identified itself unambiguously.
    Confirmed,
}

#[cfg(test)]
mod tests {
    use super::Confidence;

    #[test]
    fn confidence_ordering_is_assigned_lowest() {
        assert!(Confidence::Assigned < Confidence::Heuristic);
        assert!(Confidence::Heuristic < Confidence::Probable);
        assert!(Confidence::Probable < Confidence::Confirmed);
    }
}
