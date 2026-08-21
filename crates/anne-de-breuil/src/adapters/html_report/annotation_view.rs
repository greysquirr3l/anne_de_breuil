//! Maps `domain::annotations::Annotation` into what `templates/summary.html`
//! renders for the report's single editorial callout.
//!
//! `executive_summary` needs no view-layer step at all -- it's already a
//! plain `String` `view::summary_template` can hand a template directly.
//! This file exists only because `Annotation::leader_target` is a category
//! (`DiagramAnchor`), not display text or markup: turning it into
//! human-readable prose and the decorative "leader line" motif described
//! on `DiagramAnchor`'s own doc comment is a presentation decision, the
//! same kind of thing `view.rs`'s label/CSS-class functions already do for
//! every other domain enum a template needs to render.

use crate::domain::annotations::{DiagramAnchor, select_annotation};
use crate::domain::report_model::ReportModel;

/// What `summary.html`'s `{% match annotation %}` renders.
///
/// `headline` is plain prose -- Askama HTML-escapes it on interpolation,
/// same as every other text field this module hands a template, so it is
/// never marked `|safe`. `leader_svg` is a fixed decorative constant with
/// no interpolated content (see [`LEADER_SVG`]), spliced in via `|safe`
/// the same way `tokens_css`/the diagram SVGs already are.
pub(super) struct AnnotationView {
    pub(super) headline: String,
    pub(super) target_label: &'static str,
    pub(super) leader_svg: &'static str,
}

/// Builds the report's single annotation callout, if [`select_annotation`]
/// found a qualifying finding -- `None` otherwise, which
/// `templates/summary.html` renders as no markup at all, not an empty
/// shell.
pub(super) fn annotation_view(model: &ReportModel) -> Option<AnnotationView> {
    select_annotation(model).map(|annotation| AnnotationView {
        headline: annotation.headline,
        target_label: target_label(annotation.leader_target),
        leader_svg: LEADER_SVG,
    })
}

const fn target_label(anchor: DiagramAnchor) -> &'static str {
    match anchor {
        DiagramAnchor::ExposureMap => "the exposure map",
        DiagramAnchor::DriftTimeline => "the drift timeline",
    }
}

/// A fixed, non-data-driven decorative "leader line": a dashed cubic Bezier
/// curve, styled through `.annotation-leader-path` (`tokens.css`, `--accent`
/// via `stroke`, never a hex literal). No caller-supplied text ever reaches
/// this string, so unlike `domain::svg::escape_svg_text`'s callers, nothing
/// here needs escaping -- this constant *is* the entire SVG document, not a
/// template being filled in. See `domain::annotations::DiagramAnchor`'s doc
/// comment for why this motif -- rather than a literal pointer at a
/// specific diagram shape -- is the honest choice here.
const LEADER_SVG: &str = r#"<svg class="annotation-leader" width="48" height="32" viewBox="0 0 48 32" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" focusable="false"><path d="M2 4 C 20 4, 12 28, 46 28" class="annotation-leader-path"/></svg>"#;

#[cfg(test)]
mod tests {
    use super::{annotation_view, target_label};
    use crate::domain::annotations::DiagramAnchor;
    use crate::domain::bind_address::BindAddress;
    use crate::domain::endpoint::Endpoint;
    use crate::domain::ids::{HostId, ScanId};
    use crate::domain::port::Port;
    use crate::domain::process::ProcessPath;
    use crate::domain::protocol::Protocol;
    use crate::domain::publisher::SignatureStatus;
    use crate::domain::report_model::ReportModel;
    use crate::domain::service::ServiceName;
    use crate::domain::snapshot::ScanSnapshot;
    use crate::domain::target_strategy::TargetStrategy;
    use core::str::FromStr as _;

    fn model_with_unsigned_all_interfaces_listener() -> ReportModel {
        let endpoint = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("0.0.0.0").expect("valid ip"),
            Port::try_from(21u16).expect("nonzero port"),
            None,
            Some(ProcessPath::from_str("C:\\svc\\ftp.exe").expect("non-empty path")),
            vec![ServiceName::try_from("Ftp".to_owned()).expect("non-empty name")],
            SignatureStatus::Unsigned,
            None,
        );
        let snapshot = ScanSnapshot::new(
            HostId::generate(),
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "1.0.0".to_owned(),
            vec![endpoint],
            vec![],
            vec![],
            TargetStrategy::Execute,
        );
        ReportModel::build(&[snapshot], None, true).expect("fixture model builds")
    }

    fn clean_model() -> ReportModel {
        let endpoint = Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str("127.0.0.1").expect("valid ip"),
            Port::try_from(8080u16).expect("nonzero port"),
            None,
            None,
            vec![],
            SignatureStatus::Unknown,
            None,
        );
        let snapshot = ScanSnapshot::new(
            HostId::generate(),
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "1.0.0".to_owned(),
            vec![endpoint],
            vec![],
            vec![],
            TargetStrategy::Execute,
        );
        ReportModel::build(&[snapshot], None, true).expect("fixture model builds")
    }

    #[test]
    fn target_label_covers_every_anchor_variant() {
        assert_eq!(target_label(DiagramAnchor::ExposureMap), "the exposure map");
        assert_eq!(
            target_label(DiagramAnchor::DriftTimeline),
            "the drift timeline"
        );
    }

    #[test]
    fn annotation_view_is_none_for_a_clean_model() {
        assert!(annotation_view(&clean_model()).is_none());
    }

    #[test]
    fn annotation_view_carries_real_headline_and_leader_svg_for_a_finding() {
        let view = annotation_view(&model_with_unsigned_all_interfaces_listener())
            .expect("finding present");
        assert!(view.headline.contains("Port 21"));
        assert_eq!(view.target_label, "the exposure map");
        assert!(view.leader_svg.contains("<path"));
        assert!(view.leader_svg.contains("annotation-leader-path"));
    }

    #[test]
    fn leader_svg_carries_no_raw_angle_brackets_beyond_its_own_fixed_markup() {
        // Not a data-driven-escaping test (there is no interpolated
        // content here to escape) -- pins that this constant stays a
        // single well-formed `<svg>...</svg>` document, so a future edit
        // can't accidentally leave it malformed.
        let view = annotation_view(&model_with_unsigned_all_interfaces_listener())
            .expect("finding present");
        assert!(view.leader_svg.starts_with("<svg"));
        assert!(view.leader_svg.ends_with("</svg>"));
    }
}
