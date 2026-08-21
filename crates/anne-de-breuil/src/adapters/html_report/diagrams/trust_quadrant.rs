//! Trust quadrant: exposure (loopback/specific interface vs all
//! interfaces) on one axis, signature confidence (signed vs
//! not-confirmed-signed) on the other.
//!
//! Both axes collapse a multi-state domain enum
//! ([`crate::domain::exposure::Exposure`] has three states,
//! [`crate::domain::publisher::SignatureStatus`] has four) into the one
//! boundary the task's own design calls out explicitly: "all interfaces"
//! is the exposed pole, "unsigned" is the risk pole. A 3x4 grid would be
//! more literal but nobody could read it at a glance -- the whole point
//! of a quadrant chart is picking the one distinction that matters. The
//! exposed + not-confirmed-signed quadrant is the one focal element and
//! the only one that gets the accent colour.

use crate::domain::exposure::Exposure;
use crate::domain::publisher::SignatureStatus;
use crate::domain::report_model::HostSection;
use crate::domain::svg::SvgCanvas;

use super::{geometry_i32, short_host_id};

const CELL_SIZE: i32 = 160;
const ORIGIN_X: i32 = 40;
const ORIGIN_Y: i32 = 40;
const MARKER_SIZE: i32 = 8;
const MARKERS_PER_ROW: i32 = 12;

const fn is_exposed(exposure: Exposure) -> bool {
    matches!(exposure, Exposure::AllInterfaces)
}

const fn is_unconfirmed_signed(status: &SignatureStatus) -> bool {
    !matches!(status, SignatureStatus::Signed(_))
}

pub(in crate::adapters::html_report) fn render(host: &HostSection) -> String {
    let width = ORIGIN_X * 2 + CELL_SIZE * 2;
    let height = ORIGIN_Y * 2 + CELL_SIZE * 2 + 20;
    let mut canvas = SvgCanvas::new(width, height);

    canvas.rect(ORIGIN_X, ORIGIN_Y, CELL_SIZE, CELL_SIZE, "svg-node");
    canvas.rect(
        ORIGIN_X + CELL_SIZE,
        ORIGIN_Y,
        CELL_SIZE,
        CELL_SIZE,
        "svg-node",
    );
    canvas.rect(
        ORIGIN_X,
        ORIGIN_Y + CELL_SIZE,
        CELL_SIZE,
        CELL_SIZE,
        "svg-node",
    );
    // The focal quadrant: exposed on all interfaces, not confirmed signed.
    canvas.rect(
        ORIGIN_X + CELL_SIZE,
        ORIGIN_Y + CELL_SIZE,
        CELL_SIZE,
        CELL_SIZE,
        "svg-fill-accent-weak",
    );

    canvas.text(ORIGIN_X, ORIGIN_Y - 8, "contained", "svg-text-muted");
    canvas.text(
        ORIGIN_X + CELL_SIZE,
        ORIGIN_Y - 8,
        "all interfaces",
        "svg-text-muted",
    );
    canvas.text(
        ORIGIN_X,
        ORIGIN_Y + CELL_SIZE * 2 + 16,
        "signed",
        "svg-text-muted",
    );
    canvas.text(
        ORIGIN_X + CELL_SIZE,
        ORIGIN_Y + CELL_SIZE * 2 + 16,
        "unsigned/unknown",
        "svg-text-muted",
    );

    let mut contained_signed = 0i32;
    let mut contained_risky = 0i32;
    let mut exposed_signed = 0i32;
    let mut exposed_risky = 0i32;

    for endpoint in &host.endpoints {
        let exposed = is_exposed(endpoint.exposure);
        let risky = is_unconfirmed_signed(&endpoint.signature_status);
        let (cell_x, cell_y, counter, class) = match (exposed, risky) {
            (false, false) => (ORIGIN_X, ORIGIN_Y, &mut contained_signed, "svg-fill-muted"),
            (false, true) => (
                ORIGIN_X,
                ORIGIN_Y + CELL_SIZE,
                &mut contained_risky,
                "svg-fill-muted",
            ),
            (true, false) => (
                ORIGIN_X + CELL_SIZE,
                ORIGIN_Y,
                &mut exposed_signed,
                "svg-fill-muted",
            ),
            (true, true) => (
                ORIGIN_X + CELL_SIZE,
                ORIGIN_Y + CELL_SIZE,
                &mut exposed_risky,
                "svg-fill-accent",
            ),
        };
        let index = *counter;
        *counter += 1;
        let col = index % MARKERS_PER_ROW;
        let row = index / MARKERS_PER_ROW;
        let marker_x = cell_x + 12 + col * (MARKER_SIZE + 4);
        let marker_y = cell_y + 12 + row * (MARKER_SIZE + 4);
        canvas.rect(marker_x, marker_y, MARKER_SIZE, MARKER_SIZE, class);
    }

    let title = format!("Trust quadrant for host {}", short_host_id(host));
    let desc = format!(
        "{} endpoint(s) unsigned or unconfirmed-signed on all interfaces -- the focal quadrant, \
         out of {} total.",
        exposed_risky,
        geometry_i32(host.endpoints.len())
    );
    canvas.render(&title, &desc)
}

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;

    use super::render;
    use crate::domain::bind_address::BindAddress;
    use crate::domain::endpoint::Endpoint;
    use crate::domain::ids::{HostId, ScanId};
    use crate::domain::port::Port;
    use crate::domain::process::ProcessPath;
    use crate::domain::protocol::Protocol;
    use crate::domain::publisher::{PublisherName, SignatureStatus};
    use crate::domain::report_model::{HostSection, ReportModel};
    use crate::domain::snapshot::ScanSnapshot;
    use crate::domain::target_strategy::TargetStrategy;

    fn endpoint(bind: &str, port: u16, status: SignatureStatus, process_name: &str) -> Endpoint {
        Endpoint::new(
            Protocol::Tcp,
            BindAddress::from_str(bind).expect("valid ip"),
            Port::try_from(port).expect("nonzero port"),
            None,
            Some(ProcessPath::from_str(process_name).expect("non-empty path")),
            vec![],
            status,
            None,
        )
    }

    fn host_with(endpoints: Vec<Endpoint>) -> HostSection {
        let snapshot = ScanSnapshot::new(
            HostId::generate(),
            ScanId::generate(),
            time::OffsetDateTime::UNIX_EPOCH,
            "1.0.0".to_owned(),
            endpoints,
            vec![],
            vec![],
            TargetStrategy::Execute,
        );
        let model = ReportModel::build(&[snapshot], None, true).expect("model builds");
        model.hosts.into_iter().next().expect("one host")
    }

    #[test]
    fn unsigned_all_interfaces_endpoint_lands_in_the_focal_quadrant() {
        let host = host_with(vec![endpoint(
            "0.0.0.0",
            8443,
            SignatureStatus::Unsigned,
            "/usr/bin/app",
        )]);
        let svg = render(&host);
        assert!(svg.contains("1 endpoint(s) unsigned or unconfirmed-signed"));
        assert!(svg.contains("svg-fill-accent\""));
    }

    #[test]
    fn signed_loopback_endpoint_never_uses_the_focal_accent_class() {
        let publisher = PublisherName::try_from("Contoso".to_owned()).expect("non-empty");
        let host = host_with(vec![endpoint(
            "127.0.0.1",
            22,
            SignatureStatus::Signed(publisher),
            "/usr/sbin/sshd",
        )]);
        let svg = render(&host);
        assert!(!svg.contains("svg-fill-accent\""));
        assert!(svg.contains("0 endpoint(s) unsigned or unconfirmed-signed"));
    }

    #[test]
    fn rendering_twice_is_byte_identical() {
        let host = host_with(vec![endpoint(
            "0.0.0.0",
            443,
            SignatureStatus::Unknown,
            "/usr/bin/app",
        )]);
        assert_eq!(render(&host), render(&host));
    }

    #[test]
    fn every_x_y_width_height_is_divisible_by_four() {
        let host = host_with(vec![endpoint(
            "0.0.0.0",
            443,
            SignatureStatus::Unknown,
            "/usr/bin/app",
        )]);
        let svg = render(&host);
        for value in
            super::super::tests_support::extract_numeric_attrs(&svg, &["x", "y", "width", "height"])
        {
            assert!(value.is_multiple_of(4), "{value} is not divisible by 4");
        }
    }

    #[test]
    fn svg_has_title_and_desc() {
        let host = host_with(vec![]);
        let svg = render(&host);
        assert!(svg.contains("<title>"));
        assert!(svg.contains("<desc>"));
    }
}
