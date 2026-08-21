//! Exposure map: host, then interface, then port grouped by reachability,
//! then owning process — one row per port, hairline-connected back to its
//! interface, and the interface back to the host node. The "components and
//! connections" architecture-style layout the task calls for.
//!
//! Degrades to a one-line summary above
//! [`super::NODE_DENSITY_THRESHOLD`] endpoints — a several-hundred-port
//! host does not get a several-hundred-node hairball; see
//! [`render_summary`].

use std::collections::BTreeMap;

use crate::domain::report_model::{EndpointView, HostSection};
use crate::domain::svg::SvgCanvas;

use super::{
    NODE_DENSITY_THRESHOLD, geometry_i32, reachability_fill_class, reachability_rank, short_host_id,
};

const CANVAS_WIDTH: i32 = 800;
const ROW_HEIGHT: i32 = 24;
const TOP_MARGIN: i32 = 20;
const LEFT_MARGIN: i32 = 20;
const HOST_WIDTH: i32 = 200;
const INTERFACE_INDENT: i32 = 24;
const INTERFACE_WIDTH: i32 = 180;
const PORT_INDENT: i32 = 48;
const PORT_WIDTH: i32 = 160;
const PROCESS_GAP: i32 = 172;

pub(in crate::adapters::html_report) fn render(host: &HostSection) -> String {
    if host.endpoints.len() > NODE_DENSITY_THRESHOLD {
        return render_summary(host);
    }

    let mut by_interface: BTreeMap<String, Vec<&EndpointView>> = BTreeMap::new();
    for endpoint in &host.endpoints {
        by_interface
            .entry(endpoint.bind_address.to_string())
            .or_default()
            .push(endpoint);
    }

    let row_count = 1 + by_interface.len() + host.endpoints.len();
    let height = TOP_MARGIN + geometry_i32(row_count) * ROW_HEIGHT + TOP_MARGIN;
    let mut canvas = SvgCanvas::new(CANVAS_WIDTH, height);

    let host_label = format!("host {}", short_host_id(host));
    let mut y = TOP_MARGIN;
    canvas.rect(LEFT_MARGIN, y, HOST_WIDTH, 20, "svg-node");
    canvas.text(LEFT_MARGIN + 8, y + 14, &host_label, "svg-text");
    let host_anchor_y = y + 10;
    y += ROW_HEIGHT;

    for (interface, endpoints) in &by_interface {
        canvas.line(
            LEFT_MARGIN + 8,
            host_anchor_y,
            LEFT_MARGIN + INTERFACE_INDENT + 8,
            y + 10,
            "svg-stroke-hairline",
        );
        canvas.rect(
            LEFT_MARGIN + INTERFACE_INDENT,
            y,
            INTERFACE_WIDTH,
            20,
            "svg-node",
        );
        canvas.text(
            LEFT_MARGIN + INTERFACE_INDENT + 8,
            y + 14,
            interface,
            "svg-text-mono",
        );
        let interface_anchor_y = y + 10;
        y += ROW_HEIGHT;

        let mut sorted = endpoints.clone();
        sorted.sort_by_key(|endpoint| {
            (
                reachability_rank(endpoint.reachability),
                endpoint.port.get(),
            )
        });

        for endpoint in sorted {
            canvas.line(
                LEFT_MARGIN + INTERFACE_INDENT + 8,
                interface_anchor_y,
                LEFT_MARGIN + PORT_INDENT + 8,
                y + 10,
                "svg-stroke-hairline",
            );
            let class = reachability_fill_class(endpoint.reachability);
            canvas.rect(LEFT_MARGIN + PORT_INDENT, y, PORT_WIDTH, 20, class);
            let port_label = format!("{}/{}", endpoint.protocol, endpoint.port);
            canvas.text(
                LEFT_MARGIN + PORT_INDENT + 8,
                y + 14,
                &port_label,
                "svg-text-mono",
            );
            if let Some(path) = &endpoint.process_path {
                canvas.text(
                    LEFT_MARGIN + PORT_INDENT + PROCESS_GAP,
                    y + 14,
                    &path.to_string(),
                    "svg-text-muted",
                );
            }
            y += ROW_HEIGHT;
        }
    }

    let title = format!("Exposure map for host {}", short_host_id(host));
    let desc = format!(
        "{} endpoint(s) across {} interface(s), grouped by reachability within each interface",
        host.endpoints.len(),
        by_interface.len()
    );
    canvas.render(&title, &desc)
}

/// The degraded variant: a several-hundred-port host gets one summary row,
/// never a several-hundred-node hairball. The literal phrase "see table"
/// points the reader at the accessible `<table>` this diagram sits beside
/// — the real detail lives there.
fn render_summary(host: &HostSection) -> String {
    let mut canvas = SvgCanvas::new(CANVAS_WIDTH, 60);
    canvas.rect(LEFT_MARGIN, TOP_MARGIN, 400, 24, "svg-node");
    let label = format!("{} ports, see table for detail", host.endpoints.len());
    canvas.text(LEFT_MARGIN + 8, TOP_MARGIN + 16, &label, "svg-text");

    let title = format!("Exposure map for host {} (summarized)", short_host_id(host));
    let desc = format!(
        "{} endpoints exceeds the {NODE_DENSITY_THRESHOLD}-node density threshold; rendered as a \
         summary, full detail in the endpoint table",
        host.endpoints.len()
    );
    canvas.render(&title, &desc)
}

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;

    use super::{NODE_DENSITY_THRESHOLD, render};
    use crate::domain::bind_address::BindAddress;
    use crate::domain::endpoint::Endpoint;
    use crate::domain::ids::{HostId, ScanId};
    use crate::domain::port::Port;
    use crate::domain::process::ProcessPath;
    use crate::domain::protocol::Protocol;
    use crate::domain::publisher::SignatureStatus;
    use crate::domain::report_model::ReportModel;
    use crate::domain::snapshot::ScanSnapshot;
    use crate::domain::target_strategy::TargetStrategy;

    fn host_with_endpoints(
        count: usize,
        process_name: &str,
    ) -> crate::domain::report_model::HostSection {
        let endpoints: Vec<Endpoint> = (0..count)
            .map(|index| {
                let port = 1024 + u16::try_from(index).unwrap_or(0);
                Endpoint::new(
                    Protocol::Tcp,
                    BindAddress::from_str(if index.is_multiple_of(2) {
                        "0.0.0.0"
                    } else {
                        "127.0.0.1"
                    })
                    .expect("valid ip"),
                    Port::try_from(port).expect("nonzero port"),
                    None,
                    Some(ProcessPath::from_str(process_name).expect("non-empty path")),
                    vec![],
                    SignatureStatus::Unknown,
                    None,
                )
            })
            .collect();
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
    fn density_threshold_triggers_the_summarized_variant() {
        let host = host_with_endpoints(NODE_DENSITY_THRESHOLD + 1, "/usr/bin/app");
        let svg = render(&host);
        assert!(svg.contains("see table"));
    }

    #[test]
    fn below_threshold_renders_one_row_per_endpoint() {
        let host = host_with_endpoints(5, "/usr/bin/app");
        let svg = render(&host);
        assert!(!svg.contains("see table"));
        assert_eq!(svg.matches("<rect").count(), 1 + 2 + 5);
    }

    #[test]
    fn rendering_twice_is_byte_identical() {
        let host = host_with_endpoints(12, "/usr/bin/app");
        assert_eq!(render(&host), render(&host));
    }

    #[test]
    fn every_x_y_width_height_is_divisible_by_four() {
        let host = host_with_endpoints(8, "/usr/bin/app");
        let svg = render(&host);
        for value in
            super::super::tests_support::extract_numeric_attrs(&svg, &["x", "y", "width", "height"])
        {
            assert!(value.is_multiple_of(4), "{value} is not divisible by 4");
        }
    }

    #[test]
    fn svg_has_title_and_escapes_a_malicious_process_name() {
        let host = host_with_endpoints(3, "<script>alert(1)</script>");
        let svg = render(&host);
        assert!(svg.contains("<title>"));
        assert!(!svg.contains("<script>alert"));
    }
}
