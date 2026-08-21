//! [`Grid4`]/[`SvgCanvas`]: deterministic, escaped SVG geometry primitives
//! shared by every T25 report diagram.
//!
//! Pure and zero I/O, like [`crate::domain::report_render`] and
//! [`crate::domain::contrast`] before it. Every coordinate a caller passes
//! to [`SvgCanvas::rect`]/[`SvgCanvas::text`]/[`SvgCanvas::line`] is snapped
//! to a 4px grid *at construction* via [`Grid4::snap`], not validated
//! afterward — there is no code path in this module that can emit a
//! non-grid-aligned value. Every piece of text content is escaped through
//! [`escape_svg_text`] before it reaches the output string, so a hostile
//! process name or firewall rule display name (both free-form platform
//! text with no domain-level validation) can never break out of the
//! surrounding markup.

/// A coordinate or length snapped to the nearest lower multiple of 4.
///
/// Diagram layout constants elsewhere in this codebase are chosen to
/// already be multiples of 4, but nothing downstream needs to trust that —
/// every value that reaches rendered output has passed through here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Grid4(i32);

impl Grid4 {
    /// Snaps `value` down to the nearest multiple of 4.
    ///
    /// Diagram geometry in this codebase is always non-negative, so
    /// truncating integer division toward zero and rounding toward
    /// negative infinity coincide here; this is not a general-purpose
    /// rounding function for negative input.
    #[must_use]
    pub const fn snap(value: i32) -> Self {
        Self((value / 4) * 4)
    }

    #[must_use]
    pub const fn get(self) -> i32 {
        self.0
    }
}

/// Escapes text for safe interpolation into SVG markup, in either a text
/// node or a quoted attribute value.
///
/// SVG is XML: `&` and `<` are always structurally significant, `>` closes
/// a tag early in some parsers' error-recovery paths, and `"`/`'` can
/// terminate a quoted attribute value early. Escaping all five
/// unconditionally, regardless of which context the caller intends to use
/// the result in, is what makes this function safe to call once and reuse
/// the result anywhere in this module — a caller never has to reason about
/// which subset of characters matters for the specific spot it's about to
/// interpolate into.
#[must_use]
pub fn escape_svg_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// A single SVG diagram under construction.
///
/// Every element-producing method returns `&mut Self` so a diagram
/// renderer can chain calls without holding a separate mutable binding
/// per shape — the same builder shape the task's own code sketch uses.
pub struct SvgCanvas {
    width: Grid4,
    height: Grid4,
    elements: Vec<String>,
}

impl SvgCanvas {
    #[must_use]
    pub const fn new(width: i32, height: i32) -> Self {
        Self {
            width: Grid4::snap(width),
            height: Grid4::snap(height),
            elements: Vec::new(),
        }
    }

    /// Appends a rounded rectangle. `class` selects styling entirely
    /// through the report's existing CSS custom-property tokens (see
    /// `templates/tokens.css`'s `svg-*` rules) — this module never emits a
    /// hex literal or an inline `style` attribute.
    pub fn rect(&mut self, x: i32, y: i32, w: i32, h: i32, class: &str) -> &mut Self {
        let (x, y, w, h) = (
            Grid4::snap(x),
            Grid4::snap(y),
            Grid4::snap(w),
            Grid4::snap(h),
        );
        let class = escape_svg_text(class);
        self.elements.push(format!(
            r#"<rect x="{}" y="{}" width="{}" height="{}" rx="10" class="{class}"/>"#,
            x.get(),
            y.get(),
            w.get(),
            h.get()
        ));
        self
    }

    /// Appends a text node at `(x, y)`. `content` is escaped; `class`
    /// selects font (mono for technical labels, sans otherwise) and color
    /// through the token system, same as [`SvgCanvas::rect`].
    pub fn text(&mut self, x: i32, y: i32, content: &str, class: &str) -> &mut Self {
        let (x, y) = (Grid4::snap(x), Grid4::snap(y));
        let content = escape_svg_text(content);
        let class = escape_svg_text(class);
        self.elements.push(format!(
            r#"<text x="{}" y="{}" class="{class}">{content}</text>"#,
            x.get(),
            y.get()
        ));
        self
    }

    /// Appends a 1px hairline connector between two points — the
    /// "components and connections" the exposure map's architecture-style
    /// layout needs.
    pub fn line(&mut self, x1: i32, y1: i32, x2: i32, y2: i32, class: &str) -> &mut Self {
        let (x1, y1, x2, y2) = (
            Grid4::snap(x1),
            Grid4::snap(y1),
            Grid4::snap(x2),
            Grid4::snap(y2),
        );
        let class = escape_svg_text(class);
        self.elements.push(format!(
            r#"<line x1="{}" y1="{}" x2="{}" y2="{}" class="{class}"/>"#,
            x1.get(),
            y1.get(),
            x2.get(),
            y2.get()
        ));
        self
    }

    /// Renders the finished diagram. Every `<svg>` this module produces
    /// carries `role="img"`, `aria-label`, a `<title>`, and a `<desc>` —
    /// the task's own accessibility requirement, applied unconditionally
    /// rather than left to each diagram renderer to remember.
    #[must_use]
    pub fn render(&self, title: &str, desc: &str) -> String {
        let title = escape_svg_text(title);
        let desc = escape_svg_text(desc);
        format!(
            r#"<svg role="img" aria-label="{title}" width="{}" height="{}" xmlns="http://www.w3.org/2000/svg"><title>{title}</title><desc>{desc}</desc>{}</svg>"#,
            self.width.get(),
            self.height.get(),
            self.elements.join("")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Grid4, SvgCanvas, escape_svg_text};

    #[test]
    fn grid4_snaps_down_to_the_nearest_multiple_of_four() {
        assert_eq!(Grid4::snap(0).get(), 0);
        assert_eq!(Grid4::snap(3).get(), 0);
        assert_eq!(Grid4::snap(4).get(), 4);
        assert_eq!(Grid4::snap(23).get(), 20);
        assert_eq!(Grid4::snap(800).get(), 800);
    }

    #[test]
    fn escape_svg_text_neutralizes_every_structurally_significant_character() {
        let escaped = escape_svg_text(r#"</svg><script>alert(1)</script>&"'"#);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(!escaped.contains('\''));
        assert_eq!(
            escaped,
            "&lt;/svg&gt;&lt;script&gt;alert(1)&lt;/script&gt;&amp;&quot;&apos;"
        );
    }

    #[test]
    fn escape_svg_text_leaves_ordinary_text_untouched() {
        assert_eq!(escape_svg_text("port 443, TCP"), "port 443, TCP");
    }

    #[test]
    fn rect_snaps_every_dimension_and_hardcodes_the_radius_ceiling() {
        let mut canvas = SvgCanvas::new(100, 100);
        canvas.rect(21, 23, 199, 17, "svg-node");
        let svg = canvas.render("t", "d");
        assert!(svg.contains(r#"x="20" y="20" width="196" height="16" rx="10""#));
    }

    #[test]
    fn text_escapes_content_and_class() {
        let mut canvas = SvgCanvas::new(100, 100);
        canvas.text(4, 4, "<script>alert(1)</script>", "svg-text");
        let svg = canvas.render("t", "d");
        assert!(!svg.contains("<script>alert"));
        assert!(svg.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn render_carries_title_desc_role_and_aria_label() {
        let canvas = SvgCanvas::new(40, 40);
        let svg = canvas.render("A title", "A description");
        assert!(svg.contains(r#"role="img""#));
        assert!(svg.contains(r#"aria-label="A title""#));
        assert!(svg.contains("<title>A title</title>"));
        assert!(svg.contains("<desc>A description</desc>"));
    }

    #[test]
    fn render_escapes_hostile_title_and_desc() {
        let canvas = SvgCanvas::new(40, 40);
        let svg = canvas.render("</title><script>alert(1)</script>", "d");
        assert!(!svg.contains("<script>alert"));
    }

    #[test]
    fn rendering_twice_from_the_same_input_is_byte_identical() {
        let build = || {
            let mut canvas = SvgCanvas::new(80, 80);
            canvas.rect(4, 4, 40, 20, "svg-node");
            canvas.text(8, 16, "443", "svg-text-mono");
            canvas.render("t", "d")
        };
        assert_eq!(build(), build());
    }
}
