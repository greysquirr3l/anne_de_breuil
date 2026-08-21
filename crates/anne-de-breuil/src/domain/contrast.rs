//! WCAG contrast-ratio calculation for the HTML report's colour tokens.
//!
//! Pure math, no I/O — this is what lets the palette in
//! `adapters::html_report` be checked against the WCAG AA threshold
//! (4.5:1 for normal text) by a real computed test rather than an
//! eyeballed hex value. See <https://www.w3.org/TR/WCAG21/#dfn-relative-luminance>
//! and <https://www.w3.org/TR/WCAG21/#dfn-contrast-ratio> for the formulas
//! this implements verbatim.

/// Parses a `#rrggbb` string into its three byte components.
///
/// Malformed input (wrong length, non-hex digits) decodes any unreadable
/// channel as `0` rather than panicking — this function only ever sees
/// literal palette constants in this codebase, and a wrong contrast
/// number from bad input is a test failure, not something that should
/// crash a report render.
fn parse_hex_rgb(hex: &str) -> (u8, u8, u8) {
    let digits = hex.strip_prefix('#').unwrap_or(hex);
    let channel = |start: usize| {
        digits
            .get(start..start + 2)
            .and_then(|byte| u8::from_str_radix(byte, 16).ok())
            .unwrap_or(0)
    };
    (channel(0), channel(2), channel(4))
}

/// WCAG relative luminance of an sRGB colour: gamma-corrects each channel
/// to linear light, then takes the perceptual-weighted sum.
fn relative_luminance(hex: &str) -> f64 {
    let (r, g, b) = parse_hex_rgb(hex);
    let linear = |byte: u8| {
        let c = f64::from(byte) / 255.0;
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126_f64.mul_add(linear(r), 0.7152_f64.mul_add(linear(g), 0.0722 * linear(b)))
}

/// WCAG contrast ratio between two `#rrggbb` colours.
///
/// Ranges from `1.0` (identical luminance) to `21.0` (pure black on pure
/// white). Argument order doesn't matter — the lighter of the two always
/// goes in the numerator.
#[must_use]
pub fn contrast_ratio(fg_hex: &str, bg_hex: &str) -> f64 {
    let (l1, l2) = (relative_luminance(fg_hex), relative_luminance(bg_hex));
    let (lighter, darker) = if l1 > l2 { (l1, l2) } else { (l2, l1) };
    (lighter + 0.05) / (darker + 0.05)
}

#[cfg(test)]
mod tests {
    use super::contrast_ratio;

    const WCAG_AA_NORMAL_TEXT: f64 = 4.5;

    #[test]
    fn ink_on_paper_meets_wcag_aa() {
        assert!(contrast_ratio("#111111", "#f5f5f4") >= WCAG_AA_NORMAL_TEXT);
    }

    /// `--exposure-specific` is `#84681c`, not the task sketch's literal
    /// `#8a6d1f` — computed against `--paper` (`#f5f5f4`), the sketch's
    /// own value is 4.4893:1, just under AA. Darkened while keeping the
    /// same ochre hue and "specific interface" role; the adjusted value
    /// clears 4.8391:1. See PROGRESS.md's T23 section for the full set of
    /// computed numbers.
    #[test]
    fn every_exposure_state_colour_meets_wcag_aa_on_paper() {
        for hex in ["#4b5a6b", "#84681c", "#c4432b"] {
            assert!(
                contrast_ratio(hex, "#f5f5f4") >= WCAG_AA_NORMAL_TEXT,
                "{hex} fails AA on --paper"
            );
        }
    }

    #[test]
    fn identical_colours_have_a_ratio_of_one() {
        assert!((contrast_ratio("#808080", "#808080") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn black_on_white_is_the_maximum_ratio() {
        assert!((contrast_ratio("#000000", "#ffffff") - 21.0).abs() < 0.01);
    }

    #[test]
    fn ratio_is_symmetric_in_argument_order() {
        let a = contrast_ratio("#111111", "#f5f5f4");
        let b = contrast_ratio("#f5f5f4", "#111111");
        assert!((a - b).abs() < 1e-9);
    }
}
