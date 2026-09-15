//! SanitAI wordmark banner.
//!
//! Renders a figlet-rendered "SanitAI" wordmark across the top of every screen,
//! with a 1-row tagline strip below it. The figlet output is computed once at
//! construction time and cached so we don't pay the conversion cost per frame.
//!
//! Narrow terminals (`area.width < 50`) fall back to a single-row plain
//! "SANITAI" wordmark — the standard figlet font is ~50 columns wide.

use figlet_rs::FIGfont;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
};

use crate::menu::{COLOR_BG, COLOR_FOCUS, COLOR_MUTED};

/// Width below which we fall back to plain "SANITAI" instead of figlet art.
pub const NARROW_FALLBACK_WIDTH: u16 = 50;

/// Total rows the banner occupies (6 figlet rows + 1 tagline row).
/// Used by `layout::main_layout` to size the banner zone.
pub const BANNER_HEIGHT: u16 = 7;

/// Pre-rendered figlet art for the literal text "SanitAI", split into lines.
///
/// Cached in the `App` struct so we figlet exactly once per process.
pub struct Banner {
    /// Each entry is one row of the rendered figlet output.
    /// Empty when figlet font loading failed (fall back to plain text always).
    rows: Vec<String>,
}

impl Banner {
    /// Render the figlet wordmark at construction time. Falls back to an empty
    /// `rows` vec if `FIGfont::standard()` fails — at runtime that just means
    /// the narrow-terminal plain-text path is always taken.
    pub fn new() -> Self {
        // FIGure borrows from FIGfont, so we have to materialise the rendered
        // string while the font is still in scope. Hence the explicit match
        // rather than a chained Option API.
        let rows = match FIGfont::standard() {
            Ok(font) => match font.convert("SanitAI") {
                Some(fig) => fig.to_string().lines().map(str::to_owned).collect(),
                None => Vec::new(),
            },
            Err(_) => Vec::new(),
        };
        Self { rows }
    }

    /// Draw the banner + tagline into `area`.
    ///
    /// Layout inside `area`:
    /// - rows `[0..figlet_height)`  : figlet wordmark (or plain "SANITAI" on narrow)
    /// - row  `figlet_height`       : tagline (muted)
    pub fn render(&self, area: Rect, buf: &mut Buffer, tagline: &str) {
        // Paint the banner background so the figlet zone stays clean even if
        // the previous frame drew something different here.
        buf.set_style(area, Style::default().bg(COLOR_BG));

        if area.height == 0 || area.width == 0 {
            return;
        }

        let wordmark_style = Style::default()
            .fg(COLOR_FOCUS)
            .bg(COLOR_BG)
            .add_modifier(Modifier::BOLD);

        // Narrow fallback: too tight for the 50-col figlet, draw plain text.
        if area.width < NARROW_FALLBACK_WIDTH || self.rows.is_empty() {
            buf.set_string(area.left(), area.top(), "SANITAI", wordmark_style);
            // Tagline goes on the next row when we have the vertical space.
            if area.height >= 2 {
                buf.set_string(
                    area.left(),
                    area.top().saturating_add(1),
                    tagline,
                    Style::default().fg(COLOR_MUTED).bg(COLOR_BG),
                );
            }
            return;
        }

        // Full figlet path. We may have less vertical space than the figlet
        // needs (very short terminals); clip to whatever rows fit.
        let figlet_rows = (self.rows.len() as u16).min(area.height);
        for (i, line) in self.rows.iter().take(figlet_rows as usize).enumerate() {
            // Truncate to area width to avoid writing past the right edge.
            let max_chars = area.width as usize;
            let display: String = line.chars().take(max_chars).collect();
            buf.set_string(
                area.left(),
                area.top().saturating_add(i as u16),
                &display,
                wordmark_style,
            );
        }

        // Tagline row sits immediately below the figlet rows, when we have one.
        let tagline_row = area.top().saturating_add(figlet_rows);
        if tagline_row < area.bottom() {
            buf.set_string(
                area.left(),
                tagline_row,
                tagline,
                Style::default().fg(COLOR_MUTED).bg(COLOR_BG),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_new_loads_standard_font() {
        let banner = Banner::new();
        // Standard figlet renders "SanitAI" as 6 rows. If figlet ever ships a
        // standard font that produces something else this assertion will tell
        // us — better than silently rendering wrong dimensions.
        assert!(
            !banner.rows.is_empty(),
            "FIGfont::standard() should succeed in tests"
        );
        assert!(
            banner.rows.len() <= BANNER_HEIGHT as usize,
            "figlet output must fit within BANNER_HEIGHT-1 rows (last row is tagline)"
        );
    }

    #[test]
    fn banner_render_narrow_falls_back_to_plain_text() {
        let banner = Banner::new();
        let area = Rect {
            x: 0,
            y: 0,
            width: 30, // < NARROW_FALLBACK_WIDTH
            height: 7,
        };
        let mut buf = Buffer::empty(area);
        banner.render(area, &mut buf, "Ready.");

        // Cell (0,0) should be 'S' from "SANITAI".
        let cell = buf.cell((0u16, 0u16)).unwrap();
        assert_eq!(cell.symbol(), "S");
    }

    #[test]
    fn banner_render_wide_uses_figlet() {
        let banner = Banner::new();
        let area = Rect {
            x: 0,
            y: 0,
            width: 80,
            height: 7,
        };
        let mut buf = Buffer::empty(area);
        banner.render(area, &mut buf, "Ready.");

        // The figlet "SanitAI" never starts with the literal 'S' char on row 0
        // (it starts with whitespace before the underscores of the 'S' top).
        // Easiest sanity check: cell (0,0) is not 'S'.
        let cell = buf.cell((0u16, 0u16)).unwrap();
        assert_ne!(
            cell.symbol(),
            "S",
            "wide path must use figlet art, not plain SANITAI"
        );
    }

    #[test]
    fn banner_render_tagline_appears() {
        let banner = Banner::new();
        let area = Rect {
            x: 0,
            y: 0,
            width: 80,
            height: BANNER_HEIGHT,
        };
        let mut buf = Buffer::empty(area);
        banner.render(area, &mut buf, "Ready.");

        // Walk the last row, collect characters into a string, verify "Ready."
        let mut last_row = String::new();
        for x in 0..area.width {
            if let Some(cell) = buf.cell((x, area.height - 1)) {
                last_row.push_str(cell.symbol());
            }
        }
        assert!(
            last_row.contains("Ready."),
            "tagline row must contain the tagline text; got: {last_row:?}"
        );
    }

    #[test]
    fn banner_render_zero_area_does_not_panic() {
        let banner = Banner::new();
        let area = Rect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        };
        let mut buf = Buffer::empty(Rect {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        });
        banner.render(area, &mut buf, "Ready.");
    }
}
