use ratatui::{buffer::Buffer, layout::Rect, style::Style, widgets::Widget};

use crate::menu::{COLOR_BG, COLOR_FG, COLOR_FOCUS, COLOR_MUTED, COLOR_WARN};

// ---------------------------------------------------------------------------
// HelpOverlay — centered popup drawn on top of the existing buffer
// ---------------------------------------------------------------------------

pub struct HelpOverlay;

impl Widget for &HelpOverlay {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let popup = centered_rect(60, 24, area);

        if popup.width < 4 || popup.height < 4 {
            return;
        }

        // Fill the interior with the background colour so whatever was behind
        // the box is fully covered.
        buf.set_style(popup, Style::default().bg(COLOR_BG));

        render_border(popup, buf);
        render_content(popup, buf);
    }
}

// ---------------------------------------------------------------------------
// Border
// ---------------------------------------------------------------------------

fn render_border(area: Rect, buf: &mut Buffer) {
    let border_style = Style::default().fg(COLOR_FOCUS).bg(COLOR_BG);
    let w = area.width as usize;
    let x0 = area.left();
    let x1 = area.right().saturating_sub(1);
    let y0 = area.top();
    let y1 = area.bottom().saturating_sub(1);

    // Top border: ╔══ Help ══╗
    // We build it so the title is centred inside the top edge.
    let title = " Help ";
    let inner_width = w.saturating_sub(2); // space between ╔ and ╗
    let title_pad_total = inner_width.saturating_sub(title.len());
    let pad_left = title_pad_total / 2;
    let pad_right = title_pad_total - pad_left;
    let top_line = format!(
        "\u{2554}{}{}{}\u{2557}",
        "\u{2550}".repeat(pad_left),
        title,
        "\u{2550}".repeat(pad_right),
    );
    buf.set_string(x0, y0, &top_line, border_style);

    // Bottom border: ╚══════╝
    let bottom_line = format!("\u{255a}{}\u{255d}", "\u{2550}".repeat(inner_width));
    buf.set_string(x0, y1, &bottom_line, border_style);

    // Left and right borders
    for y in (y0 + 1)..y1 {
        buf.set_string(x0, y, "\u{2551}", border_style);
        buf.set_string(x1, y, "\u{2551}", border_style);
    }
}

// ---------------------------------------------------------------------------
// Content
// ---------------------------------------------------------------------------

/// A content section entry.
/// `None` in the key field marks a section header or separator.
struct Row {
    key: Option<&'static str>,
    desc: &'static str,
}

fn content_rows() -> Vec<Row> {
    vec![
        Row {
            key: None,
            desc: "Navigation",
        },
        Row {
            key: None,
            desc:
                "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        },
        Row {
            key: Some("j / \u{2193}"),
            desc: "Move down",
        },
        Row {
            key: Some("k / \u{2191}"),
            desc: "Move up",
        },
        Row {
            key: Some("Enter"),
            desc: "Select / confirm",
        },
        Row {
            key: Some("q / Esc"),
            desc: "Go back / quit",
        },
        Row {
            key: Some("Tab"),
            desc: "Switch tabs (Settings)",
        },
        Row {
            key: None,
            desc: "",
        }, // blank spacer
        Row {
            key: None,
            desc: "Scanning",
        },
        Row {
            key: None,
            desc:
                "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        },
        Row {
            key: Some("S"),
            desc: "Run scan from main menu",
        },
        Row {
            key: Some("(any key)"),
            desc: "Dismiss results",
        },
        Row {
            key: None,
            desc: "",
        }, // blank spacer
        Row {
            key: None,
            desc: "History",
        },
        Row {
            key: None,
            desc:
                "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        },
        Row {
            key: Some("/"),
            desc: "Start filter",
        },
        Row {
            key: Some("Esc"),
            desc: "Clear filter / cancel",
        },
        Row {
            key: None,
            desc: "",
        }, // blank spacer
        Row {
            key: None,
            desc: "General",
        },
        Row {
            key: None,
            desc:
                "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        },
        Row {
            key: Some("?"),
            desc: "Show this help",
        },
    ]
}

fn render_content(area: Rect, buf: &mut Buffer) {
    // Content starts at column x0+2 (inside the double border + 1 space).
    let content_x = area.left() + 2;
    // Rows available between top border and footer (last interior row).
    // y0 = top border, y1 = bottom border.
    // Interior rows: y0+1 .. y1-1 (inclusive).
    // We reserve the last interior row for the footer hint.
    let y_start = area.top() + 1;
    let y_end_border = area.bottom().saturating_sub(1); // bottom border row
                                                        // Last content row is y_end_border - 2 (leave one row for footer).
    let footer_row = y_end_border.saturating_sub(1);

    let rows = content_rows();
    let mut y = y_start;

    for row in &rows {
        if y >= footer_row {
            break;
        }

        match row.key {
            None => {
                // Could be a section header, separator, or blank spacer.
                if row.desc.is_empty() {
                    // blank spacer — just advance y
                } else if row.desc.starts_with('\u{2500}') {
                    // separator line
                    buf.set_string(
                        content_x,
                        y,
                        row.desc,
                        Style::default().fg(COLOR_MUTED).bg(COLOR_BG),
                    );
                } else {
                    // section header
                    buf.set_string(
                        content_x,
                        y,
                        row.desc,
                        Style::default().fg(COLOR_FOCUS).bg(COLOR_BG),
                    );
                }
            }
            Some(key) => {
                // Key column (fixed 12 chars wide so descriptions align)
                let key_col = format!("{:<12}", key);
                buf.set_string(
                    content_x,
                    y,
                    &key_col,
                    Style::default().fg(COLOR_WARN).bg(COLOR_BG),
                );
                buf.set_string(
                    content_x + 12,
                    y,
                    row.desc,
                    Style::default().fg(COLOR_FG).bg(COLOR_BG),
                );
            }
        }

        y += 1;
    }

    // Footer hint
    if footer_row > y_start && footer_row < y_end_border {
        buf.set_string(
            content_x,
            footer_row,
            "Press ? or Esc to close",
            Style::default().fg(COLOR_MUTED).bg(COLOR_BG),
        );
    }
}

// ---------------------------------------------------------------------------
// Centering helper
// ---------------------------------------------------------------------------

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect {
        x,
        y,
        width: width.min(area.width),
        height: height.min(area.height),
    }
}
