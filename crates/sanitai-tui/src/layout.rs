use ratatui::layout::{Constraint, Direction, Layout, Rect};

use crate::banner::BANNER_HEIGHT;

/// Split the terminal into three vertical zones:
///
/// ```text
/// ┌──────────────────────────┐
/// │   SanitAI wordmark       │  banner_area  (BANNER_HEIGHT rows)
/// │   tagline                │
/// ├──────────────────────────┤
/// │                          │
/// │   screen body            │  body_area    (full remaining width)
/// │                          │
/// ├──────────────────────────┤
/// │ keys │ last-scan         │  footer_area  (1 row)
/// └──────────────────────────┘
/// ```
///
/// On terminals shorter than `BANNER_HEIGHT + 2` rows the banner zone is
/// clipped by ratatui's layout solver — the body still gets at least 1 row.
pub fn main_layout(area: Rect) -> (Rect, Rect, Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(BANNER_HEIGHT), // banner + tagline
            Constraint::Min(1),                // body
            Constraint::Length(1),             // footer
        ])
        .split(area);

    (chunks[0], chunks[1], chunks[2])
}
