use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Split the terminal into three vertical zones:
/// [menu area | nix area] stacked, with footer at the bottom.
pub fn main_layout(area: Rect) -> (Rect, Rect, Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),   // main body
            Constraint::Length(1), // footer
        ])
        .split(area);

    let body = chunks[0];
    let footer = chunks[1];

    // Split body: menu on left, Nix on right (fixed 22 cols)
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(30), Constraint::Length(22)])
        .split(body);

    (body_chunks[0], body_chunks[1], footer)
}
