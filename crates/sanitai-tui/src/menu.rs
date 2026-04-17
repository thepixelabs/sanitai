use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Widget},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MenuItem {
    Scan,
    History,
    Report,
    Scrub,
    Settings,
    Help,
    Quit,
}

pub struct Menu {
    pub items: Vec<(MenuItem, &'static str, bool)>, // (variant, label, is_active)
    pub state: ratatui::widgets::ListState,
}

impl Default for Menu {
    fn default() -> Self {
        Self::new()
    }
}

impl Menu {
    pub fn new() -> Self {
        let items = vec![
            (MenuItem::Scan, "scan", true),
            (MenuItem::History, "history", true),
            (MenuItem::Report, "report", false),
            (MenuItem::Scrub, "redact", true),
            (MenuItem::Settings, "settings", true),
            (MenuItem::Help, "help", true),
            (MenuItem::Quit, "quit", true),
        ];
        let mut state = ratatui::widgets::ListState::default();
        state.select(Some(0)); // default: scan
        Self { items, state }
    }

    pub fn selected_item(&self) -> Option<MenuItem> {
        self.state
            .selected()
            .and_then(|i| self.items.get(i))
            .map(|(m, _, _)| *m)
    }

    pub fn move_down(&mut self) {
        let i = self.state.selected().unwrap_or(0);
        let next = (i + 1) % self.items.len();
        self.state.select(Some(next));
    }

    pub fn move_up(&mut self) {
        let i = self.state.selected().unwrap_or(0);
        let prev = if i == 0 { self.items.len() - 1 } else { i - 1 };
        self.state.select(Some(prev));
    }
}

// Color constants (SanitAI palette — Phase 2 subset)
pub const COLOR_BG: Color = Color::Indexed(233); // midnight navy
pub const COLOR_FG: Color = Color::Indexed(230); // warm ivory
pub const COLOR_FOCUS: Color = Color::Indexed(51); // electric cyan
pub const COLOR_MUTED: Color = Color::Indexed(241); // medium gray
pub const COLOR_SAFE: Color = Color::Indexed(85); // mint green
pub const COLOR_WARN: Color = Color::Indexed(222); // amber
#[allow(dead_code)] // used by Phase 3 alert styling
pub const COLOR_DANGER: Color = Color::Indexed(210); // coral red

impl Widget for &mut Menu {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .title(Span::styled(
                " SanitAI ",
                Style::default()
                    .fg(COLOR_FOCUS)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(COLOR_MUTED))
            .style(Style::default().bg(COLOR_BG));

        let inner = block.inner(area);
        block.render(area, buf);

        // Render items manually to control active/muted/selected styles
        for (idx, (_, label, is_active)) in self.items.iter().enumerate() {
            let is_selected = self.state.selected() == Some(idx);
            // 1-row top padding; saturating_add prevents u16 overflow
            let row = inner.top().saturating_add(1).saturating_add(idx as u16);

            if row >= inner.bottom() {
                break;
            }

            let (prefix, style) = if is_selected && *is_active {
                (
                    " ▸ ",
                    Style::default()
                        .fg(COLOR_FOCUS)
                        .add_modifier(Modifier::BOLD),
                )
            } else if is_selected && !is_active {
                (" ▸ ", Style::default().fg(COLOR_MUTED))
            } else if *is_active {
                ("   ", Style::default().fg(COLOR_FG))
            } else {
                ("   ", Style::default().fg(COLOR_MUTED))
            };

            let suffix = if !is_active { " ·" } else { "" };
            let text = format!("{prefix}{label}{suffix}");

            buf.set_string(inner.left(), row, &text, style);
        }

        // "report" is the only stub — note it quietly
        let legend_row = inner.bottom().saturating_sub(1);
        buf.set_string(
            inner.left().saturating_add(2),
            legend_row,
            "\u{00b7} report coming soon",
            Style::default().fg(COLOR_MUTED),
        );
    }
}
