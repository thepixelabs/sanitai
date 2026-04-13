use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    widgets::Widget,
};

use crate::menu::{COLOR_BG, COLOR_FG, COLOR_FOCUS, COLOR_MUTED, COLOR_SAFE};

// ---------------------------------------------------------------------------
// AppSettings — the persisted config state (owned by App)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppSettings {
    pub show_mascot: bool,
    pub mascot_speech: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            show_mascot: true,
            mascot_speech: true,
        }
    }
}

// ---------------------------------------------------------------------------
// SettingsTab
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SettingsTab {
    General,
    Rules,
}

// ---------------------------------------------------------------------------
// General tab items — enumerate to keep cursor bounds correct
// ---------------------------------------------------------------------------

const GENERAL_ITEM_COUNT: usize = 2;

// ---------------------------------------------------------------------------
// SettingsScreen
// ---------------------------------------------------------------------------

pub struct SettingsScreen {
    pub settings: AppSettings,
    pub active_tab: SettingsTab,
    pub general_cursor: usize,
}

impl SettingsScreen {
    pub fn new(settings: AppSettings) -> Self {
        Self {
            settings,
            active_tab: SettingsTab::General,
            general_cursor: 0,
        }
    }

    pub fn next_tab(&mut self) {
        self.active_tab = match self.active_tab {
            SettingsTab::General => SettingsTab::Rules,
            SettingsTab::Rules => SettingsTab::General,
        };
    }

    pub fn move_down(&mut self) {
        if self.active_tab == SettingsTab::General {
            self.general_cursor = (self.general_cursor + 1) % GENERAL_ITEM_COUNT;
        }
    }

    pub fn move_up(&mut self) {
        if self.active_tab == SettingsTab::General {
            self.general_cursor = if self.general_cursor == 0 {
                GENERAL_ITEM_COUNT - 1
            } else {
                self.general_cursor - 1
            };
        }
    }

    pub fn toggle_selected(&mut self) {
        if self.active_tab == SettingsTab::General {
            match self.general_cursor {
                0 => self.settings.show_mascot = !self.settings.show_mascot,
                1 => self.settings.mascot_speech = !self.settings.mascot_speech,
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Widget impl
// ---------------------------------------------------------------------------

impl Widget for &mut SettingsScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Fill background
        buf.set_style(area, Style::default().bg(COLOR_BG));

        if area.height == 0 {
            return;
        }

        let mut row = area.top();

        // --- Title bar ---
        if row < area.bottom() {
            buf.set_string(
                area.left(),
                row,
                "  Settings",
                Style::default()
                    .fg(COLOR_FOCUS)
                    .add_modifier(Modifier::BOLD),
            );
            row += 1;
        }

        // --- Tab bar ---
        if row < area.bottom() {
            let general_style = if self.active_tab == SettingsTab::General {
                Style::default().fg(COLOR_FOCUS).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(COLOR_MUTED)
            };
            let rules_style = if self.active_tab == SettingsTab::Rules {
                Style::default().fg(COLOR_FOCUS).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(COLOR_MUTED)
            };

            // Build the tab bar manually so each tab can carry its own style.
            // We write them as separate strings placed side by side.
            let x = area.left() + 2;
            buf.set_string(x, row, "[ General ]", general_style);
            buf.set_string(x + 13, row, "[ Rules ]", rules_style);
            row += 1;
        }

        // --- Separator ---
        if row < area.bottom() {
            let sep = "\u{2500}".repeat(area.width as usize);
            buf.set_string(
                area.left(),
                row,
                &sep,
                Style::default().fg(COLOR_MUTED),
            );
            row += 1;
        }

        // --- Footer (reserve the last row before we render content) ---
        let footer_row = area.bottom().saturating_sub(1);

        // --- Content area ---
        let content_bottom = footer_row; // rows [row, footer_row)

        match self.active_tab {
            SettingsTab::General => {
                render_general(self, area.left(), row, content_bottom, buf);
            }
            SettingsTab::Rules => {
                render_rules(area.left(), row, content_bottom, buf);
            }
        }

        // --- Footer ---
        if footer_row >= area.top() && footer_row < area.bottom() {
            buf.set_string(
                area.left(),
                footer_row,
                "  Tab switch tabs  \u{00b7}  j/k navigate  \u{00b7}  Space toggle  \u{00b7}  q back",
                Style::default().fg(COLOR_MUTED),
            );
        }
    }
}

fn render_general(
    screen: &SettingsScreen,
    left: u16,
    top: u16,
    bottom: u16,
    buf: &mut Buffer,
) {
    let items: &[(&str, bool)] = &[
        ("Show mascot   ", screen.settings.show_mascot),
        ("Mascot speech ", screen.settings.mascot_speech),
    ];

    for (idx, (label, value)) in items.iter().enumerate() {
        let row = top + idx as u16;
        if row >= bottom {
            break;
        }

        let is_selected = screen.general_cursor == idx;

        let prefix = if is_selected { "\u{25b8} " } else { "  " };
        let prefix_style = Style::default().fg(if is_selected { COLOR_FOCUS } else { COLOR_FG });

        let value_str = if *value { "[on ]" } else { "[off]" };
        let value_style = Style::default().fg(if *value { COLOR_SAFE } else { COLOR_MUTED });

        let label_style = Style::default().fg(if is_selected { COLOR_FG } else { COLOR_FG });

        let x = left + 4;

        // Prefix arrow
        buf.set_string(x, row, prefix, prefix_style);
        // Label
        buf.set_string(x + 2, row, label, label_style);
        // Toggle value
        buf.set_string(x + 2 + label.len() as u16, row, value_str, value_style);
    }
}

fn render_rules(left: u16, top: u16, bottom: u16, buf: &mut Buffer) {
    let lines = [
        "  Detector rules will appear here in a future update.",
        "  All detectors are currently enabled.",
    ];
    for (idx, line) in lines.iter().enumerate() {
        let row = top + idx as u16;
        if row >= bottom {
            break;
        }
        buf.set_string(left, row, line, Style::default().fg(COLOR_MUTED));
    }
}
