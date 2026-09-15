use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    widgets::Widget,
};
use sanitai_core::config::RedactMode;

use crate::menu::{COLOR_BG, COLOR_FG, COLOR_FOCUS, COLOR_MUTED, COLOR_SAFE, COLOR_WARN};

// ---------------------------------------------------------------------------
// AppSettings — the persisted config state (owned by App)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppSettings {
    /// When true, the Results detail pane shows the literal credential value
    /// (`Finding.matched_raw`). Default false — the value never appears
    /// anywhere in the UI unless the user has explicitly opted in.
    pub reveal_secrets: bool,
    /// Redaction strategy used by the Redact screen and the Results-screen
    /// `R` shortcut. Mirrors the CLI's `--mode` flag so all three entry
    /// points (CLI redact, Redact screen, R-from-Results) behave the same.
    pub redact_mode: RedactMode,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            reveal_secrets: false,
            redact_mode: RedactMode::Mask,
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
// SettingsScreen
// ---------------------------------------------------------------------------

/// Number of items in the General tab. Two today: reveal-secrets toggle
/// and the redact-mode cycle. If you add a row to `render_general` you
/// must bump this constant or the keyboard cursor won't reach it.
const GENERAL_ITEM_COUNT: usize = 2;

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
        if self.active_tab == SettingsTab::General && GENERAL_ITEM_COUNT > 0 {
            self.general_cursor = (self.general_cursor + 1) % GENERAL_ITEM_COUNT;
        }
    }

    pub fn move_up(&mut self) {
        if self.active_tab == SettingsTab::General && GENERAL_ITEM_COUNT > 0 {
            self.general_cursor = if self.general_cursor == 0 {
                GENERAL_ITEM_COUNT - 1
            } else {
                self.general_cursor - 1
            };
        }
    }

    /// Activate the currently-selected General item. Boolean toggles flip;
    /// the redact-mode item cycles through the four `RedactMode` variants
    /// in the order `Mask → Hash → Partial → VaultRef → Mask`.
    pub fn toggle_selected(&mut self) {
        if self.active_tab != SettingsTab::General {
            return;
        }
        match self.general_cursor {
            0 => self.settings.reveal_secrets = !self.settings.reveal_secrets,
            1 => self.settings.redact_mode = cycle_redact_mode(&self.settings.redact_mode),
            _ => {}
        }
    }
}

/// Pure helper so the cycle order is unit-testable without a SettingsScreen.
fn cycle_redact_mode(current: &RedactMode) -> RedactMode {
    match current {
        RedactMode::Mask => RedactMode::Hash,
        RedactMode::Hash => RedactMode::Partial,
        RedactMode::Partial => RedactMode::VaultRef,
        RedactMode::VaultRef => RedactMode::Mask,
    }
}

fn redact_mode_label(mode: &RedactMode) -> &'static str {
    match mode {
        RedactMode::Mask => "Mask",
        RedactMode::Hash => "Hash",
        RedactMode::Partial => "Partial",
        RedactMode::VaultRef => "VaultRef",
    }
}

// ---------------------------------------------------------------------------
// Widget impl
// ---------------------------------------------------------------------------

impl Widget for &mut SettingsScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        buf.set_style(area, Style::default().bg(COLOR_BG));

        if area.height == 0 {
            return;
        }

        let mut row = area.top();

        // Title.
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

        // Tab bar.
        if row < area.bottom() {
            let general_style = if self.active_tab == SettingsTab::General {
                Style::default()
                    .fg(COLOR_FOCUS)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(COLOR_MUTED)
            };
            let rules_style = if self.active_tab == SettingsTab::Rules {
                Style::default()
                    .fg(COLOR_FOCUS)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(COLOR_MUTED)
            };

            let x = area.left() + 2;
            buf.set_string(x, row, "[ General ]", general_style);
            buf.set_string(x + 13, row, "[ Rules ]", rules_style);
            row += 1;
        }

        // Separator.
        if row < area.bottom() {
            let sep = "\u{2500}".repeat(area.width as usize);
            buf.set_string(area.left(), row, &sep, Style::default().fg(COLOR_MUTED));
            row += 1;
        }

        let footer_row = area.bottom().saturating_sub(1);
        let content_bottom = footer_row;

        match self.active_tab {
            SettingsTab::General => {
                render_general(self, area.left(), row, content_bottom, buf);
            }
            SettingsTab::Rules => {
                render_rules(area.left(), row, content_bottom, buf);
            }
        }

        // Footer.
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

fn render_general(screen: &SettingsScreen, left: u16, top: u16, bottom: u16, buf: &mut Buffer) {
    if top >= bottom {
        return;
    }

    // Two items today. Item 0 is a boolean toggle (renders [on]/[off]).
    // Item 1 is the redact-mode cycle (renders [<mode>]). The shared
    // rendering loop draws prefix → label → value → help line below.
    let mut row = top;

    // Item 0 — Reveal secret values
    row = render_general_item(
        buf,
        left,
        row,
        bottom,
        screen.general_cursor == 0,
        "Reveal secret values",
        if screen.settings.reveal_secrets {
            "[on ]"
        } else {
            "[off]"
        },
        if screen.settings.reveal_secrets {
            COLOR_WARN
        } else {
            COLOR_SAFE
        },
        "Shows the literal credential in the finding detail pane. \
         Off by default \u{2014} keep off when sharing your screen.",
    );

    if row >= bottom {
        return;
    }

    // Item 1 — Redaction mode
    let mode_label = redact_mode_label(&screen.settings.redact_mode);
    let _ = render_general_item(
        buf,
        left,
        row,
        bottom,
        screen.general_cursor == 1,
        "Redaction mode",
        &format!("[{mode_label}]"),
        COLOR_FOCUS,
        "Mask = ***, Hash = SHA-256 prefix, Partial = first/last 4 chars, \
         VaultRef = ${VAULT:fp} placeholder.",
    );
}

/// Render one General-tab item: the cursor prefix, label, value pill, and
/// a wrapped help line beneath it. Returns the next row (post help line +
/// blank) so the caller can chain rows without manually tracking offsets.
#[allow(clippy::too_many_arguments)]
fn render_general_item(
    buf: &mut Buffer,
    left: u16,
    top: u16,
    bottom: u16,
    selected: bool,
    label: &str,
    value_str: &str,
    value_color: ratatui::style::Color,
    help: &str,
) -> u16 {
    if top >= bottom {
        return top;
    }
    let prefix = if selected { "\u{25b8} " } else { "  " };
    let prefix_style = Style::default().fg(if selected { COLOR_FOCUS } else { COLOR_FG });

    let value_style = Style::default().fg(value_color);
    let label_style = Style::default().fg(COLOR_FG);
    let x = left + 4;

    buf.set_string(x, top, prefix, prefix_style);
    buf.set_string(x + 2, top, label, label_style);
    buf.set_string(x + 2 + label.len() as u16 + 2, top, value_str, value_style);

    let row = top.saturating_add(1);
    if row >= bottom {
        return row;
    }
    buf.set_string(x + 2, row, help, Style::default().fg(COLOR_MUTED));
    row.saturating_add(2)
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Pressing space on the redact_mode item must cycle through all four
    /// modes in the documented order, then loop back to Mask. This is the
    /// only mechanism the user has to change the mode in the TUI, so the
    /// cycle order is part of the public contract.
    #[test]
    fn space_on_redact_mode_cycles_through_all_four() {
        let mut s = SettingsScreen::new(AppSettings::default());
        // Move cursor to item 1 (redact_mode).
        s.move_down();
        assert_eq!(s.general_cursor, 1);

        assert!(matches!(s.settings.redact_mode, RedactMode::Mask));
        s.toggle_selected();
        assert!(matches!(s.settings.redact_mode, RedactMode::Hash));
        s.toggle_selected();
        assert!(matches!(s.settings.redact_mode, RedactMode::Partial));
        s.toggle_selected();
        assert!(matches!(s.settings.redact_mode, RedactMode::VaultRef));
        s.toggle_selected();
        assert!(
            matches!(s.settings.redact_mode, RedactMode::Mask),
            "must wrap back to Mask after VaultRef"
        );
    }

    /// Pressing space on item 0 still toggles `reveal_secrets`, and does
    /// NOT touch `redact_mode`. (Regression guard: easy to wire up the
    /// new item in a way that fires on both indices.)
    #[test]
    fn space_on_reveal_secrets_only_toggles_that_field() {
        let mut s = SettingsScreen::new(AppSettings::default());
        assert_eq!(s.general_cursor, 0);
        assert!(!s.settings.reveal_secrets);
        let mode_before = s.settings.redact_mode.clone();

        s.toggle_selected();
        assert!(s.settings.reveal_secrets);
        assert_eq!(
            s.settings.redact_mode, mode_before,
            "redact_mode must not change when toggling reveal_secrets"
        );

        s.toggle_selected();
        assert!(!s.settings.reveal_secrets);
        assert_eq!(s.settings.redact_mode, mode_before);
    }

    /// j/k cursor navigation must reach both items (cursor 0 and cursor 1)
    /// and wrap correctly. With only one item the previous code accidentally
    /// no-op'd `move_down`; we want to be sure two items work as expected.
    #[test]
    fn cursor_navigation_reaches_both_items() {
        let mut s = SettingsScreen::new(AppSettings::default());
        assert_eq!(s.general_cursor, 0);
        s.move_down();
        assert_eq!(s.general_cursor, 1);
        s.move_down();
        assert_eq!(s.general_cursor, 0, "wraps back to 0 after 1");
        s.move_up();
        assert_eq!(s.general_cursor, 1, "wraps backward from 0 to 1");
    }

    #[test]
    fn cycle_redact_mode_helper_is_pure() {
        assert!(matches!(
            cycle_redact_mode(&RedactMode::Mask),
            RedactMode::Hash
        ));
        assert!(matches!(
            cycle_redact_mode(&RedactMode::Hash),
            RedactMode::Partial
        ));
        assert!(matches!(
            cycle_redact_mode(&RedactMode::Partial),
            RedactMode::VaultRef
        ));
        assert!(matches!(
            cycle_redact_mode(&RedactMode::VaultRef),
            RedactMode::Mask
        ));
    }

    #[test]
    fn redact_mode_labels_match_user_facing_names() {
        assert_eq!(redact_mode_label(&RedactMode::Mask), "Mask");
        assert_eq!(redact_mode_label(&RedactMode::Hash), "Hash");
        assert_eq!(redact_mode_label(&RedactMode::Partial), "Partial");
        assert_eq!(redact_mode_label(&RedactMode::VaultRef), "VaultRef");
    }
}
