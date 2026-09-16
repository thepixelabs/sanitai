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
    Ignore,
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
    /// `policy.ignore_patterns` as currently persisted (mirrors the config
    /// file; App keeps its own copy for the scan runner).
    pub ignore_patterns: Vec<String>,
    pub ignore_cursor: usize,
    /// `Some` while the user is typing a new pattern on the Ignore tab.
    pub ignore_input: Option<String>,
    /// One-line status under the list ("saved to …", "invalid pattern …").
    pub ignore_status: String,
}

impl SettingsScreen {
    pub fn new(settings: AppSettings) -> Self {
        Self::with_ignore_patterns(settings, Vec::new())
    }

    pub fn with_ignore_patterns(settings: AppSettings, ignore_patterns: Vec<String>) -> Self {
        Self {
            settings,
            active_tab: SettingsTab::General,
            general_cursor: 0,
            ignore_patterns,
            ignore_cursor: 0,
            ignore_input: None,
            ignore_status: String::new(),
        }
    }

    // ----- Ignore tab -----------------------------------------------------

    pub fn is_typing(&self) -> bool {
        self.ignore_input.is_some()
    }

    pub fn begin_ignore_input(&mut self) {
        self.ignore_input = Some(String::new());
        self.ignore_status =
            "Type a glob or a path fragment, Enter to save, Esc to cancel".to_owned();
    }

    pub fn push_ignore_char(&mut self, c: char) {
        if let Some(buf) = self.ignore_input.as_mut() {
            buf.push(c);
        }
    }

    pub fn pop_ignore_char(&mut self) {
        if let Some(buf) = self.ignore_input.as_mut() {
            buf.pop();
        }
    }

    pub fn cancel_ignore_input(&mut self) {
        self.ignore_input = None;
        self.ignore_status.clear();
    }

    /// Persist the typed pattern. Returns the pattern when one was added so
    /// the caller can update its own copy.
    pub fn commit_ignore_input(&mut self) -> Option<String> {
        let pattern = self.ignore_input.take()?.trim().to_owned();
        if pattern.is_empty() {
            self.ignore_status.clear();
            return None;
        }
        match sanitai_core::config::add_ignore_pattern(&pattern) {
            Ok((path, true)) => {
                self.ignore_patterns.push(pattern.clone());
                self.ignore_cursor = self.ignore_patterns.len().saturating_sub(1);
                self.ignore_status = format!("Saved to {}", path.display());
                Some(pattern)
            }
            Ok((_, false)) => {
                self.ignore_status = "Already in the list".to_owned();
                None
            }
            Err(e) => {
                self.ignore_status = format!("Not saved: {e}");
                None
            }
        }
    }

    /// Remove the selected pattern from the config. Returns it on success.
    pub fn remove_selected_ignore(&mut self) -> Option<String> {
        let pattern = self.ignore_patterns.get(self.ignore_cursor)?.clone();
        match sanitai_core::config::remove_ignore_pattern(&pattern) {
            Ok((path, _)) => {
                self.ignore_patterns.remove(self.ignore_cursor);
                if self.ignore_cursor >= self.ignore_patterns.len() {
                    self.ignore_cursor = self.ignore_patterns.len().saturating_sub(1);
                }
                self.ignore_status = format!("Removed; saved to {}", path.display());
                Some(pattern)
            }
            Err(e) => {
                self.ignore_status = format!("Not removed: {e}");
                None
            }
        }
    }

    pub fn next_tab(&mut self) {
        self.active_tab = match self.active_tab {
            SettingsTab::General => SettingsTab::Rules,
            SettingsTab::Rules => SettingsTab::Ignore,
            SettingsTab::Ignore => SettingsTab::General,
        };
    }

    pub fn move_down(&mut self) {
        if self.active_tab == SettingsTab::Ignore {
            if self.ignore_cursor + 1 < self.ignore_patterns.len() {
                self.ignore_cursor += 1;
            }
            return;
        }
        if self.active_tab == SettingsTab::General && GENERAL_ITEM_COUNT > 0 {
            self.general_cursor = (self.general_cursor + 1) % GENERAL_ITEM_COUNT;
        }
    }

    pub fn move_up(&mut self) {
        if self.active_tab == SettingsTab::Ignore {
            self.ignore_cursor = self.ignore_cursor.saturating_sub(1);
            return;
        }
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

            let ignore_style = if self.active_tab == SettingsTab::Ignore {
                Style::default()
                    .fg(COLOR_FOCUS)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(COLOR_MUTED)
            };

            let x = area.left() + 2;
            buf.set_string(x, row, "[ General ]", general_style);
            buf.set_string(x + 13, row, "[ Rules ]", rules_style);
            buf.set_string(x + 24, row, "[ Ignore ]", ignore_style);
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
            SettingsTab::Ignore => {
                render_ignore(self, area, row, content_bottom, buf);
            }
        }

        // Footer.
        if footer_row >= area.top() && footer_row < area.bottom() {
            let hints = match (self.active_tab, self.is_typing()) {
                (SettingsTab::Ignore, true) => "  Enter save  \u{00b7}  Esc cancel",
                (SettingsTab::Ignore, false) => {
                    "  Tab switch tabs  \u{00b7}  j/k navigate  \u{00b7}  a add  \u{00b7}  d delete  \u{00b7}  q back"
                }
                _ => "  Tab switch tabs  \u{00b7}  j/k navigate  \u{00b7}  Space toggle  \u{00b7}  q back",
            };
            buf.set_string(
                area.left(),
                footer_row,
                hints,
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

/// The Ignore tab: the persisted `policy.ignore_patterns`, a cursor, and an
/// optional input line while adding.
fn render_ignore(screen: &SettingsScreen, area: Rect, top: u16, bottom: u16, buf: &mut Buffer) {
    let left = area.left();
    let width = area.width as usize;
    let mut row = top;
    let put = |buf: &mut Buffer, row: u16, text: &str, style: Style| {
        let clipped: String = text.chars().take(width).collect();
        buf.set_string(left, row, clipped, style);
    };
    if row >= bottom {
        return;
    }
    let config_path = sanitai_core::config::global_config_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(config path unavailable)".to_owned());
    put(
        buf,
        row,
        &format!("  Files matching these patterns are skipped. Stored in {config_path}"),
        Style::default().fg(COLOR_MUTED),
    );
    row += 1;
    if row < bottom {
        put(
            buf,
            row,
            "  `*` matches across `/`; a pattern without wildcards matches any path containing it.",
            Style::default().fg(COLOR_MUTED),
        );
        row += 1;
    }
    if row < bottom {
        row += 1; // spacer
    }
    if screen.ignore_patterns.is_empty() && screen.ignore_input.is_none() && row < bottom {
        put(
            buf,
            row,
            "  (no ignore patterns yet \u{2014} press a to add one, or i on a result)",
            Style::default().fg(COLOR_MUTED),
        );
        row += 1;
    }
    for (idx, pattern) in screen.ignore_patterns.iter().enumerate() {
        if row >= bottom {
            break;
        }
        let selected = idx == screen.ignore_cursor && !screen.is_typing();
        let prefix = if selected { " \u{25b8} " } else { "   " };
        let style = if selected {
            Style::default()
                .fg(COLOR_FOCUS)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(COLOR_FG)
        };
        put(buf, row, &format!("{prefix}{pattern}"), style);
        row += 1;
    }
    if let Some(input) = &screen.ignore_input {
        if row < bottom {
            put(
                buf,
                row,
                &format!(" + {input}\u{2588}"),
                Style::default().fg(COLOR_WARN).add_modifier(Modifier::BOLD),
            );
            row += 1;
        }
    }
    if !screen.ignore_status.is_empty() && row + 1 < bottom {
        row += 1;
        put(
            buf,
            row,
            &format!("  {}", screen.ignore_status),
            Style::default().fg(COLOR_SAFE),
        );
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
