use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    widgets::Widget,
};
use sanitai_store::ScanRecord;

use crate::menu::{
    COLOR_BG, COLOR_DANGER, COLOR_FG, COLOR_FOCUS, COLOR_MUTED, COLOR_WARN,
};

// Low-severity finding color (yellow-ish, distinct from amber warn)
const COLOR_LOW: ratatui::style::Color = ratatui::style::Color::Indexed(228);

// ---------------------------------------------------------------------------
// Timestamp helper — no chrono dependency, pure integer math
// ---------------------------------------------------------------------------

fn format_timestamp(ns: i64) -> String {
    // Convert nanoseconds to whole seconds; clamp negative values to 0
    let secs = (ns / 1_000_000_000).max(0) as u64;
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hh = time_of_day / 3600;
    let mm = (time_of_day % 3600) / 60;

    // Gregorian calendar from days since 1970-01-01
    // Algorithm: http://howardhinnant.github.io/date_algorithms.html
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{:04}-{:02}-{:02} {:02}:{:02}", y, m, d, hh, mm)
}

// ---------------------------------------------------------------------------
// HistoryScreen
// ---------------------------------------------------------------------------

pub struct HistoryScreen {
    pub records: Vec<ScanRecord>,
    /// Index of the topmost visible record in the filtered list.
    pub scroll: usize,
    /// Index of the currently highlighted record in the filtered list.
    pub selected: usize,
    /// Live filter text (empty = no filter active).
    pub filter: String,
    /// `true` while the user is typing a filter string (/ was pressed).
    pub filtering: bool,
}

impl HistoryScreen {
    pub fn new(records: Vec<ScanRecord>) -> Self {
        Self {
            records,
            scroll: 0,
            selected: 0,
            filter: String::new(),
            filtering: false,
        }
    }

    /// Records matching the current filter. If `filter` is empty, all records
    /// are returned. Matching is case-insensitive substring on `scan_id`,
    /// `project_name`, and `claude_account`.
    pub fn filtered_records(&self) -> Vec<&ScanRecord> {
        if self.filter.is_empty() {
            return self.records.iter().collect();
        }
        let needle = self.filter.to_lowercase();
        self.records
            .iter()
            .filter(|r| {
                r.scan_id.to_lowercase().contains(&needle)
                    || r.project_name
                        .as_deref()
                        .map(|p| p.to_lowercase().contains(&needle))
                        .unwrap_or(false)
                    || r.claude_account
                        .as_deref()
                        .map(|a| a.to_lowercase().contains(&needle))
                        .unwrap_or(false)
            })
            .collect()
    }

    pub fn move_down(&mut self) {
        let len = self.filtered_records().len();
        if len == 0 {
            return;
        }
        if self.selected + 1 < len {
            self.selected += 1;
        }
    }

    pub fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    /// Enter filter input mode. Clears any previous filter text.
    pub fn start_filter(&mut self) {
        self.filtering = true;
        self.filter.clear();
        // Reset selection so it stays coherent with a brand-new filter.
        self.selected = 0;
        self.scroll = 0;
    }

    /// Append a character to the live filter (call when `filtering == true`).
    pub fn push_filter_char(&mut self, c: char) {
        self.filter.push(c);
        // Keep selection in-bounds after the filter narrows the list.
        let len = self.filtered_records().len();
        if len == 0 {
            self.selected = 0;
            self.scroll = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    /// Remove the last character from the live filter.
    pub fn pop_filter_char(&mut self) {
        self.filter.pop();
        // Re-clamp selection after the filter potentially widens the list.
        let len = self.filtered_records().len();
        if len == 0 {
            self.selected = 0;
            self.scroll = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    /// Commit or cancel filter input (Enter or Esc).
    pub fn end_filter(&mut self) {
        self.filtering = false;
    }
}

// ---------------------------------------------------------------------------
// Widget implementation
// ---------------------------------------------------------------------------

impl Widget for &mut HistoryScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Paint background.
        buf.set_style(area, Style::default().bg(COLOR_BG).fg(COLOR_FG));

        if area.height < 3 {
            // Absolute minimum: title only.
            buf.set_string(
                area.left(),
                area.top(),
                "  History",
                Style::default()
                    .fg(COLOR_FOCUS)
                    .add_modifier(Modifier::BOLD),
            );
            return;
        }

        // Split into title | filter-bar | body | status.
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // title bar
                Constraint::Length(1), // filter / hint bar
                Constraint::Min(1),    // records list
                Constraint::Length(1), // status bar
            ])
            .split(area);

        let title_area = chunks[0];
        let filter_area = chunks[1];
        let list_area = chunks[2];
        let status_area = chunks[3];

        render_title(title_area, buf, self.records.len());
        render_filter_bar(filter_area, buf, &self.filter, self.filtering);
        render_list(list_area, buf, self);
        render_status(status_area, buf, self);
    }
}

// ---------------------------------------------------------------------------
// Sub-renderers
// ---------------------------------------------------------------------------

fn render_title(area: Rect, buf: &mut Buffer, total: usize) {
    let title = "  History";
    buf.set_string(
        area.left(),
        area.top(),
        title,
        Style::default()
            .fg(COLOR_FOCUS)
            .add_modifier(Modifier::BOLD),
    );

    // Right-align the count.
    let count_str = format!("{} scans  ", total);
    let count_x = area
        .right()
        .saturating_sub(count_str.len() as u16);
    if count_x > area.left().saturating_add(title.len() as u16) {
        buf.set_string(
            count_x,
            area.top(),
            &count_str,
            Style::default().fg(COLOR_MUTED),
        );
    }
}

fn render_filter_bar(area: Rect, buf: &mut Buffer, filter: &str, filtering: bool) {
    if filtering {
        let text = format!("  Filter: [{}_]", filter);
        buf.set_string(area.left(), area.top(), &text, Style::default().fg(COLOR_FG));
    } else {
        let hints = "  / filter  \u{00b7}  j/k scroll  \u{00b7}  Enter select  \u{00b7}  q back";
        buf.set_string(
            area.left(),
            area.top(),
            hints,
            Style::default().fg(COLOR_MUTED),
        );
    }
}

fn render_list(area: Rect, buf: &mut Buffer, screen: &mut HistoryScreen) {
    // Collect into owned vec so we can mutate screen.scroll while still using the data.
    let filtered: Vec<ScanRecord> = screen.filtered_records().into_iter().cloned().collect();

    // --- Empty states ---
    if filtered.is_empty() {
        if screen.filter.is_empty() {
            // True first-run: no scans ever.
            render_empty_onboarding(area, buf);
        } else {
            // Filter matched nothing.
            buf.set_string(
                area.left().saturating_add(2),
                area.top().saturating_add(1),
                "  No matching scans.",
                Style::default().fg(COLOR_MUTED),
            );
        }
        return;
    }

    // Keep scroll so selected row stays visible.
    let visible_rows = area.height as usize;
    if screen.selected < screen.scroll {
        screen.scroll = screen.selected;
    } else if screen.selected >= screen.scroll + visible_rows {
        screen.scroll = screen.selected + 1 - visible_rows;
    }

    let start = screen.scroll;
    let end = (start + visible_rows).min(filtered.len());

    for (row_idx, rec) in filtered[start..end].iter().enumerate() {
        let abs_idx = start + row_idx;
        let y = area.top() + row_idx as u16;
        if y >= area.bottom() {
            break;
        }
        let is_selected = abs_idx == screen.selected;
        render_row(area, buf, rec, y, is_selected);
    }
}

fn render_row(area: Rect, buf: &mut Buffer, rec: &ScanRecord, y: u16, selected: bool) {
    // Highlight the whole row when selected.
    if selected {
        buf.set_style(
            Rect { x: area.left(), y, width: area.width, height: 1 },
            Style::default().bg(ratatui::style::Color::Indexed(235)),
        );
    }

    let arrow = if selected { "\u{25b8}" } else { " " }; // ▸ or space
    let arrow_style = if selected {
        Style::default().fg(COLOR_FOCUS)
    } else {
        Style::default().fg(COLOR_MUTED)
    };

    let mut x = area.left().saturating_add(2);

    // Arrow
    buf.set_string(x, y, arrow, arrow_style);
    x += 2;

    // Date  "YYYY-MM-DD HH:MM"
    let date = format_timestamp(rec.started_at_ns);
    buf.set_string(x, y, &date, Style::default().fg(COLOR_FG));
    x += date.len() as u16 + 2;

    // Files
    let files_str = if rec.total_files == 1 {
        "1 file ".to_owned()
    } else {
        format!("{} files", rec.total_files)
    };
    buf.set_string(x, y, &files_str, Style::default().fg(COLOR_FG));
    x += files_str.len() as u16 + 2;

    // Findings "2H 0M 1L"
    x = render_findings(buf, rec, x, y);
    x += 2;

    // Duration
    let dur_str = format!("{}ms", rec.duration_ms);
    buf.set_string(x, y, &dur_str, Style::default().fg(COLOR_MUTED));
    x += dur_str.len() as u16 + 2;

    // Project name (or em-dash placeholder)
    let project = rec.project_name.as_deref().unwrap_or("\u{2014}");
    if x < area.right() {
        buf.set_string(x, y, project, Style::default().fg(COLOR_MUTED));
    }
}

/// Renders the "2H 0M 1L" findings segment starting at `x`, returns new `x`.
fn render_findings(buf: &mut Buffer, rec: &ScanRecord, mut x: u16, y: u16) -> u16 {
    // HIGH
    let h_str = format!("{}H ", rec.findings_high);
    let h_style = if rec.findings_high > 0 {
        Style::default().fg(COLOR_DANGER)
    } else {
        Style::default().fg(COLOR_MUTED)
    };
    buf.set_string(x, y, &h_str, h_style);
    x += h_str.len() as u16;

    // MEDIUM
    let m_str = format!("{}M ", rec.findings_medium);
    let m_style = if rec.findings_medium > 0 {
        Style::default().fg(COLOR_WARN)
    } else {
        Style::default().fg(COLOR_MUTED)
    };
    buf.set_string(x, y, &m_str, m_style);
    x += m_str.len() as u16;

    // LOW
    let l_str = format!("{}L", rec.findings_low);
    let l_style = if rec.findings_low > 0 {
        Style::default().fg(COLOR_LOW)
    } else {
        Style::default().fg(COLOR_MUTED)
    };
    buf.set_string(x, y, &l_str, l_style);
    x += l_str.len() as u16;

    x
}

fn render_empty_onboarding(area: Rect, buf: &mut Buffer) {
    // Vertically center the onboarding block (7 lines of content).
    let content_height = 7u16;
    let top_pad = area.height.saturating_sub(content_height) / 2;
    let mut y = area.top().saturating_add(top_pad);

    let left = area.left().saturating_add(4);

    let fg = Style::default().fg(COLOR_FG);
    let muted = Style::default().fg(COLOR_MUTED);

    buf.set_string(left, y, "No scans yet.", fg);
    y += 2; // blank line

    buf.set_string(
        left,
        y,
        "Press q to go back, then Scan to run your first scan.",
        fg,
    );
    y += 2; // blank line

    buf.set_string(left, y, "Where to find your exports:", muted);
    y += 1;

    buf.set_string(
        left.saturating_add(2),
        y,
        "Claude  \u{2014} claude.ai \u{2192} Settings \u{2192} Export Data",
        muted,
    );
    y += 1;

    buf.set_string(
        left.saturating_add(2),
        y,
        "ChatGPT \u{2014} chat.openai.com \u{2192} Settings \u{2192} Export Data",
        muted,
    );
}

fn render_status(area: Rect, buf: &mut Buffer, screen: &HistoryScreen) {
    let filtered = screen.filtered_records();
    if filtered.is_empty() {
        return;
    }
    let Some(rec) = filtered.get(screen.selected) else {
        return;
    };

    let total = rec.findings_high + rec.findings_medium + rec.findings_low;
    let status = if total == 0 {
        format!(
            "  {} \u{00b7} clean \u{00b7} {} files \u{00b7} {}ms",
            rec.scan_id, rec.total_files, rec.duration_ms
        )
    } else {
        format!(
            "  {} \u{00b7} {}H {}M {}L \u{00b7} {} files \u{00b7} {}ms",
            rec.scan_id,
            rec.findings_high,
            rec.findings_medium,
            rec.findings_low,
            rec.total_files,
            rec.duration_ms,
        )
    };

    // Truncate to fit.
    let max_chars = area.width as usize;
    let display = if status.len() > max_chars {
        &status[..max_chars]
    } else {
        &status
    };

    buf.set_string(
        area.left(),
        area.top(),
        display,
        Style::default().fg(COLOR_MUTED),
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(id: &str, project: Option<&str>, h: i64, m: i64, l: i64) -> ScanRecord {
        ScanRecord {
            scan_id: id.to_owned(),
            started_at_ns: 1_775_917_380_000_000_000, // 2026-04-11 14:23:00 UTC
            duration_ms: 123,
            project_name: project.map(ToOwned::to_owned),
            claude_account: None,
            total_files: 3,
            total_turns: 10,
            format: "tui".to_owned(),
            exit_code: 0,
            findings_high: h,
            findings_medium: m,
            findings_low: l,
        }
    }

    #[test]
    fn test_format_timestamp_known_value() {
        // 2026-04-11 14:23:00 UTC
        let ns: i64 = 1_775_917_380_000_000_000;
        let result = format_timestamp(ns);
        assert_eq!(result, "2026-04-11 14:23");
    }

    #[test]
    fn test_format_timestamp_epoch() {
        let result = format_timestamp(0);
        assert_eq!(result, "1970-01-01 00:00");
    }

    #[test]
    fn test_filter_empty_returns_all() {
        let screen = HistoryScreen::new(vec![
            make_record("abc", Some("proj-a"), 1, 0, 0),
            make_record("def", Some("proj-b"), 0, 0, 0),
        ]);
        assert_eq!(screen.filtered_records().len(), 2);
    }

    #[test]
    fn test_filter_by_scan_id() {
        let mut screen = HistoryScreen::new(vec![
            make_record("abc123", Some("proj"), 0, 0, 0),
            make_record("xyz999", None, 0, 0, 0),
        ]);
        screen.filter = "abc".to_owned();
        let filtered = screen.filtered_records();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].scan_id, "abc123");
    }

    #[test]
    fn test_filter_by_project_case_insensitive() {
        let mut screen = HistoryScreen::new(vec![
            make_record("id1", Some("MyProject"), 0, 0, 0),
            make_record("id2", Some("other"), 0, 0, 0),
        ]);
        screen.filter = "myproject".to_owned();
        assert_eq!(screen.filtered_records().len(), 1);
    }

    #[test]
    fn test_move_down_clamps() {
        let mut screen = HistoryScreen::new(vec![
            make_record("a", None, 0, 0, 0),
            make_record("b", None, 0, 0, 0),
        ]);
        screen.move_down();
        assert_eq!(screen.selected, 1);
        screen.move_down(); // should clamp at 1
        assert_eq!(screen.selected, 1);
    }

    #[test]
    fn test_move_up_clamps_at_zero() {
        let mut screen = HistoryScreen::new(vec![make_record("a", None, 0, 0, 0)]);
        screen.move_up();
        assert_eq!(screen.selected, 0);
    }

    #[test]
    fn test_push_and_pop_filter_char() {
        let mut screen = HistoryScreen::new(vec![make_record("abc", None, 0, 0, 0)]);
        screen.start_filter();
        screen.push_filter_char('a');
        screen.push_filter_char('b');
        assert_eq!(screen.filter, "ab");
        screen.pop_filter_char();
        assert_eq!(screen.filter, "a");
    }

    #[test]
    fn test_end_filter_clears_mode() {
        let mut screen = HistoryScreen::new(vec![]);
        screen.start_filter();
        assert!(screen.filtering);
        screen.end_filter();
        assert!(!screen.filtering);
    }
}
