use crate::menu::{
    COLOR_BG, COLOR_DANGER, COLOR_FG, COLOR_FOCUS, COLOR_MUTED, COLOR_SAFE, COLOR_WARN,
};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    widgets::Widget,
};
use sanitai_core::{
    config::RedactMode,
    finding::{Confidence, Finding},
};
use sanitai_redactor::Redactor;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RedactPhase {
    List,
    Confirm,
    Done,
}

pub struct RedactResult {
    pub output_path: PathBuf,
    pub finding_count: usize,
    pub success: bool,
    pub message: String,
}

pub struct RedactScreen {
    pub findings: Vec<Finding>,
    pub selected: usize,
    pub phase: RedactPhase,
    pub last_result: Option<RedactResult>,
}

// ---------------------------------------------------------------------------
// Impl
// ---------------------------------------------------------------------------

impl RedactScreen {
    pub fn new(findings: Vec<Finding>) -> Self {
        Self {
            findings,
            selected: 0,
            phase: RedactPhase::List,
            last_result: None,
        }
    }

    pub fn move_down(&mut self) {
        if !self.findings.is_empty() {
            self.selected = (self.selected + 1).min(self.findings.len() - 1);
        }
    }

    pub fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn begin_confirm(&mut self) {
        self.phase = RedactPhase::Confirm;
    }

    pub fn cancel_confirm(&mut self) {
        self.phase = RedactPhase::List;
    }

    /// Execute the redaction: read the file, apply Redactor::Mask to all
    /// findings from that file, write output to "<original_path>.sanitized".
    pub fn execute_redact(&mut self) {
        if self.findings.is_empty() {
            self.last_result = Some(RedactResult {
                output_path: PathBuf::new(),
                finding_count: 0,
                success: false,
                message: "No findings to redact.".to_string(),
            });
            self.phase = RedactPhase::Done;
            return;
        }

        // Get the file path for the selected finding.
        let file_arc: Arc<PathBuf> = Arc::clone(&self.findings[self.selected].turn_id.0);
        let file_path: &Path = file_arc.as_ref();

        // Collect all findings that reference this same file.
        let file_findings: Vec<Finding> = self
            .findings
            .iter()
            .filter(|f| f.turn_id.0 == file_arc)
            .cloned()
            .collect();

        let finding_count = file_findings.len();

        // Read the source file.
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(e) => {
                self.last_result = Some(RedactResult {
                    output_path: PathBuf::new(),
                    finding_count,
                    success: false,
                    message: format!("Cannot read file: {}", e),
                });
                self.phase = RedactPhase::Done;
                return;
            }
        };

        // Apply Mask redaction.
        let mut redactor = Redactor::new(RedactMode::Mask);
        let redacted = redactor.redact(&content, &file_findings);

        // Write to <original_path>.sanitized.
        let mut out_path = file_path.as_os_str().to_owned();
        out_path.push(".sanitized");
        let out_path = PathBuf::from(out_path);

        let result = match std::fs::write(&out_path, redacted.as_bytes()) {
            Ok(()) => RedactResult {
                output_path: out_path,
                finding_count,
                success: true,
                message: String::new(),
            },
            Err(e) => RedactResult {
                output_path: out_path,
                finding_count,
                success: false,
                message: format!("Cannot write output: {}", e),
            },
        };

        self.last_result = Some(result);
        self.phase = RedactPhase::Done;
    }
}

// ---------------------------------------------------------------------------
// Widget
// ---------------------------------------------------------------------------

impl Widget for &mut RedactScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        buf.set_style(area, Style::default().bg(COLOR_BG).fg(COLOR_FG));

        match self.phase {
            RedactPhase::List => render_list(area, buf, self),
            RedactPhase::Confirm => render_confirm(area, buf, self),
            RedactPhase::Done => render_done(area, buf, self),
        }
    }
}

// ---------------------------------------------------------------------------
// Phase::List
// ---------------------------------------------------------------------------

fn render_list(area: Rect, buf: &mut Buffer, screen: &RedactScreen) {
    if area.height == 0 {
        return;
    }

    // Layout: title (1) | list (fill) | footer (1)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    let title_area = chunks[0];
    let list_area = chunks[1];
    let footer_area = chunks[2];

    // Title
    buf.set_style(title_area, Style::default().bg(COLOR_BG));
    buf.set_string(
        title_area.left(),
        title_area.top(),
        "  Redact \u{2014} select a file to sanitize",
        Style::default()
            .fg(COLOR_FOCUS)
            .add_modifier(Modifier::BOLD),
    );

    // Footer
    buf.set_style(footer_area, Style::default().bg(COLOR_BG));
    buf.set_string(
        footer_area.left(),
        footer_area.top(),
        "  j/k scroll  \u{00b7}  Enter confirm redact  \u{00b7}  q back",
        Style::default().fg(COLOR_MUTED),
    );

    // Empty state
    if screen.findings.is_empty() {
        let msg = "  No findings to redact. Run a scan first.";
        let mid_y = list_area.top() + list_area.height / 2;
        buf.set_string(
            list_area.left(),
            mid_y,
            msg,
            Style::default().fg(COLOR_MUTED),
        );
        return;
    }

    // Build a sorted-by-file view. We want to group by file while preserving
    // the original slice order within each file group.
    // We track which file path was last emitted so we can insert dim separators.
    let visible_rows = list_area.height as usize;
    let mut row: u16 = 0;

    // Collect (file_key, finding_index) pairs, grouped by file.
    // We need the order to match what the user sees: same order as self.findings
    // but with file-group separators injected.
    let mut last_file: Option<Arc<PathBuf>> = None;

    for (idx, finding) in screen.findings.iter().enumerate() {
        if row as usize >= visible_rows {
            break;
        }

        let this_file = Arc::clone(&finding.turn_id.0);

        // Separator when file changes.
        let new_file = last_file.as_ref().is_none_or(|lf| *lf != this_file);
        if new_file {
            if last_file.is_some() {
                // Skip a separator row if we have room.
                if (row as usize) < visible_rows {
                    let y = list_area.top() + row;
                    let basename = this_file
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("?");
                    let sep = format!(
                        "  \u{2500}\u{2500} {} \u{2500}{}",
                        basename,
                        "\u{2500}".repeat(24)
                    );
                    buf.set_string(
                        list_area.left(),
                        y,
                        clip_str(&sep, list_area.width as usize),
                        Style::default().fg(COLOR_MUTED),
                    );
                    row += 1;
                }
            }
            last_file = Some(this_file);
        }

        if row as usize >= visible_rows {
            break;
        }

        let y = list_area.top() + row;
        render_list_row(list_area, buf, finding, idx == screen.selected, y);
        row += 1;
    }
}

#[allow(unused_assignments)]
fn render_list_row(area: Rect, buf: &mut Buffer, finding: &Finding, is_selected: bool, y: u16) {
    let mut x = area.left();
    let right = area.right();

    macro_rules! put {
        ($text:expr, $style:expr) => {{
            let s: &str = $text;
            if x < right {
                let available = (right - x) as usize;
                let clipped = clip_str(s, available);
                buf.set_string(x, y, clipped, $style);
                x = x.saturating_add(clipped.len() as u16);
            }
        }};
    }

    // Selection prefix
    if is_selected {
        put!(" \u{25b8}", Style::default().fg(COLOR_FOCUS));
    } else {
        put!("  ", Style::default().fg(COLOR_MUTED));
    }

    // Severity badge: 6 chars
    let (badge, badge_style) = severity_badge(&finding.confidence);
    put!(badge, badge_style);

    put!(" ", Style::default().fg(COLOR_FG));

    // Detector name: 22 chars
    let detector = fixed_width(finding.detector_id, 22);
    put!(&detector, Style::default().fg(COLOR_FG));

    put!(" ", Style::default().fg(COLOR_FG));

    // Filename: 24 chars
    let filename = {
        let basename = Path::new(finding.turn_id.0.as_ref())
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?");
        fixed_width(basename, 24)
    };
    put!(&filename, Style::default().fg(COLOR_MUTED));

    put!(" ", Style::default().fg(COLOR_FG));

    // Turn index
    let turn_str = format!("turn {}", finding.turn_id.1);
    put!(&turn_str, Style::default().fg(COLOR_MUTED));
}

// ---------------------------------------------------------------------------
// Phase::Confirm
// ---------------------------------------------------------------------------

fn render_confirm(area: Rect, buf: &mut Buffer, screen: &RedactScreen) {
    // Dialog dimensions
    const BOX_W: u16 = 64;
    const BOX_H: u16 = 14;

    if screen.findings.is_empty() {
        return;
    }

    let file_arc = Arc::clone(&screen.findings[screen.selected].turn_id.0);
    let file_findings: Vec<&Finding> = screen
        .findings
        .iter()
        .filter(|f| f.turn_id.0 == file_arc)
        .collect();

    let basename = file_arc.file_name().and_then(|n| n.to_str()).unwrap_or("?");
    let out_name = format!("{}.sanitized", basename);
    let count = file_findings.len();

    // Center the dialog.
    let dialog_x = area
        .left()
        .saturating_add(area.width.saturating_sub(BOX_W) / 2);
    let dialog_y = area
        .top()
        .saturating_add(area.height.saturating_sub(BOX_H) / 2);
    let dialog_w = BOX_W.min(area.width);
    let dialog_h = BOX_H.min(area.height);

    // Fill box background.
    for dy in 0..dialog_h {
        buf.set_style(
            Rect::new(dialog_x, dialog_y + dy, dialog_w, 1),
            Style::default().bg(COLOR_BG),
        );
    }

    // Draw rounded border.
    draw_box(buf, dialog_x, dialog_y, dialog_w, dialog_h);

    // Inner content starts at (dialog_x + 2, dialog_y + 1).
    let ix = dialog_x + 2;
    let inner_w = (dialog_w.saturating_sub(4)) as usize;

    // Row 1: "Redact: <filename>"
    {
        let y = dialog_y + 1;
        buf.set_string(ix, y, "Redact: ", Style::default().fg(COLOR_WARN));
        let fx = ix + 8;
        let available = inner_w.saturating_sub(8);
        buf.set_string(
            fx,
            y,
            clip_str(basename, available),
            Style::default().fg(COLOR_FG).add_modifier(Modifier::BOLD),
        );
    }

    // Row 2: "<N> findings will be replaced with [REDACTED]"
    {
        let y = dialog_y + 2;
        let count_style = if count > 0 {
            Style::default().fg(COLOR_DANGER)
        } else {
            Style::default().fg(COLOR_FG)
        };
        let msg = format!("{} findings will be replaced with [REDACTED]", count);
        buf.set_string(ix, y, clip_str(&msg, inner_w), count_style);
    }

    // Row 3: blank
    // Row 4: "Output: <out_name>"
    {
        let y = dialog_y + 4;
        buf.set_string(ix, y, "Output: ", Style::default().fg(COLOR_FG));
        let fx = ix + 8;
        let available = inner_w.saturating_sub(8);
        buf.set_string(
            fx,
            y,
            clip_str(&out_name, available),
            Style::default().fg(COLOR_SAFE),
        );
    }

    // Row 5: "Original file will NOT be modified."
    {
        let y = dialog_y + 5;
        buf.set_string(
            ix,
            y,
            clip_str("Original file will NOT be modified.", inner_w),
            Style::default()
                .fg(COLOR_MUTED)
                .add_modifier(Modifier::ITALIC),
        );
    }

    // Row 6: blank
    // Row 7: detector list box header "┌─ Detectors ─...┐"
    {
        let y = dialog_y + 7;
        let list_w = inner_w.saturating_sub(2);
        let header_label = " Detectors ";
        let dashes_right = list_w
            .saturating_sub(2) // leading \u{2500} + space
            .saturating_sub(header_label.len());
        let top_border = format!(
            "\u{250c}\u{2500}{}{}\u{2510}",
            header_label,
            "\u{2500}".repeat(dashes_right)
        );
        buf.set_string(
            ix,
            y,
            clip_str(&top_border, inner_w),
            Style::default().fg(COLOR_MUTED),
        );
    }

    // Rows 8..N-1: detector entries (up to 2 shown to fit in box height)
    let list_inner_x = ix + 2;
    let list_inner_w = inner_w.saturating_sub(4);
    for (i, f) in file_findings.iter().take(2).enumerate() {
        let y = dialog_y + 8 + i as u16;
        let entry = format!("{}  (turn {})", f.detector_id, f.turn_id.1);
        buf.set_string(
            list_inner_x,
            y,
            clip_str(&entry, list_inner_w),
            Style::default().fg(COLOR_MUTED),
        );
        // Side borders for the inner list box.
        buf.set_string(ix, y, "\u{2502}", Style::default().fg(COLOR_MUTED));
        let right_border_x = ix + inner_w as u16 - 1;
        if right_border_x < area.right() {
            buf.set_string(
                right_border_x,
                y,
                "\u{2502}",
                Style::default().fg(COLOR_MUTED),
            );
        }
    }

    // Bottom of detector list box
    {
        let y = dialog_y + 10;
        let list_w = inner_w.saturating_sub(2);
        let bottom_border = format!("\u{2514}{}\u{2518}", "\u{2500}".repeat(list_w));
        buf.set_string(
            ix,
            y,
            clip_str(&bottom_border, inner_w),
            Style::default().fg(COLOR_MUTED),
        );
    }

    // Row 12: "[ y  confirm ]    [ n  cancel ]"
    {
        let y = dialog_y + 12;
        let confirm_label = "[ y  confirm ]";
        let cancel_label = "[ n  cancel ]";
        // Lay them out with 4-space gap, centered within inner_w.
        let total = confirm_label.len() + 4 + cancel_label.len();
        let pad = inner_w.saturating_sub(total) / 2;
        let cx = ix + pad as u16;
        buf.set_string(
            cx,
            y,
            confirm_label,
            Style::default().fg(COLOR_SAFE).add_modifier(Modifier::BOLD),
        );
        let nx = cx + confirm_label.len() as u16 + 4;
        buf.set_string(nx, y, cancel_label, Style::default().fg(COLOR_DANGER));
    }
}

/// Draw a rounded-corner box border (╭╮╰╯ ─ │).
fn draw_box(buf: &mut Buffer, x: u16, y: u16, w: u16, h: u16) {
    if w < 2 || h < 2 {
        return;
    }
    let style = Style::default().fg(COLOR_FOCUS);
    let right = x + w - 1;
    let bottom = y + h - 1;

    // Top edge
    buf.set_string(x, y, "\u{256d}", style);
    for dx in 1..(w - 1) {
        buf.set_string(x + dx, y, "\u{2500}", style);
    }
    buf.set_string(right, y, "\u{256e}", style);

    // Bottom edge
    buf.set_string(x, bottom, "\u{2570}", style);
    for dx in 1..(w - 1) {
        buf.set_string(x + dx, bottom, "\u{2500}", style);
    }
    buf.set_string(right, bottom, "\u{256f}", style);

    // Side edges
    for dy in 1..(h - 1) {
        buf.set_string(x, y + dy, "\u{2502}", style);
        buf.set_string(right, y + dy, "\u{2502}", style);
    }
}

// ---------------------------------------------------------------------------
// Phase::Done
// ---------------------------------------------------------------------------

fn render_done(area: Rect, buf: &mut Buffer, screen: &RedactScreen) {
    let Some(ref result) = screen.last_result else {
        return;
    };

    // Center content vertically — use a simple 5-line block.
    let content_h = 5u16;
    let start_y = area
        .top()
        .saturating_add(area.height.saturating_sub(content_h) / 2);

    let ix = area.left() + 4;
    let available_w = area.width.saturating_sub(8) as usize;

    if result.success {
        // Line 1: "Done. Sanitized copy written to:"
        buf.set_string(
            ix,
            start_y,
            clip_str("Done. Sanitized copy written to:", available_w),
            Style::default().fg(COLOR_FG),
        );

        // Line 2: output path
        let path_str = result.output_path.to_string_lossy();
        buf.set_string(
            ix,
            start_y + 1,
            clip_str(&path_str, available_w),
            Style::default().fg(COLOR_SAFE),
        );

        // Line 3: blank
        // Line 4: "N findings replaced."
        let plural = if result.finding_count == 1 { "" } else { "s" };
        let count_msg = format!("{} finding{} replaced.", result.finding_count, plural);
        buf.set_string(
            ix,
            start_y + 3,
            clip_str(&count_msg, available_w),
            Style::default().fg(COLOR_FG),
        );
    } else {
        // Line 1: "Something went wrong:"
        buf.set_string(
            ix,
            start_y,
            clip_str("Something went wrong:", available_w),
            Style::default().fg(COLOR_FG),
        );

        // Line 2: error message
        buf.set_string(
            ix,
            start_y + 1,
            clip_str(&result.message, available_w),
            Style::default().fg(COLOR_DANGER),
        );
    }

    // Footer: "(any key to return)"
    let footer_y = area.bottom().saturating_sub(1);
    buf.set_string(
        area.left(),
        footer_y,
        "  (any key to return)",
        Style::default().fg(COLOR_MUTED),
    );
}

// ---------------------------------------------------------------------------
// Helpers (mirror pattern from results.rs)
// ---------------------------------------------------------------------------

fn severity_badge(confidence: &Confidence) -> (&'static str, Style) {
    const COLOR_LOW: ratatui::style::Color = ratatui::style::Color::Indexed(228);
    match confidence {
        Confidence::High => (
            "  HIGH",
            Style::default()
                .fg(COLOR_DANGER)
                .add_modifier(Modifier::BOLD),
        ),
        Confidence::Medium => ("  MED ", Style::default().fg(COLOR_WARN)),
        Confidence::Low => ("  LOW ", Style::default().fg(COLOR_LOW)),
    }
}

fn fixed_width(s: &str, width: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= width {
        let mut out = s.to_owned();
        for _ in char_count..width {
            out.push(' ');
        }
        out
    } else {
        let truncated: String = s.chars().take(width.saturating_sub(1)).collect();
        format!("{}\u{2026}", truncated)
    }
}

fn clip_str(s: &str, max_chars: usize) -> &str {
    if max_chars == 0 {
        return "";
    }
    match s.char_indices().nth(max_chars) {
        Some((byte_idx, _)) => &s[..byte_idx],
        None => s,
    }
}
