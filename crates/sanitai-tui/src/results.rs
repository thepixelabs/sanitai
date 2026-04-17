use crate::app::ResultsFilter;
use crate::menu::{
    COLOR_BG, COLOR_DANGER, COLOR_FG, COLOR_FOCUS, COLOR_MUTED, COLOR_SAFE, COLOR_WARN,
};
use crate::scan_runner::ScanSummary;
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::Widget,
};
use sanitai_core::finding::Confidence;
use std::path::Path;

// Pale yellow for LOW severity — one step softer than amber.
const COLOR_LOW: Color = Color::Indexed(228);

pub struct ResultsWidget<'a> {
    pub summary: &'a ScanSummary,
    /// Row offset for scrolling: index of the first visible finding.
    pub scroll: usize,
    /// Optional display filter — when `None`, every finding is shown.
    pub filter: Option<&'a ResultsFilter>,
}

impl Widget for &ResultsWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Fill background.
        buf.set_style(area, Style::default().bg(COLOR_BG).fg(COLOR_FG));

        // Build sorted findings view: High first, then Medium, then Low.
        // Within the same confidence level, preserve original order (stable sort).
        // Apply filter (if any) before sorting so counts reflect what's visible.
        let mut sorted: Vec<&sanitai_core::finding::Finding> = if let Some(f) = self.filter {
            self.summary
                .findings
                .iter()
                .filter(|finding| f.matches(finding))
                .collect()
        } else {
            self.summary.findings.iter().collect()
        };
        sorted.sort_by_key(|f| match f.confidence {
            Confidence::High => 0u8,
            Confidence::Medium => 1,
            Confidence::Low => 2,
        });

        // Compute per-severity counts from the *filtered* view so the summary
        // bar and table stay consistent.
        let findings_high = sorted
            .iter()
            .filter(|f| matches!(f.confidence, Confidence::High))
            .count();
        let findings_medium = sorted
            .iter()
            .filter(|f| matches!(f.confidence, Confidence::Medium))
            .count();
        let findings_low = sorted
            .iter()
            .filter(|f| matches!(f.confidence, Confidence::Low))
            .count();
        let total = findings_high + findings_medium + findings_low;
        let filter_active = self
            .filter
            .map(|f| !f.show_all_context || f.min_confidence.is_some())
            .unwrap_or(false);

        // --- Layout: summary bar (1) | table (fill) | keybinds bar (1) ---
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(0),
                Constraint::Length(1),
            ])
            .split(area);

        let summary_area = chunks[0];
        let table_area = chunks[1];
        let keybinds_area = chunks[2];

        render_summary_bar(
            summary_area,
            buf,
            self.summary,
            total,
            findings_high,
            findings_medium,
            findings_low,
            filter_active,
        );
        render_findings_table(table_area, buf, &sorted, self.scroll);
        render_keybinds_bar(keybinds_area, buf);
    }
}

/// Render the single-line summary bar.
#[allow(clippy::too_many_arguments)]
fn render_summary_bar(
    area: Rect,
    buf: &mut Buffer,
    summary: &ScanSummary,
    total: usize,
    findings_high: usize,
    findings_medium: usize,
    findings_low: usize,
    filter_active: bool,
) {
    buf.set_style(area, Style::default().bg(COLOR_BG));

    if total == 0 {
        // Clean path — affirming tone.
        let suffix = if filter_active { " (filtered)" } else { "" };
        let msg = format!(
            "  Clean. {} files scanned in {}ms \u{2014} nothing found.{}",
            summary.total_files, summary.duration_ms, suffix
        );
        buf.set_string(
            area.left(),
            area.top(),
            &msg,
            Style::default().fg(COLOR_SAFE),
        );
        return;
    }

    // Findings path — discovery tone, not alarm.
    // Render segments with per-severity colors.
    let mut x = area.left();
    let y = area.top();
    let right = area.right();

    macro_rules! put {
        ($text:expr, $style:expr) => {{
            let s: &str = $text;
            if x < right {
                let available = (right - x) as usize;
                let clipped = clip_str(s, available);
                buf.set_string(x, y, clipped, $style);
                #[allow(unused_assignments)]
                {
                    x = x.saturating_add(clipped.len() as u16);
                }
            }
        }};
    }

    let prefix = format!("  {} findings:  ", total);
    put!(&prefix, Style::default().fg(COLOR_FG));

    if findings_high > 0 {
        let seg = format!("{} HIGH  ", findings_high);
        put!(
            &seg,
            Style::default()
                .fg(COLOR_DANGER)
                .add_modifier(Modifier::BOLD)
        );
    }

    if findings_medium > 0 {
        let seg = format!("{} MED  ", findings_medium);
        put!(&seg, Style::default().fg(COLOR_WARN));
    }

    if findings_low > 0 {
        let seg = format!("{} LOW  ", findings_low);
        put!(&seg, Style::default().fg(COLOR_LOW));
    }

    let filter_note = if filter_active { "  (filtered)" } else { "" };
    let suffix = format!(
        "\u{00b7}  {} files  \u{00b7}  {}ms{}",
        summary.total_files, summary.duration_ms, filter_note
    );
    put!(&suffix, Style::default().fg(COLOR_FG));
}

/// Render the findings table.
fn render_findings_table(
    area: Rect,
    buf: &mut Buffer,
    findings: &[&sanitai_core::finding::Finding],
    scroll: usize,
) {
    if area.height == 0 {
        return;
    }

    buf.set_style(area, Style::default().bg(COLOR_BG));

    let visible_rows = area.height as usize;
    let start = scroll.min(findings.len().saturating_sub(1));

    // If there are no findings, nothing to render.
    if findings.is_empty() {
        return;
    }

    for (row_idx, finding) in findings.iter().skip(start).take(visible_rows).enumerate() {
        let is_selected = row_idx == 0; // selected = topmost visible (scroll-relative)
        let y = area.top() + row_idx as u16;

        render_finding_row(area, buf, finding, y, is_selected);
    }
}

/// Render one finding row.
///
/// Column layout (all space-separated, left-aligned from column start):
///   [prefix 1] [severity 6] [space 1] [detector 22] [space 1] [filename 24] [space 1] [turn N]
fn render_finding_row(
    area: Rect,
    buf: &mut Buffer,
    finding: &sanitai_core::finding::Finding,
    y: u16,
    is_selected: bool,
) {
    let mut x = area.left();
    let right = area.right();

    macro_rules! put {
        ($text:expr, $style:expr) => {{
            let s: &str = $text;
            if x < right {
                let available = (right - x) as usize;
                let clipped = clip_str(s, available);
                buf.set_string(x, y, clipped, $style);
                #[allow(unused_assignments)]
                {
                    x = x.saturating_add(clipped.len() as u16);
                }
            }
        }};
    }

    // Selection prefix: 1 char + leading space = 2 chars total ("  " or " ▸")
    if is_selected {
        put!(" \u{25b8}", Style::default().fg(COLOR_FOCUS));
    } else {
        put!("  ", Style::default().fg(COLOR_MUTED));
    }

    // Severity badge: 6 chars fixed-width ("  HIGH", "  MED ", "  LOW ")
    let (badge, badge_style) = severity_badge(&finding.confidence);
    put!(badge, badge_style);

    // Column separator
    put!(" ", Style::default().fg(COLOR_FG));

    // Detector name: 22 chars, right-padded, truncated with ellipsis
    let detector = fixed_width(finding.detector_id, 22);
    put!(&detector, Style::default().fg(COLOR_FG));

    put!(" ", Style::default().fg(COLOR_FG));

    // Filename: basename of turn_id.0, 24 chars
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

/// Render the single-line keybinds bar.
fn render_keybinds_bar(area: Rect, buf: &mut Buffer) {
    buf.set_style(area, Style::default().bg(COLOR_BG));
    let hints = "  j/k scroll  \u{00b7}  q back  \u{00b7}  e export markdown";
    buf.set_string(
        area.left(),
        area.top(),
        hints,
        Style::default().fg(COLOR_MUTED),
    );
}

/// Return a fixed-width string of exactly `width` visible chars.
/// If the source is shorter, pad with spaces. If longer, truncate and append `…`.
fn fixed_width(s: &str, width: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= width {
        let mut out = s.to_owned();
        for _ in char_count..width {
            out.push(' ');
        }
        out
    } else {
        // Truncate to width-1 chars then append ellipsis.
        let truncated: String = s.chars().take(width.saturating_sub(1)).collect();
        format!("{}\u{2026}", truncated)
    }
}

/// Clip a string to at most `max_chars` visible characters (no ellipsis, hard clip).
fn clip_str(s: &str, max_chars: usize) -> &str {
    if max_chars == 0 {
        return "";
    }
    // Find the byte offset of the max_chars-th char boundary.
    match s.char_indices().nth(max_chars) {
        Some((byte_idx, _)) => &s[..byte_idx],
        None => s,
    }
}

/// Return the severity badge string (fixed 6 chars) and its style.
fn severity_badge(confidence: &Confidence) -> (&'static str, Style) {
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
