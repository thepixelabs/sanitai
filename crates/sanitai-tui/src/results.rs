use crate::app::ResultsFilter;
use crate::menu::{
    COLOR_BG, COLOR_DANGER, COLOR_FG, COLOR_FOCUS, COLOR_MUTED, COLOR_SAFE, COLOR_WARN,
};
use crate::scan_runner::ScanSummary;
use crate::suppressions::Suppressions;
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::Widget,
};
use sanitai_core::finding::{Confidence, ContextClass};
use sanitai_core::turn::Role;
use std::path::Path;

// Pale yellow for LOW severity — one step softer than amber.
const COLOR_LOW: Color = Color::Indexed(228);

pub struct ResultsWidget<'a> {
    pub summary: &'a ScanSummary,
    /// Selected row index (always; no separate "scroll" concept — we let the
    /// renderer compute viewport offset from a single integer).
    pub scroll: usize,
    /// Optional display filter — when `None`, every finding is shown.
    pub filter: Option<&'a ResultsFilter>,
    /// On-disk suppression set, for strikethrough rendering and `[suppressed]`
    /// tags. Lookups are by 8-char fingerprint hex.
    pub suppressions: &'a Suppressions,
    /// When true, devote the bottom 1/3 of the body to a detail pane for the
    /// currently-selected finding.
    pub detail_open: bool,
    /// When true, the detail pane includes a `Match` row with the literal
    /// credential value (`Finding.matched_raw`). Off by default; user opts in
    /// via Settings → "Reveal secret values".
    pub reveal_secrets: bool,
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

        // --- Layout: summary bar (1) | body (fill) | keybinds bar (1) ---
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(0),
                Constraint::Length(1),
            ])
            .split(area);

        let summary_area = chunks[0];
        let body_area = chunks[1];
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

        // Body splits into table (top 2/3) and detail pane (bottom 1/3) when
        // the user has opened a row. With no detail pane the table fills the
        // body.
        if self.detail_open && !sorted.is_empty() {
            // Reserve a third of the body for the detail pane (min 8 rows so
            // every finding field is visible).
            let pane_height = (body_area.height / 3).max(8).min(body_area.height);
            let table_height = body_area.height.saturating_sub(pane_height);
            let table_area = Rect {
                x: body_area.x,
                y: body_area.y,
                width: body_area.width,
                height: table_height,
            };
            let detail_area = Rect {
                x: body_area.x,
                y: body_area.y.saturating_add(table_height),
                width: body_area.width,
                height: pane_height,
            };
            render_findings_table(table_area, buf, &sorted, self.scroll, self.suppressions);
            let selected = sorted.get(self.scroll).copied();
            if let Some(finding) = selected {
                render_detail_pane(
                    detail_area,
                    buf,
                    finding,
                    self.suppressions,
                    self.reveal_secrets,
                );
            }
        } else {
            render_findings_table(body_area, buf, &sorted, self.scroll, self.suppressions);
        }
        render_keybinds_bar(keybinds_area, buf, self.detail_open);
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
    selected: usize,
    suppressions: &Suppressions,
) {
    if area.height == 0 {
        return;
    }

    buf.set_style(area, Style::default().bg(COLOR_BG));

    // Compute viewport offset so that the selected row stays inside the
    // visible region. Old behaviour treated `scroll` as the top row; we
    // now treat it as the cursor and derive the offset on every render.
    let visible_rows = area.height as usize;
    if findings.is_empty() {
        return;
    }
    let max_idx = findings.len().saturating_sub(1);
    let cursor = selected.min(max_idx);
    let offset = cursor.saturating_sub(visible_rows.saturating_sub(1));

    for (row_idx, finding) in findings.iter().skip(offset).take(visible_rows).enumerate() {
        let absolute_idx = offset + row_idx;
        let is_selected = absolute_idx == cursor;
        let y = area.top() + row_idx as u16;
        render_finding_row(area, buf, finding, y, is_selected, suppressions);
    }
}

/// Render one finding row.
///
/// Column layout (space-separated):
///   [prefix 2] [severity 6] [space] [role 4] [space] [fingerprint 10]
///     [space] [ctx 11] [space] [detector 28] [space] [filename 24]
///     [space] [location] [space] [optional [suppressed] tag]
///
/// `location` is `Lnnn` when the parser attached a line number to the
/// finding, else `msg N` where N is the 0-based message index inside the
/// file. We never render both — line is preferred because the user can
/// jump straight to it.
fn render_finding_row(
    area: Rect,
    buf: &mut Buffer,
    finding: &sanitai_core::finding::Finding,
    y: u16,
    is_selected: bool,
    suppressions: &Suppressions,
) {
    let mut x = area.left();
    let right = area.right();

    let suppressed = suppressions.is_suppressed(&finding.fingerprint_hex());
    let dimmed = is_dimmed_context(&finding.context_class);

    // The base style for non-severity columns. When the finding's context
    // class is one of the noisy categories (Educational, DocQuote,
    // Hallucination), or when the finding is suppressed, the whole row
    // dims so the user's eye lands on RealPaste rows first.
    let base_style = if suppressed {
        Style::default()
            .fg(COLOR_MUTED)
            .add_modifier(Modifier::CROSSED_OUT)
    } else if dimmed {
        Style::default().fg(COLOR_MUTED)
    } else {
        Style::default().fg(COLOR_FG)
    };

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

    // Severity badge: 6 chars fixed-width ("  HIGH", "  MED ", "  LOW ").
    // When the row is dimmed (or suppressed), the badge dims with it so the
    // colour gradient stays consistent.
    let (badge, badge_style) = if dimmed || suppressed {
        let muted = if suppressed {
            Style::default()
                .fg(COLOR_MUTED)
                .add_modifier(Modifier::CROSSED_OUT)
        } else {
            Style::default().fg(COLOR_MUTED)
        };
        (severity_text(&finding.confidence), muted)
    } else {
        severity_badge(&finding.confidence)
    };
    put!(badge, badge_style);

    // Column separator
    put!(" ", base_style);

    // Role: 4-char fixed width ("user", "asst", "sys ", "tool", "—   ").
    put!(&fixed_width(role_label(&finding.role), 4), base_style);
    put!(" ", base_style);

    // Fingerprint in brackets — always rendered.
    let fp = format!("[{}]", finding.fingerprint_hex());
    put!(&fp, base_style);
    put!(" ", base_style);

    // Context class — 11 chars wide ("DocQuote   ", "Educational", etc).
    let (ctx_text, ctx_style) =
        context_class_label(&finding.context_class, base_style, dimmed, suppressed);
    put!(&fixed_width(ctx_text, 11), ctx_style);
    put!(" ", base_style);

    // Detector name: 28 chars, right-padded, truncated with ellipsis. Use
    // the human-readable display name; fall back to the canonical id only
    // when the detector has been removed (stale finding).
    let detector_label = {
        let pretty = sanitai_detectors::display_name_for(finding.detector_id);
        if pretty.is_empty() {
            finding.detector_id
        } else {
            pretty
        }
    };
    let detector = fixed_width(detector_label, 28);
    put!(&detector, base_style);
    put!(" ", base_style);

    // Filename: basename of turn_id.0, 24 chars
    let filename = {
        let basename = Path::new(finding.turn_id.0.as_ref())
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?");
        fixed_width(basename, 24)
    };
    let muted_style = if suppressed {
        Style::default()
            .fg(COLOR_MUTED)
            .add_modifier(Modifier::CROSSED_OUT)
    } else {
        Style::default().fg(COLOR_MUTED)
    };
    put!(&filename, muted_style);
    put!(" ", base_style);

    // Location: `Lnnn` if the parser produced a source line, otherwise
    // `msg N` (the old "turn N" column relabeled — `turn` was confusing
    // against an LLM "turn"; "msg" reads cleaner when no line exists).
    let location_str = location_label(finding);
    put!(&location_str, muted_style);

    // Suppression tag — appended at the end so users see it without scanning
    // every column. We render it even though the row is already
    // strikethrough so it survives terminals that drop CROSSED_OUT.
    if suppressed {
        put!(" ", base_style);
        put!(
            "[suppressed]",
            Style::default()
                .fg(COLOR_MUTED)
                .add_modifier(Modifier::ITALIC)
        );
    }
}

/// Render the bottom-pane detail view for the selected finding. By default
/// `matched_raw` (the secret value) is hidden; if `reveal_secrets` is true
/// (set via Settings → "Reveal secret values") a `Match` row shows the
/// literal value. The setting is opt-in and off by default.
fn render_detail_pane(
    area: Rect,
    buf: &mut Buffer,
    finding: &sanitai_core::finding::Finding,
    suppressions: &Suppressions,
    reveal_secrets: bool,
) {
    if area.height == 0 {
        return;
    }
    buf.set_style(area, Style::default().bg(COLOR_BG));

    // Top separator line — visually demarcates the pane from the table.
    let sep_y = area.top();
    let sep = "\u{2500}".repeat(area.width as usize);
    buf.set_string(area.left(), sep_y, &sep, Style::default().fg(COLOR_MUTED));

    let left = area.left().saturating_add(2);
    let mut y = area.top().saturating_add(1);
    let bottom = area.bottom();

    let suppressed = suppressions.is_suppressed(&finding.fingerprint_hex());
    let title = if suppressed {
        "  Detail (suppressed)"
    } else {
        "  Detail"
    };
    buf.set_string(
        left,
        y,
        title,
        Style::default()
            .fg(COLOR_FOCUS)
            .add_modifier(Modifier::BOLD),
    );
    y = y.saturating_add(1);

    // Each field is one row. We bail out early if we run out of vertical
    // space rather than wrap — the pane height is sized to fit the standard
    // field set on any reasonable terminal.
    let confidence_text = match finding.confidence {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    };
    let role_text = role_label(&finding.role);
    let context_text = context_class_full(&finding.context_class);
    let transform_chain = if finding.transform.is_empty() {
        "(none)".to_owned()
    } else {
        finding
            .transform
            .0
            .iter()
            .map(|t| format!("{t:?}").to_lowercase())
            .collect::<Vec<_>>()
            .join(" \u{2192} ")
    };
    let span_kind_text = match &finding.span_kind {
        sanitai_core::finding::SpanKind::Single => "single".to_owned(),
        sanitai_core::finding::SpanKind::CrossTurn { contributing_turns } => {
            format!("cross-turn ({:?})", contributing_turns)
        }
    };

    // Detector field: pretty label + canonical id in parentheses so the
    // user sees both the human name they expect and the stable id used in
    // JSON / SARIF / suppressions.
    let detector_field = {
        let pretty = sanitai_detectors::display_name_for(finding.detector_id);
        if pretty.is_empty() {
            finding.detector_id.to_owned()
        } else {
            format!("{pretty}  ({})", finding.detector_id)
        }
    };
    // Location: prefer the source line (`Lnnn`) over the message index when
    // the parser supplied one; otherwise show both so the detail still
    // contains the message index for tree-structured exports.
    let location_field = match finding.line_in_file {
        Some(n) => format!("L{n}  (msg {})", finding.turn_id.1),
        None => format!("msg {}", finding.turn_id.1),
    };
    let excerpt_field = if finding.excerpt.is_empty() {
        "(unavailable)".to_owned()
    } else {
        finding.excerpt.clone()
    };

    // Match row text: three states.
    //   * reveal off                      → "[hidden — toggle ...]"
    //   * reveal on,  matched_raw present → the literal value
    //   * reveal on,  matched_raw empty   → historical-scan marker; we never
    //     persist secret values to disk, so a row reloaded from History has
    //     no `matched_raw` to reveal even when the setting is on.
    let match_field = if reveal_secrets {
        if finding.matched_raw.is_empty() {
            "[not stored \u{2014} historical scan]".to_owned()
        } else {
            finding.matched_raw.clone()
        }
    } else {
        "[hidden \u{2014} toggle 'Reveal secret values' in Settings]".to_owned()
    };

    let lines: Vec<(&str, String)> = vec![
        ("Detector", detector_field),
        ("File", finding.turn_id.0.display().to_string()),
        ("Location", location_field),
        ("Match", match_field),
        ("Excerpt", excerpt_field),
        ("Role", role_text.to_owned()),
        ("Context", context_text.to_owned()),
        ("Confidence", confidence_text.to_owned()),
        ("Entropy", format!("{:.2} bits/byte", finding.entropy_score)),
        ("Transforms", transform_chain),
        (
            "Byte range",
            format!("{}..{}", finding.byte_range.start, finding.byte_range.end),
        ),
        ("Fingerprint", finding.fingerprint_hex()),
        ("Span kind", span_kind_text),
        ("Synthetic", finding.synthetic.to_string()),
    ];

    for (label, value) in &lines {
        if y >= bottom {
            return;
        }
        let line = format!("  {:<12} {}", label, value);
        let truncated = clip_str(&line, area.width as usize);
        // The Match row gets warn-colour bold treatment when actually revealed
        // so the user's eye lands on it and they know they've turned the
        // setting on. When hidden, render it muted.
        let style = if *label == "Match" {
            if reveal_secrets {
                Style::default().fg(COLOR_WARN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(COLOR_MUTED)
            }
        } else {
            Style::default().fg(COLOR_FG)
        };
        buf.set_string(left, y, truncated, style);
        y = y.saturating_add(1);
    }

    if y < bottom {
        let actions =
            "  Actions: f suppress \u{00b7} o open \u{00b7} c copy fp \u{00b7} Enter close";
        let truncated = clip_str(actions, area.width as usize);
        buf.set_string(left, y, truncated, Style::default().fg(COLOR_MUTED));
    }
}

/// Render the single-line keybinds bar.
fn render_keybinds_bar(area: Rect, buf: &mut Buffer, detail_open: bool) {
    buf.set_style(area, Style::default().bg(COLOR_BG));
    let hints = if detail_open {
        "  j/k scroll  \u{00b7}  Enter close  \u{00b7}  f suppress  \u{00b7}  o open  \u{00b7}  c copy fp  \u{00b7}  q back"
    } else {
        "  j/k scroll  \u{00b7}  Enter detail  \u{00b7}  f suppress  \u{00b7}  o open  \u{00b7}  c copy fp  \u{00b7}  q back"
    };
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

/// Severity text only (no style); used when the row is dimmed/suppressed
/// and we want to share the muted style across every column including the
/// severity column.
fn severity_text(confidence: &Confidence) -> &'static str {
    match confidence {
        Confidence::High => "  HIGH",
        Confidence::Medium => "  MED ",
        Confidence::Low => "  LOW ",
    }
}

/// Map a Role (or absence of one) to a 4-char column label.
fn role_label(role: &Option<Role>) -> &'static str {
    match role {
        Some(Role::User) => "user",
        Some(Role::Assistant) => "asst",
        Some(Role::System) => "sys ",
        Some(Role::Tool) => "tool",
        None => "\u{2014}   ",
    }
}

/// Map a context class to its abbreviated row-label and (style, dimmed?) tuple.
/// `base_style` is the per-row style; we only override the foreground to
/// COLOR_MUTED when the context class itself wants a quiet rendering.
fn context_class_label(
    cc: &ContextClass,
    base_style: Style,
    row_dimmed: bool,
    suppressed: bool,
) -> (&'static str, Style) {
    let muted_style = if suppressed {
        Style::default()
            .fg(COLOR_MUTED)
            .add_modifier(Modifier::CROSSED_OUT)
    } else {
        Style::default().fg(COLOR_MUTED)
    };

    match cc {
        ContextClass::RealPaste => {
            // Normal foreground unless the row is otherwise dimmed (it isn't,
            // since RealPaste rows render normally — but be defensive).
            let style = if row_dimmed { muted_style } else { base_style };
            ("RealPaste", style)
        }
        ContextClass::Educational => ("Educational", muted_style),
        ContextClass::DocumentationQuote => ("DocQuote", muted_style),
        ContextClass::ModelHallucination => ("Halluc.", muted_style),
        ContextClass::Unclassified => ("\u{2014}", muted_style),
    }
}

fn context_class_full(cc: &ContextClass) -> &'static str {
    match cc {
        ContextClass::RealPaste => "RealPaste",
        ContextClass::Educational => "Educational",
        ContextClass::DocumentationQuote => "DocumentationQuote",
        ContextClass::ModelHallucination => "ModelHallucination",
        ContextClass::Unclassified => "Unclassified",
    }
}

/// Whether a context class should dim its whole row even when the
/// `show_all_context` filter is on. RealPaste and Unclassified render
/// normally; the three "noisy" classes dim.
fn is_dimmed_context(cc: &ContextClass) -> bool {
    matches!(
        cc,
        ContextClass::Educational
            | ContextClass::DocumentationQuote
            | ContextClass::ModelHallucination
    )
}

/// Build the location label for a finding row.
///
/// We render exactly one of `Lnnn` (preferred — points at a line the user
/// can jump straight to in their editor) or `msg N` (fallback for tree-
/// structured exports like ChatGPT JSON, where line attribution is not
/// meaningful). Showing both would clutter the row without telling the
/// user anything they can't get from the detail pane.
fn location_label(finding: &sanitai_core::finding::Finding) -> String {
    match finding.line_in_file {
        Some(n) => format!("L{n}"),
        None => format!("msg {}", finding.turn_id.1),
    }
}
