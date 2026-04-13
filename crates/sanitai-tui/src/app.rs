use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    widgets::Widget,
    Terminal,
};
use sanitai_core::finding::Confidence;
use sanitai_store::{FindingRecord, ScanRecord, Store};

use crate::{
    help::HelpOverlay,
    history_screen::HistoryScreen,
    layout::main_layout,
    menu::{Menu, MenuItem, COLOR_BG, COLOR_FOCUS, COLOR_MUTED},
    nix::{NixMood, NixWidget},
    redact_screen::{RedactPhase, RedactScreen},
    results::ResultsWidget,
    scan_runner::{run_auto_scan, ScanSummary},
    settings::{AppSettings, SettingsScreen},
};

// Launch lines — all ≤ 18 visible chars (sidebar body width).
const NIX_LAUNCH_LINES: &[&str] = &[
    "Watching.",
    "Ready.",
    "Go ahead.",
    "When you're ready.",
    "Not on my watch.",
];

#[derive(PartialEq, Eq, Clone, Copy)]
enum AppState {
    Menu,
    Scanning,
    Results,
    History,
    Settings,
    Redact,
}

/// Active filters for the results view.
#[derive(Debug, Clone, Default)]
pub struct ResultsFilter {
    /// When true, show all context classes including Educational and DocumentationQuote.
    /// Default false: those are hidden to reduce noise.
    pub show_all_context: bool,
    /// Minimum confidence to show. None = show all.
    pub min_confidence: Option<sanitai_core::finding::Confidence>,
}

impl ResultsFilter {
    pub fn matches(&self, finding: &sanitai_core::finding::Finding) -> bool {
        // Context class filter
        if !self.show_all_context {
            use sanitai_core::finding::ContextClass;
            match &finding.context_class {
                ContextClass::Educational | ContextClass::DocumentationQuote => return false,
                _ => {}
            }
        }

        // Confidence floor filter
        if let Some(min_conf) = &self.min_confidence {
            let level = |c: &sanitai_core::finding::Confidence| -> u8 {
                match c {
                    sanitai_core::finding::Confidence::High => 2,
                    sanitai_core::finding::Confidence::Medium => 1,
                    sanitai_core::finding::Confidence::Low => 0,
                }
            };
            if level(&finding.confidence) < level(min_conf) {
                return false;
            }
        }

        true
    }
}

struct App {
    menu: Menu,
    state: AppState,
    nix_mood: NixMood,
    nix_speech: Option<String>,
    last_scan: Option<ScanSummary>,
    last_scan_label: Option<String>,
    should_quit: bool,
    // Per-screen state
    results_scroll: usize,
    history_screen: Option<HistoryScreen>,
    settings_screen: SettingsScreen,
    redact_screen: Option<RedactScreen>,
    // Overlays
    show_help: bool,
    // User preferences
    app_settings: AppSettings,
    /// Active filters for the results view.
    filter: ResultsFilter,
}

impl App {
    fn new() -> Self {
        let minute = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
            / 60;
        let line = NIX_LAUNCH_LINES[(minute as usize) % NIX_LAUNCH_LINES.len()];

        // Read the last scan for the footer label and Nix's startup mood.
        let last_scan_record = Store::open()
            .ok()
            .and_then(|s| s.recent_scans(1).ok())
            .and_then(|mut v| v.pop());

        let (last_scan_label, startup_mood) = match &last_scan_record {
            Some(rec) => {
                let total = rec.findings_high + rec.findings_medium + rec.findings_low;
                let label = if total == 0 {
                    format!("Last scan: clean \u{00b7} {}ms", rec.duration_ms)
                } else {
                    format!(
                        "Last scan: {} HIGH \u{00b7} {} MED \u{00b7} {}ms",
                        rec.findings_high, rec.findings_medium, rec.duration_ms
                    )
                };
                // Nix holds the sign if prior scan had unaddressed findings.
                let mood = if total > 0 {
                    NixMood::WithSign
                } else {
                    NixMood::Normal
                };
                (Some(label), mood)
            }
            None => (None, NixMood::Normal),
        };

        let app_settings = AppSettings::default();
        let settings_screen = SettingsScreen::new(app_settings.clone());

        Self {
            menu: Menu::new(),
            state: AppState::Menu,
            nix_mood: startup_mood,
            nix_speech: Some(line.to_owned()),
            last_scan: None,
            last_scan_label,
            should_quit: false,
            results_scroll: 0,
            history_screen: None,
            settings_screen,
            redact_screen: None,
            show_help: false,
            app_settings,
            filter: ResultsFilter::default(),
        }
    }

    fn handle_key(&mut self, code: KeyCode) {
        // Help overlay intercepts everything when open.
        if self.show_help {
            match code {
                KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') => {
                    self.show_help = false;
                }
                _ => {}
            }
            return;
        }

        match self.state {
            AppState::Menu => match code {
                KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
                KeyCode::Char('j') | KeyCode::Down => self.menu.move_down(),
                KeyCode::Char('k') | KeyCode::Up => self.menu.move_up(),
                KeyCode::Char('?') => self.show_help = true,
                KeyCode::Enter => self.activate_selected(),
                _ => {}
            },

            AppState::Scanning => {
                // Ignore all input while scanning.
            }

            AppState::Results => match code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    self.state = AppState::Menu;
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    let max = self
                        .last_scan
                        .as_ref()
                        .map(|s| s.findings.len().saturating_sub(1))
                        .unwrap_or(0);
                    self.results_scroll = (self.results_scroll + 1).min(max);
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    self.results_scroll = self.results_scroll.saturating_sub(1);
                }
                KeyCode::Char('?') => self.show_help = true,
                KeyCode::Char('e') => {
                    // Export stub — Nix acknowledges, feature pending.
                    self.nix_speech = Some("Export coming soon.".to_owned());
                }
                KeyCode::Char('f') | KeyCode::Tab => {
                    // Toggle hiding of Educational / DocumentationQuote findings.
                    self.filter.show_all_context = !self.filter.show_all_context;
                    self.results_scroll = 0;
                }
                KeyCode::Char('1') => {
                    self.filter.min_confidence = Some(Confidence::High);
                    self.results_scroll = 0;
                }
                KeyCode::Char('2') => {
                    self.filter.min_confidence = Some(Confidence::Medium);
                    self.results_scroll = 0;
                }
                KeyCode::Char('3') => {
                    self.filter.min_confidence = Some(Confidence::Low);
                    self.results_scroll = 0;
                }
                KeyCode::Char('0') => {
                    self.filter.min_confidence = None;
                    self.results_scroll = 0;
                }
                _ => {}
            },

            AppState::History => {
                if let Some(ref mut hs) = self.history_screen {
                    if hs.filtering {
                        match code {
                            KeyCode::Esc => hs.end_filter(),
                            KeyCode::Enter => hs.end_filter(),
                            KeyCode::Backspace => hs.pop_filter_char(),
                            KeyCode::Char(c) => hs.push_filter_char(c),
                            _ => {}
                        }
                    } else {
                        match code {
                            KeyCode::Char('q') | KeyCode::Esc => {
                                self.state = AppState::Menu;
                            }
                            KeyCode::Char('j') | KeyCode::Down => hs.move_down(),
                            KeyCode::Char('k') | KeyCode::Up => hs.move_up(),
                            KeyCode::Char('/') => hs.start_filter(),
                            KeyCode::Char('?') => self.show_help = true,
                            _ => {}
                        }
                    }
                }
            }

            AppState::Settings => match code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    // Sync settings back to app before leaving.
                    self.app_settings = self.settings_screen.settings.clone();
                    self.state = AppState::Menu;
                }
                KeyCode::Tab => self.settings_screen.next_tab(),
                KeyCode::Char('j') | KeyCode::Down => self.settings_screen.move_down(),
                KeyCode::Char('k') | KeyCode::Up => self.settings_screen.move_up(),
                KeyCode::Char(' ') | KeyCode::Enter => self.settings_screen.toggle_selected(),
                KeyCode::Char('?') => self.show_help = true,
                _ => {}
            },

            AppState::Redact => {
                if let Some(ref mut rs) = self.redact_screen {
                    match rs.phase {
                        RedactPhase::List => match code {
                            KeyCode::Char('q') | KeyCode::Esc => {
                                self.state = AppState::Menu;
                            }
                            KeyCode::Char('j') | KeyCode::Down => rs.move_down(),
                            KeyCode::Char('k') | KeyCode::Up => rs.move_up(),
                            KeyCode::Enter => rs.begin_confirm(),
                            KeyCode::Char('?') => self.show_help = true,
                            _ => {}
                        },
                        RedactPhase::Confirm => match code {
                            KeyCode::Char('y') | KeyCode::Char('Y') => rs.execute_redact(),
                            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                                rs.cancel_confirm()
                            }
                            _ => {}
                        },
                        RedactPhase::Done => {
                            // Any key returns to the list so the user can redact more files.
                            rs.phase = RedactPhase::List;
                        }
                    }
                }
            }
        }
    }

    fn activate_selected(&mut self) {
        match self.menu.selected_item() {
            Some(MenuItem::Scan) => {
                self.state = AppState::Scanning;
                self.nix_speech = Some("On it.".to_owned());
                self.nix_mood = NixMood::Normal;
            }
            Some(MenuItem::History) => {
                // Lazily load history from the store each time we open it.
                let records = Store::open()
                    .ok()
                    .and_then(|s| s.recent_scans(200).ok())
                    .unwrap_or_default();
                self.history_screen = Some(HistoryScreen::new(records));
                self.state = AppState::History;
            }
            Some(MenuItem::Scrub) => {
                // Navigate to the Redact screen.
                // If there's a recent scan with findings use those; otherwise start empty.
                let findings = self
                    .last_scan
                    .as_ref()
                    .map(|s| s.findings.clone())
                    .unwrap_or_default();
                self.redact_screen = Some(RedactScreen::new(findings));
                self.state = AppState::Redact;
            }
            Some(MenuItem::Settings) => {
                // Sync current app_settings into the screen before opening.
                self.settings_screen = SettingsScreen::new(self.app_settings.clone());
                self.state = AppState::Settings;
            }
            Some(MenuItem::Help) => {
                self.show_help = true;
            }
            Some(MenuItem::Report) => {
                // Stub — report is a future keyboard shortcut on the Results screen.
                self.nix_speech = Some("Export coming soon.".to_owned());
            }
            Some(MenuItem::Quit) => {
                self.should_quit = true;
            }
            _ => {}
        }
    }

    fn run_scan_and_update(&mut self) {
        match run_auto_scan() {
            Ok(summary) => {
                let total =
                    summary.findings_high + summary.findings_medium + summary.findings_low;
                if total == 0 {
                    self.nix_mood = NixMood::Happy;
                    self.nix_speech = Some("Clean. Sleep well.".to_owned());
                    self.last_scan_label = Some(format!(
                        "Last scan: clean \u{00b7} {}ms \u{00b7} {} files",
                        summary.duration_ms, summary.total_files
                    ));
                } else {
                    self.nix_mood = NixMood::Alert;
                    self.nix_speech = Some(format!("Found {}. Look at this.", total));
                    self.last_scan_label = Some(format!(
                        "Last scan: {} HIGH \u{00b7} {} MED \u{00b7} {}ms",
                        summary.findings_high, summary.findings_medium, summary.duration_ms
                    ));
                }

                write_scan_to_store(&summary);
                self.results_scroll = 0;
                self.last_scan = Some(summary);
            }
            Err(e) => {
                tracing::warn!("TUI scan error: {e}");
                self.nix_mood = NixMood::Alert;
                self.nix_speech = Some("Try the command line.".to_owned());
            }
        }
        // Go directly to results screen so the user sees what was found.
        self.state = AppState::Results;
    }
}

fn write_scan_to_store(summary: &ScanSummary) {
    let scan_record = ScanRecord {
        scan_id: summary.scan_id.clone(),
        started_at_ns: summary.started_at_ns,
        duration_ms: summary.duration_ms as i64,
        project_name: None,
        claude_account: None,
        total_files: summary.total_files as i64,
        total_turns: summary.total_turns as i64,
        format: "tui".to_owned(),
        exit_code: 0,
        findings_high: summary.findings_high as i64,
        findings_medium: summary.findings_medium as i64,
        findings_low: summary.findings_low as i64,
    };

    let file_paths: Vec<String> = summary
        .paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    let finding_records: Vec<FindingRecord> = summary
        .findings
        .iter()
        .map(|f| FindingRecord {
            scan_id: summary.scan_id.clone(),
            detector_id: f.detector_id.to_owned(),
            file_path: f.turn_id.0.to_string_lossy().into_owned(),
            turn_idx: f.turn_id.1 as i64,
            confidence: match f.confidence {
                Confidence::High => "high".to_owned(),
                Confidence::Medium => "medium".to_owned(),
                Confidence::Low => "low".to_owned(),
            },
            transforms: serde_json::to_string(
                &f.transform
                    .0
                    .iter()
                    .map(|t| format!("{t:?}").to_lowercase())
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_else(|_| "[]".to_owned()),
            synthetic: f.synthetic,
            role: f.role.as_ref().map(|r| format!("{r:?}").to_lowercase()),
            category: Some(format!("{:?}", f.category).to_lowercase()),
            entropy_score: Some(f.entropy_score),
            context_class: Some(format!("{:?}", f.context_class).to_lowercase()),
            secret_hash: None,
        })
        .collect();

    match Store::open() {
        Ok(store) => {
            if let Err(e) = store.record_scan(&scan_record, &file_paths, &finding_records) {
                tracing::warn!("TUI history store write failed: {e}");
            }
        }
        Err(e) => tracing::warn!("TUI history store open failed: {e}"),
    }
}

/// Render the footer bar.
fn render_footer(area: Rect, buf: &mut Buffer, last_scan: Option<&str>) {
    buf.set_style(area, Style::default().bg(COLOR_BG).fg(COLOR_MUTED));

    let hints =
        "\u{2191}\u{2193}/jk navigate \u{2502} Enter select \u{2502} q quit \u{2502} ? help \u{2502} Esc quit";
    buf.set_string(area.left(), area.top(), hints, Style::default().fg(COLOR_MUTED));

    if let Some(label) = last_scan {
        let label_len = label.len() as u16;
        if label_len.saturating_add(hints.len() as u16).saturating_add(4) < area.width {
            let x = area.right().saturating_sub(label_len + 1);
            buf.set_string(x, area.top(), label, Style::default().fg(COLOR_FOCUS));
        }
    }
}

/// Full-screen "Scanning..." overlay.
fn render_scanning_screen(area: Rect, buf: &mut Buffer, nix_mood: NixMood) {
    buf.set_style(area, Style::default().bg(COLOR_BG));

    let msg = "  Scanning for secrets \u{2014} please wait\u{2026}";
    let y = area.height / 2;
    buf.set_string(
        area.left().saturating_add(2),
        area.top().saturating_add(y),
        msg,
        Style::default().fg(COLOR_FOCUS).add_modifier(Modifier::BOLD),
    );
    buf.set_string(
        area.left().saturating_add(2),
        area.top().saturating_add(y).saturating_add(1),
        "  Nix is on it.",
        Style::default().fg(COLOR_MUTED),
    );

    // Render Nix in the bottom-right corner.
    let nix_w: u16 = 22;
    let nix_h: u16 = 14;
    if area.width >= nix_w && area.height >= nix_h {
        let nix_area = Rect {
            x: area.right().saturating_sub(nix_w),
            y: area.bottom().saturating_sub(nix_h),
            width: nix_w,
            height: nix_h,
        };
        let nix = NixWidget {
            mood: nix_mood,
            speech: Some("On it.".to_owned()),
        };
        nix.render(nix_area, buf);
    }
}

/// Install a panic hook that restores the terminal before printing the panic.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        default_hook(info);
    }));
}

/// Public entry point called from sanitai-cli.
pub fn run() -> Result<()> {
    install_panic_hook();

    // Initialise App (opens Store, reads last scan) before raw mode so any
    // startup errors surface as normal terminal output.
    let mut app = App::new();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    loop {
        // Scanning: render once then block on the scan.
        if app.state == AppState::Scanning {
            let mood = app.nix_mood;
            terminal.draw(|frame| {
                render_scanning_screen(frame.area(), frame.buffer_mut(), mood);
            })?;
            app.run_scan_and_update();
            continue;
        }

        terminal.draw(|frame| {
            let area = frame.area();
            let buf = frame.buffer_mut();

            buf.set_style(area, Style::default().bg(COLOR_BG));

            match app.state {
                AppState::Menu => {
                    let (menu_area, nix_area, footer_area) = main_layout(area);

                    app.menu.render(menu_area, buf);

                    if app.app_settings.show_mascot {
                        let speech = if app.app_settings.mascot_speech {
                            app.nix_speech.clone()
                        } else {
                            None
                        };
                        let nix = NixWidget { mood: app.nix_mood, speech };
                        nix.render(nix_area, buf);
                    }

                    render_footer(footer_area, buf, app.last_scan_label.as_deref());
                }

                AppState::Results => {
                    if let Some(ref summary) = app.last_scan {
                        let widget = ResultsWidget {
                            summary,
                            scroll: app.results_scroll,
                            filter: Some(&app.filter),
                        };
                        (&widget).render(area, buf);
                    }
                }

                AppState::History => {
                    if let Some(ref mut hs) = app.history_screen {
                        hs.render(area, buf);
                    }
                }

                AppState::Settings => {
                    app.settings_screen.render(area, buf);
                }

                AppState::Redact => {
                    if let Some(ref mut rs) = app.redact_screen {
                        rs.render(area, buf);
                    }
                }

                AppState::Scanning => unreachable!("handled above"),
            }

            // Help overlay renders on top of any state.
            if app.show_help {
                let overlay = HelpOverlay;
                (&overlay).render(area, buf);
            }
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.handle_key(key.code);
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod filter_tests {
    use super::ResultsFilter;
    use sanitai_core::finding::{
        Confidence, ContextClass, Finding, SpanKind, TransformChain,
    };
    use sanitai_core::traits::Category;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn sample_finding() -> Finding {
        Finding {
            turn_id: (Arc::new(PathBuf::from("/tmp/x")), 0),
            detector_id: "test_rule",
            byte_range: 0..4,
            matched_raw: "abcd".to_owned(),
            transform: TransformChain::default(),
            confidence: Confidence::Medium,
            span_kind: SpanKind::Single,
            synthetic: false,
            role: None,
            category: Category::Secret,
            entropy_score: 2.0,
            context_class: ContextClass::Unclassified,
        }
    }

    #[test]
    fn results_filter_hides_educational_by_default() {
        let mut f1 = sample_finding();
        f1.context_class = ContextClass::RealPaste;
        let mut f2 = sample_finding();
        f2.context_class = ContextClass::Educational;

        let filter = ResultsFilter::default();
        assert!(filter.matches(&f1), "RealPaste should be visible by default");
        assert!(
            !filter.matches(&f2),
            "Educational should be hidden by default"
        );
    }

    #[test]
    fn results_filter_hides_documentation_quote_by_default() {
        let mut f = sample_finding();
        f.context_class = ContextClass::DocumentationQuote;
        let filter = ResultsFilter::default();
        assert!(!filter.matches(&f));
    }

    #[test]
    fn results_filter_show_all_shows_educational() {
        let mut f = sample_finding();
        f.context_class = ContextClass::Educational;
        let filter = ResultsFilter {
            show_all_context: true,
            ..Default::default()
        };
        assert!(
            filter.matches(&f),
            "Educational should be visible with show_all_context"
        );
    }

    #[test]
    fn results_filter_confidence_gate() {
        let mut f = sample_finding();
        f.confidence = Confidence::Low;

        let filter = ResultsFilter {
            show_all_context: true,
            min_confidence: Some(Confidence::Medium),
        };
        assert!(
            !filter.matches(&f),
            "Low confidence should be hidden when min is Medium"
        );

        let filter2 = ResultsFilter {
            show_all_context: true,
            min_confidence: Some(Confidence::Low),
        };
        assert!(
            filter2.matches(&f),
            "Low confidence should be visible when min is Low"
        );
    }
}
