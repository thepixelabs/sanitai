use std::collections::VecDeque;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossbeam_channel::Receiver;
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
use sanitai_core::finding::{Confidence, ContextClass, Finding, SpanKind, TransformChain};
use sanitai_core::traits::Category;
use sanitai_core::turn::Role;
use sanitai_store::{BeginScanRecord, FinalizeScanInput, FindingRecord, ScanRecord, Store};

use crate::{
    banner::Banner,
    help::HelpOverlay,
    history_screen::HistoryScreen,
    layout::main_layout,
    menu::{Menu, MenuItem, COLOR_BG, COLOR_FG, COLOR_FOCUS, COLOR_MUTED, COLOR_SAFE, COLOR_WARN},
    open_in_editor::{self, EditorResolution, ProcessEnv},
    redact_screen::{RedactPhase, RedactScreen},
    results::ResultsWidget,
    scan_runner::{run_auto_scan_progress, ScanProgressEvent, ScanSummary},
    settings::{AppSettings, SettingsScreen},
    suppressions::Suppressions,
};

// Tagline rotation — these used to be Nix's launch lines. They survive as the
// muted single-row strip below the wordmark; the personality stays, the
// character art is gone.
const NIX_LAUNCH_LINES: &[&str] = &[
    "Watching.",
    "Ready.",
    "Go ahead.",
    "When you're ready.",
    "Not on my watch.",
];

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum AppState {
    Menu,
    Scanning,
    Results,
    History,
    Settings,
    Redact,
}

/// State captured when the user presses `R` on the Results screen — the
/// file path to redact and the number of findings in that file. Stored
/// once at the moment of the keystroke so the prompt's text is stable
/// across re-renders even if the user's selection moves later. (It can't
/// move while the prompt is up, but we still cache to keep the y/n
/// handler simple.)
#[derive(Debug, Clone)]
pub(crate) struct ResultsRedactPrompt {
    pub file: PathBuf,
    pub finding_count: usize,
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
    /// Single-row tagline displayed in the muted strip below the wordmark.
    /// Rotated on state transitions to keep the brand voice without a mascot.
    current_tagline: String,
    banner: Banner,
    last_scan: Option<ScanSummary>,
    last_scan_label: Option<String>,
    should_quit: bool,
    // Per-screen state
    results_scroll: usize,
    /// Whether the bottom-pane finding detail view is currently open. The
    /// selected row stays in `results_scroll`; this flag only controls
    /// layout.
    results_detail_open: bool,
    /// When `Some`, the Results screen is showing the inline `R` redact
    /// confirmation row at the bottom of the body. The pending prompt
    /// captures the file we'll redact and the count of findings in it
    /// so the y/n handler doesn't have to reach back into `last_scan` /
    /// `selected_finding`. `None` everywhere else — the prompt is a
    /// sub-state of `AppState::Results`, not its own AppState variant,
    /// because every other Results-screen key (jk, Tab, /, ?) should
    /// stay disabled while the prompt is up.
    results_redact_prompt: Option<ResultsRedactPrompt>,
    history_screen: Option<HistoryScreen>,
    settings_screen: SettingsScreen,
    redact_screen: Option<RedactScreen>,
    /// Live progress state while a scan is running. Populated when entering
    /// AppState::Scanning, cleared once the worker's terminal `Done` event is
    /// finalised.
    scan_progress: Option<ScanProgress>,
    // Overlays
    show_help: bool,
    // User preferences
    app_settings: AppSettings,
    /// Active filters for the results view.
    filter: ResultsFilter,
    /// Persistent set of suppressed finding fingerprints. Loaded from disk
    /// at startup; mutated via `f` on the Results screen.
    suppressions: Suppressions,
}

// ---------------------------------------------------------------------------
// ScanProgress — live state for the in-flight scan
// ---------------------------------------------------------------------------

const TAIL_LEN: usize = 8;
const THROUGHPUT_WINDOW: Duration = Duration::from_secs(3);

#[derive(Clone)]
struct FileTailEntry {
    name: String,
    size: u64,
    findings: usize,
    skipped: bool,
}

#[derive(Clone, Copy)]
struct ThroughputSample {
    at: Instant,
    bytes: u64,
}

struct ScanProgress {
    rx: Receiver<ScanProgressEvent>,
    cancel: Arc<AtomicBool>,
    started_at: Instant,
    total_files: usize,
    total_bytes: u64,
    processed_files: usize,
    processed_bytes: u64,
    findings_count: usize,
    skipped_files: usize,
    tail: VecDeque<FileTailEntry>,
    samples: VecDeque<ThroughputSample>,
    plan_received: bool,
    cancel_requested: bool,
    current_file: Option<PathBuf>,
    /// History store handle. Held for the lifetime of the scan so we can
    /// commit per-file rows without reopening the DB on every event. None
    /// if the store could not be opened — persistence is best-effort and
    /// non-fatal so the scan still runs.
    store: Option<Store>,
    /// True once `begin_scan` has been issued for `scan_id`. We can't
    /// `begin_scan` until we hear the worker's `Plan` event so we know the
    /// scan_id and started_at_ns from the worker's `Done` summary — but
    /// `Done` is the last event, so we synthesise our own values here at
    /// spawn time and `begin_scan` lazily on the first Plan event.
    scan_started: bool,
    /// scan_id we'll use when calling begin_scan / commit_file / finalize.
    /// Generated upfront so the row exists from the moment the user hits
    /// Scan in the menu — without this, a kill before the worker's Plan
    /// event would leave nothing in the store.
    scan_id: String,
    /// Wall-clock start as Unix nanoseconds — fixed at spawn so the
    /// recovery sweep can compute a reasonable duration if the process
    /// is killed before finalize_scan runs.
    started_at_ns: i64,
}

impl ScanProgress {
    fn spawn() -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_thread = Arc::clone(&cancel);
        std::thread::spawn(move || run_auto_scan_progress(tx, cancel_thread));

        // Open the store eagerly so we can write the in-progress placeholder
        // the moment the worker emits Plan. A failure here is non-fatal —
        // the scan still runs, just without history persistence.
        let store = match Store::open() {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!("TUI history store open failed: {e}");
                None
            }
        };

        let scan_id = ulid::Ulid::new().to_string();
        let started_at_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);

        Self {
            rx,
            cancel,
            started_at: Instant::now(),
            total_files: 0,
            total_bytes: 0,
            processed_files: 0,
            processed_bytes: 0,
            findings_count: 0,
            skipped_files: 0,
            tail: VecDeque::with_capacity(TAIL_LEN),
            samples: VecDeque::with_capacity(64),
            plan_received: false,
            cancel_requested: false,
            current_file: None,
            store,
            scan_started: false,
            scan_id,
            started_at_ns,
        }
    }

    fn request_cancel(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.cancel_requested = true;
    }

    /// Issue `begin_scan` once, the first time we have enough information
    /// (which is now — scan_id and started_at_ns are pinned at spawn time).
    /// We call this from `Plan` rather than `spawn` purely so the row's
    /// `total_files` reflects the worker's discovery total. Persistence is
    /// best-effort; failures are warned and ignored.
    fn ensure_begin_scan(&mut self, total_files: usize) {
        if self.scan_started {
            return;
        }
        self.scan_started = true;
        let Some(ref store) = self.store else {
            return;
        };
        if let Err(e) = store.begin_scan(&BeginScanRecord {
            scan_id: self.scan_id.clone(),
            started_at_ns: self.started_at_ns,
            project_name: None,
            claude_account: None,
            total_files: total_files as i64,
            format: "tui".to_owned(),
        }) {
            tracing::warn!("TUI begin_scan failed: {e}");
        }
    }

    /// Commit a single file's progress to the store. The TUI does not yet
    /// know per-file findings (the worker only sends counts), so the
    /// findings slice is always empty here — the actual `FindingRecord`s
    /// are written by `commit_findings_at_finalize` when `Done` arrives.
    /// This call still records the path and bumps total_files for the
    /// recovery sweep / History view.
    fn commit_file_progress(&self, path: &std::path::Path) {
        let Some(ref store) = self.store else {
            return;
        };
        // Skip our internal "<stdin>" sentinel and any non-utf8 paths
        // gracefully — to_string_lossy is fine for display, and SQLite's
        // TEXT type accepts the replaced bytes.
        let p = path.to_string_lossy();
        if let Err(e) = store.commit_file(&self.scan_id, &p, &[]) {
            tracing::warn!("TUI commit_file (progress) failed: {e}");
        }
    }

    /// Once the worker emits `Done`, write the actual findings into the
    /// store grouped by file. `commit_file` is idempotent on path so the
    /// progress callbacks above don't conflict with these enriched calls.
    fn commit_findings_at_finalize(&self, summary: &ScanSummary) {
        let Some(ref store) = self.store else {
            return;
        };
        // Group findings by file path. ScanSummary keeps full Findings,
        // not records, so we map them through `summary_finding_to_record`.
        let mut by_path: std::collections::HashMap<String, Vec<FindingRecord>> =
            std::collections::HashMap::new();
        for f in &summary.findings {
            let path = f.turn_id.0.to_string_lossy().into_owned();
            by_path
                .entry(path)
                .or_default()
                .push(summary_finding_to_record(f, &self.scan_id));
        }
        for (path, recs) in by_path {
            if let Err(e) = store.commit_file(&self.scan_id, &path, &recs) {
                tracing::warn!(path = %path, "TUI commit_file (finalize) failed: {e}");
            }
        }
    }

    fn drain(&mut self) -> Option<ScanSummary> {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                ScanProgressEvent::Plan {
                    total_files,
                    total_bytes,
                } => {
                    self.total_files = total_files;
                    self.total_bytes = total_bytes;
                    self.plan_received = true;
                    // First moment we know the planned file count — open
                    // the placeholder scans row so a kill before any file
                    // is processed still leaves a recoverable record.
                    self.ensure_begin_scan(total_files);
                }
                ScanProgressEvent::FileStart { path, size: _ } => {
                    self.current_file = Some(path);
                }
                ScanProgressEvent::FileDone {
                    path,
                    size,
                    findings,
                    ms: _,
                } => {
                    self.processed_bytes = self.processed_bytes.saturating_add(size);
                    self.processed_files = self.processed_files.saturating_add(1);
                    self.findings_count = self.findings_count.saturating_add(findings);
                    self.push_tail(&path, size, findings, false);
                    self.record_sample();
                    // Record per-file progress in the history store. Each
                    // call is its own transaction so a force-kill mid-scan
                    // still leaves rows for everything before this point.
                    self.commit_file_progress(&path);
                    self.current_file = None;
                }
                ScanProgressEvent::FileSkipped { path, size } => {
                    self.processed_bytes = self.processed_bytes.saturating_add(size);
                    self.processed_files = self.processed_files.saturating_add(1);
                    self.skipped_files = self.skipped_files.saturating_add(1);
                    self.push_tail(&path, size, 0, true);
                    self.record_sample();
                    self.commit_file_progress(&path);
                    self.current_file = None;
                }
                ScanProgressEvent::Done(summary) => {
                    return Some(*summary);
                }
                ScanProgressEvent::Error(e) => {
                    tracing::warn!("scan worker error: {e}");
                }
            }
        }
        None
    }

    fn push_tail(&mut self, path: &std::path::Path, size: u64, findings: usize, skipped: bool) {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        if self.tail.len() == TAIL_LEN {
            self.tail.pop_front();
        }
        self.tail.push_back(FileTailEntry {
            name,
            size,
            findings,
            skipped,
        });
    }

    fn record_sample(&mut self) {
        let now = Instant::now();
        self.samples.push_back(ThroughputSample {
            at: now,
            bytes: self.processed_bytes,
        });
        let cutoff = now.checked_sub(THROUGHPUT_WINDOW);
        while self.samples.len() > 1 {
            let drop = match (self.samples.front(), cutoff) {
                (Some(s), Some(c)) => s.at < c,
                _ => false,
            };
            if drop {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    fn bytes_per_sec(&self) -> Option<f64> {
        if self.samples.len() < 2 {
            return None;
        }
        let first = self.samples.front()?;
        let last = self.samples.back()?;
        let elapsed = last.at.duration_since(first.at).as_secs_f64();
        if elapsed <= 0.0 {
            return None;
        }
        Some((last.bytes.saturating_sub(first.bytes)) as f64 / elapsed)
    }

    fn files_per_sec(&self) -> Option<f64> {
        let elapsed = self.started_at.elapsed().as_secs_f64();
        if elapsed <= 0.0 || self.processed_files == 0 {
            return None;
        }
        Some(self.processed_files as f64 / elapsed)
    }

    fn eta_seconds(&self) -> Option<u64> {
        let bps = self.bytes_per_sec()?;
        if bps <= 0.0 {
            return None;
        }
        let remaining = self.total_bytes.saturating_sub(self.processed_bytes);
        Some((remaining as f64 / bps) as u64)
    }

    fn fraction(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.processed_bytes as f64 / self.total_bytes as f64).clamp(0.0, 1.0)
    }
}

impl App {
    fn new() -> Self {
        let minute = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
            / 60;
        let line = NIX_LAUNCH_LINES[(minute as usize) % NIX_LAUNCH_LINES.len()];

        // Read the last scan so we can label the footer with the previous result.
        let last_scan_record = Store::open()
            .ok()
            .and_then(|s| s.recent_scans(1).ok())
            .and_then(|mut v| v.pop());

        let last_scan_label = last_scan_record.as_ref().map(|rec| {
            let total = rec.findings_high + rec.findings_medium + rec.findings_low;
            if total == 0 {
                format!("Last scan: clean \u{00b7} {}ms", rec.duration_ms)
            } else {
                format!(
                    "Last scan: {} HIGH \u{00b7} {} MED \u{00b7} {}ms",
                    rec.findings_high, rec.findings_medium, rec.duration_ms
                )
            }
        });

        let app_settings = AppSettings::default();
        let settings_screen = SettingsScreen::new(app_settings.clone());

        Self {
            menu: Menu::new(),
            state: AppState::Menu,
            current_tagline: line.to_owned(),
            banner: Banner::new(),
            last_scan: None,
            last_scan_label,
            should_quit: false,
            results_scroll: 0,
            results_detail_open: false,
            results_redact_prompt: None,
            history_screen: None,
            settings_screen,
            redact_screen: None,
            scan_progress: None,
            show_help: false,
            app_settings,
            filter: ResultsFilter::default(),
            suppressions: Suppressions::load(),
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

            AppState::Scanning => match code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    if let Some(ref mut sp) = self.scan_progress {
                        sp.request_cancel();
                        self.current_tagline = "Cancelling\u{2026}".to_owned();
                    }
                }
                _ => {}
            },

            AppState::Results => {
                // Inline redact prompt absorbs every key while it's up — y
                // confirms, n / Esc cancels, anything else is ignored. We
                // peek before the regular dispatch so the user can't, e.g.,
                // press `j` to move selection while the prompt thinks they
                // mean "yes" about a different file.
                if self.results_redact_prompt.is_some() {
                    match code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            self.execute_results_redact();
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            self.results_redact_prompt = None;
                        }
                        _ => {}
                    }
                    return;
                }

                match code {
                    KeyCode::Char('q') => {
                        // q always exits the Results screen entirely. (Esc, by
                        // contrast, only closes the detail pane when one is
                        // open — see the Esc arm below.)
                        self.results_detail_open = false;
                        self.state = AppState::Menu;
                    }
                    KeyCode::Esc => {
                        if self.results_detail_open {
                            self.results_detail_open = false;
                        } else {
                            self.state = AppState::Menu;
                        }
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
                    KeyCode::Enter => {
                        // Toggle the detail pane for the currently-selected row.
                        // Pressing Enter again (or Esc) closes it.
                        self.results_detail_open = !self.results_detail_open;
                    }
                    KeyCode::Char('?') => self.show_help = true,
                    KeyCode::Char('e') => {
                        // Export stub — feature pending.
                        self.current_tagline = "Export coming soon.".to_owned();
                    }
                    KeyCode::Tab => {
                        // Tab toggles the show-all-context filter. We previously
                        // double-bound this to `f`, but `f` now carries the
                        // suppression action — Tab is the only filter shortcut.
                        self.filter.show_all_context = !self.filter.show_all_context;
                        self.results_scroll = 0;
                    }
                    KeyCode::Char('f') => self.toggle_selected_suppression(),
                    KeyCode::Char('o') => self.open_selected_in_editor(),
                    KeyCode::Char('c') => self.copy_selected_fingerprint(),
                    KeyCode::Char('R') => self.begin_results_redact_prompt(),
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
                }
            }

            AppState::History => {
                // Two-phase dispatch: while the user is typing a filter (`/`)
                // every printable goes into the filter buffer; otherwise we
                // honour the History screen's nav keys plus Enter-to-load.
                //
                // Enter is intentionally split between the two phases —
                // inside filter mode it commits the filter; outside it
                // promotes the highlighted scan into the Results view.
                if let Some(hs) = self.history_screen.as_mut() {
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
                            KeyCode::Enter => self.load_selected_history_scan(),
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
                            KeyCode::Char('y') | KeyCode::Char('Y') => {
                                rs.execute_redact(self.app_settings.redact_mode.clone())
                            }
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

    /// Resolve the currently-selected finding in the Results view, applying
    /// the same filter + sort as the widget so the user's `f` / `o` / `c`
    /// keys act on the row their cursor is actually on.
    ///
    /// Returns a clone — borrowing through `last_scan` would force the caller
    /// to drop the borrow before mutating `self.suppressions` etc., and
    /// Findings are cheap-ish to clone (`detector_id` is `&'static str`,
    /// `turn_id.0` is an `Arc`, the matched_raw is the only allocation).
    fn selected_finding(&self) -> Option<sanitai_core::finding::Finding> {
        let summary = self.last_scan.as_ref()?;
        let mut sorted: Vec<&sanitai_core::finding::Finding> = summary
            .findings
            .iter()
            .filter(|f| self.filter.matches(f))
            .collect();
        sorted.sort_by_key(|f| match f.confidence {
            Confidence::High => 0u8,
            Confidence::Medium => 1,
            Confidence::Low => 2,
        });
        sorted.get(self.results_scroll).map(|f| (*f).clone())
    }

    fn toggle_selected_suppression(&mut self) {
        let Some(finding) = self.selected_finding() else {
            self.current_tagline = "No finding selected.".to_owned();
            return;
        };
        let fp = finding.fingerprint_hex();
        let now_suppressed = self.suppressions.toggle(&fp);
        self.current_tagline = if now_suppressed {
            format!("Suppressed [{fp}].")
        } else {
            format!("Un-suppressed [{fp}].")
        };
    }

    fn open_selected_in_editor(&mut self) {
        let Some(finding) = self.selected_finding() else {
            self.current_tagline = "No finding selected.".to_owned();
            return;
        };
        // Prefer the parser-computed source line; fall back to turn_idx+1
        // for tree-structured exports (ChatGPT JSON, Cursor SQLite) where
        // each turn is roughly one line of the JSONL it would have been if
        // the export had been line-oriented.
        let line = match finding.line_in_file {
            Some(n) => n as usize,
            None => finding.turn_id.1.saturating_add(1),
        };
        let path = finding.turn_id.0.as_ref().clone();
        match open_in_editor::resolve(&path, line, &ProcessEnv, &open_in_editor::ProcessWhich) {
            EditorResolution::Spawn(argv) => match open_in_editor::spawn(&argv) {
                Ok(()) => {
                    let display_bin = argv.first().cloned().unwrap_or_default();
                    self.current_tagline = format!("Opened in {}.", basename(&display_bin));
                }
                Err(e) => {
                    tracing::warn!("editor spawn failed: {e}");
                    self.current_tagline =
                        "No editor found. Set $VISUAL or install code/cursor/subl/vim.".to_owned();
                }
            },
            EditorResolution::NoEditor => {
                self.current_tagline =
                    "No editor found. Set $VISUAL or install code/cursor/subl/vim.".to_owned();
            }
        }
    }

    fn copy_selected_fingerprint(&mut self) {
        let Some(finding) = self.selected_finding() else {
            self.current_tagline = "No finding selected.".to_owned();
            return;
        };
        let fp = finding.fingerprint_hex();
        match arboard::Clipboard::new() {
            Ok(mut cb) => match cb.set_text(fp.clone()) {
                Ok(()) => self.current_tagline = format!("Copied [{fp}]."),
                Err(e) => {
                    tracing::warn!("clipboard set_text failed: {e}");
                    self.current_tagline = "Clipboard unavailable.".to_owned();
                }
            },
            Err(e) => {
                tracing::warn!("clipboard init failed: {e}");
                self.current_tagline = "Clipboard unavailable.".to_owned();
            }
        }
    }

    /// Capture the current selection's file path and the count of findings
    /// in that same file (the redactor operates per-file, matching the
    /// existing Redact-screen semantics), then arm the inline `R` prompt.
    ///
    /// Refuses with a tagline when the selected finding looks historical —
    /// either an empty `byte_range` (start == end) or an empty `matched_raw`.
    /// Both signal a row reconstructed from the SQLite store rather than a
    /// live scan, and the redactor would either no-op or write an empty
    /// replacement that corrupts the source file. The user is steered to
    /// re-run the scan instead.
    fn begin_results_redact_prompt(&mut self) {
        let Some(finding) = self.selected_finding() else {
            self.current_tagline = "No finding selected.".to_owned();
            return;
        };
        if finding.byte_range.start == finding.byte_range.end || finding.matched_raw.is_empty() {
            self.current_tagline =
                "Cannot redact historical scan \u{2014} re-run to redact.".to_owned();
            return;
        }
        let file = finding.turn_id.0.as_ref().clone();
        // Count every finding in `last_scan` that points at this same file.
        // We deliberately ignore `self.filter` here — redacting a file
        // should remove every finding the redactor knows about, not just
        // the ones the user happens to be displaying right now.
        let finding_count = self
            .last_scan
            .as_ref()
            .map(|s| {
                s.findings
                    .iter()
                    .filter(|f| f.turn_id.0.as_ref() == &file)
                    .count()
            })
            .unwrap_or(0);
        self.results_redact_prompt = Some(ResultsRedactPrompt {
            file,
            finding_count,
        });
    }

    /// Run the redactor on the prompted file using `app_settings.redact_mode`,
    /// write `<file>.sanitized`, then return to the Results view with a
    /// tagline that summarises what happened. Failures (read / write / no
    /// findings) all surface as taglines rather than overlays so the user
    /// stays oriented.
    fn execute_results_redact(&mut self) {
        let Some(prompt) = self.results_redact_prompt.take() else {
            return;
        };
        let Some(ref summary) = self.last_scan else {
            self.current_tagline = "No scan loaded.".to_owned();
            return;
        };

        // Collect the findings to redact — every finding whose `turn_id.0`
        // matches the prompt's file. Cloned so we don't keep a borrow on
        // `self.last_scan` while we mutate other fields.
        let file_findings: Vec<sanitai_core::finding::Finding> = summary
            .findings
            .iter()
            .filter(|f| f.turn_id.0.as_ref() == &prompt.file)
            .cloned()
            .collect();

        if file_findings.is_empty() {
            self.current_tagline = "No findings in that file to redact.".to_owned();
            return;
        }

        let content = match std::fs::read_to_string(&prompt.file) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(path = %prompt.file.display(), "redact read failed: {e}");
                self.current_tagline = format!("Cannot read source file: {}", e);
                return;
            }
        };

        let mut redactor = sanitai_redactor::Redactor::new(self.app_settings.redact_mode.clone());
        let redacted = redactor.redact(&content, &file_findings);

        let mut out_path = prompt.file.as_os_str().to_owned();
        out_path.push(".sanitized");
        let out_path = PathBuf::from(out_path);

        match std::fs::write(&out_path, redacted.as_bytes()) {
            Ok(()) => {
                let basename = out_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("output");
                self.current_tagline = format!(
                    "Wrote {} redaction{} to {}.",
                    prompt.finding_count,
                    if prompt.finding_count == 1 { "" } else { "s" },
                    basename
                );
            }
            Err(e) => {
                tracing::warn!(path = %out_path.display(), "redact write failed: {e}");
                self.current_tagline = format!("Cannot write redacted file: {}", e);
            }
        }
    }

    /// Promote the currently-highlighted History row into the Results view.
    ///
    /// Reads the selected `ScanRecord` from `history_screen`, opens the
    /// real history store, and dispatches to `load_history_scan_from_store`.
    /// Split this way so tests can exercise the reconstruction logic against
    /// a tempfile-backed `Store` without touching the user's real DB.
    fn load_selected_history_scan(&mut self) {
        // Snapshot the selected record so we drop the borrow on
        // `history_screen` before mutating `self.last_scan` etc.
        let selected: Option<ScanRecord> = self.history_screen.as_ref().and_then(|hs| {
            hs.filtered_records()
                .get(hs.selected)
                .map(|rec| (*rec).clone())
        });
        let Some(record) = selected else {
            self.current_tagline = "No scan selected.".to_owned();
            return;
        };

        let store = match Store::open() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("history reload: store open failed: {e}");
                self.current_tagline = "Cannot open history store.".to_owned();
                return;
            }
        };

        self.load_history_scan_from_store(&store, record);
    }

    /// Reconstruct a `ScanSummary` from `record` + the persisted findings in
    /// `store`, install it as `last_scan`, and transition to Results.
    ///
    /// Surfaces failures (missing findings, etc.) as a tagline so the user
    /// stays oriented in History rather than landing in a half-loaded
    /// Results view. Pulled out of `load_selected_history_scan` so tests can
    /// drive it against a tempfile-backed Store.
    fn load_history_scan_from_store(&mut self, store: &Store, record: ScanRecord) {
        let records = match store.findings_for_scan(&record.scan_id) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    scan_id = %record.scan_id,
                    "history reload: findings_for_scan failed: {e}",
                );
                self.current_tagline = "Cannot load findings for that scan.".to_owned();
                return;
            }
        };

        let findings: Vec<Finding> = records.into_iter().map(finding_record_to_finding).collect();

        // Build a ScanSummary shell from the record. We don't have the
        // original file paths cheaply (they live in scan_files but we don't
        // surface that as a public Store API); leaving `paths` empty is
        // fine — the Results widget reads `findings`, totals, and duration.
        let summary = ScanSummary {
            scan_id: record.scan_id.clone(),
            started_at_ns: record.started_at_ns,
            total_files: record.total_files as usize,
            total_turns: record.total_turns as usize,
            findings_high: record.findings_high as usize,
            findings_medium: record.findings_medium as usize,
            findings_low: record.findings_low as usize,
            duration_ms: record.duration_ms as u64,
            paths: Vec::new(),
            findings,
            cancelled: record.cancelled,
        };

        let scan_id_short: String = record.scan_id.chars().take(8).collect();
        let finding_count = summary.findings.len();
        self.current_tagline = format!(
            "Loaded scan {} \u{00b7} {} findings",
            scan_id_short, finding_count
        );

        self.last_scan = Some(summary);
        self.results_scroll = 0;
        self.results_detail_open = false;
        self.results_redact_prompt = None;
        self.state = AppState::Results;
    }

    fn activate_selected(&mut self) {
        match self.menu.selected_item() {
            Some(MenuItem::Scan) => {
                self.state = AppState::Scanning;
                self.current_tagline = "On it.".to_owned();
                self.scan_progress = Some(ScanProgress::spawn());
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
                self.current_tagline = "Export coming soon.".to_owned();
            }
            Some(MenuItem::Quit) => {
                self.should_quit = true;
            }
            _ => {}
        }
    }

    /// Called once the worker has emitted its terminal `Done` event. Updates
    /// tagline, footer label, flushes findings + finalize_scan to the
    /// history store, and transitions to the Results screen.
    fn finalize_scan(&mut self, summary: ScanSummary) {
        let total = summary.findings_high + summary.findings_medium + summary.findings_low;
        if summary.cancelled {
            self.current_tagline = "Scan cancelled.".to_owned();
            self.last_scan_label = Some(format!(
                "Cancelled at {} files \u{00b7} {}ms",
                summary.total_files, summary.duration_ms
            ));
        } else if total == 0 {
            self.current_tagline = "Clean. Sleep well.".to_owned();
            self.last_scan_label = Some(format!(
                "Last scan: clean \u{00b7} {}ms \u{00b7} {} files",
                summary.duration_ms, summary.total_files
            ));
        } else {
            self.current_tagline = format!("Found {}. Look at this.", total);
            self.last_scan_label = Some(format!(
                "Last scan: {} HIGH \u{00b7} {} MED \u{00b7} {}ms",
                summary.findings_high, summary.findings_medium, summary.duration_ms
            ));
        }

        // Flush per-file findings then mark the row complete. begin_scan
        // and per-file commit_file calls already ran via the drain path,
        // so this just enriches existing rows with finding records and
        // flips `complete = 1`.
        if let Some(ref sp) = self.scan_progress {
            sp.commit_findings_at_finalize(&summary);
            if let Some(ref store) = sp.store {
                if let Err(e) = store.finalize_scan(
                    &sp.scan_id,
                    &FinalizeScanInput {
                        duration_ms: summary.duration_ms as i64,
                        total_turns: summary.total_turns as i64,
                        exit_code: 0,
                        cancelled: summary.cancelled,
                    },
                ) {
                    tracing::warn!("TUI finalize_scan failed: {e}");
                }
            }
        }

        self.results_scroll = 0;
        self.last_scan = Some(summary);
        self.scan_progress = None;
        self.state = AppState::Results;
    }
}

/// Best-effort filename extraction. Used only for the "Opened in <name>"
/// tagline — never for path resolution — so it tolerates any input shape.
fn basename(s: &str) -> String {
    std::path::Path::new(s)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(s)
        .to_owned()
}

/// Convert one in-memory `Finding` into a `FindingRecord` for SQLite. Used
/// by `ScanProgress::commit_findings_at_finalize`. The caller is responsible
/// for grouping by `file_path` so the per-file `commit_file` API receives
/// a tight bundle.
fn summary_finding_to_record(f: &sanitai_core::finding::Finding, scan_id: &str) -> FindingRecord {
    FindingRecord {
        scan_id: scan_id.to_owned(),
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
        // v4 fields: persisted so the History → Results reload path can
        // reconstruct an actionable display row without ever storing the
        // secret value itself.
        line_in_file: f.line_in_file.map(|n| n as i64),
        fingerprint: Some(f.fingerprint_hex()),
        byte_start: Some(f.byte_range.start as i64),
        byte_end: Some(f.byte_range.end as i64),
        excerpt: Some(f.excerpt.clone()),
    }
}

/// Reconstruct an in-memory `Finding` from a stored `FindingRecord`.
///
/// The opposite of `summary_finding_to_record`. Used by
/// `App::load_selected_history_scan` to populate a `ScanSummary` shell so
/// the Results widget can render a historical scan with the same UX as a
/// live one.
///
/// Five fields don't survive the round-trip:
///   - `matched_raw` — we deliberately never persist secret values, so the
///     reconstructed finding holds an empty string. The Results detail pane
///     special-cases empty-match-with-reveal-on by showing
///     "[not stored — historical scan]".
///   - `transform: TransformChain::default()` — the transforms text we
///     persisted is human-readable JSON, not the original enum chain. Round-
///     tripping it cleanly would mean re-parsing names back to variants for
///     a display-only field. We leave it default; the detail pane shows
///     "(none)" which is honest.
///   - `span_kind: SpanKind::Single` — we don't persist span kind details.
///   - `synthetic: false` — only matters for the synthetic filter on live
///     scans; reconstructed historical findings never participate in that
///     filter.
///   - `entropy_score` — we do round-trip this from the persisted column
///     when it's `Some`, defaulting to 0.0 when null.
fn finding_record_to_finding(rec: FindingRecord) -> Finding {
    use std::path::PathBuf;
    use std::sync::Arc;

    // Finding's `detector_id` is `&'static str`. We persist arbitrary detector
    // ids as TEXT, so on reload we leak each unique id into 'static. The
    // number of distinct detector_ids in any session is bounded by the
    // detector registry (~30) plus whatever's in history (~30 again at
    // worst), so the leak is fixed-cost in practice — same trade-off the
    // redact-from-Results path already accepts.
    let detector_id: &'static str = Box::leak(rec.detector_id.into_boxed_str());

    let confidence = match rec.confidence.as_str() {
        "high" => Confidence::High,
        "medium" => Confidence::Medium,
        // "low" or anything we don't recognise — default Low so the row
        // still renders rather than crashing on a stale enum value.
        _ => Confidence::Low,
    };

    // Role round-trip: persisted as the snake_case Debug form
    // ("user", "assistant", "system", "tool"). Anything else → None.
    let role = rec.role.as_deref().and_then(|s| match s {
        "user" => Some(Role::User),
        "assistant" => Some(Role::Assistant),
        "system" => Some(Role::System),
        "tool" => Some(Role::Tool),
        _ => None,
    });

    // Category round-trip — default to Secret on anything we don't
    // recognise. Category is display-only here, so a wrong default just
    // means the detail pane reads "secret" for an old / unknown category.
    let category = rec
        .category
        .as_deref()
        .map(|s| match s {
            "secret" => Category::Secret,
            "credential" => Category::Credential,
            "pii" => Category::Pii,
            "pci" => Category::Pci,
            "highentropy" | "high_entropy" => Category::HighEntropy,
            _ => Category::Secret,
        })
        .unwrap_or(Category::Secret);

    let context_class = rec
        .context_class
        .as_deref()
        .map(|s| match s {
            "real_paste" | "realpaste" => ContextClass::RealPaste,
            "educational" => ContextClass::Educational,
            "documentation_quote" | "documentationquote" | "docquote" => {
                ContextClass::DocumentationQuote
            }
            "model_hallucination" | "modelhallucination" | "halluc" => {
                ContextClass::ModelHallucination
            }
            _ => ContextClass::Unclassified,
        })
        .unwrap_or(ContextClass::Unclassified);

    let byte_start = rec.byte_start.unwrap_or(0).max(0) as usize;
    let byte_end = rec.byte_end.unwrap_or(0).max(0) as usize;
    let byte_range = byte_start..byte_end;

    let fingerprint = rec
        .fingerprint
        .as_deref()
        .map(fingerprint_from_hex)
        .unwrap_or([0; 4]);

    let line_in_file = rec.line_in_file.and_then(|n| u32::try_from(n).ok());

    let path = PathBuf::from(rec.file_path);
    let turn_id = (Arc::new(path), rec.turn_idx.max(0) as usize);

    Finding {
        turn_id,
        detector_id,
        byte_range,
        // We never persist the secret value. Empty `matched_raw` is the
        // load-bearing signal that this is a historical row — the R-redact
        // path uses it to refuse, and the detail pane swaps the Match row
        // for "[not stored — historical scan]" when the user has reveal on.
        matched_raw: String::new(),
        transform: TransformChain::default(),
        confidence,
        span_kind: SpanKind::Single,
        synthetic: false,
        role,
        category,
        entropy_score: rec.entropy_score.unwrap_or(0.0),
        context_class,
        fingerprint,
        line_in_file,
        excerpt: rec.excerpt.unwrap_or_default(),
    }
}

/// Parse an 8-char lowercase hex fingerprint back into 4 bytes.
///
/// Tolerant: any non-hex character or unexpected length yields `[0; 4]`,
/// which renders as `00000000` and lets the Results widget keep going.
/// This pairs with `Finding::fingerprint_hex` which always emits exactly
/// 8 lowercase hex characters.
fn fingerprint_from_hex(s: &str) -> [u8; 4] {
    if s.len() != 8 {
        return [0; 4];
    }
    let mut out = [0u8; 4];
    for (i, byte_chunk) in s.as_bytes().chunks(2).enumerate() {
        if i >= 4 {
            break;
        }
        let hi = match (byte_chunk[0] as char).to_digit(16) {
            Some(v) => v as u8,
            None => return [0; 4],
        };
        let lo = match (byte_chunk[1] as char).to_digit(16) {
            Some(v) => v as u8,
            None => return [0; 4],
        };
        out[i] = (hi << 4) | lo;
    }
    out
}

/// Render the inline `R` confirmation prompt at the bottom of the Results
/// body. One row, painted with `COLOR_WARN` so it visually stands out
/// against the rest of the screen. Falls back gracefully if the body area
/// is too narrow or has zero height.
fn render_results_redact_prompt(area: Rect, buf: &mut Buffer, prompt: &ResultsRedactPrompt) {
    if area.height == 0 {
        return;
    }
    let row = area.bottom().saturating_sub(1);
    // Wipe the row so any prior content (e.g. the widget's own help line)
    // doesn't bleed through.
    buf.set_style(
        Rect {
            x: area.left(),
            y: row,
            width: area.width,
            height: 1,
        },
        Style::default().bg(COLOR_BG),
    );

    let basename = prompt
        .file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?");
    let plural = if prompt.finding_count == 1 { "" } else { "s" };
    let text = format!(
        "  Redact {} finding{} in {}? [y/n]",
        prompt.finding_count, plural, basename
    );
    buf.set_string(
        area.left(),
        row,
        text,
        Style::default().fg(COLOR_WARN).add_modifier(Modifier::BOLD),
    );
}

/// Render the footer bar.
fn render_footer(area: Rect, buf: &mut Buffer, last_scan: Option<&str>) {
    buf.set_style(area, Style::default().bg(COLOR_BG).fg(COLOR_MUTED));

    let hints =
        "\u{2191}\u{2193}/jk navigate \u{2502} Enter select \u{2502} q quit \u{2502} ? help \u{2502} Esc quit";
    buf.set_string(
        area.left(),
        area.top(),
        hints,
        Style::default().fg(COLOR_MUTED),
    );

    if let Some(label) = last_scan {
        let label_len = label.len() as u16;
        if label_len
            .saturating_add(hints.len() as u16)
            .saturating_add(4)
            < area.width
        {
            let x = area.right().saturating_sub(label_len + 1);
            buf.set_string(x, area.top(), label, Style::default().fg(COLOR_FOCUS));
        }
    }
}

/// Live scan progress body — gauge, file/byte counters, rolling throughput,
/// EWMA-based ETA, and a scrolling tail of the most recently scanned files.
/// Reads only `ScanProgress` state; the worker thread populates that via
/// `drain()` on each render tick.
fn render_scanning_body(area: Rect, buf: &mut Buffer, progress: &ScanProgress) {
    buf.set_style(area, Style::default().bg(COLOR_BG));

    if area.height == 0 {
        return;
    }

    let left = area.left().saturating_add(2);
    let mut y = area.top().saturating_add(1);

    // Title.
    let title = if progress.cancel_requested {
        "  Cancelling\u{2026}"
    } else if !progress.plan_received {
        "  Discovering conversation files\u{2026}"
    } else {
        "  Scanning conversation histories"
    };
    buf.set_string(
        left,
        y,
        title,
        Style::default()
            .fg(COLOR_FOCUS)
            .add_modifier(Modifier::BOLD),
    );
    y = y.saturating_add(2);

    // Progress bar.
    let bar_width: u16 = area.width.saturating_sub(8).min(60);
    let pct = progress.fraction();
    let filled = ((bar_width as f64) * pct).round() as u16;
    let mut bar = String::with_capacity(bar_width as usize);
    for i in 0..bar_width {
        bar.push(if i < filled { '\u{2588}' } else { '\u{2591}' });
    }
    buf.set_string(left, y, &bar, Style::default().fg(COLOR_FOCUS));
    let pct_label = format!("  {:>3}%", (pct * 100.0).round() as u32);
    buf.set_string(
        left.saturating_add(bar_width),
        y,
        &pct_label,
        Style::default().fg(COLOR_FG).add_modifier(Modifier::BOLD),
    );
    y = y.saturating_add(2);

    // Counters.
    let counters = format!(
        "  {processed_files}/{total_files} files \u{00b7} {processed_b} / {total_b} \u{00b7} {findings} findings",
        processed_files = progress.processed_files,
        total_files = progress.total_files,
        processed_b = format_bytes(progress.processed_bytes),
        total_b = format_bytes(progress.total_bytes),
        findings = progress.findings_count,
    );
    buf.set_string(left, y, &counters, Style::default().fg(COLOR_FG));
    y = y.saturating_add(1);

    // Throughput + ETA.
    let bps = progress.bytes_per_sec().unwrap_or(0.0);
    let fps = progress.files_per_sec().unwrap_or(0.0);
    let eta = match progress.eta_seconds() {
        Some(_) if progress.cancel_requested => "\u{2014}".to_owned(),
        Some(s) => format_eta(s),
        None => "calculating\u{2026}".to_owned(),
    };
    let elapsed = format_eta(progress.started_at.elapsed().as_secs());
    let throughput_line = format!(
        "  {bps}/s \u{00b7} {fps:.1} files/s \u{00b7} elapsed {elapsed} \u{00b7} ETA {eta}",
        bps = format_bytes(bps as u64),
    );
    buf.set_string(left, y, &throughput_line, Style::default().fg(COLOR_MUTED));
    y = y.saturating_add(2);

    // Recent files panel.
    buf.set_string(
        left,
        y,
        "  Recent files",
        Style::default()
            .fg(COLOR_FOCUS)
            .add_modifier(Modifier::BOLD),
    );
    y = y.saturating_add(1);
    let sep = "\u{2500}".repeat(area.width.saturating_sub(4) as usize);
    buf.set_string(left, y, &sep, Style::default().fg(COLOR_MUTED));
    y = y.saturating_add(1);

    let max_rows = area.bottom().saturating_sub(y).saturating_sub(2);
    for (i, entry) in progress
        .tail
        .iter()
        .rev()
        .take(max_rows as usize)
        .enumerate()
    {
        let row_y = y.saturating_add(i as u16);
        let row = format_tail_row(entry, area.width.saturating_sub(4));
        let style = if entry.skipped {
            Style::default().fg(COLOR_MUTED)
        } else if entry.findings > 0 {
            Style::default().fg(COLOR_WARN)
        } else {
            Style::default().fg(COLOR_SAFE)
        };
        buf.set_string(left, row_y, &row, style);
    }

    // Cancel hint at the bottom of the body.
    let footer_y = area.bottom().saturating_sub(1);
    buf.set_string(
        left,
        footer_y,
        "  q / Esc to cancel",
        Style::default().fg(COLOR_MUTED),
    );
}

fn format_bytes(b: u64) -> String {
    const KB: u64 = 1_000;
    const MB: u64 = 1_000_000;
    const GB: u64 = 1_000_000_000;
    if b >= GB {
        format!("{:.2} GB", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.1} MB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.1} KB", b as f64 / KB as f64)
    } else {
        format!("{} B", b)
    }
}

fn format_eta(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}s", secs)
    }
}

fn format_tail_row(entry: &FileTailEntry, width: u16) -> String {
    let prefix = if entry.skipped {
        "  \u{00b7} "
    } else if entry.findings > 0 {
        "  \u{2716} "
    } else {
        "  \u{2713} "
    };
    let size = format_bytes(entry.size);
    let suffix = if entry.skipped {
        format!("[{}, skipped]", size)
    } else if entry.findings > 0 {
        format!(
            "[{}, {} finding{}]",
            size,
            entry.findings,
            if entry.findings == 1 { "" } else { "s" }
        )
    } else {
        format!("[{}, clean]", size)
    };
    let max_name =
        (width as usize).saturating_sub(prefix.chars().count() + suffix.chars().count() + 2);
    let name: String = if entry.name.chars().count() > max_name {
        let truncated: String = entry
            .name
            .chars()
            .take(max_name.saturating_sub(1))
            .collect();
        format!("{}\u{2026}", truncated)
    } else {
        entry.name.clone()
    };
    format!("{prefix}{name}  {suffix}")
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
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    loop {
        // Drain progress events at the top of each tick. If the worker has
        // emitted Done, finalize and let the next iteration render Results.
        if app.state == AppState::Scanning {
            if let Some(ref mut sp) = app.scan_progress {
                if let Some(summary) = sp.drain() {
                    app.finalize_scan(summary);
                }
            }
        }

        terminal.draw(|frame| {
            let area = frame.area();
            let buf = frame.buffer_mut();

            buf.set_style(area, Style::default().bg(COLOR_BG));

            let (banner_area, body_area, footer_area) = main_layout(area);
            app.banner.render(banner_area, buf, &app.current_tagline);

            match app.state {
                AppState::Menu => {
                    app.menu.render(body_area, buf);
                }

                AppState::Results => {
                    if let Some(ref summary) = app.last_scan {
                        let widget = ResultsWidget {
                            summary,
                            scroll: app.results_scroll,
                            filter: Some(&app.filter),
                            suppressions: &app.suppressions,
                            detail_open: app.results_detail_open,
                            reveal_secrets: app.app_settings.reveal_secrets,
                        };
                        (&widget).render(body_area, buf);
                    }
                    // Inline `R` redact confirmation overlay — paints over
                    // the bottom row of the body so the user stays in the
                    // Results view. The Results widget's own footer is
                    // already drawn at the row just below; we deliberately
                    // overwrite the last *body* row so we don't fight the
                    // global footer.
                    if let Some(ref prompt) = app.results_redact_prompt {
                        render_results_redact_prompt(body_area, buf, prompt);
                    }
                }

                AppState::History => {
                    if let Some(ref mut hs) = app.history_screen {
                        hs.render(body_area, buf);
                    }
                }

                AppState::Settings => {
                    app.settings_screen.render(body_area, buf);
                }

                AppState::Redact => {
                    if let Some(ref mut rs) = app.redact_screen {
                        rs.render(body_area, buf);
                    }
                }

                AppState::Scanning => {
                    if let Some(ref sp) = app.scan_progress {
                        render_scanning_body(body_area, buf, sp);
                    }
                }
            }

            render_footer(footer_area, buf, app.last_scan_label.as_deref());

            // Help overlay renders on top of any state.
            if app.show_help {
                let overlay = HelpOverlay;
                (&overlay).render(area, buf);
            }
        })?;

        // Tighter poll while scanning so the progress UI updates at ~30 Hz.
        let poll_ms = if app.state == AppState::Scanning {
            33
        } else {
            100
        };
        if event::poll(Duration::from_millis(poll_ms))? {
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
    use sanitai_core::finding::{Confidence, ContextClass, Finding, SpanKind, TransformChain};
    use sanitai_core::traits::Category;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn sample_finding() -> Finding {
        let path = PathBuf::from("/tmp/x");
        let fingerprint =
            sanitai_core::finding::compute_fingerprint(b"abcd", "test_rule", &path, 0);
        Finding {
            turn_id: (Arc::new(path), 0),
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
            fingerprint,
            line_in_file: None,
            excerpt: String::new(),
        }
    }

    #[test]
    fn results_filter_hides_educational_by_default() {
        let mut f1 = sample_finding();
        f1.context_class = ContextClass::RealPaste;
        let mut f2 = sample_finding();
        f2.context_class = ContextClass::Educational;

        let filter = ResultsFilter::default();
        assert!(
            filter.matches(&f1),
            "RealPaste should be visible by default"
        );
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

#[cfg(test)]
mod results_redact_tests {
    //! Tests for the R-from-Results inline confirmation flow.
    //!
    //! These tests construct an `App` directly via struct-literal so they
    //! sidestep `App::new()` (which would touch the user's real history
    //! store). The cost is a verbose setup helper; the benefit is that
    //! every test runs hermetically against a tempdir source file.
    //!
    //! We verify three things end-to-end:
    //! 1. Pressing `R` on Results lands the app in the redact-confirm
    //!    sub-state with the correct file + finding count captured.
    //! 2. Pressing `y` runs the configured `RedactMode` against the file
    //!    (we check the on-disk output for mode-specific markers).
    //! 3. Pressing `n` cancels without writing.
    use super::*;
    use crossterm::event::KeyCode;
    use sanitai_core::config::RedactMode;
    use sanitai_core::finding::{Confidence, ContextClass, Finding, SpanKind, TransformChain};
    use sanitai_core::traits::Category;
    use std::sync::Arc;

    /// Build a minimal `Finding` whose byte_range points at a substring
    /// in `content`. Caller-supplied `start..end` must be on char
    /// boundaries; we trust the test author here.
    fn finding_in(path: &std::path::Path, content: &str, needle: &str) -> Finding {
        let start = content.find(needle).expect("needle in content");
        let end = start + needle.len();
        let arc = Arc::new(path.to_path_buf());
        let fingerprint =
            sanitai_core::finding::compute_fingerprint(needle.as_bytes(), "test_rule", path, 0);
        Finding {
            turn_id: (arc, 0),
            detector_id: "test_rule",
            byte_range: start..end,
            matched_raw: needle.to_owned(),
            transform: TransformChain::default(),
            confidence: Confidence::High,
            span_kind: SpanKind::Single,
            synthetic: false,
            role: None,
            category: Category::Secret,
            entropy_score: 0.0,
            context_class: ContextClass::Unclassified,
            fingerprint,
            line_in_file: None,
            excerpt: String::new(),
        }
    }

    /// Construct an `App` with hand-populated state, bypassing `App::new()`.
    /// Returns the App configured for `AppState::Results` with one finding
    /// pointing at `source_path`. The corresponding ScanSummary is stored
    /// so `selected_finding()` returns the test's finding.
    fn app_with_results(
        source_path: &std::path::Path,
        content: &str,
        needle: &str,
        redact_mode: RedactMode,
    ) -> App {
        let settings = AppSettings {
            redact_mode,
            ..AppSettings::default()
        };
        let settings_screen = SettingsScreen::new(settings.clone());

        let f = finding_in(source_path, content, needle);

        let summary = ScanSummary {
            scan_id: "test".to_owned(),
            started_at_ns: 0,
            total_files: 1,
            total_turns: 1,
            findings_high: 1,
            findings_medium: 0,
            findings_low: 0,
            duration_ms: 1,
            paths: vec![source_path.to_path_buf()],
            findings: vec![f],
            cancelled: false,
        };

        App {
            menu: Menu::new(),
            state: AppState::Results,
            current_tagline: String::new(),
            banner: Banner::new(),
            last_scan: Some(summary),
            last_scan_label: None,
            should_quit: false,
            results_scroll: 0,
            results_detail_open: false,
            results_redact_prompt: None,
            history_screen: None,
            settings_screen,
            redact_screen: None,
            scan_progress: None,
            show_help: false,
            app_settings: settings,
            filter: ResultsFilter::default(),
            suppressions: Suppressions::default(),
        }
    }

    /// Pressing `R` on the Results screen arms the inline prompt with
    /// the selected finding's file and the count of findings in that
    /// file.
    #[test]
    fn shift_r_lands_in_confirm_sub_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("conv.jsonl");
        std::fs::write(&path, "secret: AKIAFAKE12345EXAMPLE\n").unwrap();
        let mut app = app_with_results(
            &path,
            "secret: AKIAFAKE12345EXAMPLE\n",
            "AKIAFAKE12345EXAMPLE",
            RedactMode::Mask,
        );

        assert!(app.results_redact_prompt.is_none(), "no prompt before R");
        app.handle_key(KeyCode::Char('R'));
        let prompt = app
            .results_redact_prompt
            .as_ref()
            .expect("R should arm the inline prompt");
        assert_eq!(prompt.file, path);
        assert_eq!(prompt.finding_count, 1);
    }

    /// Pressing `y` while the prompt is up runs the redactor with the
    /// configured mode and writes `<file>.sanitized`. We use Mask here
    /// because its replacement is a fixed string (`[REDACTED]`) that's
    /// trivial to assert.
    #[test]
    fn y_runs_redactor_with_configured_mode_mask() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("conv.jsonl");
        let content = "key=AKIAFAKE12345EXAMPLE end\n";
        std::fs::write(&path, content).unwrap();
        let mut app = app_with_results(&path, content, "AKIAFAKE12345EXAMPLE", RedactMode::Mask);

        app.handle_key(KeyCode::Char('R'));
        app.handle_key(KeyCode::Char('y'));

        // Prompt should be cleared; output file should exist with the
        // mask replacement applied.
        assert!(app.results_redact_prompt.is_none(), "y clears the prompt");
        let out_path = path.with_extension("jsonl.sanitized");
        let written = std::fs::read_to_string(&out_path).expect("output written");
        assert_eq!(written, "key=[REDACTED] end\n");
        assert!(
            app.current_tagline.contains("Wrote 1 redaction"),
            "tagline should announce the redaction; got: {}",
            app.current_tagline
        );
    }

    /// Pressing `y` with `RedactMode::VaultRef` produces the
    /// vault-style placeholder. Proves the `app_settings.redact_mode`
    /// value is the one actually plumbed to `Redactor::new` rather
    /// than a hard-coded default.
    #[test]
    fn y_runs_redactor_with_configured_mode_vaultref() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("conv.jsonl");
        let content = "key=AKIAFAKE12345EXAMPLE end\n";
        std::fs::write(&path, content).unwrap();
        let mut app =
            app_with_results(&path, content, "AKIAFAKE12345EXAMPLE", RedactMode::VaultRef);

        app.handle_key(KeyCode::Char('R'));
        app.handle_key(KeyCode::Char('y'));

        let out_path = path.with_extension("jsonl.sanitized");
        let written = std::fs::read_to_string(&out_path).expect("output written");
        assert!(
            written.contains("${VAULT:test_rule_1}"),
            "expected VaultRef placeholder; got: {written:?}"
        );
    }

    /// Pressing `n` while the prompt is up cancels — no file is written
    /// and the prompt is cleared.
    #[test]
    fn n_cancels_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("conv.jsonl");
        let content = "key=AKIAFAKE12345EXAMPLE end\n";
        std::fs::write(&path, content).unwrap();
        let mut app = app_with_results(&path, content, "AKIAFAKE12345EXAMPLE", RedactMode::Mask);

        app.handle_key(KeyCode::Char('R'));
        assert!(app.results_redact_prompt.is_some());
        app.handle_key(KeyCode::Char('n'));

        assert!(app.results_redact_prompt.is_none(), "n clears the prompt");
        let out_path = path.with_extension("jsonl.sanitized");
        assert!(!out_path.exists(), "n must not write the .sanitized output");
    }

    /// While the prompt is up, navigation keys (jk, Tab, etc.) must not
    /// act on the underlying Results view. The prompt absorbs everything
    /// except y/n/Esc.
    #[test]
    fn prompt_absorbs_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("conv.jsonl");
        std::fs::write(&path, "k\n").unwrap();
        let mut app = app_with_results(&path, "k\n", "k", RedactMode::Mask);

        app.handle_key(KeyCode::Char('R'));
        let scroll_before = app.results_scroll;
        app.handle_key(KeyCode::Char('j')); // would normally scroll
        app.handle_key(KeyCode::Tab); // would normally toggle filter
                                      // Prompt must still be up; scroll and filter must be unchanged.
        assert!(app.results_redact_prompt.is_some());
        assert_eq!(app.results_scroll, scroll_before);
        assert!(!app.filter.show_all_context);
    }
}

#[cfg(test)]
mod history_reload_tests {
    //! Tests for the History → Results "Enter to load" flow.
    //!
    //! Two behaviours under test:
    //!
    //! 1. Enter on a History row reconstructs a `ScanSummary` from the
    //!    persisted scan + findings rows and lands the app in
    //!    `AppState::Results` with that summary as `last_scan`.
    //! 2. The reconstructed finding has empty `matched_raw` and (in the
    //!    test fixture) empty `byte_range`. Pressing `R` on it must refuse
    //!    with the historical-scan tagline; no `<file>.sanitized` may be
    //!    written.
    //!
    //! All Store I/O goes through a tempfile-backed handle; the user's
    //! real `~/.local/share/sanitai/history.db` is never touched.
    use super::*;
    use crossterm::event::KeyCode;
    use sanitai_core::config::RedactMode;
    use sanitai_store::{BeginScanRecord, FinalizeScanInput, FindingRecord, Store};

    /// Build a minimal `App` in `AppState::History` with the given list of
    /// records pre-populated and `selected` pointing at the first.
    fn app_with_history(records: Vec<sanitai_store::ScanRecord>) -> App {
        let settings = AppSettings::default();
        let settings_screen = SettingsScreen::new(settings.clone());
        App {
            menu: Menu::new(),
            state: AppState::History,
            current_tagline: String::new(),
            banner: Banner::new(),
            last_scan: None,
            last_scan_label: None,
            should_quit: false,
            results_scroll: 0,
            results_detail_open: false,
            results_redact_prompt: None,
            history_screen: Some(crate::history_screen::HistoryScreen::new(records)),
            settings_screen,
            redact_screen: None,
            scan_progress: None,
            show_help: false,
            app_settings: settings,
            filter: ResultsFilter::default(),
            suppressions: crate::suppressions::Suppressions::default(),
        }
    }

    /// Seed a tempfile-backed Store with a single completed scan that has
    /// two findings. Returns the Store, the temp DB file, the seeded
    /// `ScanRecord`, and the tempdir holding the conversation file path
    /// the findings reference (so `.sanitized` write checks have a stable
    /// root to inspect).
    fn seed_store_with_scan() -> (
        Store,
        tempfile::NamedTempFile,
        sanitai_store::ScanRecord,
        tempfile::TempDir,
    ) {
        let f = tempfile::NamedTempFile::new().unwrap();
        let store = Store::open_at(f.path()).unwrap();
        let conv_dir = tempfile::tempdir().unwrap();
        let conv_path = conv_dir.path().join("hist.jsonl");
        let conv_path_str = conv_path.to_string_lossy().into_owned();

        let scan_id = "01HISTORY_RELOAD".to_owned();
        store
            .begin_scan(&BeginScanRecord {
                scan_id: scan_id.clone(),
                started_at_ns: 1_700_000_000_000_000_000,
                project_name: Some("hist-test".to_owned()),
                claude_account: None,
                total_files: 1,
                format: "tui".to_owned(),
            })
            .unwrap();

        let mk = |det: &str, conf: &str, fp: &str| FindingRecord {
            scan_id: scan_id.clone(),
            detector_id: det.to_owned(),
            file_path: conv_path_str.clone(),
            turn_idx: 0,
            confidence: conf.to_owned(),
            transforms: "[]".to_owned(),
            synthetic: false,
            role: Some("user".to_owned()),
            category: Some("secret".to_owned()),
            entropy_score: Some(4.2),
            context_class: Some("real_paste".to_owned()),
            secret_hash: None,
            line_in_file: Some(11),
            // We deliberately leave byte_start == byte_end so the
            // reconstructed Finding has an empty byte_range — the same
            // shape the R-redact path treats as "historical, refuse".
            fingerprint: Some(fp.to_owned()),
            byte_start: Some(0),
            byte_end: Some(0),
            excerpt: Some("ctx [FP:".to_owned() + fp + "] more"),
        };

        store
            .commit_file(
                &scan_id,
                &conv_path_str,
                &[
                    mk("aws_access_key", "high", "deadbeef"),
                    mk("github_pat", "medium", "cafef00d"),
                ],
            )
            .unwrap();

        store
            .finalize_scan(
                &scan_id,
                &FinalizeScanInput {
                    duration_ms: 99,
                    total_turns: 3,
                    exit_code: 1,
                    cancelled: false,
                },
            )
            .unwrap();

        let rec = store
            .recent_scans(1)
            .unwrap()
            .into_iter()
            .next()
            .expect("seeded record present");
        (store, f, rec, conv_dir)
    }

    #[test]
    fn enter_on_history_loads_summary() {
        let (store, _tmp, record, _conv_dir) = seed_store_with_scan();
        let mut app = app_with_history(vec![record.clone()]);

        // Sanity: starting state is History with no last_scan.
        assert_eq!(app.state, AppState::History);
        assert!(app.last_scan.is_none());

        // Drive the same code path Enter triggers in `handle_key`. We can't
        // call `handle_key(Enter)` directly because that branch calls
        // `Store::open()` (the user's real DB); the inner method takes the
        // store explicitly so tests can pass a tempfile-backed handle.
        app.load_history_scan_from_store(&store, record.clone());

        assert_eq!(
            app.state,
            AppState::Results,
            "Enter on History must transition to Results",
        );
        let summary = app
            .last_scan
            .as_ref()
            .expect("last_scan must be populated after reload");
        assert_eq!(summary.scan_id, record.scan_id);
        assert_eq!(summary.duration_ms, record.duration_ms as u64);
        assert_eq!(summary.findings_high, record.findings_high as usize);
        assert_eq!(summary.findings_medium, record.findings_medium as usize);
        assert_eq!(
            summary.findings.len(),
            2,
            "both seeded findings must round-trip into the summary",
        );
        // matched_raw must be empty — we never persist secret values.
        for f in &summary.findings {
            assert!(
                f.matched_raw.is_empty(),
                "historical findings must have empty matched_raw",
            );
        }
        // Tagline announces the load with the 8-char short ULID.
        assert!(
            app.current_tagline.contains("Loaded scan"),
            "tagline must announce the load; got: {}",
            app.current_tagline,
        );
        assert!(
            app.current_tagline.contains("01HISTOR"),
            "tagline must include the 8-char short scan id; got: {}",
            app.current_tagline,
        );
        // Selection state is reset.
        assert_eq!(app.results_scroll, 0);
        assert!(!app.results_detail_open);
        assert!(app.results_redact_prompt.is_none());
    }

    #[test]
    fn historical_finding_with_empty_match_refuses_redact() {
        let (store, _tmp, record, conv_dir) = seed_store_with_scan();
        let mut app = app_with_history(vec![record.clone()]);
        app.load_history_scan_from_store(&store, record.clone());
        // Sanity: we landed in Results.
        assert_eq!(app.state, AppState::Results);
        // The first finding has empty byte_range and empty matched_raw.
        let selected = app.selected_finding().expect("a finding must be selected");
        assert!(selected.matched_raw.is_empty());
        assert_eq!(selected.byte_range.start, selected.byte_range.end);

        // Press R — must refuse without arming the prompt.
        app.handle_key(KeyCode::Char('R'));
        assert!(
            app.results_redact_prompt.is_none(),
            "R on a historical finding must NOT arm the prompt",
        );
        assert!(
            app.current_tagline
                .contains("Cannot redact historical scan"),
            "tagline must announce the refusal; got: {}",
            app.current_tagline,
        );

        // The redactor must never run, so no `.sanitized` sibling should
        // exist next to the historical conversation file. The conversation
        // path lives inside a fresh tempdir (see seed_store_with_scan), so
        // any leftover from prior tests is impossible — the assertion is
        // crisp.
        let sanitized = conv_dir.path().join("hist.jsonl.sanitized");
        assert!(
            !sanitized.exists(),
            ".sanitized file must NOT be written when redact is refused; got: {}",
            sanitized.display(),
        );

        // The mode used here is irrelevant — the refusal happens before
        // the redactor is consulted. We just verify state is unchanged.
        let _ = RedactMode::Mask;
    }
}
