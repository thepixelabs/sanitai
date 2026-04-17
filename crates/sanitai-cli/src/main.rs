// sanitai — scan LLM conversation histories for leaked secrets and PII.
//
// 100% local processing. No network calls. Sandboxed via seccomp-bpf (Linux)
// or Seatbelt (macOS) before any untrusted input is read.
//
// Exit codes:
//   0 — clean (no reportable findings)
//   1 — findings present (suppressed with --exit-zero)
//   2 — fatal error (I/O, parse failure, sandbox error)

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use futures::StreamExt;
use sanitai_core::{
    chunk::{ChunkerConfig, DetectorScratch},
    chunker::chunk_turn,
    config::RedactMode,
    finding::{Confidence, Finding, SpanKind, Transform, TransformChain},
    traits::{ConversationParser, Detector, Sniff, SourceHint},
    CoreError, ReadSeek, Turn,
};
use sanitai_detectors::{
    CrossTurnConfig, CrossTurnCorrelator, RegexDetector, TransformConfig, TransformDetector,
};
use sanitai_parsers::{
    discover_all, ChatGptParser, ClaudeJsonlParser, CopilotParser, CursorParser, GeminiParser,
};
use sanitai_redactor::Redactor;
use sanitai_sandbox::create_sandbox;
use sanitai_store::{FindingRecord, ScanRecord, Store};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

mod sarif;

// ---------------------------------------------------------------------------
// Arg types
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "sanitai",
    version,
    about = "Scan LLM conversation histories for leaked secrets — 100% local, no network",
    long_about = "SanitAI scans Claude, ChatGPT, and other LLM conversation files for \
                  secrets, credentials, and PII. All processing is local; no data ever \
                  leaves the machine."
)]
struct Cli {
    /// Increase log verbosity. Use up to -vvvv for trace output.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Path to config file. Defaults to auto-discovery (local sanitai.toml → global).
    #[arg(long, value_name = "FILE", global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan conversation histories for secrets and PII
    Scan(ScanArgs),
    /// Redact findings from a conversation file (prints to stdout)
    Redact(RedactArgs),
    /// Self-test: verify sandbox is active and detectors can find a synthetic secret
    Verify(VerifyArgs),
    /// Launch the interactive TUI (requires a terminal)
    Tui(TuiArgs),
    /// List discovered LLM conversation sources on this machine
    Discover(DiscoverArgs),
}

#[derive(clap::Args)]
struct TuiArgs {}

#[derive(clap::Args)]
struct DiscoverArgs {
    /// Show full absolute paths (default: relative to home directory)
    #[arg(long)]
    absolute: bool,
}

#[derive(clap::Args)]
struct ScanArgs {
    /// Paths to scan (files or directories). Omit to auto-discover known sources.
    #[arg(value_name = "PATH")]
    path: Vec<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "human")]
    format: OutputFormat,

    /// Minimum confidence level to report.
    /// If omitted, falls back to config's `scan.confidence_threshold`
    /// (>=0.85 → high, >=0.50 → medium, else low).
    #[arg(long, value_enum)]
    confidence: Option<ConfidenceFilter>,

    /// Exit 0 even when findings are present (useful for non-blocking canary scans)
    #[arg(long)]
    exit_zero: bool,

    /// Include synthetic test secrets (findings carrying the SANITAI_FAKE marker)
    #[arg(long)]
    include_synthetic: bool,

    /// Disable OS process sandbox — only for debugging; never in production
    #[arg(long, hide = true)]
    no_sandbox: bool,

    /// Show all findings including educational and documentation-quote classifications.
    /// By default, findings classified as Educational or DocumentationQuote are hidden
    /// from human output and the exit-code decision. JSON/SARIF output is unaffected —
    /// consumers filter using the `context_class` field.
    #[arg(long)]
    show_all: bool,
}

#[derive(clap::Args)]
struct VerifyArgs {
    /// Disable sandbox check (useful in CI environments that restrict seccomp)
    #[arg(long)]
    no_sandbox: bool,
}

#[derive(clap::Args)]
struct RedactArgs {
    /// Source file to redact (prints redacted content to stdout)
    file: PathBuf,

    /// Findings JSON file produced by `sanitai scan --format json`
    #[arg(long, value_name = "FILE")]
    findings: PathBuf,

    /// Redaction mode
    #[arg(long, value_enum, default_value = "mask")]
    mode: RedactModeArg,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    /// SARIF 2.1.0 (Static Analysis Results Interchange Format)
    Sarif,
}

#[derive(Clone, ValueEnum)]
enum ConfidenceFilter {
    High,
    Medium,
    Low,
}

#[derive(Clone, ValueEnum)]
enum RedactModeArg {
    Mask,
    Hash,
    Partial,
    VaultRef,
}

// ---------------------------------------------------------------------------
// JSON output schema (never includes matched_raw)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct FindingJson {
    file: String,
    turn: usize,
    detector: String,
    confidence: String,
    byte_start: usize,
    byte_end: usize,
    transforms: Vec<String>,
    synthetic: bool,
}

impl From<&Finding> for FindingJson {
    fn from(f: &Finding) -> Self {
        Self {
            file: f.turn_id.0.to_string_lossy().into_owned(),
            turn: f.turn_id.1,
            detector: f.detector_id.to_owned(),
            confidence: match f.confidence {
                Confidence::High => "high",
                Confidence::Medium => "medium",
                Confidence::Low => "low",
            }
            .to_owned(),
            byte_start: f.byte_range.start,
            byte_end: f.byte_range.end,
            transforms: f
                .transform
                .0
                .iter()
                .map(|t| {
                    match t {
                        Transform::Base64 => "base64",
                        Transform::Hex => "hex",
                        Transform::UrlEncoded => "url",
                        Transform::Gzip => "gzip",
                        Transform::HtmlEntity => "html",
                    }
                    .to_owned()
                })
                .collect(),
            synthetic: f.synthetic,
        }
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    // Harden the process BEFORE argument parsing so that core dumps are
    // disabled and ptrace is denied even if early init (clap, env parsing)
    // somehow touches sensitive memory. No-op on unsupported platforms.
    sanitai_core::secure::harden_process();

    let cli = Cli::parse();

    let level = match cli.verbose {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .with_writer(std::io::stderr)
        .init();

    let cfg_path = cli.config.clone();
    let exit_code = match cli.command {
        Commands::Scan(args) => run_scan(args, cfg_path.as_deref()),
        Commands::Redact(args) => run_redact(args, cfg_path.as_deref()),
        Commands::Verify(args) => run_verify(args),
        Commands::Tui(_args) => run_tui(),
        Commands::Discover(args) => run_discover(args),
    };
    std::process::exit(exit_code);
}

// ---------------------------------------------------------------------------
// config helper
// ---------------------------------------------------------------------------

/// Load config from explicit path if provided, otherwise from the auto-
/// discovery chain. Failures on auto-discovery fall back to defaults with a
/// warning; failures on an explicit path are fatal (user asked for that file).
fn load_cli_config(
    explicit: Option<&std::path::Path>,
) -> Result<sanitai_core::config::SanitaiConfig, CoreError> {
    match explicit {
        Some(p) => sanitai_core::config::load_config_from(p),
        None => Ok(sanitai_core::config::load_config().unwrap_or_else(|e| {
            tracing::warn!("config load failed ({e}), using defaults");
            sanitai_core::config::SanitaiConfig::default()
        })),
    }
}

/// Map the float confidence threshold from config into the CLI's discrete
/// filter. Thresholds follow the documented buckets: >=0.85 high, >=0.50
/// medium, below that low.
fn threshold_to_filter(t: f32) -> ConfidenceFilter {
    if t >= 0.85 {
        ConfidenceFilter::High
    } else if t >= 0.50 {
        ConfidenceFilter::Medium
    } else {
        ConfidenceFilter::Low
    }
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

fn run_scan(args: ScanArgs, config_path: Option<&std::path::Path>) -> i32 {
    // Capture timing and generate a unique scan ID before any work begins.
    let scan_id = Ulid::new().to_string();
    let scan_start = Instant::now();
    let started_at_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos() as i64;

    // Load config first — an explicit --config failure is fatal.
    let cfg = match load_cli_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sanitai: config error: {e}");
            return 2;
        }
    };

    // Resolve confidence filter: explicit --confidence wins, otherwise derive
    // from config's float threshold.
    let confidence_filter = args
        .confidence
        .clone()
        .unwrap_or_else(|| threshold_to_filter(cfg.scan.confidence_threshold));

    // Phase-1 sandbox: permissive (permits dynamic linker + rayon thread setup)
    let sandbox = create_sandbox();
    if !args.no_sandbox {
        if let Err(e) = sandbox.apply_permissive() {
            tracing::warn!("sandbox permissive phase failed: {e}");
        }
    }

    // Resolve source paths
    let raw_paths: Vec<PathBuf> = if args.path.is_empty() {
        let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let discovered = discover_all(&home);
        if discovered.is_empty() {
            eprintln!(
                "sanitai: no conversation histories found via auto-discovery.\n\
                 Try: sanitai scan <path>"
            );
        }
        discovered.into_iter().map(|d| d.path).collect()
    } else {
        // Preserve `-` as a sentinel stdin path (do not pass through expand_paths,
        // which would try to stat it as a file/dir).
        let (stdin_paths, file_args): (Vec<_>, Vec<_>) = args
            .path
            .iter()
            .cloned()
            .partition(|p| p.as_os_str() == "-");
        let mut out = expand_paths(&file_args);
        out.extend(stdin_paths);
        out
    };

    let (stdin_paths, file_paths): (Vec<PathBuf>, Vec<PathBuf>) =
        raw_paths.into_iter().partition(|p| p.as_os_str() == "-");

    // Build detectors once. RegexDetector::new() is cheap (sets a &'static pointer).
    // `regex_arc` is shared between the TransformDetector and the CrossTurnCorrelator.
    let regex_arc = Arc::new(RegexDetector::new());
    let detectors: Vec<Box<dyn sanitai_core::traits::Detector>> = vec![
        Box::new(RegexDetector::new()),
        Box::new(TransformDetector::new(
            Arc::clone(&regex_arc),
            TransformConfig::default(),
        )),
    ];

    let chunker_cfg = ChunkerConfig::default();
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut total_turns: usize = 0;
    let mut scanned_file_paths: Vec<String> = Vec::new();

    // Cross-turn correlator: one instance shared across all files so that a
    // secret split across the end of one file and the start of the next is
    // still caught. (File order is deterministic from CLI / discovery.)
    let mut correlator =
        CrossTurnCorrelator::new(Arc::clone(&regex_arc), CrossTurnConfig::default());

    // Read stdin BEFORE applying the strict sandbox. On Linux seccomp-bpf the
    // `read` syscall on fd 0 is on the allowlist, but reading stdin up front
    // keeps the behaviour identical across platforms and lets us treat the
    // sandbox boundary as "no new input sources after this point".
    let mut stdin_findings: Vec<Finding> = Vec::new();
    for _ in &stdin_paths {
        scanned_file_paths.push("<stdin>".to_owned());
        match scan_stdin(&detectors, &chunker_cfg, &mut correlator) {
            Ok(findings) => stdin_findings.extend(findings),
            Err(e) => tracing::warn!("stdin scan error: {e}"),
        }
    }

    // Phase-2 sandbox: strict (blocks network + exec before touching untrusted data)
    if !args.no_sandbox {
        if let Err(e) = sandbox.apply_strict() {
            tracing::warn!("sandbox strict phase failed: {e}");
        }
    }

    for f in stdin_findings {
        if f.is_synthetic() && !args.include_synthetic {
            continue;
        }
        if confidence_passes(&f.confidence, &confidence_filter) {
            all_findings.push(f);
        }
    }

    for path in &file_paths {
        scanned_file_paths.push(path.to_string_lossy().into_owned());
        match scan_path(path, &detectors, &chunker_cfg, Some(&mut correlator)) {
            Ok((findings, turns)) => {
                total_turns += turns;
                for f in findings {
                    if f.is_synthetic() && !args.include_synthetic {
                        continue;
                    }
                    if confidence_passes(&f.confidence, &confidence_filter) {
                        all_findings.push(f);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), "scan error: {e}");
            }
        }
    }

    // Build the human-view filter. Unless --show-all is set, hide findings
    // classified as Educational or DocumentationQuote. JSON/SARIF outputs
    // always include every finding so programmatic consumers can filter
    // using the `context_class` field themselves.
    let display_findings: Vec<Finding> = if args.show_all {
        all_findings.clone()
    } else {
        all_findings
            .iter()
            .filter(|f| {
                use sanitai_core::finding::ContextClass;
                !matches!(
                    f.context_class,
                    ContextClass::Educational | ContextClass::DocumentationQuote
                )
            })
            .cloned()
            .collect()
    };

    // Exit code reflects the human-visible view: if the user runs without
    // --show-all and every finding was suppressed, the tool exits clean.
    let has_findings = !display_findings.is_empty();

    match args.format {
        OutputFormat::Human => print_human(&display_findings),
        OutputFormat::Json => {
            if let Err(e) = print_json(&all_findings) {
                eprintln!("sanitai: JSON output error: {e}");
                return 2;
            }
        }
        OutputFormat::Sarif => {
            if let Err(e) = print_sarif(&all_findings, env!("CARGO_PKG_VERSION")) {
                eprintln!("sanitai: SARIF output error: {e}");
                return 2;
            }
        }
    }

    // ── history store write (non-fatal) ─────────────────────────────────────
    let elapsed_ms = scan_start.elapsed().as_millis() as i64;
    let project_name = infer_project_name(&file_paths);
    let claude_account = infer_claude_account(&file_paths);

    let scan_record = ScanRecord {
        scan_id: scan_id.clone(),
        started_at_ns,
        duration_ms: elapsed_ms,
        project_name,
        claude_account,
        total_files: scanned_file_paths.len() as i64,
        total_turns: total_turns as i64,
        format: match args.format {
            OutputFormat::Human => "human",
            OutputFormat::Json => "json",
            OutputFormat::Sarif => "sarif",
        }
        .to_owned(),
        exit_code: if has_findings && !args.exit_zero {
            1
        } else {
            0
        },
        findings_high: all_findings
            .iter()
            .filter(|f| matches!(f.confidence, Confidence::High))
            .count() as i64,
        findings_medium: all_findings
            .iter()
            .filter(|f| matches!(f.confidence, Confidence::Medium))
            .count() as i64,
        findings_low: all_findings
            .iter()
            .filter(|f| matches!(f.confidence, Confidence::Low))
            .count() as i64,
    };

    let finding_records: Vec<FindingRecord> = all_findings
        .iter()
        .map(|f| FindingRecord {
            scan_id: scan_id.clone(),
            detector_id: f.detector_id.to_owned(),
            file_path: f.turn_id.0.to_string_lossy().into_owned(),
            turn_idx: f.turn_id.1 as i64,
            confidence: match f.confidence {
                Confidence::High => "high",
                Confidence::Medium => "medium",
                Confidence::Low => "low",
            }
            .to_owned(),
            transforms: {
                let names: Vec<&str> = f
                    .transform
                    .0
                    .iter()
                    .map(|t| match t {
                        Transform::Base64 => "base64",
                        Transform::Hex => "hex",
                        Transform::UrlEncoded => "url",
                        Transform::Gzip => "gzip",
                        Transform::HtmlEntity => "html",
                    })
                    .collect();
                serde_json::to_string(&names).unwrap_or_else(|_| "[]".to_owned())
            },
            synthetic: f.synthetic,
            role: f.role.as_ref().map(|r| format!("{r:?}").to_lowercase()),
            category: Some(format!("{:?}", f.category).to_lowercase()),
            entropy_score: Some(f.entropy_score),
            context_class: Some(format!("{:?}", f.context_class).to_lowercase()),
            // secret_hash is computed by the store layer with the installation
            // key in a later phase; None for now.
            secret_hash: None,
        })
        .collect();

    match Store::open() {
        Ok(store) => {
            if let Err(e) = store.record_scan(&scan_record, &scanned_file_paths, &finding_records) {
                tracing::warn!("history store write failed: {e}");
            }
        }
        Err(e) => tracing::warn!("history store open failed: {e}"),
    }
    // ────────────────────────────────────────────────────────────────────────

    if has_findings && !args.exit_zero {
        1
    } else {
        0
    }
}

fn scan_path(
    path: &std::path::Path,
    detectors: &[Box<dyn sanitai_core::traits::Detector>],
    chunker_cfg: &ChunkerConfig,
    mut correlator: Option<&mut CrossTurnCorrelator>,
) -> Result<(Vec<Finding>, usize)> {
    // Read head bytes for parser sniffing (up to 4 KB)
    let mut head_buf = [0u8; 4096];
    let head_len = {
        let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
        f.read(&mut head_buf)
            .with_context(|| format!("read head {}", path.display()))?
    };
    let hint = SourceHint {
        path,
        head: &head_buf[..head_len],
    };

    // Sniff which parser handles this file. We build each parser once and
    // ask it to score the hint; the highest score wins. Ties prefer the
    // more specific parsers (Claude before ChatGPT before the newcomers)
    // via the declaration order below.
    let claude = ClaudeJsonlParser::with_path(path.to_path_buf());
    let chatgpt = ChatGptParser::with_path(path.to_path_buf());
    let cursor = CursorParser::with_path(path.to_path_buf());
    let copilot = CopilotParser::with_path(path.to_path_buf());
    let gemini = GeminiParser::with_path(path.to_path_buf());

    let scores: [(&str, u8); 5] = [
        ("claude", sniff_score(claude.can_parse(&hint))),
        ("chatgpt", sniff_score(chatgpt.can_parse(&hint))),
        ("cursor", sniff_score(cursor.can_parse(&hint))),
        ("copilot", sniff_score(copilot.can_parse(&hint))),
        ("gemini", sniff_score(gemini.can_parse(&hint))),
    ];
    let Some(winner) = scores
        .iter()
        .filter(|(_, s)| *s > 0)
        .max_by_key(|(_, s)| *s)
        .map(|(name, _)| *name)
    else {
        tracing::debug!(path = %path.display(), "no parser recognises this file; skipping");
        return Ok((Vec::new(), 0));
    };

    // Open source for streaming
    let source: Box<dyn ReadSeek> = Box::new(BufReader::new(
        File::open(path).with_context(|| format!("open {}", path.display()))?,
    ));

    let turns: Vec<Result<Turn, CoreError>> = match winner {
        "claude" => futures::executor::block_on(claude.parse(source).collect()),
        "chatgpt" => futures::executor::block_on(chatgpt.parse(source).collect()),
        "cursor" => futures::executor::block_on(cursor.parse(source).collect()),
        "copilot" => futures::executor::block_on(copilot.parse(source).collect()),
        "gemini" => futures::executor::block_on(gemini.parse(source).collect()),
        _ => Vec::new(),
    };

    let mut findings: Vec<Finding> = Vec::new();
    let mut scratch = DetectorScratch::default();
    let mut turn_count: usize = 0;

    for turn_result in turns {
        let turn = match turn_result {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(path = %path.display(), "turn error: {e}");
                continue;
            }
        };
        turn_count += 1;

        let pre_turn_len = findings.len();
        for chunk in chunk_turn(&turn, chunker_cfg) {
            for det in detectors {
                det.scan(&chunk, &mut scratch, &mut findings);
            }
        }
        // Backfill the turn role onto findings produced by this turn's chunks.
        // `Detector::scan` operates on a `Chunk` which does not carry role
        // metadata, so per-chunk findings come back with `role: None`.
        for f in &mut findings[pre_turn_len..] {
            if f.role.is_none() {
                f.role = Some(turn.role.clone());
            }
        }

        // Cross-turn correlation: feed the turn to the shared correlator.
        // Any finding whose match spans a prior turn's tail + this turn's
        // head is returned here with SpanKind::CrossTurn.
        if let Some(corr) = correlator.as_deref_mut() {
            let cross_findings = corr.push_turn(&turn);
            findings.extend(cross_findings);
        }
    }

    Ok((findings, turn_count))
}

fn scan_stdin(
    detectors: &[Box<dyn sanitai_core::traits::Detector>],
    chunker_cfg: &ChunkerConfig,
    correlator: &mut CrossTurnCorrelator,
) -> Result<Vec<Finding>> {
    use std::io::Read as _;
    let mut content = String::new();
    std::io::stdin()
        .read_to_string(&mut content)
        .context("read stdin")?;

    // Synthesise a single Turn with a virtual path. Stdin is treated as a
    // single user turn: we do not try to reparse it as a conversation file.
    let turn = Turn {
        id: (Arc::new(PathBuf::from("<stdin>")), 0),
        role: sanitai_core::turn::Role::User,
        content,
        byte_range: 0u64..0u64,
        source: sanitai_core::turn::SourceKind::Stdin,
        meta: sanitai_core::turn::TurnMeta::default(),
    };

    let mut findings: Vec<Finding> = Vec::new();
    let mut scratch = DetectorScratch::default();
    for chunk in chunk_turn(&turn, chunker_cfg) {
        for det in detectors {
            det.scan(&chunk, &mut scratch, &mut findings);
        }
    }

    // Feed into the shared cross-turn correlator as well, so secrets split
    // across stdin and subsequent files (or vice versa) are still caught.
    let cross = correlator.push_turn(&turn);
    findings.extend(cross);

    Ok(findings)
}

#[inline]
fn sniff_score(s: Sniff) -> u8 {
    match s {
        Sniff::No => 0,
        Sniff::Maybe => 1,
        Sniff::Yes => 2,
    }
}

fn confidence_passes(actual: &Confidence, min: &ConfidenceFilter) -> bool {
    match (actual, min) {
        (_, ConfidenceFilter::Low) => true,
        (Confidence::Low, ConfidenceFilter::Medium | ConfidenceFilter::High) => false,
        (Confidence::Medium, ConfidenceFilter::Medium) => true,
        (Confidence::Medium, ConfidenceFilter::High) => false,
        (Confidence::High, _) => true,
    }
}

fn expand_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_dir() {
            walkdir::WalkDir::new(p)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .for_each(|e| out.push(e.into_path()));
        } else {
            out.push(p.clone());
        }
    }
    out
}

/// Walk up from each scanned path to find a `.git` directory.
/// Returns the name of the git root directory, or None.
fn infer_project_name(paths: &[PathBuf]) -> Option<String> {
    for path in paths {
        let mut current = path.as_path();
        loop {
            if current.join(".git").exists() {
                return current
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_owned());
            }
            match current.parent() {
                Some(p) => current = p,
                None => break,
            }
        }
    }
    None
}

/// Extract Claude project name from a path matching `.claude/projects/<name>/`.
/// Returns None if no such path pattern exists.
fn infer_claude_account(paths: &[PathBuf]) -> Option<String> {
    for path in paths {
        let s = path.to_string_lossy();
        // Match: .claude/projects/<project-name>/...
        if let Some(idx) = s.find(".claude/projects/") {
            let after = &s[idx + ".claude/projects/".len()..];
            let name = after.split('/').next().filter(|n| !n.is_empty());
            if let Some(n) = name {
                return Some(n.to_owned());
            }
        }
    }
    None
}

fn print_human(findings: &[Finding]) {
    if findings.is_empty() {
        println!("sanitai: no findings.");
        return;
    }
    for f in findings {
        let conf = match f.confidence {
            Confidence::High => "HIGH  ",
            Confidence::Medium => "MEDIUM",
            Confidence::Low => "LOW   ",
        };
        let file = f.turn_id.0.display();
        let turn = f.turn_id.1;
        let det = f.detector_id;
        let bs = f.byte_range.start;
        let be = f.byte_range.end;
        if f.transform.is_empty() {
            println!("[{conf}] {file}  turn={turn}  {det}  bytes={bs}..{be}");
        } else {
            let chain: Vec<&str> = f
                .transform
                .0
                .iter()
                .map(|t| match t {
                    Transform::Base64 => "base64",
                    Transform::Hex => "hex",
                    Transform::UrlEncoded => "url",
                    Transform::Gzip => "gzip",
                    Transform::HtmlEntity => "html",
                })
                .collect();
            println!(
                "[{conf}] {file}  turn={turn}  {det}  bytes={bs}..{be}  via={}",
                chain.join("+")
            );
        }
    }
    eprintln!("\n{} finding(s).", findings.len());
}

fn print_json(findings: &[Finding]) -> Result<()> {
    let out: Vec<FindingJson> = findings.iter().map(FindingJson::from).collect();
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/// Emit findings as SARIF 2.1.0. One rule per distinct `detector_id`,
/// one `result` per finding. Like `print_json`, this never emits
/// `matched_raw` — only metadata and byte offsets.
fn print_sarif(findings: &[Finding], tool_version: &str) -> Result<()> {
    let log = sarif::findings_to_sarif(findings, tool_version);
    println!("{}", serde_json::to_string_pretty(&log)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// redact
// ---------------------------------------------------------------------------

fn run_redact(args: RedactArgs, config_path: Option<&std::path::Path>) -> i32 {
    // Load config so that future redact defaults (mode, preserve_structure)
    // can be sourced here. Explicit --config failure is fatal.
    let _cfg = match load_cli_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sanitai: config error: {e}");
            return 2;
        }
    };

    match do_redact(args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("sanitai redact: {e}");
            2
        }
    }
}

fn do_redact(args: RedactArgs) -> Result<()> {
    let findings_bytes = std::fs::read(&args.findings)
        .with_context(|| format!("read findings file {}", args.findings.display()))?;
    let json_findings: Vec<FindingJson> =
        serde_json::from_slice(&findings_bytes).with_context(|| "parse findings JSON")?;

    let content = std::fs::read_to_string(&args.file)
        .with_context(|| format!("read {}", args.file.display()))?;

    let arc_path = Arc::new(args.file.clone());

    // Reconstruct minimal Finding structs for the redactor.
    // `detector_id` must be `&'static str`; we leak the strings here.
    // This is intentional: the CLI is a short-lived process and there are at
    // most O(50) distinct detector IDs, so the leaked memory is bounded.
    let findings: Vec<Finding> = json_findings
        .iter()
        .filter_map(|jf| {
            let start = jf.byte_start;
            let end = jf.byte_end;
            if start > end || end > content.len() {
                tracing::warn!(
                    byte_start = start,
                    byte_end = end,
                    "finding byte range out of bounds; skipping"
                );
                return None;
            }
            // Safe: range is validated above.
            let raw = content[start..end].to_owned();
            let id: &'static str = Box::leak(jf.detector.clone().into_boxed_str());
            Some(Finding {
                turn_id: (Arc::clone(&arc_path), jf.turn),
                detector_id: id,
                byte_range: start..end,
                matched_raw: raw,
                transform: TransformChain::default(),
                confidence: Confidence::High,
                span_kind: SpanKind::Single,
                synthetic: jf.synthetic,
                role: None,
                category: sanitai_core::Category::Secret,
                entropy_score: 0.0,
                context_class: sanitai_core::ContextClass::Unclassified,
            })
        })
        .collect();

    let mode = match args.mode {
        RedactModeArg::Mask => RedactMode::Mask,
        RedactModeArg::Hash => RedactMode::Hash,
        RedactModeArg::Partial => RedactMode::Partial,
        RedactModeArg::VaultRef => RedactMode::VaultRef,
    };

    let mut redactor = Redactor::new(mode);
    let redacted = redactor.redact(&content, &findings);
    print!("{redacted}");
    Ok(())
}

// ---------------------------------------------------------------------------
// tui
// ---------------------------------------------------------------------------

fn run_tui() -> i32 {
    // Verify we are actually on a TTY before launching the TUI.
    // If stdout is piped, ratatui will produce garbage output.
    if !atty::is(atty::Stream::Stdout) || !atty::is(atty::Stream::Stdin) {
        eprintln!("sanitai: the TUI requires an interactive terminal. Use `sanitai scan` for non-interactive use.");
        return 2;
    }
    match sanitai_tui::run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("sanitai tui: {e}");
            2
        }
    }
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/// Self-test: confirm the sandbox applies and detectors can match a known-bad
/// synthetic secret. Exits 0 on success, 1 on detector regression.
///
/// Note: the synthetic payload uses a real-looking AWS access key prefix so
/// the regex detector actually matches it. The `SANITAI_FAKE` suffix sits
/// outside the 20-char match window, which means `Finding::is_synthetic()`
/// (which inspects `matched_raw`) returns false here — so we check for *any*
/// finding rather than a synthetic one. That's fine: this runs on a controlled
/// in-memory string, not user input, so any match is proof-of-life for the
/// detector pipeline.
fn run_verify(args: VerifyArgs) -> i32 {
    let mut ok = true;

    // 1. Sandbox check — platform-dependent, never fatal.
    if !args.no_sandbox {
        let sandbox = create_sandbox();
        match sandbox.apply_strict() {
            Ok(()) => println!("[OK] sandbox: strict profile applied"),
            Err(e) => {
                eprintln!("[WARN] sandbox: {e} (non-fatal on some platforms)");
            }
        }
    }

    // 2. Detector smoke test — scan a synthetic AWS key.
    // Must end with a non-word char (or end-of-string) to satisfy \b.
    // Underscores are word chars so "...SANITAI_FAKE" would kill the boundary.
    let synthetic_key = "AKIASANITAIFAKE12345";
    let arc_path = Arc::new(PathBuf::from("<verify>"));
    let turn = sanitai_core::Turn {
        id: (Arc::clone(&arc_path), 0),
        role: sanitai_core::turn::Role::User,
        content: synthetic_key.to_owned(),
        byte_range: 0..(synthetic_key.len() as u64),
        source: sanitai_core::turn::SourceKind::Generic,
        meta: sanitai_core::turn::TurnMeta::default(),
    };

    let det = RegexDetector::new();
    let cfg = ChunkerConfig::default();
    let mut findings: Vec<Finding> = Vec::new();
    let mut scratch = DetectorScratch::default();
    for chunk in chunk_turn(&turn, &cfg) {
        det.scan(&chunk, &mut scratch, &mut findings);
    }

    if findings.is_empty() {
        eprintln!("[FAIL] detectors: synthetic key not detected");
        ok = false;
    } else {
        println!(
            "[OK] detectors: synthetic secret detected ({} finding(s))",
            findings.len()
        );
    }

    if ok {
        println!("\nsanitai: all checks passed");
        0
    } else {
        1
    }
}

// ---------------------------------------------------------------------------
// discover
// ---------------------------------------------------------------------------

fn run_discover(args: DiscoverArgs) -> i32 {
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let sources = discover_all(&home);
    if sources.is_empty() {
        println!("sanitai: no LLM conversation sources found.");
        println!("Try `sanitai scan <path>` to scan a specific file.");
        return 0;
    }

    println!("Found {} conversation source(s):", sources.len());
    for src in &sources {
        let display = if args.absolute {
            src.path.display().to_string()
        } else {
            match src.path.strip_prefix(&home) {
                Ok(rel) => format!("~/{}", rel.display()),
                Err(_) => src.path.display().to_string(),
            }
        };
        println!("  [{:?}] {}", src.kind, display);
    }
    println!("\nUse `sanitai scan <path>` to scan a specific source.");
    0
}
