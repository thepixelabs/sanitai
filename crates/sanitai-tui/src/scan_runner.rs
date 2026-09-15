use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use crossbeam_channel::Sender;
use sanitai_core::{
    chunk::{ChunkerConfig, DetectorScratch},
    chunker::chunk_turn,
    finding::{Confidence, Finding},
    traits::{ConversationParser, Detector, Sniff, SourceHint},
};
use sanitai_detectors::{
    CrossTurnConfig, CrossTurnCorrelator, RegexDetector, TransformConfig, TransformDetector,
};
use sanitai_parsers::{discover_all, ChatGptParser, ClaudeJsonlParser};
use sanitai_sandbox::create_sandbox;

use futures::StreamExt;

pub struct ScanSummary {
    pub scan_id: String,
    pub started_at_ns: i64,
    pub total_files: usize,
    pub total_turns: usize,
    pub findings_high: usize,
    pub findings_medium: usize,
    pub findings_low: usize,
    pub duration_ms: u64,
    pub paths: Vec<PathBuf>,
    /// All findings retained so the caller can write them to the store.
    pub findings: Vec<Finding>,
    /// True if the user cancelled the scan before it completed.
    pub cancelled: bool,
}

/// Events sent from the worker thread back to the UI thread during a scan.
///
/// `Plan` arrives first and tells the UI the size of the work. `FileStart` /
/// `FileDone` bracket each file so the UI can show a scrolling tail and
/// recompute throughput. `Done` carries the full `ScanSummary` for the
/// Results screen.
#[allow(dead_code)] // some fields are wire-only; the UI is free to ignore them
pub enum ScanProgressEvent {
    Plan {
        total_files: usize,
        total_bytes: u64,
    },
    FileStart {
        path: PathBuf,
        size: u64,
    },
    FileDone {
        path: PathBuf,
        size: u64,
        findings: usize,
        ms: u64,
    },
    /// File was discovered but had no recognised parser. Bytes still count
    /// toward processed_bytes so the gauge advances honestly.
    FileSkipped {
        path: PathBuf,
        size: u64,
    },
    Done(Box<ScanSummary>),
    Error(String),
}

/// Run the auto-discovery scan, emitting progress events to `tx`. Checks
/// `cancel` between files; on cancel, sends a final `Done` with whatever was
/// scanned and `cancelled: true`.
///
/// Designed to be called from a worker thread spawned by the TUI. The caller
/// owns the receiver and drains it on each render tick.
pub fn run_auto_scan_progress(tx: Sender<ScanProgressEvent>, cancel: Arc<AtomicBool>) {
    let start = Instant::now();
    let scan_id = ulid::Ulid::new().to_string();
    let started_at_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos() as i64;

    // Apply OS-level sandbox before touching untrusted files.
    let sandbox = create_sandbox();
    if let Err(e) = sandbox.apply_strict() {
        tracing::warn!("TUI sandbox apply_strict failed (non-fatal): {e}");
    }

    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let discovered = discover_all(&home);
    let paths: Vec<PathBuf> = discovered.into_iter().map(|d| d.path).collect();

    // Compute total bytes upfront so the gauge has an honest denominator.
    // Files whose metadata fails get size 0 and won't break the total — they
    // just contribute 0 to the gauge advance.
    let sizes: Vec<u64> = paths
        .iter()
        .map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .collect();
    let total_bytes: u64 = sizes.iter().sum();

    let _ = tx.send(ScanProgressEvent::Plan {
        total_files: paths.len(),
        total_bytes,
    });

    let regex_arc = Arc::new(RegexDetector::new());
    let detectors: Vec<Box<dyn Detector>> = vec![
        Box::new(RegexDetector::new()),
        Box::new(TransformDetector::new(
            Arc::clone(&regex_arc),
            TransformConfig::default(),
        )),
    ];

    let chunker_cfg = ChunkerConfig::default();
    let mut correlator =
        CrossTurnCorrelator::new(Arc::clone(&regex_arc), CrossTurnConfig::default());
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut total_turns = 0usize;
    let mut cancelled = false;

    for (path, size) in paths.iter().zip(sizes.iter()) {
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }

        let _ = tx.send(ScanProgressEvent::FileStart {
            path: path.clone(),
            size: *size,
        });

        let file_start = Instant::now();
        match scan_one(path, &detectors, &chunker_cfg, &mut correlator) {
            Ok((findings, turns)) => {
                let count = findings.len();
                if count == 0 && turns == 0 {
                    // Parser didn't recognise the file — count as skipped so
                    // the UI can show that visually rather than as "0 findings".
                    let _ = tx.send(ScanProgressEvent::FileSkipped {
                        path: path.clone(),
                        size: *size,
                    });
                    continue;
                }
                total_turns += turns;
                all_findings.extend(findings);
                let _ = tx.send(ScanProgressEvent::FileDone {
                    path: path.clone(),
                    size: *size,
                    findings: count,
                    ms: file_start.elapsed().as_millis() as u64,
                });
            }
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "skipping file");
                let _ = tx.send(ScanProgressEvent::FileSkipped {
                    path: path.clone(),
                    size: *size,
                });
            }
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    let findings_high = all_findings
        .iter()
        .filter(|f| matches!(f.confidence, Confidence::High))
        .count();
    let findings_medium = all_findings
        .iter()
        .filter(|f| matches!(f.confidence, Confidence::Medium))
        .count();
    let findings_low = all_findings
        .iter()
        .filter(|f| matches!(f.confidence, Confidence::Low))
        .count();

    let summary = ScanSummary {
        scan_id,
        started_at_ns,
        total_files: paths.len(),
        total_turns,
        findings_high,
        findings_medium,
        findings_low,
        duration_ms,
        paths,
        findings: all_findings,
        cancelled,
    };

    let _ = tx.send(ScanProgressEvent::Done(Box::new(summary)));
}

fn scan_one(
    path: &std::path::Path,
    detectors: &[Box<dyn Detector>],
    chunker_cfg: &ChunkerConfig,
    correlator: &mut CrossTurnCorrelator,
) -> Result<(Vec<Finding>, usize)> {
    let mut head_buf = [0u8; 4096];
    let head_len = {
        let mut f = File::open(path)?;
        f.read(&mut head_buf)?
    };
    let hint = SourceHint {
        path,
        head: &head_buf[..head_len],
    };

    let claude_score =
        sniff_score(ClaudeJsonlParser::with_path(path.to_path_buf()).can_parse(&hint));
    let chatgpt_score = sniff_score(ChatGptParser::with_path(path.to_path_buf()).can_parse(&hint));

    if claude_score == 0 && chatgpt_score == 0 {
        return Ok((Vec::new(), 0));
    }

    let source: Box<dyn sanitai_core::traits::ReadSeek> =
        Box::new(BufReader::new(File::open(path)?));

    let turns_result: Vec<_> = if claude_score >= chatgpt_score {
        futures::executor::block_on(
            ClaudeJsonlParser::with_path(path.to_path_buf())
                .parse(source)
                .collect(),
        )
    } else {
        futures::executor::block_on(
            ChatGptParser::with_path(path.to_path_buf())
                .parse(source)
                .collect(),
        )
    };

    let mut findings = Vec::new();
    let mut scratch = DetectorScratch::default();
    let mut turn_count = 0usize;

    for turn in turns_result.into_iter().flatten() {
        turn_count += 1;
        for chunk in chunk_turn(&turn, chunker_cfg) {
            // NOTE: reset_for_chunk() clears the per-chunk decode budget.
            // The CLI does not call this (architectural debt tracked separately).
            // Calling it here makes each chunk start with a clean decode budget,
            // which is the intended behaviour of DetectorScratch.
            scratch.reset_for_chunk();
            for det in detectors {
                det.scan(&chunk, &mut scratch, &mut findings);
            }
        }
        findings.extend(correlator.push_turn(&turn));
    }

    // Deduplicate within the file. The cross-turn correlator's sliding-window
    // pass and the per-chunk regex pass can both report a secret that lies
    // entirely within one turn — same matched_raw, same detector_id, same
    // turn_idx → same fingerprint. Drop the second occurrence.
    sanitai_core::finding::dedupe_by_fingerprint(&mut findings);

    Ok((findings, turn_count))
}

fn sniff_score(s: Sniff) -> u8 {
    match s {
        Sniff::No => 0,
        Sniff::Maybe => 1,
        Sniff::Yes => 2,
    }
}
