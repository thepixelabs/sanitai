//! differential — precision/recall evaluator for the SanitAI scanner.
//!
//! Reads a labeled JSONL corpus (produced by `corpus-gen`), pipes each entry's
//! text through `sanitai scan --format json`, and scores the outputs against
//! the ground-truth labels. Emits a markdown report and exits non-zero if
//! overall precision or recall falls below the CI gate.
//!
//! Gates (v0.1 acceptance):
//!   * overall recall    >= 0.95
//!   * overall precision >= 0.98

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs::{create_dir_all, File};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

const RECALL_GATE: f64 = 0.95;
const PRECISION_GATE: f64 = 0.98;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "differential", about = "SanitAI precision/recall evaluator")]
struct Cli {
    /// Path to labeled corpus JSONL (output of corpus-gen).
    #[arg(long)]
    corpus: PathBuf,

    /// Path to the sanitai binary to evaluate.
    #[arg(long, default_value = "./target/release/sanitai")]
    sanitai_bin: PathBuf,

    /// Report output path (markdown).
    #[arg(long, default_value = "results/report.md")]
    out: PathBuf,

    /// Optional limit on number of entries to evaluate (for smoke runs).
    #[arg(long)]
    limit: Option<usize>,

    /// Do not enforce CI gates. Useful during local exploration.
    #[arg(long, default_value_t = false)]
    no_gate: bool,
}

// ---------------------------------------------------------------------------
// Corpus types (mirror of corpus-gen schema)
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
struct CorpusEntry {
    id: String,
    #[allow(dead_code)]
    source: String,
    text: String,
    findings: Vec<LabeledFinding>,
    #[allow(dead_code)]
    negative: bool,
}

#[derive(Deserialize, Debug, Clone)]
struct LabeledFinding {
    class: String,
    span: [usize; 2],
    #[allow(dead_code)]
    seed: u64,
    #[allow(dead_code)]
    synthetic: bool,
}

// ---------------------------------------------------------------------------
// Scanner output (tolerant JSON shape)
// ---------------------------------------------------------------------------
//
// We deliberately do NOT pull in sanitai-core here so the harness can evolve
// independently of the scanner's exact Finding struct. We parse a minimal
// subset via serde_json::Value lookups.

#[derive(Debug, Clone)]
struct NormalizedFinding {
    #[allow(dead_code)]
    entry_id: String,
    class: String,
    span: [usize; 2],
}

// ---------------------------------------------------------------------------
// Per-class scoring
// ---------------------------------------------------------------------------

#[derive(Default, Debug, Clone)]
struct Score {
    tp: u64,
    fp: u64,
    fn_: u64,
}

impl Score {
    fn precision(&self) -> f64 {
        let denom = self.tp + self.fp;
        if denom == 0 {
            return 1.0;
        }
        self.tp as f64 / denom as f64
    }
    fn recall(&self) -> f64 {
        let denom = self.tp + self.fn_;
        if denom == 0 {
            return 1.0;
        }
        self.tp as f64 / denom as f64
    }
    fn f1(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            return 0.0;
        }
        2.0 * p * r / (p + r)
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    let file =
        File::open(&cli.corpus).with_context(|| format!("opening corpus {:?}", cli.corpus))?;
    let reader = BufReader::new(file);

    let mut per_class: BTreeMap<String, Score> = BTreeMap::new();
    let mut total = Score::default();
    let mut n_entries = 0u64;

    for (lineno, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("reading corpus line {lineno}"))?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(limit) = cli.limit {
            if n_entries as usize >= limit {
                break;
            }
        }
        let entry: CorpusEntry =
            serde_json::from_str(&line).with_context(|| format!("parsing corpus line {lineno}"))?;
        n_entries += 1;

        let predicted = run_sanitai(&cli.sanitai_bin, &entry)?;
        score_entry(&entry, &predicted, &mut per_class, &mut total);
    }

    // Emit report.
    if let Some(parent) = cli.out.parent() {
        if !parent.as_os_str().is_empty() {
            create_dir_all(parent)?;
        }
    }
    let mut out =
        File::create(&cli.out).with_context(|| format!("creating report {:?}", cli.out))?;
    write_report(&mut out, &per_class, &total, n_entries)?;

    // Also echo totals to stderr for CI logs.
    eprintln!(
        "differential: entries={} precision={:.4} recall={:.4} f1={:.4}",
        n_entries,
        total.precision(),
        total.recall(),
        total.f1()
    );

    // Gate.
    if !cli.no_gate {
        if total.recall() < RECALL_GATE {
            bail!("recall {:.4} below gate {:.2}", total.recall(), RECALL_GATE);
        }
        if total.precision() < PRECISION_GATE {
            bail!(
                "precision {:.4} below gate {:.2}",
                total.precision(),
                PRECISION_GATE
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Scanner invocation
// ---------------------------------------------------------------------------

fn run_sanitai(bin: &PathBuf, entry: &CorpusEntry) -> Result<Vec<NormalizedFinding>> {
    let mut child = Command::new(bin)
        .args(["scan", "--format", "json", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {:?}", bin))?;
    {
        let stdin = child.stdin.as_mut().context("opening sanitai stdin")?;
        stdin.write_all(entry.text.as_bytes())?;
    }
    let output = child.wait_with_output().context("awaiting sanitai")?;
    if !output.status.success() {
        bail!(
            "sanitai exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    parse_sanitai_output(&entry.id, &output.stdout)
}

fn parse_sanitai_output(entry_id: &str, stdout: &[u8]) -> Result<Vec<NormalizedFinding>> {
    // Tolerate either { "findings": [...] } or a bare array.
    let v: serde_json::Value = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) if stdout.is_empty() => return Ok(Vec::new()),
        Err(e) => return Err(e).context("parsing sanitai json"),
    };
    let arr = if let Some(findings) = v.get("findings").and_then(|f| f.as_array()) {
        findings.clone()
    } else if let Some(findings) = v.as_array() {
        findings.clone()
    } else {
        return Ok(Vec::new());
    };

    let mut out = Vec::with_capacity(arr.len());
    for f in arr {
        let class = f
            .get("detector_id")
            .or_else(|| f.get("class"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let (start, end) = extract_span(&f).unwrap_or((0, 0));
        out.push(NormalizedFinding {
            entry_id: entry_id.to_string(),
            class,
            span: [start, end],
        });
    }
    Ok(out)
}

fn extract_span(f: &serde_json::Value) -> Option<(usize, usize)> {
    // Support several historical shapes:
    //   { "byte_range": { "start": N, "end": M } }
    //   { "byte_range": [N, M] }
    //   { "span": [N, M] }
    if let Some(br) = f.get("byte_range") {
        if let (Some(s), Some(e)) = (br.get("start"), br.get("end")) {
            return Some((s.as_u64()? as usize, e.as_u64()? as usize));
        }
        if let Some(arr) = br.as_array() {
            if arr.len() == 2 {
                return Some((arr[0].as_u64()? as usize, arr[1].as_u64()? as usize));
            }
        }
    }
    if let Some(arr) = f.get("span").and_then(|s| s.as_array()) {
        if arr.len() == 2 {
            return Some((arr[0].as_u64()? as usize, arr[1].as_u64()? as usize));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/// Span overlap predicate: two spans "match" if they overlap by >= 1 byte
/// AND their class strings are equal. This is deliberately lenient on exact
/// boundaries because detectors may include or exclude surrounding delimiters.
fn spans_overlap(a: [usize; 2], b: [usize; 2]) -> bool {
    a[0] < b[1] && b[0] < a[1]
}

fn score_entry(
    entry: &CorpusEntry,
    predicted: &[NormalizedFinding],
    per_class: &mut BTreeMap<String, Score>,
    total: &mut Score,
) {
    let mut label_matched = vec![false; entry.findings.len()];
    let mut pred_matched = vec![false; predicted.len()];

    for (li, label) in entry.findings.iter().enumerate() {
        for (pi, pred) in predicted.iter().enumerate() {
            if pred_matched[pi] {
                continue;
            }
            if pred.class == label.class && spans_overlap(pred.span, label.span) {
                label_matched[li] = true;
                pred_matched[pi] = true;
                per_class.entry(label.class.clone()).or_default().tp += 1;
                total.tp += 1;
                break;
            }
        }
    }

    // Unmatched labels = false negatives.
    for (li, matched) in label_matched.iter().enumerate() {
        if !*matched {
            let class = &entry.findings[li].class;
            per_class.entry(class.clone()).or_default().fn_ += 1;
            total.fn_ += 1;
        }
    }

    // Unmatched predictions = false positives.
    for (pi, matched) in pred_matched.iter().enumerate() {
        if !*matched {
            let class = &predicted[pi].class;
            per_class.entry(class.clone()).or_default().fp += 1;
            total.fp += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

fn write_report(
    w: &mut impl Write,
    per_class: &BTreeMap<String, Score>,
    total: &Score,
    n_entries: u64,
) -> Result<()> {
    writeln!(w, "# SanitAI Differential Report")?;
    writeln!(w)?;
    writeln!(w, "Corpus entries evaluated: **{n_entries}**")?;
    writeln!(w)?;
    writeln!(w, "## Per-class scores")?;
    writeln!(w)?;
    writeln!(w, "| Detector | TP | FP | FN | Precision | Recall | F1 |")?;
    writeln!(w, "|---|---:|---:|---:|---:|---:|---:|")?;
    for (class, score) in per_class {
        writeln!(
            w,
            "| `{}` | {} | {} | {} | {:.4} | {:.4} | {:.4} |",
            class,
            score.tp,
            score.fp,
            score.fn_,
            score.precision(),
            score.recall(),
            score.f1(),
        )?;
    }
    writeln!(w)?;
    writeln!(w, "## Overall")?;
    writeln!(w)?;
    writeln!(
        w,
        "| TP | FP | FN | Precision | Recall | F1 |\n|---:|---:|---:|---:|---:|---:|"
    )?;
    writeln!(
        w,
        "| {} | {} | {} | {:.4} | {:.4} | {:.4} |",
        total.tp,
        total.fp,
        total.fn_,
        total.precision(),
        total.recall(),
        total.f1()
    )?;
    writeln!(w)?;
    writeln!(
        w,
        "Gates: precision >= {:.2}, recall >= {:.2}",
        PRECISION_GATE, RECALL_GATE
    )?;
    Ok(())
}
