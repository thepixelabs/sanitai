//! corpus-gen — labeled JSONL benchmark corpus generator for SanitAI.
//!
//! Produces a deterministic, labeled corpus of synthetic conversation turns for
//! precision/recall evaluation. Every secret embedded is SANITAI_FAKE-marked
//! and structurally invalid — the corpus is safe to check into CI artifacts.
//!
//! Distribution (defaults, all configurable):
//!   30% single-secret TPs
//!    6% two-secret TPs
//!   24% hard negatives (high-entropy non-secrets: UUIDs, git hashes, base64)
//!   16% near-miss patterns (wrong prefix / wrong length lookalikes)
//!   24% clean developer prose (Markov-generated)

use anyhow::{Context, Result};
use clap::Parser;
use rand::rngs::SmallRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use sanitai_fixtures::{generate_in_context, generate_secret, TokenClass};
use serde::Serialize;
use std::fs::{create_dir_all, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "corpus-gen",
    about = "Generate a labeled SanitAI benchmark corpus"
)]
struct Cli {
    /// Total number of corpus entries to emit.
    #[arg(long, default_value_t = 50_000)]
    count: usize,

    /// Master RNG seed.
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Output JSONL path.
    #[arg(long, default_value = "corpus/corpus.jsonl")]
    out: PathBuf,

    /// Percent of entries that are single-secret positives (0-100).
    #[arg(long, default_value_t = 30)]
    pct_single: u32,

    /// Percent of entries that are two-secret positives.
    #[arg(long, default_value_t = 6)]
    pct_double: u32,

    /// Percent of entries that are hard negatives (entropy lookalikes).
    #[arg(long, default_value_t = 24)]
    pct_hard_neg: u32,

    /// Percent of entries that are near-miss lookalikes.
    #[arg(long, default_value_t = 16)]
    pct_near_miss: u32,

    /// Percent of entries that are clean prose.
    #[arg(long, default_value_t = 24)]
    pct_clean: u32,
}

#[derive(Serialize)]
struct CorpusEntry {
    id: String,
    source: String,
    text: String,
    findings: Vec<LabeledFinding>,
    negative: bool,
}

#[derive(Serialize)]
struct LabeledFinding {
    class: String,
    span: [usize; 2],
    seed: u64,
    synthetic: bool,
}

#[derive(Clone, Copy, Debug)]
enum Bucket {
    SingleSecret,
    DoubleSecret,
    HardNegative,
    NearMiss,
    Clean,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let total_pct =
        cli.pct_single + cli.pct_double + cli.pct_hard_neg + cli.pct_near_miss + cli.pct_clean;
    anyhow::ensure!(
        total_pct == 100,
        "percent flags must sum to 100, got {total_pct}"
    );

    if let Some(parent) = cli.out.parent() {
        if !parent.as_os_str().is_empty() {
            create_dir_all(parent)
                .with_context(|| format!("creating output directory {parent:?}"))?;
        }
    }

    let file =
        File::create(&cli.out).with_context(|| format!("creating output file {:?}", cli.out))?;
    let mut writer = BufWriter::new(file);

    let mut rng = SmallRng::seed_from_u64(cli.seed);
    let buckets = build_bucket_plan(cli.count, &cli, &mut rng);

    let all_classes = TokenClass::ALL;

    for (i, bucket) in buckets.iter().enumerate() {
        let id = format!("turn_{:06}", i);
        // Alternate source deterministically.
        let source = if i % 2 == 0 { "claude" } else { "chatgpt" };
        // Each entry gets its own derived seed so a single entry is
        // reproducible without replaying the whole stream.
        let entry_seed = cli
            .seed
            .wrapping_add(i as u64)
            .wrapping_mul(0x9E3779B97F4A7C15);
        let mut entry_rng = SmallRng::seed_from_u64(entry_seed);

        let entry = match bucket {
            Bucket::SingleSecret => {
                make_single(&id, source, all_classes, entry_seed, &mut entry_rng)
            }
            Bucket::DoubleSecret => {
                make_double(&id, source, all_classes, entry_seed, &mut entry_rng)
            }
            Bucket::HardNegative => make_hard_neg(&id, source, &mut entry_rng),
            Bucket::NearMiss => make_near_miss(&id, source, &mut entry_rng),
            Bucket::Clean => make_clean(&id, source, &mut entry_rng),
        };

        serde_json::to_writer(&mut writer, &entry)?;
        writer.write_all(b"\n")?;
    }

    writer.flush()?;
    eprintln!("wrote {} entries to {:?}", cli.count, cli.out);
    Ok(())
}

fn build_bucket_plan(count: usize, cli: &Cli, rng: &mut SmallRng) -> Vec<Bucket> {
    let n_single = count * cli.pct_single as usize / 100;
    let n_double = count * cli.pct_double as usize / 100;
    let n_hard = count * cli.pct_hard_neg as usize / 100;
    let n_near = count * cli.pct_near_miss as usize / 100;
    let assigned = n_single + n_double + n_hard + n_near;
    let n_clean = count - assigned;

    let mut plan: Vec<Bucket> = Vec::with_capacity(count);
    plan.extend(std::iter::repeat_n(Bucket::SingleSecret, n_single));
    plan.extend(std::iter::repeat_n(Bucket::DoubleSecret, n_double));
    plan.extend(std::iter::repeat_n(Bucket::HardNegative, n_hard));
    plan.extend(std::iter::repeat_n(Bucket::NearMiss, n_near));
    plan.extend(std::iter::repeat_n(Bucket::Clean, n_clean));
    plan.shuffle(rng);
    plan
}

fn make_single(
    id: &str,
    source: &str,
    classes: &[TokenClass],
    seed: u64,
    rng: &mut SmallRng,
) -> CorpusEntry {
    let class = classes[rng.gen_range(0..classes.len())];
    let text = generate_in_context(class, seed);
    let secret = generate_secret(class, seed);
    let findings = locate_single(&text, &secret, class, seed);
    CorpusEntry {
        id: id.to_string(),
        source: source.to_string(),
        text,
        findings,
        negative: false,
    }
}

fn make_double(
    id: &str,
    source: &str,
    classes: &[TokenClass],
    seed: u64,
    rng: &mut SmallRng,
) -> CorpusEntry {
    let class_a = classes[rng.gen_range(0..classes.len())];
    let class_b = classes[rng.gen_range(0..classes.len())];
    let seed_a = seed;
    let seed_b = seed ^ 0xDEADBEEF;
    let text_a = generate_in_context(class_a, seed_a);
    let text_b = generate_in_context(class_b, seed_b);
    let text = format!("{text_a}\n\n---\n\n{text_b}");

    let mut findings = Vec::new();
    let secret_a = generate_secret(class_a, seed_a);
    if let Some(start) = text.find(secret_a.as_str()) {
        findings.push(LabeledFinding {
            class: class_a.as_str().to_string(),
            span: [start, start + secret_a.len()],
            seed: seed_a,
            synthetic: true,
        });
    }
    let secret_b = generate_secret(class_b, seed_b);
    // find from the end offset so two identical secrets map to distinct spans.
    let search_from = findings.last().map(|f| f.span[1]).unwrap_or(0);
    if let Some(off) = text[search_from..].find(secret_b.as_str()) {
        let start = search_from + off;
        findings.push(LabeledFinding {
            class: class_b.as_str().to_string(),
            span: [start, start + secret_b.len()],
            seed: seed_b,
            synthetic: true,
        });
    }
    CorpusEntry {
        id: id.to_string(),
        source: source.to_string(),
        text,
        findings,
        negative: false,
    }
}

fn locate_single(text: &str, secret: &str, class: TokenClass, seed: u64) -> Vec<LabeledFinding> {
    match text.find(secret) {
        Some(start) => vec![LabeledFinding {
            class: class.as_str().to_string(),
            span: [start, start + secret.len()],
            seed,
            synthetic: true,
        }],
        None => Vec::new(),
    }
}

// ---------- negative / near-miss generators ----------

fn make_hard_neg(id: &str, source: &str, rng: &mut SmallRng) -> CorpusEntry {
    let kind = rng.gen_range(0..4);
    let text = match kind {
        0 => {
            // Random UUID v4-like.
            format!("Deploy id: {}", fake_uuid(rng))
        }
        1 => {
            // Git SHA.
            format!("Fixed in commit {}", rand_hex(rng, 40))
        }
        2 => {
            // Raw base64 blob (no known prefix).
            format!("Payload: {}", rand_b64(rng, 64))
        }
        _ => {
            // Docker image digest.
            format!("pulled image sha256:{}", rand_hex(rng, 64))
        }
    };
    CorpusEntry {
        id: id.to_string(),
        source: source.to_string(),
        text,
        findings: Vec::new(),
        negative: true,
    }
}

fn make_near_miss(id: &str, source: &str, rng: &mut SmallRng) -> CorpusEntry {
    let kind = rng.gen_range(0..5);
    let text = match kind {
        // Wrong-length AWS key (too short).
        0 => format!("my key: AKIA{}", rand_alnum(rng, 10)),
        // Wrong-prefix GitHub-like.
        1 => format!("token: ghx_{}", rand_alnum(rng, 36)),
        // "sk-" prefix but far too short to be OpenAI.
        2 => format!("key=sk-{}", rand_alnum(rng, 5)),
        // JWT-like 2-segment (missing signature).
        3 => format!("partial jwt: {}.{}", rand_b64(rng, 24), rand_b64(rng, 32)),
        // Stripe-ish but with wrong separator.
        _ => format!("stripe: sklive{}", rand_alnum(rng, 24)),
    };
    CorpusEntry {
        id: id.to_string(),
        source: source.to_string(),
        text,
        findings: Vec::new(),
        negative: true,
    }
}

fn make_clean(id: &str, source: &str, rng: &mut SmallRng) -> CorpusEntry {
    let n = rng.gen_range(8..24);
    let text = markov_sentence(rng, n);
    CorpusEntry {
        id: id.to_string(),
        source: source.to_string(),
        text,
        findings: Vec::new(),
        negative: true,
    }
}

// ---------- randomness primitives ----------

fn rand_alnum(rng: &mut SmallRng, n: usize) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..n)
        .map(|_| A[rng.gen_range(0..A.len())] as char)
        .collect()
}
fn rand_hex(rng: &mut SmallRng, n: usize) -> String {
    const A: &[u8] = b"0123456789abcdef";
    (0..n)
        .map(|_| A[rng.gen_range(0..A.len())] as char)
        .collect()
}
fn rand_b64(rng: &mut SmallRng, n: usize) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    (0..n)
        .map(|_| A[rng.gen_range(0..A.len())] as char)
        .collect()
}
fn fake_uuid(rng: &mut SmallRng) -> String {
    const VARIANT: &[u8] = b"89ab";
    let variant_char = VARIANT[rng.gen_range(0..VARIANT.len())] as char;
    format!(
        "{}-{}-4{}-{}{}-{}",
        rand_hex(rng, 8),
        rand_hex(rng, 4),
        rand_hex(rng, 3),
        variant_char,
        rand_hex(rng, 3),
        rand_hex(rng, 12)
    )
}

// ---------- tiny Markov chain for clean developer prose ----------

const WORDS: &[&str] = &[
    "the",
    "a",
    "I",
    "we",
    "can",
    "you",
    "help",
    "me",
    "with",
    "this",
    "function",
    "bug",
    "error",
    "undefined",
    "null",
    "variable",
    "config",
    "docker",
    "container",
    "deploy",
    "test",
    "please",
    "explain",
    "how",
    "to",
    "refactor",
    "implement",
    "feature",
    "request",
    "review",
    "code",
    "pull",
    "merge",
    "branch",
    "commit",
    "history",
    "debug",
    "stack",
    "trace",
    "server",
    "client",
    "request",
    "response",
    "timeout",
    "latency",
    "cache",
    "database",
    "query",
    "slow",
    "optimize",
    "index",
    "schema",
    "migration",
    "thanks",
    "yes",
    "no",
    "maybe",
    "probably",
    "think",
    "know",
    "see",
    "looks",
    "working",
    "broken",
    "runs",
    "compiles",
    "fails",
];

fn markov_sentence(rng: &mut SmallRng, n_words: usize) -> String {
    let mut out = String::new();
    for i in 0..n_words {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(WORDS[rng.gen_range(0..WORDS.len())]);
    }
    out.push('.');
    out
}
