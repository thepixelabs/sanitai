//! Evaluates the ContextClassifier against the labeled corpus.
//!
//! Usage: context-eval [--corpus <path>] [--min-precision <f64>] [--min-recall <f64>]
//!
//! Exits 0 if precision/recall gates pass, 1 if they fail.

use std::path::PathBuf;

use anyhow::{Context, Result};
use sanitai_core::{
    finding::{Confidence, ContextClass, Finding, SpanKind, TransformChain},
    traits::Category,
    turn::{Role, SourceKind, Turn, TurnMeta},
};
use sanitai_detectors::ContextClassifier;
use serde::Deserialize;

#[derive(Deserialize)]
struct CorpusEntry {
    id: String,
    expected_class: String,
    finding_turn_idx: usize,
    #[allow(dead_code)]
    detector_id: Option<String>,
    matched_raw: Option<String>,
    entropy_score: Option<f64>,
    span_kind: Option<String>,
    turns: Vec<CorpusTurn>,
}

#[derive(Deserialize)]
struct CorpusTurn {
    role: String,
    content: String,
}

fn parse_role(s: &str) -> Role {
    match s {
        "assistant" | "model" => Role::Assistant,
        "system" => Role::System,
        "tool" => Role::Tool,
        _ => Role::User,
    }
}

fn parse_context_class(s: &str) -> ContextClass {
    match s {
        "real_paste" => ContextClass::RealPaste,
        "educational" => ContextClass::Educational,
        "documentation_quote" => ContextClass::DocumentationQuote,
        "model_hallucination" => ContextClass::ModelHallucination,
        _ => ContextClass::Unclassified,
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let corpus_path = args
        .iter()
        .position(|a| a == "--corpus")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("corpora/context/index.jsonl"));

    let min_precision: f64 = args
        .iter()
        .position(|a| a == "--min-precision")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.90);

    let min_recall: f64 = args
        .iter()
        .position(|a| a == "--min-recall")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.85);

    let content = std::fs::read_to_string(&corpus_path)
        .with_context(|| format!("read corpus {}", corpus_path.display()))?;

    let classifier = ContextClassifier::with_defaults();

    let mut tp = 0usize; // true positives  (pred RealPaste, actual RealPaste)
    let mut fp = 0usize; // false positives (pred RealPaste, actual other)
    let mut fn_ = 0usize; // false negatives (pred other, actual RealPaste)
    let mut total = 0usize;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let entry: CorpusEntry = serde_json::from_str(line).with_context(|| {
            format!("parse corpus line: {}", &line[..line.len().min(60)])
        })?;

        total += 1;
        let expected = parse_context_class(&entry.expected_class);

        // Build Turn slice from corpus entry
        let file_path = std::sync::Arc::new(PathBuf::from(format!("/corpus/{}", entry.id)));
        let turns: Vec<Turn> = entry
            .turns
            .iter()
            .enumerate()
            .map(|(i, t)| Turn {
                id: (file_path.clone(), i),
                role: parse_role(&t.role),
                content: t.content.clone(),
                byte_range: 0..t.content.len() as u64,
                source: SourceKind::Generic,
                meta: TurnMeta::default(),
            })
            .collect();

        // Build a minimal Finding
        let matched = entry.matched_raw.as_deref().unwrap_or("placeholder");
        let span_kind = match entry.span_kind.as_deref() {
            Some("cross_turn") => SpanKind::CrossTurn {
                contributing_turns: vec![0, 1],
            },
            _ => SpanKind::Single,
        };
        let finding = Finding {
            turn_id: (file_path, entry.finding_turn_idx),
            detector_id: "corpus_eval",
            byte_range: 0..matched.len(),
            matched_raw: matched.to_owned(),
            transform: TransformChain::default(),
            confidence: Confidence::High,
            span_kind,
            synthetic: false,
            role: turns.get(entry.finding_turn_idx).map(|t| t.role.clone()),
            category: Category::Credential,
            entropy_score: entry.entropy_score.unwrap_or(4.0),
            context_class: ContextClass::Unclassified,
        };

        let predicted = classifier.classify(&finding, &turns);

        match (
            predicted == ContextClass::RealPaste,
            expected == ContextClass::RealPaste,
        ) {
            (true, true) => tp += 1,
            (true, false) => fp += 1,
            (false, true) => fn_ += 1,
            (false, false) => {} // TN
        }

        let status = if predicted == expected { "OK" } else { "FAIL" };
        println!(
            "[{}] {} — expected: {:?}, predicted: {:?}",
            status, entry.id, expected, predicted
        );
    }

    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else {
        1.0
    };
    let recall = if tp + fn_ > 0 {
        tp as f64 / (tp + fn_) as f64
    } else {
        1.0
    };

    println!("\n--- Results ---");
    println!("Total entries: {}", total);
    println!(
        "RealPaste precision: {:.3} (gate: >= {:.2})",
        precision, min_precision
    );
    println!(
        "RealPaste recall:    {:.3} (gate: >= {:.2})",
        recall, min_recall
    );

    let pass = precision >= min_precision && recall >= min_recall;
    if pass {
        println!("PASS");
        Ok(())
    } else {
        println!("FAIL — gates not met");
        std::process::exit(1);
    }
}
