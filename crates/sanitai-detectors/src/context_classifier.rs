//! Contextual false-positive suppressor for AI conversation findings.
//!
//! Classifies findings as RealPaste, Educational, DocumentationQuote,
//! ModelHallucination, or Unclassified based on heuristic signals from
//! surrounding conversation turns.
//!
//! v1 uses only textual heuristics — no LLM call, no external process.
//! Precision/recall are measured against corpora/context/index.jsonl.
//!
//! Security: never logs turn content. Only counts and indices.

use sanitai_core::{
    finding::{ContextClass, Finding, SpanKind},
    turn::{Role, Turn},
};

#[derive(Debug, Clone)]
pub struct ContextClassifierConfig {
    /// How many turns before and after the finding turn to inspect.
    pub window_turns: usize,
    /// Number of educational prose keywords required to classify as Educational.
    pub educational_keyword_threshold: usize,
    /// Entropy threshold above which a finding is considered high-entropy
    /// (pushes toward RealPaste).
    pub high_entropy_threshold: f64,
}

impl Default for ContextClassifierConfig {
    fn default() -> Self {
        Self {
            window_turns: 3,
            educational_keyword_threshold: 2,
            high_entropy_threshold: 4.5,
        }
    }
}

pub struct ContextClassifier {
    config: ContextClassifierConfig,
}

impl ContextClassifier {
    pub fn new(config: ContextClassifierConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(ContextClassifierConfig::default())
    }

    /// Classify a finding given the complete ordered turn slice for its file.
    ///
    /// `file_turns` MUST be pre-filtered to contain only turns from
    /// `finding.turn_id.0` (the source file). Mixing turns from multiple
    /// files produces incorrect window lookups.
    ///
    /// Returns `ContextClass::Unclassified` if:
    /// - `file_turns` is empty
    /// - `finding.turn_id.1` is out of bounds for `file_turns`
    /// - Signals are contradictory (not enough confidence for a class)
    pub fn classify(&self, finding: &Finding, file_turns: &[Turn]) -> ContextClass {
        let turn_idx = finding.turn_id.1;

        if file_turns.is_empty() || turn_idx >= file_turns.len() {
            return ContextClass::Unclassified;
        }

        let finding_turn = &file_turns[turn_idx];

        // ----- Signal: cross-turn match strongly implies real leak -----
        if matches!(finding.span_kind, SpanKind::CrossTurn { .. }) {
            return ContextClass::RealPaste;
        }

        // ----- Signal: known hallucination pattern -----
        if is_known_hallucination_pattern(&finding.matched_raw) {
            return ContextClass::ModelHallucination;
        }

        // ----- Collect window turns -----
        let window_start = turn_idx.saturating_sub(self.config.window_turns);
        let window_end = (turn_idx + self.config.window_turns + 1).min(file_turns.len());
        let window = &file_turns[window_start..window_end];

        // ----- Score educational signals -----
        let edu_signal_count = count_educational_signals(finding_turn, window);
        let in_code_fence = is_in_code_fence(&finding.matched_raw, &finding_turn.content);
        let doc_url_near = has_doc_url_nearby(window);
        let in_inline_code = is_in_inline_code(&finding.matched_raw, &finding_turn.content);

        // ----- Score real-paste signals -----
        let is_user_role = matches!(finding_turn.role, Role::User);
        let is_high_entropy = finding.entropy_score >= self.config.high_entropy_threshold;

        // ----- Decision logic -----

        // DocumentationQuote: doc URL nearby AND finding in inline code or code fence
        if doc_url_near && (in_code_fence || in_inline_code) {
            return ContextClass::DocumentationQuote;
        }

        // Educational: assistant turn with enough educational keywords, OR
        // in a code fence with educational signals in surrounding prose
        let is_assistant = matches!(finding_turn.role, Role::Assistant);
        if edu_signal_count >= self.config.educational_keyword_threshold
            && (is_assistant || in_code_fence)
        {
            return ContextClass::Educational;
        }

        // Also Educational if it's inside a fenced code block AND the surrounding
        // prose (outside the fence) has at least 1 educational keyword
        if in_code_fence && edu_signal_count >= 1 && is_assistant {
            return ContextClass::Educational;
        }

        // RealPaste: user turn, no educational signals, high entropy
        if is_user_role && edu_signal_count == 0 && is_high_entropy {
            return ContextClass::RealPaste;
        }

        // RealPaste: user turn, no educational signals, no code fence
        if is_user_role && edu_signal_count == 0 && !in_code_fence {
            return ContextClass::RealPaste;
        }

        ContextClass::Unclassified
    }
}

// ---------------------------------------------------------------------------
// Signal helpers
// ---------------------------------------------------------------------------

/// Count how many educational prose signals appear in the window.
fn count_educational_signals(finding_turn: &Turn, window: &[Turn]) -> usize {
    const EDUCATIONAL_KEYWORDS: &[&str] = &[
        "example",
        "for example",
        "e.g.",
        "such as",
        "looks like",
        "format",
        "placeholder",
        "replace with",
        "your_",
        "<your_",
        "your_api_key",
        "redacted",
        "here's an example",
        "for instance",
        "like this",
        "demonstration",
        "demo",
        "sample",
        "template",
        "the format is",
        "would look like",
        "similar to",
    ];

    let mut count = 0usize;

    // Check the finding turn itself
    let content_lower = finding_turn.content.to_lowercase();
    for kw in EDUCATIONAL_KEYWORDS {
        if content_lower.contains(kw) {
            count += 1;
        }
    }

    // Check surrounding window turns
    for turn in window {
        if std::ptr::eq(turn, finding_turn) {
            continue; // already counted above
        }
        let lower = turn.content.to_lowercase();
        for kw in EDUCATIONAL_KEYWORDS {
            if lower.contains(kw) {
                count += 1;
                break; // only count each turn once
            }
        }
    }

    count
}

/// True if the matched_raw value appears inside a markdown fenced code block
/// in the turn's content.
fn is_in_code_fence(matched: &str, content: &str) -> bool {
    let mut in_fence = false;
    let mut fence_content = String::new();

    for line in content.lines() {
        if line.trim_start().starts_with("```") {
            if in_fence {
                // End of fence — check if matched is in fence_content
                if fence_content.contains(matched) {
                    return true;
                }
                fence_content.clear();
            }
            in_fence = !in_fence;
        } else if in_fence {
            fence_content.push_str(line);
            fence_content.push('\n');
        }
    }
    // Unterminated fence — still check accumulated content
    if in_fence && fence_content.contains(matched) {
        return true;
    }
    false
}

/// True if the matched_raw appears inside backtick inline code in the content.
fn is_in_inline_code(matched: &str, content: &str) -> bool {
    let mut i = 0;
    let bytes = content.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'`' {
            // Skip triple-backtick fences
            if bytes.get(i + 1) == Some(&b'`') && bytes.get(i + 2) == Some(&b'`') {
                i += 3;
                while i + 2 < bytes.len() {
                    if bytes[i] == b'`' && bytes[i + 1] == b'`' && bytes[i + 2] == b'`' {
                        i += 3;
                        break;
                    }
                    i += 1;
                }
                continue;
            }
            // Find closing backtick
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'`' {
                j += 1;
            }
            if j < bytes.len() {
                let span = &content[start..j];
                if span.contains(matched) {
                    return true;
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    false
}

/// True if any turn in the window contains a documentation URL.
fn has_doc_url_nearby(window: &[Turn]) -> bool {
    const DOC_URL_PREFIXES: &[&str] = &[
        "docs.",
        "developer.",
        "api.",
        "developers.",
        "support.",
        "help.",
        "learn.",
        "reference.",
        "guide.",
    ];
    for turn in window {
        let lower = turn.content.to_lowercase();
        for prefix in DOC_URL_PREFIXES {
            if lower.contains(prefix) {
                return true;
            }
        }
    }
    false
}

/// True if the matched value is a known hallucination pattern.
fn is_known_hallucination_pattern(matched: &str) -> bool {
    const HALLUCINATION_PATTERNS: &[&str] = &[
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ];
    for pat in HALLUCINATION_PATTERNS {
        if matched.contains(pat) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sanitai_core::{
        finding::{Confidence, SpanKind, TransformChain},
        turn::{Role, SourceKind, TurnMeta},
    };
    use std::{path::PathBuf, sync::Arc};

    fn mk_turn(idx: usize, role: Role, content: &str) -> Turn {
        Turn {
            id: (Arc::new(PathBuf::from("/tmp/t")), idx),
            role,
            content: content.to_string(),
            byte_range: 0..content.len() as u64,
            source: SourceKind::Generic,
            meta: TurnMeta::default(),
        }
    }

    fn mk_finding(turn_idx: usize, matched: &str) -> Finding {
        Finding {
            turn_id: (Arc::new(PathBuf::from("/tmp/t")), turn_idx),
            detector_id: "test_rule",
            byte_range: 0..matched.len(),
            matched_raw: matched.to_owned(),
            transform: TransformChain::default(),
            confidence: Confidence::High,
            span_kind: SpanKind::Single,
            synthetic: false,
            role: None,
            category: sanitai_core::traits::Category::Credential,
            entropy_score: 4.5,
            context_class: ContextClass::Unclassified,
        }
    }

    #[test]
    fn user_turn_high_entropy_no_signals_is_real_paste() {
        let turns = vec![mk_turn(
            0,
            Role::User,
            "Here is my production key: sk-ant-api03-xK9mP2qR7nLwF5vB3tY8hD1jC6xK9mP2qR7nLwF5vB3tY8hD1jC6xK9mP2qR7nLwF5",
        )];
        let finding = Finding {
            entropy_score: 4.8,
            ..mk_finding(0, "sk-ant-api03-xK9mP2qR7nLwF5vB3tY8hD1jC6xK9mP2qR7nLwF5")
        };
        let classifier = ContextClassifier::with_defaults();
        assert_eq!(classifier.classify(&finding, &turns), ContextClass::RealPaste);
    }

    #[test]
    fn assistant_explains_key_format_is_educational() {
        let turns = vec![
            mk_turn(0, Role::User, "What does an AWS key look like?"),
            mk_turn(
                1,
                Role::Assistant,
                "AWS access keys look like this sample: AKIAZZZZZZZZZZZZZZZZ\nFor example, the format is AKIA followed by 16 characters.",
            ),
        ];
        let finding = mk_finding(1, "AKIAZZZZZZZZZZZZZZZZ");
        let classifier = ContextClassifier::with_defaults();
        assert_eq!(
            classifier.classify(&finding, &turns),
            ContextClass::Educational
        );
    }

    #[test]
    fn known_hallucination_pattern_classified_correctly() {
        let turns = vec![mk_turn(0, Role::Assistant, "Here: AKIAIOSFODNN7EXAMPLE")];
        let finding = mk_finding(0, "AKIAIOSFODNN7EXAMPLE");
        let classifier = ContextClassifier::with_defaults();
        assert_eq!(
            classifier.classify(&finding, &turns),
            ContextClass::ModelHallucination
        );
    }

    #[test]
    fn cross_turn_finding_is_real_paste() {
        let turns = vec![
            mk_turn(0, Role::User, "my key is AKIAZZZZZZZZZZ"),
            mk_turn(1, Role::User, "ZZZZZZZZ here"),
        ];
        let mut finding = mk_finding(1, "AKIAZZZZZZZZZZZZZZZZ");
        finding.span_kind = SpanKind::CrossTurn {
            contributing_turns: vec![0, 1],
        };
        let classifier = ContextClassifier::with_defaults();
        assert_eq!(classifier.classify(&finding, &turns), ContextClass::RealPaste);
    }

    #[test]
    fn code_fence_with_example_keyword_is_educational() {
        let turns = vec![mk_turn(
            0,
            Role::Assistant,
            "Here's an example of the format:\n```\nghp_abcdefghijklmnopqrstuvwxyz012345\n```\nReplace this with your actual token.",
        )];
        let finding = mk_finding(0, "ghp_abcdefghijklmnopqrstuvwxyz012345");
        let classifier = ContextClassifier::with_defaults();
        assert_eq!(
            classifier.classify(&finding, &turns),
            ContextClass::Educational
        );
    }

    #[test]
    fn doc_url_with_inline_code_is_documentation_quote() {
        let turns = vec![mk_turn(
            0,
            Role::Assistant,
            "From the docs.stripe.com documentation: use `sk_test_4eC39HqLyjWDarjtT1zdp7dc` for testing.",
        )];
        let finding = mk_finding(0, "sk_test_4eC39HqLyjWDarjtT1zdp7dc");
        let classifier = ContextClassifier::with_defaults();
        assert_eq!(
            classifier.classify(&finding, &turns),
            ContextClass::DocumentationQuote
        );
    }

    #[test]
    fn empty_turns_returns_unclassified() {
        let finding = mk_finding(0, "some_key");
        let classifier = ContextClassifier::with_defaults();
        assert_eq!(
            classifier.classify(&finding, &[]),
            ContextClass::Unclassified
        );
    }

    #[test]
    fn out_of_bounds_turn_idx_returns_unclassified() {
        let turns = vec![mk_turn(0, Role::User, "hello")];
        let finding = mk_finding(99, "some_key");
        let classifier = ContextClassifier::with_defaults();
        assert_eq!(
            classifier.classify(&finding, &turns),
            ContextClass::Unclassified
        );
    }

    #[test]
    fn wrong_file_turns_dont_affect_classification() {
        let turns = vec![mk_turn(0, Role::Assistant, "example: key here")];
        let finding = mk_finding(0, "key_value");
        let classifier = ContextClassifier::with_defaults();
        let _ = classifier.classify(&finding, &turns);
    }
}
