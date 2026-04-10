//! Cross-turn fragment reassembly.
//!
//! Motivation: an attacker (or a sloppy user) might split a secret across
//! two or more turns to defeat a naive detector. Example:
//!
//! ```text
//! turn 1: "my key is AKIAIOSFOD"
//! turn 2: "NN7EXAMPLE and here is the rest"
//! ```
//!
//! Neither turn contains a full AWS access key, but concatenating the tail
//! of turn 1 with the head of turn 2 does. This module keeps a sliding
//! window of the **tail** of the last N turns and, on each new turn,
//! concatenates them with the new turn's head, then rescans the join
//! region. A finding is only emitted if the match genuinely **spans** the
//! join offset — this avoids re-reporting findings that already exist in a
//! single turn.
//!
//! Security:
//! - The window buffer holds raw turn content (which may include secrets),
//!   so the [`TurnTail`] type is `ZeroizeOnDrop`.
//! - We never log the reassembled content; only indices and byte offsets.

use crate::regex_detector::RegexDetector;
use sanitai_core::{
    finding::{Finding, SpanKind, TransformChain},
    turn::{Turn, TurnId},
};
use std::collections::VecDeque;
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
pub struct CrossTurnConfig {
    /// How many prior turns to keep in the window.
    pub lookahead_turns: usize,
    /// Minimum bytes from the tail of a prior turn and head of a new turn
    /// to consider for joining.
    pub min_prefix_bytes: usize,
    /// Maximum bytes of tail to keep per turn. Bounds memory.
    pub max_tail_bytes: usize,
}

impl Default for CrossTurnConfig {
    fn default() -> Self {
        Self {
            lookahead_turns: 3,
            min_prefix_bytes: 8,
            max_tail_bytes: 128,
        }
    }
}

/// A fragment of a turn retained for cross-turn correlation. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TurnTail {
    /// Last `max_tail_bytes` bytes of the turn's content.
    tail: String,
    #[zeroize(skip)]
    turn_index: usize,
    #[zeroize(skip)]
    #[allow(dead_code)] // retained for future attribution in cross-turn findings
    turn_id: TurnId,
}

/// A candidate reassembled across two turns.
#[derive(Debug, Clone)]
pub struct CrossTurnCandidate {
    pub head_turn_index: usize,
    pub tail_turn_index: usize,
    pub reassembled: String,
    /// Byte offset inside `reassembled` where the new turn's head begins.
    /// Any match that starts before this offset and ends after it spans
    /// the join.
    pub join_offset: usize,
}

/// Sliding-window cross-turn correlator.
pub struct CrossTurnCorrelator {
    config: CrossTurnConfig,
    window: VecDeque<TurnTail>,
    detector: Arc<RegexDetector>,
}

impl CrossTurnCorrelator {
    pub fn new(detector: Arc<RegexDetector>, config: CrossTurnConfig) -> Self {
        Self {
            config,
            window: VecDeque::new(),
            detector,
        }
    }

    pub fn with_defaults(detector: Arc<RegexDetector>) -> Self {
        Self::new(detector, CrossTurnConfig::default())
    }

    /// Feed a new turn. Returns any cross-turn findings that arise from
    /// joining this turn's head with tails of prior turns, then advances
    /// the window.
    pub fn push_turn(&mut self, turn: &Turn) -> Vec<Finding> {
        let mut out = Vec::new();

        // Head of the new turn (bounded).
        let head_len = self.config.max_tail_bytes.min(turn.content.len());
        let head = safe_byte_slice(&turn.content, 0, head_len);

        // For each prior tail, try joining and rescan.
        for prior in &self.window {
            if prior.tail.len() < self.config.min_prefix_bytes
                || head.len() < self.config.min_prefix_bytes
            {
                continue;
            }
            let join_offset = prior.tail.len();
            let mut reassembled = String::with_capacity(prior.tail.len() + head.len());
            reassembled.push_str(&prior.tail);
            reassembled.push_str(head);

            let mut scan_out: Vec<Finding> = Vec::new();
            let empty_chain = TransformChain::default();
            // We scan under the NEW turn's id — findings are attributed to
            // the turn that completed the secret.
            self.detector
                .scan_str(&reassembled, &turn.id, 0, &empty_chain, &mut scan_out);

            for mut f in scan_out {
                let start = f.byte_range.start;
                let end = f.byte_range.end;
                if start < join_offset && end > join_offset {
                    // Genuine cross-turn match.
                    f.span_kind = SpanKind::CrossTurn {
                        contributing_turns: vec![prior.turn_index, turn.id.1],
                    };
                    out.push(f);
                }
            }
            tracing::trace!(
                head_turn = prior.turn_index,
                tail_turn = turn.id.1,
                join = join_offset,
                "cross-turn scan complete"
            );
        }

        // Advance the window: append the new turn's tail.
        let tail_start = turn
            .content
            .len()
            .saturating_sub(self.config.max_tail_bytes);
        let tail = safe_byte_slice(&turn.content, tail_start, turn.content.len());
        self.window.push_back(TurnTail {
            tail: tail.to_owned(),
            turn_index: turn.id.1,
            turn_id: turn.id.clone(),
        });
        while self.window.len() > self.config.lookahead_turns {
            // Popped TurnTail is zeroized on drop.
            self.window.pop_front();
        }

        out
    }

    /// Build candidate reassemblies without scanning. Exposed for testing
    /// and for callers that want to integrate their own detector.
    pub fn candidates(&self, new_turn: &Turn) -> Vec<CrossTurnCandidate> {
        let head_len = self.config.max_tail_bytes.min(new_turn.content.len());
        let head = safe_byte_slice(&new_turn.content, 0, head_len);
        let mut out = Vec::new();
        for prior in &self.window {
            if prior.tail.len() < self.config.min_prefix_bytes
                || head.len() < self.config.min_prefix_bytes
            {
                continue;
            }
            let join_offset = prior.tail.len();
            let reassembled = format!("{}{}", prior.tail, head);
            out.push(CrossTurnCandidate {
                head_turn_index: prior.turn_index,
                tail_turn_index: new_turn.id.1,
                reassembled,
                join_offset,
            });
        }
        out
    }

    pub fn window_len(&self) -> usize {
        self.window.len()
    }
}

/// Safe UTF-8 boundary-aware slice. Shrinks `start`/`end` to the nearest
/// char boundary if they are not aligned (avoids panics on multi-byte chars).
fn safe_byte_slice(s: &str, mut start: usize, mut end: usize) -> &str {
    end = end.min(s.len());
    while start < end && !s.is_char_boundary(start) {
        start += 1;
    }
    while end > start && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[start..end]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sanitai_core::turn::{Role, SourceKind, TurnMeta};
    use std::path::PathBuf;

    fn mk_turn(idx: usize, content: &str) -> Turn {
        Turn {
            id: (Arc::new(PathBuf::from("/tmp/conv")), idx),
            role: Role::User,
            content: content.to_string(),
            byte_range: 0..(content.len() as u64),
            source: SourceKind::Generic,
            meta: TurnMeta::default(),
        }
    }

    #[test]
    fn detects_aws_key_split_at_char_12() {
        // AKIAIOSFODNN7EXAMPLE is 20 chars. Split after char 12:
        // "AKIAIOSFODNN" + "7EXAMPLE".
        let (a, b) = ("AKIAIOSFODNN", "7EXAMPLE");
        assert_eq!(a.len(), 12);
        let turn1 = mk_turn(0, &format!("here comes a key: {}", a));
        let turn2 = mk_turn(1, &format!("{} and some more words", b));

        let mut corr = CrossTurnCorrelator::with_defaults(Arc::new(RegexDetector::new()));
        let f1 = corr.push_turn(&turn1);
        assert!(f1.is_empty(), "no findings expected on first turn");
        let f2 = corr.push_turn(&turn2);
        assert!(
            f2.iter().any(|f| {
                f.detector_id == "aws_access_key_id"
                    && matches!(f.span_kind, SpanKind::CrossTurn { .. })
            }),
            "expected cross-turn AWS key finding, got {:?}",
            f2.iter().map(|f| f.detector_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn single_turn_secret_not_reported_as_cross_turn() {
        // Full key in a single turn: should be picked up by the per-turn
        // detector, NOT by the cross-turn correlator.
        let turn1 = mk_turn(0, "prefix padding to fill the tail buffer well");
        let turn2 = mk_turn(1, "AKIAIOSFODNN7EXAMPLE with trailing text");
        let mut corr = CrossTurnCorrelator::with_defaults(Arc::new(RegexDetector::new()));
        corr.push_turn(&turn1);
        let f2 = corr.push_turn(&turn2);
        // The key begins AT the start of the reassembled head section, so
        // start == join_offset which does NOT satisfy start < join_offset.
        assert!(
            f2.iter()
                .all(|f| !matches!(f.span_kind, SpanKind::CrossTurn { .. })
                    || f.detector_id != "aws_access_key_id"),
            "single-turn key should not be cross-turn reported"
        );
    }

    #[test]
    fn window_bounded_by_lookahead() {
        let mut corr = CrossTurnCorrelator::new(
            Arc::new(RegexDetector::new()),
            CrossTurnConfig {
                lookahead_turns: 2,
                min_prefix_bytes: 4,
                max_tail_bytes: 64,
            },
        );
        for i in 0..10 {
            let t = mk_turn(i, &format!("this is turn number {i}"));
            let _ = corr.push_turn(&t);
        }
        assert_eq!(corr.window_len(), 2);
    }
}
