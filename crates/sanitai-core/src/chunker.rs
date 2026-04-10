//! Sliding-window chunker.
//!
//! Turns are broken into overlapping byte windows so detectors can find
//! secrets that straddle arbitrary offsets while still bounding the amount
//! of text any one detector scans at a time. The overlap (`window - stride`)
//! is the largest secret that can safely cross a window boundary without
//! being missed by a non-reentrant detector.
//!
//! Guarantees:
//! - Every byte of `turn.content` appears in at least one chunk.
//! - Chunk boundaries never split a UTF-8 codepoint.
//! - For content shorter than `window_bytes`, exactly one chunk is emitted.
//! - For empty content, zero chunks are emitted.

#![deny(clippy::unwrap_used)]

use crate::chunk::{Chunk, ChunkerConfig, OffsetMap};
use crate::turn::Turn;

/// Iterator over `Chunk`s carved out of a `Turn`.
pub struct ChunkIter<'a> {
    // Fields are private by design; construct via `chunk_turn`.
    turn: &'a Turn,
    cfg: &'a ChunkerConfig,
    /// Next window start in bytes (pre-snap).
    cursor: usize,
    /// Set once the iterator has yielded its final chunk.
    done: bool,
}

impl<'a> Iterator for ChunkIter<'a> {
    type Item = Chunk<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let content = self.turn.content.as_bytes();
        let len = content.len();
        if len == 0 {
            self.done = true;
            return None;
        }

        // Snap start down to a char boundary (it is already zero on the first
        // iteration, so this only matters for overlap windows).
        let mut start = snap_down(&self.turn.content, self.cursor.min(len));

        // Compute end, clamped to len then snapped down.
        let raw_end = start.saturating_add(self.cfg.window_bytes).min(len);
        let mut end = snap_down(&self.turn.content, raw_end);

        // Pathological guard: if `end == start` we'd make no progress. This
        // can only happen with extremely pathological UTF-8 (a codepoint
        // longer than `window_bytes`) or misconfiguration. Extend forward.
        if end == start {
            end = snap_up(&self.turn.content, start + 1);
        }

        // Ensure the final chunk always reaches the end of content so the
        // "every byte covered" guarantee holds even when the last window
        // would otherwise be snapped short.
        if raw_end == len {
            end = len;
        }

        let chunk = Chunk {
            bytes: &content[start..end],
            offset_map: OffsetMap::new_linear(start as u64 + self.turn.byte_range.start),
            is_message_start: start == 0,
            turn_id: self.turn.id.clone(),
        };

        // Advance.
        if end >= len {
            // Last chunk. One more call will return None.
            self.done = true;
        } else {
            let next_cursor = start.saturating_add(self.cfg.stride_bytes);
            // If the stride is zero or the next start would not advance past
            // our current start, force progress so we never spin.
            if next_cursor <= start {
                start = start.saturating_add(1);
                self.cursor = start;
            } else {
                self.cursor = next_cursor;
            }
        }

        Some(chunk)
    }
}

/// Carve a `Turn` into overlapping chunks.
///
/// See module docs for the exact guarantees. The returned iterator borrows
/// from `turn` for the lifetime `'a`.
pub fn chunk_turn<'a>(
    turn: &'a Turn,
    cfg: &'a ChunkerConfig,
) -> impl Iterator<Item = Chunk<'a>> + 'a {
    ChunkIter {
        turn,
        cfg,
        cursor: 0,
        done: false,
    }
}

// ---------------------------------------------------------------------------
// UTF-8 boundary helpers
// ---------------------------------------------------------------------------

/// Snap an index down to the nearest UTF-8 char boundary (inclusive).
fn snap_down(s: &str, mut idx: usize) -> usize {
    let len = s.len();
    if idx >= len {
        return len;
    }
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

/// Snap an index up to the nearest UTF-8 char boundary (inclusive).
fn snap_up(s: &str, mut idx: usize) -> usize {
    let len = s.len();
    if idx >= len {
        return len;
    }
    while idx < len && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::turn::{Role, SourceKind, TurnMeta};
    use proptest::prelude::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn make_turn(content: String) -> Turn {
        Turn {
            id: (Arc::new(PathBuf::from("/tmp/t")), 0),
            role: Role::User,
            content,
            byte_range: 0..0,
            source: SourceKind::Generic,
            meta: TurnMeta::default(),
        }
    }

    #[test]
    fn empty_content_yields_no_chunks() {
        let turn = make_turn(String::new());
        let cfg = ChunkerConfig::default();
        assert_eq!(chunk_turn(&turn, &cfg).count(), 0);
    }

    #[test]
    fn short_content_yields_one_chunk() {
        let turn = make_turn("hello world".to_string());
        let cfg = ChunkerConfig::default();
        let chunks: Vec<_> = chunk_turn(&turn, &cfg).collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].bytes, b"hello world");
        assert!(chunks[0].is_message_start);
    }

    #[test]
    fn long_content_produces_multiple_overlapping_chunks() {
        // 10 KB of 'a' bytes.
        let content = "a".repeat(10_000);
        let turn = make_turn(content);
        let cfg = ChunkerConfig::default();
        let chunks: Vec<_> = chunk_turn(&turn, &cfg).collect();
        assert!(
            chunks.len() > 1,
            "expected multiple chunks, got {}",
            chunks.len()
        );
        assert!(chunks[0].is_message_start);
        for c in &chunks[1..] {
            assert!(!c.is_message_start);
        }
    }

    #[test]
    fn overlap_size() {
        let content = "a".repeat(10_000);
        let turn = make_turn(content);
        let cfg = ChunkerConfig::default();
        let chunks: Vec<_> = chunk_turn(&turn, &cfg).collect();

        // Recover absolute start offsets via offset_map.translate(0).
        let expected_overlap = (cfg.window_bytes - cfg.stride_bytes) as u64;
        for pair in chunks.windows(2) {
            let prev = &pair[0];
            let cur = &pair[1];
            let prev_start = prev.offset_map.translate(0);
            let prev_end = prev_start + prev.bytes.len() as u64;
            let cur_start = cur.offset_map.translate(0);
            assert!(
                prev_end >= cur_start,
                "chunks must overlap: prev_end={prev_end} cur_start={cur_start}"
            );
            assert_eq!(prev_end - cur_start, expected_overlap);
        }
    }

    #[test]
    fn total_coverage() {
        let content = "The quick brown fox jumps over the lazy dog. ".repeat(300);
        let len = content.len();
        let turn = make_turn(content);
        let cfg = ChunkerConfig::default();
        let chunks: Vec<_> = chunk_turn(&turn, &cfg).collect();

        let mut covered = vec![false; len];
        for c in &chunks {
            let start = c.offset_map.translate(0) as usize;
            let end = start + c.bytes.len();
            for slot in &mut covered[start..end] {
                *slot = true;
            }
        }
        assert!(covered.iter().all(|b| *b), "every byte must be covered");
    }

    #[test]
    fn no_chunk_boundary_splits_utf8_multibyte_fixed() {
        // 4-byte emoji (U+1F600 GRINNING FACE) packed tightly so the window
        // end will fall inside one of them.
        let content = "\u{1F600}".repeat(2000);
        let turn = make_turn(content.clone());
        let cfg = ChunkerConfig::default();
        for chunk in chunk_turn(&turn, &cfg) {
            // Slice must be valid UTF-8.
            assert!(std::str::from_utf8(chunk.bytes).is_ok());
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn no_chunk_boundary_splits_utf8_multibyte(s in "\\PC{0,2000}") {
            // `\PC` = any Unicode char except control. Up to 20k chars.
            let turn = make_turn(s.clone());
            let cfg = ChunkerConfig { window_bytes: 256, stride_bytes: 128 };
            let mut last_end: Option<usize> = None;
            let mut covered = vec![false; s.len()];
            for chunk in chunk_turn(&turn, &cfg) {
                // Always valid UTF-8.
                prop_assert!(std::str::from_utf8(chunk.bytes).is_ok());
                let start = chunk.offset_map.translate(0) as usize;
                let end = start + chunk.bytes.len();
                for slot in &mut covered[start..end] {
                    *slot = true;
                }
                if let Some(le) = last_end {
                    // Non-decreasing progress on end offset.
                    prop_assert!(end >= le);
                }
                last_end = Some(end);
            }
            prop_assert!(covered.iter().all(|b| *b));
        }
    }
}
