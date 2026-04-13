use crate::turn::TurnId;

/// Maps byte offsets within a chunk back to byte offsets in the original source file.
///
/// Sparse: only breakpoints where the mapping changes are stored.
/// For most chunks (no JSON unescaping), this holds a single entry and translation is O(1).
#[derive(Debug, Clone)]
pub struct OffsetMap {
    /// Each entry is (chunk_byte_offset, source_byte_offset).
    /// Must be sorted by chunk_byte_offset, non-decreasing.
    breakpoints: Vec<(u32, u64)>,
}

impl OffsetMap {
    pub fn new_linear(base_source_offset: u64) -> Self {
        Self {
            breakpoints: vec![(0, base_source_offset)],
        }
    }

    /// Translate a byte offset within the chunk to the corresponding source file offset.
    pub fn translate(&self, chunk_offset: usize) -> u64 {
        // Binary search for the last breakpoint <= chunk_offset.
        let pos = self
            .breakpoints
            .partition_point(|(co, _)| *co <= chunk_offset as u32);
        let (bp_chunk, bp_source) = self.breakpoints[pos.saturating_sub(1)];
        bp_source + (chunk_offset as u64 - bp_chunk as u64)
    }
}

/// Configuration for the sliding-window chunker.
pub struct ChunkerConfig {
    /// Target window size in bytes. Default: 4096.
    pub window_bytes: usize,
    /// Stride between windows in bytes. Default: 2048 (50% overlap).
    pub stride_bytes: usize,
}

impl Default for ChunkerConfig {
    fn default() -> Self {
        Self {
            window_bytes: 4096,
            stride_bytes: 2048,
        }
    }
}

/// A chunk of text fed to detectors.
#[derive(Debug, Clone)]
pub struct Chunk<'a> {
    /// Slice of the turn's content bytes. Always valid UTF-8.
    pub bytes: &'a [u8],
    /// Maps offsets within `bytes` to the original source file.
    pub offset_map: OffsetMap,
    /// True if this is the first chunk of a message (no overlap from prior chunk).
    pub is_message_start: bool,
    /// Provenance for attributing findings back to their source turn.
    pub turn_id: TurnId,
}

/// Per-thread scratch space reused across chunk scans.
/// Avoids per-chunk allocation in the hot path.
#[derive(Default)]
pub struct DetectorScratch {
    /// Reusable buffer for intermediate decoded bytes in transform cascade.
    pub decode_buf: Vec<u8>,
    /// Running tally of decode bytes used this chunk (budget control).
    pub decode_bytes_used: usize,
    /// Cycle-detection set of 64-bit hashes of decoded blobs already processed
    /// in this chunk. Prevents the transform cascade from looping on fixed
    /// points (e.g. valid base64 that decodes to itself).
    pub decode_seen: std::collections::HashSet<u64>,
}

impl DetectorScratch {
    pub fn reset_for_chunk(&mut self) {
        self.decode_buf.clear();
        self.decode_bytes_used = 0;
        self.decode_seen.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_seen_cleared_on_reset() {
        let mut s = DetectorScratch::default();
        s.decode_seen.insert(42);
        s.decode_bytes_used = 100;
        s.reset_for_chunk();
        assert!(s.decode_seen.is_empty());
        assert_eq!(s.decode_bytes_used, 0);
    }
}
