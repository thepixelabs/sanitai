use crate::{
    chunk::{Chunk, DetectorScratch},
    error::CoreError,
    finding::Finding,
    turn::Turn,
};
use futures::stream::BoxStream;
use std::ops::Range;

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

/// Category of content a detector can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Secret,
    Credential,
    Pii,
    Pci,
    HighEntropy,
}

/// A stateless scanner that inspects a single chunk for secrets.
///
/// Implementations MUST:
/// - Be `Send + Sync`
/// - Never panic on any input (use `catch_unwind` internally if needed)
/// - Never log `Finding::matched_raw` or any secret value
/// - Push findings into `out` rather than returning a `Vec` (amortizes allocation)
pub trait Detector: Send + Sync {
    /// Stable identifier, e.g. `"aws_access_key"`. Used in config allowlists.
    fn id(&self) -> &'static str;

    /// Categories this detector can emit. Used to compile detector subsets.
    fn categories(&self) -> &'static [Category];

    /// Scan `chunk` and push any findings into `out`.
    fn scan<'c>(&self, chunk: &Chunk<'c>, scratch: &mut DetectorScratch, out: &mut Vec<Finding>);
}

// ---------------------------------------------------------------------------
// ConversationParser
// ---------------------------------------------------------------------------

/// Hint passed to `can_parse` for source-type dispatch.
pub struct SourceHint<'a> {
    pub path: &'a std::path::Path,
    /// First 4KB of file content, or less if the file is smaller.
    pub head: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sniff {
    /// This parser definitely cannot handle this source.
    No,
    /// This parser might be able to handle this source (used for tie-breaking).
    Maybe,
    /// This parser is the correct one for this source.
    Yes,
}

/// A streaming parser for a specific LLM conversation format.
///
/// Parsers MUST:
/// - Stream turns lazily — never load the entire file into memory
/// - Yield individual `Err` items for corrupt messages instead of aborting
/// - Track byte offsets accurately for the `Turn::byte_range` field
pub trait ConversationParser: Send + Sync {
    /// Stable identifier, e.g. `"claude.jsonl"`.
    fn id(&self) -> &'static str;

    /// Quick content sniff to dispatch the right parser.
    fn can_parse(&self, hint: &SourceHint<'_>) -> Sniff;

    /// Produce a lazy stream of turns.
    fn parse<'a>(
        &'a self,
        source: Box<dyn crate::ReadSeek + 'a>,
    ) -> BoxStream<'a, Result<Turn, CoreError>>;
}

// ---------------------------------------------------------------------------
// Reconciler
// ---------------------------------------------------------------------------

/// Merges overlapping findings within a single message's byte range.
pub trait Reconciler: Send + Sync {
    /// Reconcile findings for one message. Input is unsorted; output is sorted
    /// by `byte_range.start`, deduplicated, and merged.
    fn reconcile(&self, message_span: Range<usize>, findings: Vec<Finding>) -> Vec<Finding>;
}

// ---------------------------------------------------------------------------
// ReadSeek helper
// ---------------------------------------------------------------------------

/// Object-safe combination of Read + Seek, used by parsers.
pub trait ReadSeek: std::io::Read + std::io::Seek + Send {}
impl<T: std::io::Read + std::io::Seek + Send> ReadSeek for T {}
