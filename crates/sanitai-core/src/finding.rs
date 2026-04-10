use crate::turn::TurnId;
use serde::{Deserialize, Serialize};
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    Base64,
    Hex,
    UrlEncoded,
    Gzip,
    HtmlEntity,
}

/// Chain of transforms applied before detection (innermost first).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransformChain(pub Vec<Transform>);

impl TransformChain {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn push(&mut self, t: Transform) {
        self.0.push(t);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpanKind {
    /// Secret found within a single turn.
    Single,
    /// Secret assembled from fragments across multiple turns.
    CrossTurn { contributing_turns: Vec<usize> },
}

/// A detected secret or PII finding.
// Finding is serialized (JSON output) but never deserialized: TurnId contains
// Arc<PathBuf> which has no serde::Deserialize impl. The CLI round-trips
// findings through FindingJson (a flat serializable DTO) instead.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// The turn this finding belongs to (primary turn for cross-turn findings).
    pub turn_id: TurnId,
    /// Stable detector identifier, e.g. `"aws_access_key"`.
    pub detector_id: &'static str,
    /// Byte range within `Turn::content`.
    pub byte_range: Range<usize>,
    /// The exact matched bytes. NEVER log this value.
    pub matched_raw: String,
    /// Transform chain applied before detection.
    pub transform: TransformChain,
    pub confidence: Confidence,
    pub span_kind: SpanKind,
    /// Whether this finding contains the SANITAI_FAKE synthetic marker.
    pub synthetic: bool,
}

impl Finding {
    pub fn is_synthetic(&self) -> bool {
        self.matched_raw.contains("SANITAI_FAKE")
    }
}
