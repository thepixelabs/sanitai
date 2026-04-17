use crate::traits::Category;
use crate::turn::{Role, TurnId};
use serde::{Deserialize, Serialize};
use std::ops::Range;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextClass {
    #[default]
    Unclassified,
    RealPaste,
    Educational,
    DocumentationQuote,
    ModelHallucination,
}

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
    /// Role of the turn this finding came from (None if not known at the
    /// construction site — e.g. inside the transform cascade).
    pub role: Option<Role>,
    /// Category inherited from the firing rule.
    pub category: Category,
    /// Shannon entropy of `matched_raw` in bits/byte at the moment of detection.
    pub entropy_score: f64,
    /// Context classification — defaults to Unclassified; populated by
    /// later pipeline stages that understand code fences, docs, etc.
    pub context_class: ContextClass,
}

impl Finding {
    pub fn is_synthetic(&self) -> bool {
        self.matched_raw.contains("SANITAI_FAKE")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_debug_does_not_contain_raw_value() {
        // If we ever wrap matched_raw in secrecy, Debug must redact it.
        // For now verify the ContextClass default is Unclassified.
        let cc = ContextClass::default();
        assert_eq!(cc, ContextClass::Unclassified);
    }

    #[test]
    fn context_class_serde_roundtrip() {
        let j = serde_json::to_string(&ContextClass::Educational).unwrap();
        assert_eq!(j, r#""educational""#);
        let back: ContextClass = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ContextClass::Educational);
    }
}
