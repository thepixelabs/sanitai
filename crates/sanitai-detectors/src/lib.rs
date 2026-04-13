// sanitai-detectors: regex, entropy, and heuristic detector implementations.
//
// IMPORTANT: Never log `Finding::matched_raw` or any secret value in this
// crate. All `tracing` calls are audited to carry only detector ids,
// byte lengths, and counts.

#![deny(clippy::unwrap_used)]

pub mod context_classifier;
pub mod cross_turn;
pub mod keyword_filter;
pub mod regex_detector;
pub mod stopwords;
pub mod transform;

pub use context_classifier::{ContextClassifier, ContextClassifierConfig};
pub use cross_turn::{CrossTurnCandidate, CrossTurnConfig, CrossTurnCorrelator};
pub use keyword_filter::KeywordFilter;
pub use regex_detector::{iban_valid, luhn_valid, shannon_entropy, RegexDetector};
pub use transform::{TransformConfig, TransformDetector};
