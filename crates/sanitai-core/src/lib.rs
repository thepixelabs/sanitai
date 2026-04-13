//! sanitai-core: shared types and traits for the SanitAI workspace.
//!
//! # Smoke-test
//!
//! The public enums re-exported below are usable without any feature flags:
//!
//! ```
//! use sanitai_core::{Confidence, Role};
//! assert_eq!(format!("{:?}", Confidence::High), "High");
//! assert_eq!(format!("{:?}", Role::User), "User");
//! ```

pub mod chunk;
pub mod chunker;
pub mod config;
pub mod error;
pub mod finding;
pub mod secure;
pub mod traits;
pub mod turn;

pub use chunk::{Chunk, ChunkerConfig, DetectorScratch, OffsetMap};
pub use chunker::{chunk_turn, ChunkIter};
pub use error::CoreError;
pub use finding::{Confidence, ContextClass, Finding, SpanKind, TransformChain};
pub use traits::{Category, ConversationParser, Detector, ReadSeek, Reconciler};
pub use turn::{Role, SourceKind, Turn, TurnMeta};
