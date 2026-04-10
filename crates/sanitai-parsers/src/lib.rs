// sanitai-parsers: Claude JSONL, ChatGPT JSON parsers and source discovery.
#![deny(clippy::unwrap_used)]

pub mod chatgpt;
pub mod claude;
pub mod discovery;

pub use chatgpt::ChatGptParser;
pub use claude::ClaudeJsonlParser;
pub use discovery::{discover_all, DiscoveredSource, FileFormat};
