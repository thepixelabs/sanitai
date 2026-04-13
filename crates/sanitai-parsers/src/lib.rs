// sanitai-parsers: Claude JSONL, ChatGPT JSON, Cursor SQLite, Copilot log,
// and Gemini Takeout parsers, plus source discovery.
#![deny(clippy::unwrap_used)]

pub mod chatgpt;
pub mod claude;
pub mod copilot;
pub mod cursor;
pub mod discovery;
pub mod gemini;

pub use chatgpt::ChatGptParser;
pub use claude::ClaudeJsonlParser;
pub use copilot::CopilotParser;
pub use cursor::CursorParser;
pub use discovery::{discover_all, DiscoveredSource, FileFormat};
pub use gemini::GeminiParser;
