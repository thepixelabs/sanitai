use serde::{Deserialize, Serialize};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

/// Unique identifier for a turn: (source file path, index within that file).
pub type TurnId = (Arc<PathBuf>, usize);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Assistant,
    System,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    ClaudeCode,
    ClaudeDesktop,
    ChatGpt,
    CodexCli,
    GeminiCli,
    GitHubCopilot,
    Cursor,
    Generic,
    Stdin,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TurnMeta {
    pub conversation_id: Option<String>,
    /// Unix timestamp in seconds.
    pub timestamp: Option<i64>,
    pub model: Option<String>,
    /// 1-based line number where this turn begins inside its source file,
    /// when the parser can compute one. Line-oriented parsers (Claude JSONL,
    /// Copilot logs) populate this; tree-structured parsers (ChatGPT export,
    /// Cursor SQLite walks) leave it `None`.
    pub line_in_file: Option<u32>,
}

/// A single message turn from a conversation, normalized across all LLM sources.
#[derive(Debug, Clone)]
pub struct Turn {
    pub id: TurnId,
    pub role: Role,
    /// Raw UTF-8 text content, all content blocks concatenated.
    pub content: String,
    /// Byte range of this turn in the originating source file.
    pub byte_range: Range<u64>,
    pub source: SourceKind,
    pub meta: TurnMeta,
}
