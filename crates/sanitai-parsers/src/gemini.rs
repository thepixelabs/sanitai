//! Google Gemini (via Google Takeout) conversation parser.
//!
//! The Google Takeout export places Gemini conversations at:
//!   Takeout/Gemini/MyActivity.json
//!
//! Canonical format:
//!
//! ```json
//! [
//!   {
//!     "title": "conversation title",
//!     "messages": [
//!       { "role": "user",  "content": "..." },
//!       { "role": "model", "content": "..." }
//!     ]
//!   }
//! ]
//! ```
//!
//! `"model"` maps to `Role::Assistant`. Real Takeout exports sometimes
//! carry extra fields (`timestamp`, `attachments`, …) which we ignore.

#![deny(clippy::unwrap_used)]

use std::io::Read;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

use futures::stream::{self, BoxStream, StreamExt};
use sanitai_core::{
    error::CoreError,
    traits::{ConversationParser, ReadSeek, Sniff, SourceHint},
    turn::{Role, SourceKind, Turn, TurnMeta},
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct RawConversation {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    messages: Vec<RawMessage>,
}

#[derive(Debug, Deserialize)]
struct RawMessage {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    timestamp: Option<serde_json::Value>,
}

pub struct GeminiParser {
    path: Arc<PathBuf>,
}

impl Default for GeminiParser {
    fn default() -> Self {
        Self {
            path: Arc::new(PathBuf::new()),
        }
    }
}

impl GeminiParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self {
            path: Arc::new(path),
        }
    }
}

impl ConversationParser for GeminiParser {
    fn id(&self) -> &'static str {
        "gemini.takeout"
    }

    fn can_parse(&self, hint: &SourceHint<'_>) -> Sniff {
        let path_str = hint.path.to_string_lossy();
        let name = hint
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let looks_gemini = path_str.contains("Gemini") && name == "MyActivity.json";
        if !looks_gemini {
            return Sniff::No;
        }
        // Confirm JSON-ish content so we don't grab unrelated files named
        // MyActivity.json that happen to sit in a "Gemini" dir.
        let head = String::from_utf8_lossy(hint.head);
        if head.trim_start().starts_with('[') || head.trim_start().starts_with('{') {
            Sniff::Maybe
        } else {
            Sniff::No
        }
    }

    fn parse<'a>(
        &'a self,
        mut source: Box<dyn ReadSeek + 'a>,
    ) -> BoxStream<'a, Result<Turn, CoreError>> {
        let path = Arc::clone(&self.path);
        let mut buf = Vec::new();
        if let Err(e) = source.read_to_end(&mut buf) {
            return stream::iter(vec![Err(CoreError::Io(e))]).boxed();
        }

        let convs: Vec<RawConversation> = match serde_json::from_slice(&buf) {
            Ok(v) => v,
            Err(e) => {
                return stream::iter(vec![Err(CoreError::Parse {
                    parser: "gemini.takeout",
                    offset: 0,
                    source: Box::new(e),
                })])
                .boxed();
            }
        };

        let mut out: Vec<Result<Turn, CoreError>> = Vec::new();
        let mut turn_index: usize = 0;
        let mut running_offset: u64 = 0;

        for conv in convs {
            let title = conv.title;
            for msg in conv.messages {
                let role = match msg.role.as_deref().unwrap_or("") {
                    "user" => Role::User,
                    "model" | "assistant" => Role::Assistant,
                    "system" => Role::System,
                    "tool" | "function" => Role::Tool,
                    _ => continue,
                };
                let content = msg.content.unwrap_or_default();
                if content.is_empty() {
                    continue;
                }
                let len = content.len() as u64;
                let start = running_offset;
                running_offset = running_offset.saturating_add(len);

                out.push(Ok(Turn {
                    id: (Arc::clone(&path), turn_index),
                    role,
                    content,
                    byte_range: Range {
                        start,
                        end: start + len,
                    },
                    source: SourceKind::GeminiCli,
                    meta: TurnMeta {
                        conversation_id: title.clone(),
                        timestamp: msg.timestamp.as_ref().and_then(|v| v.as_i64()),
                        model: None,
                    },
                }));
                turn_index += 1;
            }
        }

        stream::iter(out).boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use std::io::Cursor;

    fn parse(input: &str) -> Vec<Result<Turn, CoreError>> {
        let parser = GeminiParser::with_path(PathBuf::from("/tmp/MyActivity.json"));
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(input.to_owned().into_bytes()));
        futures::executor::block_on(parser.parse(cursor).collect::<Vec<_>>())
    }

    #[test]
    fn parses_takeout_format() {
        let doc = r#"[
            {"title":"chat","messages":[
                {"role":"user","content":"hi gemini"},
                {"role":"model","content":"hi human"}
            ]}
        ]"#;
        let turns: Vec<_> = parse(doc).into_iter().map(|r| r.expect("ok")).collect();
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].role, Role::User);
        assert_eq!(turns[0].content, "hi gemini");
        assert_eq!(turns[0].source, SourceKind::GeminiCli);
        assert_eq!(turns[1].role, Role::Assistant);
        assert_eq!(turns[1].content, "hi human");
        assert_eq!(turns[0].meta.conversation_id.as_deref(), Some("chat"));
    }

    #[test]
    fn malformed_json_returns_err() {
        let results = parse("this is not json");
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
    }

    #[test]
    fn can_parse_sniff() {
        let parser = GeminiParser::new();
        let hint = SourceHint {
            path: std::path::Path::new("Takeout/Gemini/MyActivity.json"),
            head: b"[{",
        };
        assert_eq!(parser.can_parse(&hint), Sniff::Maybe);

        let hint2 = SourceHint {
            path: std::path::Path::new("other.json"),
            head: b"[{",
        };
        assert_eq!(parser.can_parse(&hint2), Sniff::No);
    }
}
