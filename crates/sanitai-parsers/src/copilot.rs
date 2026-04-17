//! GitHub Copilot Chat log parser.
//!
//! Copilot Chat logs are found at:
//!   macOS:   ~/Library/Application Support/Code/logs/**/GitHub Copilot Chat.log
//!   Linux:   ~/.config/Code/logs/**/GitHub Copilot Chat.log
//!   Windows: %APPDATA%\Code\logs\**\GitHub Copilot Chat.log
//!
//! Format: structured log lines with a timestamp prefix and a JSON payload
//! somewhere on the line. The JSON shape is not stable across extension
//! versions, so we probe each line for the first `{` and try to parse a
//! JSON object from there, looking for `role` + `content` fields.
//!
//! Byte offsets are tracked against the full log file so findings can be
//! mapped back to a line even when the embedded JSON is offset inside it.

#![deny(clippy::unwrap_used)]

use std::io::{BufRead, BufReader};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

use futures::stream::{self, BoxStream, StreamExt};
use sanitai_core::{
    error::CoreError,
    traits::{ConversationParser, ReadSeek, Sniff, SourceHint},
    turn::{Role, SourceKind, Turn, TurnMeta},
};

pub struct CopilotParser {
    path: Arc<PathBuf>,
}

impl Default for CopilotParser {
    fn default() -> Self {
        Self {
            path: Arc::new(PathBuf::new()),
        }
    }
}

impl CopilotParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self {
            path: Arc::new(path),
        }
    }
}

impl ConversationParser for CopilotParser {
    fn id(&self) -> &'static str {
        "copilot.log"
    }

    fn can_parse(&self, hint: &SourceHint<'_>) -> Sniff {
        let name = hint.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let looks_copilot =
            name.contains("Copilot") && name.contains("Chat") && name.ends_with(".log");
        if looks_copilot {
            Sniff::Maybe
        } else {
            Sniff::No
        }
    }

    fn parse<'a>(
        &'a self,
        source: Box<dyn ReadSeek + 'a>,
    ) -> BoxStream<'a, Result<Turn, CoreError>> {
        let path = Arc::clone(&self.path);
        stream::iter(CopilotLineIter::new(source, path)).boxed()
    }
}

struct CopilotLineIter<'a> {
    reader: BufReader<Box<dyn ReadSeek + 'a>>,
    path: Arc<PathBuf>,
    byte_offset: u64,
    turn_index: usize,
    buf: String,
    done: bool,
}

impl<'a> CopilotLineIter<'a> {
    fn new(source: Box<dyn ReadSeek + 'a>, path: Arc<PathBuf>) -> Self {
        Self {
            reader: BufReader::new(source),
            path,
            byte_offset: 0,
            turn_index: 0,
            buf: String::new(),
            done: false,
        }
    }
}

impl<'a> Iterator for CopilotLineIter<'a> {
    type Item = Result<Turn, CoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            self.buf.clear();
            let read = match self.reader.read_line(&mut self.buf) {
                Ok(0) => {
                    self.done = true;
                    return None;
                }
                Ok(n) => n,
                Err(e) => {
                    self.done = true;
                    return Some(Err(CoreError::Io(e)));
                }
            };

            let line_start = self.byte_offset;
            let line_end = line_start + read as u64;
            self.byte_offset = line_end;

            let trimmed = self.buf.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                continue;
            }

            let Some(json_start) = trimmed.find('{') else {
                continue;
            };
            let candidate = &trimmed[json_start..];
            // Use the streaming deserializer so trailing log garbage after
            // the JSON payload doesn't cause the whole line to be rejected.
            let mut de =
                serde_json::Deserializer::from_str(candidate).into_iter::<serde_json::Value>();
            let Some(Ok(value)) = de.next() else {
                continue;
            };

            let Some((role, content)) = extract_message(&value) else {
                continue;
            };
            if content.is_empty() {
                continue;
            }

            let id = (Arc::clone(&self.path), self.turn_index);
            self.turn_index += 1;
            return Some(Ok(Turn {
                id,
                role,
                content,
                byte_range: Range {
                    start: line_start,
                    end: line_end,
                },
                source: SourceKind::GitHubCopilot,
                meta: TurnMeta::default(),
            }));
        }
    }
}

fn extract_message(v: &serde_json::Value) -> Option<(Role, String)> {
    // Direct shape: { "role": "...", "content": "..." }
    if let Some(obj) = v.as_object() {
        if let Some(role_str) = obj.get("role").and_then(|v| v.as_str()) {
            let role = match role_str {
                "user" => Role::User,
                "assistant" => Role::Assistant,
                "system" => Role::System,
                "tool" | "function" => Role::Tool,
                _ => return None,
            };
            let content = obj
                .get("content")
                .or_else(|| obj.get("message"))
                .or_else(|| obj.get("text"))
                .map(stringify)
                .unwrap_or_default();
            if content.is_empty() {
                return None;
            }
            return Some((role, content));
        }
        // Wrapped shape: { "message": { "role": ..., "content": ... } }
        if let Some(inner) = obj.get("message") {
            return extract_message(inner);
        }
    }
    None
}

fn stringify(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use std::io::Cursor;

    fn parse(input: &str) -> Vec<Result<Turn, CoreError>> {
        let parser = CopilotParser::with_path(PathBuf::from("/tmp/GitHub Copilot Chat.log"));
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(input.to_owned().into_bytes()));
        futures::executor::block_on(parser.parse(cursor).collect::<Vec<_>>())
    }

    #[test]
    fn extracts_inline_json_messages() {
        let input = "\
2026-01-01 12:00:00 [info] {\"role\":\"user\",\"content\":\"hey copilot\"}
2026-01-01 12:00:01 [info] {\"role\":\"assistant\",\"content\":\"hey back\"}
";
        let turns: Vec<_> = parse(input).into_iter().map(|r| r.expect("ok")).collect();
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].role, Role::User);
        assert_eq!(turns[0].content, "hey copilot");
        assert_eq!(turns[0].source, SourceKind::GitHubCopilot);
        assert_eq!(turns[1].role, Role::Assistant);
    }

    #[test]
    fn ignores_lines_without_role() {
        let input = "2026-01-01 [debug] waiting for user\nnot json at all\n";
        let results = parse(input);
        assert!(results.is_empty());
    }

    #[test]
    fn can_parse_sniffs_copilot_log() {
        let parser = CopilotParser::new();
        let hint = SourceHint {
            path: std::path::Path::new("GitHub Copilot Chat.log"),
            head: b"",
        };
        assert_eq!(parser.can_parse(&hint), Sniff::Maybe);

        let hint2 = SourceHint {
            path: std::path::Path::new("other.log"),
            head: b"",
        };
        assert_eq!(parser.can_parse(&hint2), Sniff::No);
    }
}
