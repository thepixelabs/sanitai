//! Claude Code JSONL conversation parser.
//!
//! The on-disk format (`~/.claude/projects/**/*.jsonl`) stores one JSON object
//! per line. Each line is a `user`, `assistant`, `tool`, or `summary` record.
//!
//! This parser streams the file line-by-line via a `BufReader`, emits one
//! `Turn` per recognized record, and yields `Err` items for malformed lines
//! rather than aborting. Byte offsets are tracked against the original file so
//! findings can be attributed back to the exact source range.

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
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

/// Raw JSONL envelope. The `type` discriminator tells us which branch to read.
#[derive(Debug, Deserialize)]
struct RawLine {
    #[serde(rename = "type")]
    kind: Option<String>,
    message: Option<RawMessage>,
    content: Option<RawContent>,
    #[allow(dead_code)]
    summary: Option<String>,
    #[serde(rename = "uuid")]
    _uuid: Option<String>,
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
    timestamp: Option<serde_json::Value>,
    model: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawMessage {
    role: Option<String>,
    content: Option<RawContent>,
    model: Option<String>,
}

/// Claude's `content` field is either a plain string or a list of blocks.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawContent {
    Text(String),
    Blocks(Vec<RawBlock>),
}

#[derive(Debug, Deserialize)]
struct RawBlock {
    #[serde(rename = "type")]
    kind: Option<String>,
    // Text block.
    text: Option<String>,
    // Tool use block.
    name: Option<String>,
    input: Option<serde_json::Value>,
    // Tool result block.
    content: Option<RawContent>,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

pub struct ClaudeJsonlParser {
    /// Logical path of the current file (used for `TurnId`). Parsers are
    /// usually reused across files, so we keep this as an `Option` that the
    /// caller can override via a builder. The default is an empty path; tests
    /// and higher layers that need attribution should use `with_path`.
    path: Arc<PathBuf>,
}

impl Default for ClaudeJsonlParser {
    fn default() -> Self {
        Self {
            path: Arc::new(PathBuf::new()),
        }
    }
}

impl ClaudeJsonlParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a logical source path so emitted `TurnId`s point at this file.
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            path: Arc::new(path),
        }
    }
}

impl ConversationParser for ClaudeJsonlParser {
    fn id(&self) -> &'static str {
        "claude.jsonl"
    }

    fn can_parse(&self, hint: &SourceHint<'_>) -> Sniff {
        let is_jsonl = hint
            .path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("jsonl"))
            .unwrap_or(false);
        if !is_jsonl {
            return Sniff::No;
        }
        let head = String::from_utf8_lossy(hint.head);
        if head.contains(r#""type":"user""#)
            || head.contains(r#""type":"assistant""#)
            || head.contains(r#""type": "user""#)
            || head.contains(r#""type": "assistant""#)
        {
            Sniff::Yes
        } else {
            Sniff::Maybe
        }
    }

    fn parse<'a>(
        &'a self,
        source: Box<dyn ReadSeek + 'a>,
    ) -> BoxStream<'a, Result<Turn, CoreError>> {
        let path = Arc::clone(&self.path);
        let iter = ClaudeLineIter::new(source, path);
        stream::iter(iter).boxed()
    }
}

// ---------------------------------------------------------------------------
// Blocking line iterator
// ---------------------------------------------------------------------------

struct ClaudeLineIter<'a> {
    reader: BufReader<Box<dyn ReadSeek + 'a>>,
    path: Arc<PathBuf>,
    /// Running byte counter into the original file.
    byte_offset: u64,
    /// Running turn index within this file.
    turn_index: usize,
    buf: String,
    done: bool,
}

impl<'a> ClaudeLineIter<'a> {
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

impl<'a> Iterator for ClaudeLineIter<'a> {
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

            match parse_line(trimmed) {
                Ok(Some((role, content, meta))) => {
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
                        source: SourceKind::ClaudeCode,
                        meta,
                    }));
                }
                Ok(None) => {
                    // Recognized record type we deliberately skip (e.g. `summary`).
                    continue;
                }
                Err(err) => {
                    // Malformed line: warn and yield an error item so callers
                    // see the problem but the stream keeps going on the next call.
                    tracing::warn!(
                        parser = "claude.jsonl",
                        offset = line_start,
                        error = %err,
                        "skipping malformed claude jsonl line"
                    );
                    return Some(Err(CoreError::Parse {
                        parser: "claude.jsonl",
                        offset: line_start,
                        source: Box::new(err),
                    }));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Line decoder
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct LineError(String);

/// Returns `Ok(Some(...))` for an emitted turn, `Ok(None)` for a recognized but
/// skipped record, and `Err(...)` for a malformed line.
fn parse_line(line: &str) -> Result<Option<(Role, String, TurnMeta)>, LineError> {
    let raw: RawLine = serde_json::from_str(line).map_err(|e| LineError(e.to_string()))?;

    let kind = raw.kind.as_deref().unwrap_or("");

    // Pull optional metadata that applies to any record.
    let mut meta = TurnMeta {
        conversation_id: raw.session_id.clone(),
        timestamp: extract_timestamp(raw.timestamp.as_ref()),
        model: raw.model.clone(),
    };

    match kind {
        "user" | "assistant" => {
            let message = raw
                .message
                .ok_or_else(|| LineError(format!("{} record missing `message`", kind)))?;
            if meta.model.is_none() {
                meta.model = message.model.clone();
            }
            let role = match message.role.as_deref().unwrap_or(kind) {
                "user" => Role::User,
                "assistant" => Role::Assistant,
                "system" => Role::System,
                "tool" => Role::Tool,
                other => {
                    return Err(LineError(format!("unknown role '{}'", other)));
                }
            };
            let content = match message.content {
                Some(c) => render_content(&c),
                None => String::new(),
            };
            Ok(Some((role, content, meta)))
        }
        "tool" | "tool_result" => {
            let role = Role::Tool;
            let content = match raw.content {
                Some(c) => render_content(&c),
                None => String::new(),
            };
            Ok(Some((role, content, meta)))
        }
        "summary" => {
            // Summaries are metadata, not conversation turns. Skip them.
            Ok(None)
        }
        "" => Err(LineError("record missing `type`".to_string())),
        other => {
            // Unknown record kind — log at debug, skip without erroring so
            // forward-compatible fields don't poison the stream.
            tracing::debug!(
                parser = "claude.jsonl",
                kind = other,
                "skipping unknown record"
            );
            Ok(None)
        }
    }
}

fn extract_timestamp(v: Option<&serde_json::Value>) -> Option<i64> {
    let v = v?;
    if let Some(n) = v.as_i64() {
        return Some(n);
    }
    if let Some(f) = v.as_f64() {
        return Some(f as i64);
    }
    // Claude writes ISO-8601 strings. We don't pull in chrono here; leave as None.
    None
}

/// Concatenate text from a Claude `content` field. Image blocks are dropped.
fn render_content(content: &RawContent) -> String {
    match content {
        RawContent::Text(s) => s.clone(),
        RawContent::Blocks(blocks) => {
            let mut out = String::new();
            for block in blocks {
                let kind = block.kind.as_deref().unwrap_or("");
                match kind {
                    "text" => {
                        if let Some(t) = &block.text {
                            if !out.is_empty() {
                                out.push('\n');
                            }
                            out.push_str(t);
                        }
                    }
                    "tool_use" => {
                        // Serialize the tool invocation as JSON so detectors
                        // can still see any secrets passed through `input`.
                        if !out.is_empty() {
                            out.push('\n');
                        }
                        let name = block.name.as_deref().unwrap_or("");
                        out.push_str("[tool_use ");
                        out.push_str(name);
                        out.push_str("] ");
                        if let Some(input) = &block.input {
                            out.push_str(&input.to_string());
                        }
                    }
                    "tool_result" => {
                        if let Some(inner) = &block.content {
                            if !out.is_empty() {
                                out.push('\n');
                            }
                            out.push_str(&render_content(inner));
                        }
                    }
                    "image" => {
                        // Binary payload — skip entirely.
                    }
                    _ => {
                        // Unknown block type: leave untouched.
                    }
                }
            }
            out
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use std::io::Cursor;

    fn parse_all(input: &str) -> Vec<Result<Turn, CoreError>> {
        let parser = ClaudeJsonlParser::with_path(PathBuf::from("/tmp/claude.jsonl"));
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(input.to_owned().into_bytes()));
        let stream = parser.parse(cursor);
        futures::executor::block_on(stream.collect::<Vec<_>>())
    }

    #[test]
    fn parses_plain_user_string() {
        let line = r#"{"type":"user","message":{"role":"user","content":"hello world"}}"#;
        let results = parse_all(line);
        assert_eq!(results.len(), 1);
        let turn = results.into_iter().next().expect("one item").expect("ok");
        assert_eq!(turn.role, Role::User);
        assert_eq!(turn.content, "hello world");
        assert_eq!(turn.source, SourceKind::ClaudeCode);
        assert_eq!(turn.byte_range.start, 0);
    }

    #[test]
    fn parses_assistant_content_blocks() {
        let line = r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"part one"},{"type":"tool_use","id":"t1","name":"Read","input":{"path":"/etc/passwd"}},{"type":"text","text":"part two"}]}}"#;
        let results = parse_all(line);
        let turn = results.into_iter().next().expect("one").expect("ok");
        assert_eq!(turn.role, Role::Assistant);
        assert!(turn.content.contains("part one"));
        assert!(turn.content.contains("part two"));
        assert!(turn.content.contains("[tool_use Read]"));
        assert!(turn.content.contains("/etc/passwd"));
    }

    #[test]
    fn skips_image_blocks() {
        let line = r#"{"type":"user","message":{"role":"user","content":[{"type":"image","source":{"data":"base64..."}},{"type":"text","text":"caption"}]}}"#;
        let results = parse_all(line);
        let turn = results.into_iter().next().expect("one").expect("ok");
        assert_eq!(turn.content, "caption");
    }

    #[test]
    fn malformed_line_yields_err_but_continues() {
        let input = "not json at all\n".to_string()
            + r#"{"type":"user","message":{"role":"user","content":"valid"}}"#
            + "\n";
        let results = parse_all(&input);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_err());
        let turn = results[1].as_ref().expect("second ok");
        assert_eq!(turn.content, "valid");
        // The valid turn must report its offset after the malformed line.
        assert!(turn.byte_range.start > 0);
    }

    #[test]
    fn summary_records_are_skipped() {
        let input = r#"{"type":"summary","summary":"hi"}
{"type":"user","message":{"role":"user","content":"x"}}
"#;
        let results = parse_all(input);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].as_ref().expect("ok").content, "x");
    }

    #[test]
    fn can_parse_sniffs_jsonl() {
        let parser = ClaudeJsonlParser::new();
        let head = br#"{"type":"user","message":{}}"#;
        let hint = SourceHint {
            path: std::path::Path::new("x.jsonl"),
            head,
        };
        assert_eq!(parser.can_parse(&hint), Sniff::Yes);

        let hint_wrong = SourceHint {
            path: std::path::Path::new("x.json"),
            head,
        };
        assert_eq!(parser.can_parse(&hint_wrong), Sniff::No);
    }

    #[test]
    fn byte_ranges_track_file_offsets() {
        let input = r#"{"type":"user","message":{"role":"user","content":"a"}}
{"type":"user","message":{"role":"user","content":"b"}}
"#;
        let results = parse_all(input);
        assert_eq!(results.len(), 2);
        let t0 = results[0].as_ref().expect("first");
        let t1 = results[1].as_ref().expect("second");
        assert_eq!(t0.byte_range.start, 0);
        assert_eq!(t1.byte_range.start, t0.byte_range.end);
    }
}
