//! ChatGPT `conversations.json` export parser.
//!
//! The export is an array of conversation objects. Each conversation stores
//! its messages in a DAG under the `mapping` field, keyed by UUID. A
//! root node has `parent: null`; every other node points at its parent.
//! Child ordering is given by the `children` arrays.
//!
//! We walk the DAG breadth-first starting from the root so turns are emitted
//! in the order the UI displays them. A `HashSet` of visited node IDs guards
//! against malformed exports containing cycles — a cycle would otherwise blow
//! the stack.

#![deny(clippy::unwrap_used)]

use std::collections::{HashSet, VecDeque};
use std::io::Read;
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

#[derive(Debug, Deserialize)]
struct RawConversation {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, rename = "conversation_id")]
    conversation_id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    mapping: std::collections::HashMap<String, RawNode>,
}

#[derive(Debug, Deserialize)]
struct RawNode {
    #[serde(default)]
    #[allow(dead_code)]
    id: Option<String>,
    #[serde(default)]
    message: Option<RawMessage>,
    #[serde(default)]
    parent: Option<String>,
    #[serde(default)]
    children: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawMessage {
    #[serde(default)]
    author: Option<RawAuthor>,
    #[serde(default)]
    content: Option<RawContent>,
    #[serde(default)]
    create_time: Option<f64>,
    #[serde(default)]
    metadata: Option<RawMetadata>,
}

#[derive(Debug, Deserialize)]
struct RawAuthor {
    #[serde(default)]
    role: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawContent {
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    parts: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RawMetadata {
    #[serde(default)]
    model_slug: Option<String>,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

pub struct ChatGptParser {
    path: Arc<PathBuf>,
}

impl Default for ChatGptParser {
    fn default() -> Self {
        Self {
            path: Arc::new(PathBuf::new()),
        }
    }
}

impl ChatGptParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self {
            path: Arc::new(path),
        }
    }
}

impl ConversationParser for ChatGptParser {
    fn id(&self) -> &'static str {
        "chatgpt.json"
    }

    fn can_parse(&self, hint: &SourceHint<'_>) -> Sniff {
        let is_json = hint
            .path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("json"))
            .unwrap_or(false);
        if !is_json {
            return Sniff::No;
        }
        let head = String::from_utf8_lossy(hint.head);
        let has_mapping = head.contains("\"mapping\"");
        let has_context = head.contains("\"conversation_id\"") || head.contains("\"title\"");
        if has_mapping && has_context {
            Sniff::Yes
        } else if has_mapping {
            Sniff::Maybe
        } else {
            Sniff::No
        }
    }

    fn parse<'a>(
        &'a self,
        mut source: Box<dyn ReadSeek + 'a>,
    ) -> BoxStream<'a, Result<Turn, CoreError>> {
        // ChatGPT exports are a single JSON document, not a streaming format.
        // We still honour the streaming trait by materializing turns into a
        // Vec and then wrapping them in `stream::iter`.
        let path = Arc::clone(&self.path);
        let mut buf = Vec::new();
        if let Err(e) = source.read_to_end(&mut buf) {
            return stream::iter(vec![Err(CoreError::Io(e))]).boxed();
        }

        let results = parse_document(&buf, path);
        stream::iter(results).boxed()
    }
}

// ---------------------------------------------------------------------------
// Document walker
// ---------------------------------------------------------------------------

fn parse_document(buf: &[u8], path: Arc<PathBuf>) -> Vec<Result<Turn, CoreError>> {
    // Accept both `[ ... ]` (the official export) and `{ ... }` (single-conv
    // dumps people sometimes paste into issues).
    let value: serde_json::Value = match serde_json::from_slice(buf) {
        Ok(v) => v,
        Err(e) => {
            return vec![Err(CoreError::Parse {
                parser: "chatgpt.json",
                offset: 0,
                source: Box::new(e),
            })];
        }
    };

    let convs: Vec<RawConversation> = match value {
        serde_json::Value::Array(items) => items
            .into_iter()
            .filter_map(|v| serde_json::from_value::<RawConversation>(v).ok())
            .collect(),
        serde_json::Value::Object(_) => match serde_json::from_value::<RawConversation>(value) {
            Ok(c) => vec![c],
            Err(e) => {
                return vec![Err(CoreError::Parse {
                    parser: "chatgpt.json",
                    offset: 0,
                    source: Box::new(e),
                })];
            }
        },
        _ => {
            return vec![Err(CoreError::Parse {
                parser: "chatgpt.json",
                offset: 0,
                source: Box::<dyn std::error::Error + Send + Sync>::from(
                    "expected JSON array or object at document root".to_string(),
                ),
            })];
        }
    };

    let mut out: Vec<Result<Turn, CoreError>> = Vec::new();
    let mut turn_index: usize = 0;
    // Byte range tracking inside a single JSON blob is nearly meaningless —
    // the same text appears once in the source file and we don't have
    // per-message offsets unless we re-lex the JSON. Use a running
    // character-length counter as a stable monotonic proxy so downstream
    // dedupe logic can still distinguish turns.
    let mut running_offset: u64 = 0;

    for conv in convs {
        let conv_id = conv.conversation_id.or(conv.id);
        let _title = conv.title;

        // Find the root: the node whose `parent` is `None`.
        let root_id = conv
            .mapping
            .iter()
            .find(|(_, n)| n.parent.is_none())
            .map(|(k, _)| k.clone());

        let Some(root_id) = root_id else {
            continue;
        };

        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        queue.push_back(root_id);

        while let Some(node_id) = queue.pop_front() {
            if !visited.insert(node_id.clone()) {
                // Cycle guard: skip nodes we've already seen.
                continue;
            }
            let Some(node) = conv.mapping.get(&node_id) else {
                continue;
            };

            // Enqueue children in declared order.
            for child in &node.children {
                if !visited.contains(child) {
                    queue.push_back(child.clone());
                }
            }

            let Some(message) = &node.message else {
                continue;
            };

            let role = match message
                .author
                .as_ref()
                .and_then(|a| a.role.as_deref())
                .unwrap_or("")
            {
                "user" => Role::User,
                "assistant" => Role::Assistant,
                "system" => Role::System,
                "tool" | "function" => Role::Tool,
                "" => continue, // author-less scaffolding node
                _ => continue,
            };

            let content = render_parts(message.content.as_ref());
            if content.is_empty() {
                continue;
            }

            let len = content.len() as u64;
            let start = running_offset;
            running_offset = running_offset.saturating_add(len);

            let meta = TurnMeta {
                conversation_id: conv_id.clone(),
                timestamp: message.create_time.map(|t| t as i64),
                model: message.metadata.as_ref().and_then(|m| m.model_slug.clone()),
            };

            let turn = Turn {
                id: (Arc::clone(&path), turn_index),
                role,
                content,
                byte_range: std::ops::Range {
                    start,
                    end: start + len,
                },
                source: SourceKind::ChatGpt,
                meta,
            };
            turn_index += 1;
            out.push(Ok(turn));
        }
    }

    out
}

fn render_parts(content: Option<&RawContent>) -> String {
    let Some(content) = content else {
        return String::new();
    };
    // We only render `text` content types; multimodal parts (images, audio)
    // currently stringify to the empty string and are filtered below.
    let expected_text = content
        .content_type
        .as_deref()
        .map(|t| t == "text" || t == "multimodal_text")
        .unwrap_or(true);
    if !expected_text {
        return String::new();
    }
    let mut pieces: Vec<String> = Vec::new();
    for part in &content.parts {
        match part {
            serde_json::Value::Null => {}
            serde_json::Value::String(s) if s.is_empty() => {}
            serde_json::Value::String(s) => pieces.push(s.clone()),
            other => {
                // Non-string parts (e.g. `{"asset_pointer": ...}`) are not
                // user text. Stringify them so any embedded URLs still reach
                // detectors, but keep the serialized form compact.
                let s = other.to_string();
                if !s.is_empty() && s != "null" {
                    pieces.push(s);
                }
            }
        }
    }
    pieces.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use std::io::Cursor;

    fn parse(input: &str) -> Vec<Result<Turn, CoreError>> {
        let parser = ChatGptParser::with_path(PathBuf::from("/tmp/conversations.json"));
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(input.to_owned().into_bytes()));
        futures::executor::block_on(parser.parse(cursor).collect::<Vec<_>>())
    }

    #[test]
    fn walks_simple_conversation() {
        let doc = r#"[{
            "id": "c1",
            "title": "Test",
            "mapping": {
                "root": {"id":"root","message":null,"parent":null,"children":["a"]},
                "a": {"id":"a","message":{"author":{"role":"user"},"content":{"content_type":"text","parts":["hi"]},"create_time":1.0},"parent":"root","children":["b"]},
                "b": {"id":"b","message":{"author":{"role":"assistant"},"content":{"content_type":"text","parts":["hello back"]},"create_time":2.0},"parent":"a","children":[]}
            }
        }]"#;
        let results = parse(doc);
        let turns: Vec<_> = results.into_iter().map(|r| r.expect("ok")).collect();
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].role, Role::User);
        assert_eq!(turns[0].content, "hi");
        assert_eq!(turns[0].meta.timestamp, Some(1));
        assert_eq!(turns[1].role, Role::Assistant);
        assert_eq!(turns[1].content, "hello back");
    }

    #[test]
    fn cycle_guard_prevents_infinite_loop() {
        // Deliberately malformed: root -> a -> a.
        let doc = r#"[{
            "id":"c","title":"x",
            "mapping":{
                "root":{"id":"root","message":null,"parent":null,"children":["a"]},
                "a":{"id":"a","message":{"author":{"role":"user"},"content":{"content_type":"text","parts":["loop"]}},"parent":"root","children":["a"]}
            }
        }]"#;
        let results = parse(doc);
        let turns: Vec<_> = results.into_iter().map(|r| r.expect("ok")).collect();
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].content, "loop");
    }

    #[test]
    fn skips_empty_and_null_parts() {
        let doc = r#"[{
            "id":"c","title":"x",
            "mapping":{
                "root":{"id":"root","message":null,"parent":null,"children":["a"]},
                "a":{"id":"a","message":{"author":{"role":"user"},"content":{"content_type":"text","parts":["",null,"real"]}},"parent":"root","children":[]}
            }
        }]"#;
        let results = parse(doc);
        let turns: Vec<_> = results.into_iter().map(|r| r.expect("ok")).collect();
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].content, "real");
    }

    #[test]
    fn can_parse_recognizes_export() {
        let parser = ChatGptParser::new();
        let head = br#"[{"id":"c","title":"t","mapping":{}}]"#;
        let hint = SourceHint {
            path: std::path::Path::new("conversations.json"),
            head,
        };
        assert_eq!(parser.can_parse(&hint), Sniff::Yes);
    }

    #[test]
    fn can_parse_rejects_non_json() {
        let parser = ChatGptParser::new();
        let head = b"just a log file";
        let hint = SourceHint {
            path: std::path::Path::new("log.txt"),
            head,
        };
        assert_eq!(parser.can_parse(&hint), Sniff::No);
    }
}
