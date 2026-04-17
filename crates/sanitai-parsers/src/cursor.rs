//! Cursor IDE conversation parser.
//!
//! Cursor stores AI chat history in SQLite databases under:
//!   macOS:   ~/Library/Application Support/Cursor/User/workspaceStorage/**/state.vscdb
//!   Linux:   ~/.config/Cursor/User/workspaceStorage/**/state.vscdb
//!   Windows: %APPDATA%\Cursor\User\workspaceStorage\**\state.vscdb
//!
//! The database table is `ItemTable` with JSON values for keys like
//! `aiService.conversations` and `aiService.chatHistory`. The exact schema
//! differs between Cursor versions, so we parse the JSON values flexibly
//! via `serde_json::Value` and look for arrays of objects that carry
//! `role` + `content` (or `text`) fields.
//!
//! We open the database read-only (`OPEN_READ_ONLY` + `OPEN_NO_MUTEX`) so
//! we never modify Cursor's active database files. If Cursor has the
//! database locked for writing we still get a clean stream-of-errors
//! instead of a crash.

#![deny(clippy::unwrap_used)]

use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use futures::stream::{self, BoxStream, StreamExt};
use rusqlite::{Connection, OpenFlags};
use sanitai_core::{
    error::CoreError,
    traits::{ConversationParser, ReadSeek, Sniff, SourceHint},
    turn::{Role, SourceKind, Turn, TurnMeta},
};

const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

pub struct CursorParser {
    path: Arc<PathBuf>,
}

impl Default for CursorParser {
    fn default() -> Self {
        Self {
            path: Arc::new(PathBuf::new()),
        }
    }
}

impl CursorParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self {
            path: Arc::new(path),
        }
    }
}

impl ConversationParser for CursorParser {
    fn id(&self) -> &'static str {
        "cursor.sqlite"
    }

    fn can_parse(&self, hint: &SourceHint<'_>) -> Sniff {
        let name_match = hint
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.contains("state.vscdb"))
            .unwrap_or(false);
        let is_sqlite = hint.head.starts_with(SQLITE_MAGIC);
        match (name_match, is_sqlite) {
            (true, true) => Sniff::Yes,
            (false, true) => Sniff::Maybe,
            (true, false) => Sniff::Maybe,
            (false, false) => Sniff::No,
        }
    }

    fn parse<'a>(
        &'a self,
        _source: Box<dyn ReadSeek + 'a>,
    ) -> BoxStream<'a, Result<Turn, CoreError>> {
        // SQLite needs a real path, not a stream. The `_source` argument is
        // present to satisfy the trait but intentionally unused — we open
        // the file via its path so `rusqlite` can mmap with read-only flags.
        let path = Arc::clone(&self.path);
        let results = match extract_turns(&path) {
            Ok(turns) => turns.into_iter().map(Ok).collect(),
            Err(e) => vec![Err(e)],
        };
        stream::iter(results).boxed()
    }
}

fn extract_turns(path: &Arc<PathBuf>) -> Result<Vec<Turn>, CoreError> {
    // Validate SQLite header before handing the file to rusqlite. This keeps
    // error messages sane when a caller passes something with a `.vscdb`
    // name but non-SQLite contents (which rusqlite reports as a cryptic
    // "file is not a database" error).
    let mut header = [0u8; 16];
    let read = std::fs::File::open(path.as_ref())
        .and_then(|mut f| f.read(&mut header))
        .map_err(CoreError::Io)?;
    if read < SQLITE_MAGIC.len() || &header[..SQLITE_MAGIC.len()] != SQLITE_MAGIC {
        return Err(CoreError::Parse {
            parser: "cursor.sqlite",
            offset: 0,
            source: Box::<dyn std::error::Error + Send + Sync>::from(
                "not a SQLite database (bad magic)".to_string(),
            ),
        });
    }

    let conn = Connection::open_with_flags(
        path.as_ref(),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| CoreError::Parse {
        parser: "cursor.sqlite",
        offset: 0,
        source: Box::new(e),
    })?;

    let mut stmt = conn
        .prepare("SELECT key, value FROM ItemTable WHERE key LIKE 'aiService.%'")
        .map_err(|e| CoreError::Parse {
            parser: "cursor.sqlite",
            offset: 0,
            source: Box::new(e),
        })?;

    let rows = stmt
        .query_map([], |row| {
            let key: String = row.get(0)?;
            // Cursor stores values as TEXT (JSON) in most versions but some
            // older builds use BLOB. Accept either.
            let value: String = match row.get::<_, String>(1) {
                Ok(s) => s,
                Err(_) => {
                    let bytes: Vec<u8> = row.get(1)?;
                    String::from_utf8_lossy(&bytes).into_owned()
                }
            };
            Ok((key, value))
        })
        .map_err(|e| CoreError::Parse {
            parser: "cursor.sqlite",
            offset: 0,
            source: Box::new(e),
        })?;

    let mut turns: Vec<Turn> = Vec::new();
    let mut turn_index: usize = 0;
    let mut running_offset: u64 = 0;

    for row in rows.flatten() {
        let (key, value) = row;
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&value) else {
            tracing::debug!(parser = "cursor.sqlite", %key, "skipping non-JSON ItemTable value");
            continue;
        };
        walk_value(
            &json,
            path,
            &key,
            &mut turn_index,
            &mut running_offset,
            &mut turns,
        );
    }

    Ok(turns)
}

/// Recursively walk an arbitrary JSON value looking for objects that smell
/// like chat messages (have `role` + some form of content). The shape varies
/// across Cursor versions so we stay schema-agnostic.
fn walk_value(
    v: &serde_json::Value,
    path: &Arc<PathBuf>,
    conversation_key: &str,
    turn_index: &mut usize,
    running_offset: &mut u64,
    out: &mut Vec<Turn>,
) {
    match v {
        serde_json::Value::Array(items) => {
            for item in items {
                walk_value(
                    item,
                    path,
                    conversation_key,
                    turn_index,
                    running_offset,
                    out,
                );
            }
        }
        serde_json::Value::Object(map) => {
            if let Some((role, content)) = extract_message(map) {
                let len = content.len() as u64;
                let start = *running_offset;
                *running_offset = running_offset.saturating_add(len);
                let turn = Turn {
                    id: (Arc::clone(path), *turn_index),
                    role,
                    content,
                    byte_range: start..(start + len),
                    source: SourceKind::Cursor,
                    meta: TurnMeta {
                        conversation_id: Some(conversation_key.to_owned()),
                        timestamp: None,
                        model: None,
                    },
                };
                *turn_index += 1;
                out.push(turn);
            }
            // Continue walking nested structures: Cursor often wraps chat
            // arrays under `conversation`, `messages`, `tabs`, etc.
            for (_, child) in map {
                walk_value(
                    child,
                    path,
                    conversation_key,
                    turn_index,
                    running_offset,
                    out,
                );
            }
        }
        _ => {}
    }
}

fn extract_message(map: &serde_json::Map<String, serde_json::Value>) -> Option<(Role, String)> {
    let role_str = map.get("role").and_then(|v| v.as_str())?;
    let role = match role_str {
        "user" => Role::User,
        "assistant" => Role::Assistant,
        "system" => Role::System,
        "tool" | "function" => Role::Tool,
        _ => return None,
    };
    // Content field is variously named `content`, `text`, or `message`.
    let content = map
        .get("content")
        .or_else(|| map.get("text"))
        .or_else(|| map.get("message"))
        .map(stringify_content)
        .unwrap_or_default();
    if content.is_empty() {
        return None;
    }
    Some((role, content))
}

fn stringify_content(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(items) => items
            .iter()
            .map(stringify_content)
            .collect::<Vec<_>>()
            .join("\n"),
        serde_json::Value::Object(map) => {
            // Pull `text` / `value` fields out of content blocks, else
            // stringify so detectors still see any embedded secrets.
            if let Some(s) = map.get("text").and_then(|v| v.as_str()) {
                return s.to_owned();
            }
            if let Some(s) = map.get("value").and_then(|v| v.as_str()) {
                return s.to_owned();
            }
            v.to_string()
        }
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use rusqlite::params;
    use tempfile::TempDir;

    fn mk_db(dir: &TempDir, json: &str) -> PathBuf {
        let p = dir.path().join("state.vscdb");
        let conn = Connection::open(&p).expect("open");
        conn.execute(
            "CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)",
            [],
        )
        .expect("create");
        conn.execute(
            "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
            params!["aiService.conversations", json],
        )
        .expect("insert");
        p
    }

    fn parse(path: PathBuf) -> Vec<Result<Turn, CoreError>> {
        let parser = CursorParser::with_path(path);
        // The source argument is unused for the SQLite parser but the trait
        // demands one.
        let dummy: Box<dyn ReadSeek> = Box::new(std::io::Cursor::new(Vec::<u8>::new()));
        futures::executor::block_on(parser.parse(dummy).collect::<Vec<_>>())
    }

    #[test]
    fn parses_flat_message_array() {
        let dir = TempDir::new().expect("tmp");
        let json = r#"[
            {"role":"user","content":"hello from cursor"},
            {"role":"assistant","content":"hi back"}
        ]"#;
        let path = mk_db(&dir, json);
        let results = parse(path);
        let turns: Vec<_> = results.into_iter().map(|r| r.expect("ok")).collect();
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].role, Role::User);
        assert_eq!(turns[0].content, "hello from cursor");
        assert_eq!(turns[0].source, SourceKind::Cursor);
        assert_eq!(turns[1].role, Role::Assistant);
    }

    #[test]
    fn parses_nested_schema() {
        let dir = TempDir::new().expect("tmp");
        let json = r#"{
            "tabs": [
                {"id":"t1","messages":[
                    {"role":"user","text":"nested user"},
                    {"role":"assistant","text":"nested assistant"}
                ]}
            ]
        }"#;
        let path = mk_db(&dir, json);
        let results = parse(path);
        let turns: Vec<_> = results.into_iter().map(|r| r.expect("ok")).collect();
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].content, "nested user");
        assert_eq!(turns[1].content, "nested assistant");
    }

    #[test]
    fn non_sqlite_file_returns_err() {
        let dir = TempDir::new().expect("tmp");
        let p = dir.path().join("state.vscdb");
        std::fs::write(&p, b"this is not a sqlite file at all").expect("write");
        let results = parse(p);
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
    }

    #[test]
    fn can_parse_sniff() {
        let parser = CursorParser::new();
        let mut head = Vec::from(SQLITE_MAGIC);
        head.extend_from_slice(&[0u8; 32]);
        let hint = SourceHint {
            path: std::path::Path::new("/x/state.vscdb"),
            head: &head,
        };
        assert_eq!(parser.can_parse(&hint), Sniff::Yes);

        let hint_txt = SourceHint {
            path: std::path::Path::new("/x/state.vscdb"),
            head: b"not sqlite",
        };
        assert_eq!(parser.can_parse(&hint_txt), Sniff::Maybe);
    }
}
