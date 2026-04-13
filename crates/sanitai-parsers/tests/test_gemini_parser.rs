//! Integration test: Gemini Takeout fixture round-trip.

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use futures::StreamExt;
use sanitai_core::traits::{ConversationParser, ReadSeek};
use sanitai_core::turn::{Role, SourceKind};
use sanitai_parsers::GeminiParser;

fn fixture(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push(name);
    p
}

#[test]
fn parses_gemini_takeout_fixture() {
    let path = fixture("gemini_sample.json");
    let parser = GeminiParser::with_path(path.clone());
    let source: Box<dyn ReadSeek> = Box::new(BufReader::new(File::open(&path).expect("open")));
    let turns: Vec<_> = futures::executor::block_on(parser.parse(source).collect::<Vec<_>>())
        .into_iter()
        .map(|r| r.expect("ok"))
        .collect();

    assert_eq!(turns.len(), 2);
    assert_eq!(turns[0].role, Role::User);
    assert!(turns[0].content.contains("ghp_"));
    assert_eq!(turns[0].source, SourceKind::GeminiCli);
    // "model" maps to Assistant.
    assert_eq!(turns[1].role, Role::Assistant);
}
