//! End-to-end integration tests for the `sanitai` CLI binary.
//!
//! These tests invoke the compiled `sanitai` executable via `std::process::Command`
//! and assert on exit codes and stdout shape. They deliberately do NOT link
//! against the library crates — the point is to exercise the real user-facing
//! interface, including argument parsing, exit-code contract, and JSON schema.
//!
//! All tests are `#[ignore]`'d because they require the binary to have been
//! built first. Run them with:
//!
//! ```text
//! cargo build -p sanitai-cli
//! cargo test  -p sanitai-cli --test integration -- --ignored
//! ```

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Locate the compiled `sanitai` binary in the workspace `target/` directory.
///
/// Prefers `target/debug/sanitai`; falls back to `target/release/sanitai`.
/// Panics if neither exists — the caller is expected to `cargo build` first.
fn sanitai_bin() -> PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // manifest = <workspace>/crates/sanitai-cli
    let workspace = manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root resolved from CARGO_MANIFEST_DIR");

    let debug = workspace.join("target/debug/sanitai");
    if debug.exists() {
        return debug;
    }
    let release = workspace.join("target/release/sanitai");
    assert!(
        release.exists(),
        "sanitai binary not found at {} or {}. Run `cargo build -p sanitai-cli` first.",
        debug.display(),
        release.display()
    );
    release
}

/// Write a Claude-format JSONL file with a single user turn whose content
/// contains a synthetic Anthropic API key carrying the `SANITAI_FAKE` marker.
///
/// The key uses the `sk-ant-api03-` prefix followed by `SANITAI_FAKE` and 81
/// lowercase letters. This satisfies `\bsk-ant-(?:api03-)?[A-Za-z0-9\-_]{93,}\b`
/// (93 chars after `api03-`) AND contains the literal `SANITAI_FAKE` marker
/// inside the regex match window, so `Finding::is_synthetic()` returns true.
fn claude_jsonl_with_synthetic_key() -> NamedTempFile {
    let mut f = tempfile::Builder::new()
        .suffix(".jsonl")
        .tempfile()
        .expect("create tempfile");
    let suffix = "a".repeat(81);
    let key = format!("sk-ant-api03-SANITAI_FAKE{suffix}");
    let line =
        format!(r#"{{"type":"user","message":{{"role":"user","content":"My key is {key}"}}}}"#);
    writeln!(f, "{line}").expect("write jsonl line");
    f
}

/// Write a Claude-format JSONL file with a single benign user turn.
fn claude_jsonl_clean() -> NamedTempFile {
    let mut f = tempfile::Builder::new()
        .suffix(".jsonl")
        .tempfile()
        .expect("create tempfile");
    let line =
        r#"{"type":"user","message":{"role":"user","content":"Hello world, no secrets here"}}"#;
    writeln!(f, "{line}").expect("write jsonl line");
    f
}

fn path_str(f: &NamedTempFile) -> &str {
    f.path().to_str().expect("tempfile path is valid UTF-8")
}

// ---------------------------------------------------------------------------
// scan: exit-code contract
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires compiled sanitai binary — run with: cargo test -p sanitai-cli --test integration -- --ignored"]
fn scan_exits_one_when_synthetic_secret_present() {
    let file = claude_jsonl_with_synthetic_key();
    let out = Command::new(sanitai_bin())
        .args([
            "scan",
            "--no-sandbox",
            "--include-synthetic",
            path_str(&file),
        ])
        .output()
        .expect("spawn sanitai");
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1 (findings present); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[ignore = "requires compiled sanitai binary"]
fn scan_exits_zero_when_file_is_clean() {
    let file = claude_jsonl_clean();
    let out = Command::new(sanitai_bin())
        .args(["scan", "--no-sandbox", path_str(&file)])
        .output()
        .expect("spawn sanitai");
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0 (no findings); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[ignore = "requires compiled sanitai binary"]
fn scan_exit_zero_flag_suppresses_nonzero_on_findings() {
    let file = claude_jsonl_with_synthetic_key();
    let out = Command::new(sanitai_bin())
        .args([
            "scan",
            "--no-sandbox",
            "--include-synthetic",
            "--exit-zero",
            path_str(&file),
        ])
        .output()
        .expect("spawn sanitai");
    assert_eq!(
        out.status.code(),
        Some(0),
        "--exit-zero must force exit 0 even when findings are present; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[ignore = "requires compiled sanitai binary"]
fn scan_without_include_synthetic_drops_fake_findings() {
    // The Anthropic key embeds SANITAI_FAKE inside the regex match window, so
    // is_synthetic() returns true and the finding is filtered without
    // --include-synthetic. Exit must be 0.
    let file = claude_jsonl_with_synthetic_key();
    let out = Command::new(sanitai_bin())
        .args(["scan", "--no-sandbox", path_str(&file)])
        .output()
        .expect("spawn sanitai");
    assert_eq!(
        out.status.code(),
        Some(0),
        "synthetic findings must be filtered by default; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// scan: JSON output schema
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires compiled sanitai binary"]
fn scan_json_output_never_contains_matched_raw() {
    let file = claude_jsonl_with_synthetic_key();
    let out = Command::new(sanitai_bin())
        .args([
            "scan",
            "--no-sandbox",
            "--include-synthetic",
            "--format",
            "json",
            path_str(&file),
        ])
        .output()
        .expect("spawn sanitai");

    let stdout = String::from_utf8(out.stdout).expect("stdout is UTF-8");
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\n---\n{stdout}"));

    let findings = parsed
        .as_array()
        .expect("top-level JSON value must be an array of findings");
    assert!(
        !findings.is_empty(),
        "expected at least one finding in JSON output"
    );

    for (i, f) in findings.iter().enumerate() {
        assert!(
            f.get("matched_raw").is_none(),
            "finding[{i}] leaked `matched_raw` into JSON output: {f}"
        );
        // Also spot-check the documented public schema.
        for required in [
            "file",
            "turn",
            "detector",
            "confidence",
            "byte_start",
            "byte_end",
        ] {
            assert!(
                f.get(required).is_some(),
                "finding[{i}] missing required field `{required}`: {f}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// scan: stdin streaming
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires compiled sanitai binary"]
fn scan_detects_secret_piped_via_stdin() {
    let mut child = Command::new(sanitai_bin())
        .args(["scan", "--no-sandbox", "--include-synthetic", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sanitai");

    {
        let stdin = child.stdin.as_mut().expect("child stdin open");
        // Single JSONL turn — the stdin path is still scanned through the
        // parser pipeline, so we feed a Claude-format record.
        let suffix = "a".repeat(81);
        let key = format!("sk-ant-api03-SANITAI_FAKE{suffix}");
        let line = format!(
            r#"{{"type":"user","message":{{"role":"user","content":"export KEY={key}"}}}}"#
        );
        writeln!(stdin, "{line}").expect("write to child stdin");
    }

    let out = child.wait_with_output().expect("wait for sanitai");
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1 for synthetic key on stdin; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
