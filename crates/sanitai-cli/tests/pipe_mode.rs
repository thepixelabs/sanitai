//! Pipe-mode regression gate for the `sanitai` CLI binary.
//!
//! These tests are the contract tests for non-interactive behaviour: exit codes,
//! stdout cleanliness, output format schemas, and store-failure isolation. Any
//! regression in these areas will break CI pipelines, scripts, and pre-commit
//! hooks that consume `sanitai scan` programmatically.
//!
//! # Prerequisites
//!
//! The `sanitai` binary must be compiled before this test suite runs:
//!
//! ```text
//! cargo build -p sanitai-cli
//! cargo test -p sanitai-cli --test pipe_mode
//! ```
//!
//! In CI, add `cargo build` as a step before `cargo test`. The test runner does
//! NOT rebuild the binary automatically when invoked via `--test pipe_mode`.
//!
//! # Fixture files
//!
//! `tests/fixtures/clean.txt`    — plain text, no secrets, no recognised parser format
//! `tests/fixtures/secrets.jsonl` — Claude JSONL with a real-pattern AWS access key ID

use std::path::PathBuf;
use std::process::Command;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the compiled `sanitai` binary from the workspace `target/` tree.
///
/// Prefers a debug build; falls back to release. Both paths are checked so
/// that CI release builds and local debug builds both work without changes.
fn sanitai_bin() -> PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
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

/// Absolute path to a named fixture file under `tests/fixtures/`.
fn fixture(name: &str) -> PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.join("tests/fixtures").join(name)
}

/// Run `sanitai scan [args...]` and return `(stdout, stderr, exit_code)`.
///
/// `NO_COLOR=1` and `TERM=dumb` are always set so that no ANSI escape codes
/// can leak from terminal-detection logic regardless of the test environment.
fn run_scan(args: &[&str]) -> (String, String, i32) {
    run_scan_with_env(args, &[])
}

/// Like `run_scan` but also injects caller-supplied environment variables.
fn run_scan_with_env(args: &[&str], extra_env: &[(&str, &str)]) -> (String, String, i32) {
    let mut cmd = Command::new(sanitai_bin());
    cmd.arg("scan")
        .arg("--no-sandbox")
        .env("NO_COLOR", "1")
        .env("TERM", "dumb");

    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    for arg in args {
        cmd.arg(arg);
    }

    let out = cmd.output().expect("spawning sanitai binary failed");

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let code = out.status.code().unwrap_or(-1);

    (stdout, stderr, code)
}

// ---------------------------------------------------------------------------
// Exit-code contract
// ---------------------------------------------------------------------------

#[test]
fn exit_code_zero_on_clean_file() {
    // clean.txt has no secrets and is not a recognised conversation format.
    // The parser sniffer returns Sniff::No (wrong extension), so scan_path
    // skips it — zero findings, exit 0.
    let (_, stderr, code) = run_scan(&[fixture("clean.txt")
        .to_str()
        .expect("fixture path is valid UTF-8")]);

    assert_eq!(code, 0, "expected exit 0 on a clean file; stderr: {stderr}");
}

#[test]
fn exit_code_one_on_secrets_found() {
    // secrets.jsonl contains AKIAIOSFODNN7EXAMPLE which matches the
    // aws_access_key_id pattern and is not a synthetic key (no SANITAI_FAKE).
    let (_, stderr, code) = run_scan(&[fixture("secrets.jsonl")
        .to_str()
        .expect("fixture path is valid UTF-8")]);

    assert_eq!(
        code, 1,
        "expected exit 1 when an AWS access key is found; stderr: {stderr}"
    );
}

#[test]
fn exit_code_zero_with_exit_zero_flag() {
    // --exit-zero must suppress the non-zero exit code even when findings are
    // present. This flag is the standard mechanism for non-blocking canary scans.
    let (_, stderr, code) = run_scan(&[
        "--exit-zero",
        fixture("secrets.jsonl")
            .to_str()
            .expect("fixture path is valid UTF-8"),
    ]);

    assert_eq!(
        code, 0,
        "--exit-zero must yield exit 0 even when findings are present; stderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Human output format
// ---------------------------------------------------------------------------

#[test]
fn human_output_contains_finding_severity_on_stdout() {
    // The human formatter writes one line per finding to stdout with the
    // severity bracketed: "[HIGH  ]", "[MEDIUM]", or "[LOW   ]".
    let (stdout, stderr, code) = run_scan(&[
        "--format",
        "human",
        fixture("secrets.jsonl")
            .to_str()
            .expect("fixture path is valid UTF-8"),
    ]);

    assert_eq!(
        code, 1,
        "expected exit 1 with secrets in human format; stderr: {stderr}"
    );
    assert!(
        stdout.contains("[HIGH") || stdout.contains("[MEDIUM") || stdout.contains("[LOW"),
        "expected a severity bracket on stdout; got:\n{stdout}"
    );
}

#[test]
fn human_output_finding_count_reported_on_stderr() {
    // `print_human` writes the "N finding(s)." tally to stderr via eprintln!,
    // not to stdout. This keeps stdout machine-parseable when piped.
    let (_, stderr, code) = run_scan(&[
        "--format",
        "human",
        fixture("secrets.jsonl")
            .to_str()
            .expect("fixture path is valid UTF-8"),
    ]);

    assert_eq!(
        code, 1,
        "expected exit 1 with secrets present; stderr: {stderr}"
    );
    assert!(
        stderr.contains("finding(s)"),
        "expected 'finding(s)' count on stderr; got:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Pipe-safe stdout — no ANSI escape codes
// ---------------------------------------------------------------------------

#[test]
fn no_ansi_codes_in_stdout_pipe_mode() {
    // When stdout is not a TTY (which it never is under Command::output()),
    // sanitai must emit no ANSI escape sequences. This test guards against
    // future TUI or colour-output work accidentally injecting them into the
    // machine-readable stream.
    let (stdout, _, _) = run_scan(&[fixture("secrets.jsonl")
        .to_str()
        .expect("fixture path is valid UTF-8")]);

    assert!(
        !stdout.contains('\x1b'),
        "ANSI escape code found in stdout (pipe mode must be escape-free);\
         \nstdout starts with: {:?}",
        &stdout[..stdout.len().min(200)]
    );
}

// ---------------------------------------------------------------------------
// JSON output schema
// ---------------------------------------------------------------------------

#[test]
fn json_output_is_valid_json_array() {
    let (stdout, stderr, code) = run_scan(&[
        "--format",
        "json",
        fixture("secrets.jsonl")
            .to_str()
            .expect("fixture path is valid UTF-8"),
    ]);

    assert_eq!(
        code, 1,
        "expected exit 1 with secrets present; stderr: {stderr}"
    );

    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("--format json stdout is not valid JSON: {e}\n---\n{stdout}"));

    let findings = parsed
        .as_array()
        .expect("--format json must produce a top-level JSON array");

    assert!(
        !findings.is_empty(),
        "expected at least one finding in JSON output"
    );

    for (i, f) in findings.iter().enumerate() {
        for required_field in &[
            "file",
            "turn",
            "detector",
            "confidence",
            "byte_start",
            "byte_end",
            "transforms",
            "synthetic",
        ] {
            assert!(
                f.get(required_field).is_some(),
                "finding[{i}] is missing required field `{required_field}`:\n{f}"
            );
        }

        // The raw secret value must never appear in structured output.
        assert!(
            f.get("matched_raw").is_none(),
            "finding[{i}] leaked `matched_raw` into JSON output:\n{f}"
        );
    }
}

// ---------------------------------------------------------------------------
// SARIF output schema
// ---------------------------------------------------------------------------

#[test]
fn sarif_output_has_required_schema_fields() {
    let (stdout, stderr, code) = run_scan(&[
        "--format",
        "sarif",
        fixture("secrets.jsonl")
            .to_str()
            .expect("fixture path is valid UTF-8"),
    ]);

    assert_eq!(
        code, 1,
        "expected exit 1 with secrets present; stderr: {stderr}"
    );

    let sarif: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("--format sarif stdout is not valid JSON: {e}\n---\n{stdout}"));

    assert!(
        sarif.get("$schema").is_some(),
        "SARIF output missing required `$schema` field"
    );
    assert!(
        sarif.get("version").is_some(),
        "SARIF output missing required `version` field"
    );

    let runs = sarif
        .get("runs")
        .and_then(|v| v.as_array())
        .expect("SARIF output must have a `runs` array");

    assert!(
        !runs.is_empty(),
        "SARIF `runs` array must have at least one entry"
    );

    let driver_name = runs[0]
        .get("tool")
        .and_then(|t| t.get("driver"))
        .and_then(|d| d.get("name"))
        .and_then(|n| n.as_str())
        .expect("SARIF runs[0].tool.driver.name must be a string");

    assert_eq!(
        driver_name, "sanitai",
        "SARIF runs[0].tool.driver.name must be \"sanitai\""
    );
}

// ---------------------------------------------------------------------------
// Error path: non-existent file
// ---------------------------------------------------------------------------

#[test]
fn nonexistent_file_does_not_crash() {
    // The current code warns on scan errors but continues (and exits 0 when no
    // other findings were found). The hard contract is: the process must not
    // crash (exit 2 or panic) when handed a path that doesn't exist — it should
    // emit a warning and exit cleanly.
    //
    // Note: if the implementation changes to exit 2 on missing files that is
    // also acceptable and this test should be updated, but a panic/signal is
    // never acceptable.
    let nonexistent = "/tmp/this_file_does_not_exist_sanitai_pipe_mode_test.jsonl";

    let (_, stderr, code) = run_scan(&[nonexistent]);

    assert!(
        code == 0 || code == 2,
        "expected exit 0 (warned + skipped) or exit 2 (fatal I/O), got {code};\
         \nstderr: {stderr}"
    );

    // The process must not have been killed by a signal (code would be -1).
    assert_ne!(code, -1, "sanitai was killed by a signal on a missing file");
}

// ---------------------------------------------------------------------------
// Store failure isolation
// ---------------------------------------------------------------------------

#[test]
fn store_failure_does_not_affect_exit_code_on_clean_file() {
    // Set HOME to /dev/null so that dirs_next::data_local_dir() resolves to a
    // path that cannot be created (on macOS: /dev/null/Library/Application Support,
    // on Linux: /dev/null/.local/share). create_dir_all will fail, Store::open()
    // returns Err, and the code path logs a warning and continues.
    //
    // The exit code must still be 0 — a store write failure is explicitly
    // documented as non-fatal. The scan result is the source of truth.
    let (_, stderr, code) = run_scan_with_env(
        &[fixture("clean.txt")
            .to_str()
            .expect("fixture path is valid UTF-8")],
        &[("HOME", "/dev/null")],
    );

    assert_eq!(
        code, 0,
        "store open failure must not change exit code (expected 0 on clean file);\
         \nstderr: {stderr}"
    );
}

#[test]
fn store_failure_does_not_affect_exit_code_on_secrets_file() {
    // Same store-failure scenario but with a file that has findings.
    // Exit code must still be 1 — the scan result takes precedence over the
    // store write error.
    let (_, stderr, code) = run_scan_with_env(
        &[fixture("secrets.jsonl")
            .to_str()
            .expect("fixture path is valid UTF-8")],
        &[("HOME", "/dev/null")],
    );

    assert_eq!(
        code, 1,
        "store open failure must not change exit code (expected 1 when findings present);\
         \nstderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Idempotence: second scan on the same file writes to store again without
// corrupting the first record or changing observable behaviour.
// ---------------------------------------------------------------------------

#[test]
fn repeated_scans_on_same_file_are_idempotent() {
    // Run twice in the same test process. Because each run uses a fresh
    // std::process::Command, both hits go through the full binary lifecycle
    // including store open → write → close. If the second write fails (e.g.
    // a schema migration races with itself, or WAL is corrupted), it must
    // still exit 0 — the store is non-fatal. Observable output must be
    // identical between both runs.
    let path = fixture("clean.txt");
    let path_str = path.to_str().expect("fixture path is valid UTF-8");

    let (stdout_a, _, code_a) = run_scan(&[path_str]);
    let (stdout_b, _, code_b) = run_scan(&[path_str]);

    assert_eq!(code_a, 0, "first scan of clean file must exit 0");
    assert_eq!(
        code_b, 0,
        "second scan of same clean file must also exit 0 (store idempotence)"
    );
    assert_eq!(
        stdout_a, stdout_b,
        "stdout must be identical across repeated scans of the same clean file"
    );
}
