//! Non-interactive smoke tests for the `sanitai tui` subcommand.
//!
//! The TUI requires a real TTY for meaningful operation. These tests verify the
//! guard rails that protect non-TTY environments: the TTY check in `run_tui`,
//! the subcommand registration in clap, and the `--help` short-circuit path
//! that must exit without launching the TUI even when invoked in CI.
//!
//! Every invocation sets `NO_COLOR=1 TERM=dumb` to eliminate terminal-detection
//! side effects, matching the convention established in `pipe_mode.rs`.

use std::path::PathBuf;
use std::process::Command;

// ---------------------------------------------------------------------------
// Shared helper — mirrors pipe_mode.rs to avoid a new test utility crate
// ---------------------------------------------------------------------------

/// Resolve the compiled `sanitai` binary from the workspace `target/` tree.
///
/// Prefers a debug build; falls back to release. Panics with an actionable
/// message when neither exists so CI output is clear.
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

/// Run `sanitai [args...]` (no sub-subcommand injected) and return
/// `(stdout, stderr, exit_code)`.
///
/// `NO_COLOR=1` and `TERM=dumb` are always set so colour/terminal-detection
/// logic cannot influence test results.
fn run_sanitai(args: &[&str]) -> (String, String, i32) {
    let mut cmd = Command::new(sanitai_bin());
    cmd.env("NO_COLOR", "1").env("TERM", "dumb");
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
// TTY guard — non-TTY stdin/stdout must be rejected
// ---------------------------------------------------------------------------

/// `sanitai tui` run with piped stdout (not a TTY) must exit 2 and emit a
/// message containing "requires" on stderr.
///
/// `Command::output()` always pipes stdout/stdin, so no extra redirection is
/// needed. The TTY guard in `run_tui` must fire before ratatui is initialised.
#[test]
fn tui_non_tty_exits_with_code_2() {
    let (_, stderr, code) = run_sanitai(&["tui"]);
    assert_eq!(
        code, 2,
        "sanitai tui on a non-TTY must exit 2; stderr: {stderr}"
    );
}

#[test]
fn tui_non_tty_stderr_mentions_terminal() {
    let (_, stderr, code) = run_sanitai(&["tui"]);
    assert_eq!(
        code, 2,
        "sanitai tui on a non-TTY must exit 2; stderr: {stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("terminal") || stderr.to_lowercase().contains("requires"),
        "stderr must explain that a terminal is required; got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Subcommand registration — `sanitai --help` must list "tui"
// ---------------------------------------------------------------------------

/// `sanitai --help` must include "tui" in its output, proving the subcommand
/// is registered with clap and will be visible to users.
#[test]
fn help_output_lists_tui_subcommand() {
    let (stdout, stderr, code) = run_sanitai(&["--help"]);
    assert_eq!(code, 0, "sanitai --help must exit 0; stderr: {stderr}");
    assert!(
        stdout.contains("tui"),
        "sanitai --help output must include the 'tui' subcommand; got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// `sanitai tui --help` — must exit 0 without launching the TUI
// ---------------------------------------------------------------------------

/// `sanitai tui --help` must exit 0 and print usage text without ever
/// invoking `run_tui`. Clap intercepts `--help` before any command handler
/// runs, so the TTY guard must never be reached.
#[test]
fn tui_help_exits_zero() {
    let (_, stderr, code) = run_sanitai(&["tui", "--help"]);
    assert_eq!(code, 0, "sanitai tui --help must exit 0; stderr: {stderr}");
}

#[test]
fn tui_help_prints_usage() {
    let (stdout, stderr, code) = run_sanitai(&["tui", "--help"]);
    assert_eq!(code, 0, "sanitai tui --help must exit 0; stderr: {stderr}");
    // clap always emits "Usage:" at minimum; this is the canonical marker.
    assert!(
        stdout.to_lowercase().contains("usage"),
        "sanitai tui --help must print usage text; got:\n{stdout}"
    );
}

/// `sanitai tui --help` must not emit "requires a terminal" on stderr.
///
/// If the TTY guard fires before `--help` is handled, it means the command
/// handler is being called before clap has processed help flags — a bug.
#[test]
fn tui_help_does_not_trigger_tty_guard() {
    let (_, stderr, code) = run_sanitai(&["tui", "--help"]);
    // Accept exit 0 only — this distinguishes --help from the non-TTY path.
    assert_eq!(
        code, 0,
        "sanitai tui --help must exit 0, not trigger the TTY guard; stderr: {stderr}"
    );
    assert!(
        !stderr.to_lowercase().contains("requires"),
        "tui --help must not trigger the TTY guard message; stderr: {stderr}"
    );
}
