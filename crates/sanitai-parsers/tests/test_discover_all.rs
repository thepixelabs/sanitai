//! Integration test for cross-source discovery. We plant fake files under
//! a synthetic home directory and verify `discover_all` finds them.
//!
//! We only assert platform-specific discovery for the platforms we know
//! the paths for — the test is a no-op on other targets.

use std::fs;
use std::path::PathBuf;

use sanitai_core::turn::SourceKind;
use sanitai_parsers::discover_all;

fn mktemp(label: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("sanitai-disco-{label}-{n}"));
    fs::create_dir_all(&p).expect("mkdir");
    p
}

#[cfg(target_os = "macos")]
#[test]
fn discovers_copilot_and_gemini_on_macos() {
    let home = mktemp("mac");

    // Copilot: ~/Library/Application Support/Code/logs/<sess>/GitHub Copilot Chat.log
    let copilot_dir = home.join("Library/Application Support/Code/logs/20260413T120000");
    fs::create_dir_all(&copilot_dir).expect("mkdir copilot");
    let copilot_log = copilot_dir.join("GitHub Copilot Chat.log");
    fs::write(&copilot_log, b"placeholder\n").expect("write copilot");

    // Gemini: ~/Downloads/Takeout/Gemini/MyActivity.json
    let gemini_dir = home.join("Downloads/Takeout/Gemini");
    fs::create_dir_all(&gemini_dir).expect("mkdir gemini");
    let gemini_json = gemini_dir.join("MyActivity.json");
    fs::write(&gemini_json, b"[]\n").expect("write gemini");

    let found = discover_all(&home);

    assert!(
        found.iter().any(|s| s.kind == SourceKind::GitHubCopilot),
        "expected Copilot in {found:?}"
    );
    assert!(
        found.iter().any(|s| s.kind == SourceKind::GeminiCli),
        "expected Gemini in {found:?}"
    );

    fs::remove_dir_all(&home).ok();
}

#[cfg(target_os = "linux")]
#[test]
fn discovers_copilot_and_gemini_on_linux() {
    let home = mktemp("linux");

    // Force XDG_CONFIG_HOME at ~/.config so discovery resolves predictably.
    let xdg = home.join(".config");
    fs::create_dir_all(&xdg).expect("mkdir xdg");
    std::env::set_var("XDG_CONFIG_HOME", &xdg);

    let copilot_dir = xdg.join("Code/logs/20260413T120000");
    fs::create_dir_all(&copilot_dir).expect("mkdir copilot");
    fs::write(
        copilot_dir.join("GitHub Copilot Chat.log"),
        b"placeholder\n",
    )
    .expect("write copilot");

    let gemini_dir = home.join("Downloads/Takeout/Gemini");
    fs::create_dir_all(&gemini_dir).expect("mkdir gemini");
    fs::write(gemini_dir.join("MyActivity.json"), b"[]\n").expect("write gemini");

    let found = discover_all(&home);

    assert!(
        found.iter().any(|s| s.kind == SourceKind::GitHubCopilot),
        "expected Copilot in {found:?}"
    );
    assert!(
        found.iter().any(|s| s.kind == SourceKind::GeminiCli),
        "expected Gemini in {found:?}"
    );

    std::env::remove_var("XDG_CONFIG_HOME");
    fs::remove_dir_all(&home).ok();
}
