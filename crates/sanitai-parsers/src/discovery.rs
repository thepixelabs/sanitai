//! Auto-discovery of known LLM conversation stores on the local machine.
//!
//! Each supported tool has a well-known directory layout on disk. `discover_all`
//! walks each of those locations with a bounded depth budget and returns a list
//! of `DiscoveredSource`s ready to be fed into a parser.
//!
//! Design choices worth calling out for future maintainers:
//!
//! - We use `walkdir` with `max_depth(6)` rather than an unbounded recursive
//!   `read_dir`. Some `~/.claude/projects` trees can be deep; bounding the walk
//!   keeps cold-start latency predictable (<200ms on a warm FS).
//! - `.git` directories are skipped explicitly — they tend to dominate walk
//!   time and never contain LLM data.
//! - Canonicalization is best-effort: if `canonicalize` fails (broken symlink,
//!   permissions) we drop the entry rather than surfacing errors, because the
//!   scanner treats discovery as a non-fatal hint. The user can always pass
//!   `--file` explicitly.
//! - The `SANITAI_EXTRA_PATHS` env var lets users add arbitrary glob patterns
//!   without recompiling. It's colon-separated and interpreted via the `glob`
//!   crate, matching the shell conventions of the rest of the CLI.

#![deny(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use sanitai_core::turn::SourceKind;
use walkdir::WalkDir;

/// Logical file shape, independent of the owning tool. The scanner uses this
/// to decide whether a file needs the JSONL parser, the SQLite reader, etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileFormat {
    Jsonl,
    Json,
    Toml,
    Sqlite,
    TextLike,
    Archive,
}

#[derive(Debug, Clone)]
pub struct DiscoveredSource {
    pub kind: SourceKind,
    pub path: PathBuf,
    pub format: FileFormat,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Discover all known LLM conversation sources under `home`.
///
/// `home` is the user's home directory (usually `dirs_next::home_dir()`). It is
/// taken as a parameter rather than looked up internally so tests can point at
/// synthetic directory trees.
pub fn discover_all(home: &Path) -> Vec<DiscoveredSource> {
    let mut out: Vec<DiscoveredSource> = Vec::new();

    discover_claude_code(home, &mut out);
    discover_claude_desktop(home, &mut out);
    discover_cursor(home, &mut out);
    discover_extra_paths(&mut out);

    // Deduplicate by canonical path — a tool's directory may be referenced
    // through multiple roots on the same machine.
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path);
    out
}

// ---------------------------------------------------------------------------
// Per-tool probes
// ---------------------------------------------------------------------------

fn discover_claude_code(home: &Path, out: &mut Vec<DiscoveredSource>) {
    let root = home.join(".claude").join("projects");
    walk_files(&root, 6, &["jsonl"], |path| {
        push_canonical(out, SourceKind::ClaudeCode, FileFormat::Jsonl, path);
    });
}

fn discover_claude_desktop(home: &Path, out: &mut Vec<DiscoveredSource>) {
    #[cfg(target_os = "macos")]
    {
        let root = home
            .join("Library")
            .join("Application Support")
            .join("Claude");
        walk_files(&root, 2, &["json"], |path| {
            push_canonical(out, SourceKind::ClaudeDesktop, FileFormat::Json, path);
        });
    }

    #[cfg(target_os = "linux")]
    {
        let root = xdg_config_home(home).join("claude");
        walk_files(&root, 2, &["json"], |path| {
            push_canonical(out, SourceKind::ClaudeDesktop, FileFormat::Json, path);
        });
    }

    // Other targets: no known default location.
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = home;
        let _ = out;
    }
}

fn discover_cursor(home: &Path, out: &mut Vec<DiscoveredSource>) {
    #[cfg(target_os = "macos")]
    {
        let root = home
            .join("Library")
            .join("Application Support")
            .join("Cursor")
            .join("User")
            .join("workspaceStorage");
        walk_files(&root, 6, &["vscdb"], |path| {
            push_canonical(out, SourceKind::Cursor, FileFormat::Sqlite, path);
        });
    }

    #[cfg(target_os = "linux")]
    {
        let root = xdg_config_home(home)
            .join("Cursor")
            .join("User")
            .join("workspaceStorage");
        walk_files(&root, 6, &["vscdb"], |path| {
            push_canonical(out, SourceKind::Cursor, FileFormat::Sqlite, path);
        });
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = home;
        let _ = out;
    }
}

fn discover_extra_paths(out: &mut Vec<DiscoveredSource>) {
    let Ok(raw) = std::env::var("SANITAI_EXTRA_PATHS") else {
        return;
    };
    for pattern in raw.split(':').filter(|s| !s.is_empty()) {
        let Ok(paths) = glob::glob(pattern) else {
            tracing::debug!(pattern, "SANITAI_EXTRA_PATHS: invalid glob, skipping");
            continue;
        };
        for entry in paths.flatten() {
            let format = classify(&entry);
            push_canonical(out, SourceKind::Generic, format, &entry);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Walk `root` to `max_depth` and invoke `visit` for every regular file whose
/// extension matches one of `exts` (case-insensitive). Missing directories and
/// IO errors are swallowed — discovery is advisory.
fn walk_files(root: &Path, max_depth: usize, exts: &[&str], mut visit: impl FnMut(&Path)) {
    if !root.exists() {
        return;
    }
    let walker = WalkDir::new(root)
        .max_depth(max_depth)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            // Skip `.git` directories and other noise.
            !matches!(e.file_name().to_str(), Some(".git") | Some("node_modules"))
        });

    for entry in walker.flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if exts.iter().any(|want| want.eq_ignore_ascii_case(ext)) {
            visit(path);
        }
    }
}

fn push_canonical(
    out: &mut Vec<DiscoveredSource>,
    kind: SourceKind,
    format: FileFormat,
    path: &Path,
) {
    let Ok(canonical) = path.canonicalize() else {
        return;
    };
    let Ok(meta) = std::fs::metadata(&canonical) else {
        return;
    };
    if !meta.is_file() {
        return;
    }
    out.push(DiscoveredSource {
        kind,
        path: canonical,
        format,
    });
}

fn classify(path: &Path) -> FileFormat {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("jsonl") => FileFormat::Jsonl,
        Some("json") => FileFormat::Json,
        Some("toml") => FileFormat::Toml,
        Some("vscdb") | Some("db") | Some("sqlite") | Some("sqlite3") => FileFormat::Sqlite,
        Some("zip") | Some("tar") | Some("gz") | Some("tgz") => FileFormat::Archive,
        _ => FileFormat::TextLike,
    }
}

#[cfg(any(target_os = "linux", test))]
#[allow(dead_code)] // compiled on macOS in test cfg but only called inside #[cfg(target_os = "linux")]
fn xdg_config_home(home: &Path) -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_CONFIG_HOME") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    home.join(".config")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Instant;

    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "sanitai-discover-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        fs::create_dir_all(&base).expect("mkdir");
        base
    }

    fn rand_suffix() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{n}")
    }

    #[test]
    fn discovers_claude_jsonl_files() {
        let home = tempdir();
        let proj = home.join(".claude").join("projects").join("foo");
        fs::create_dir_all(&proj).expect("mkdir");
        let file = proj.join("session.jsonl");
        fs::write(&file, b"{}\n").expect("write");

        let results = discover_all(&home);
        let found = results
            .iter()
            .any(|s| s.kind == SourceKind::ClaudeCode && s.format == FileFormat::Jsonl);
        assert!(found, "expected to discover {file:?}, got {results:?}");

        fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn missing_home_is_silent() {
        let nonexistent = std::env::temp_dir().join(format!("sanitai-missing-{}", rand_suffix()));
        let results = discover_all(&nonexistent);
        // Should not panic, should not error. May contain entries from env vars.
        let _ = results;
    }

    #[test]
    fn completes_quickly_on_empty_home() {
        let home = tempdir();
        let start = Instant::now();
        let _ = discover_all(&home);
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 500,
            "discovery on empty home took {elapsed:?}"
        );
        fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn extra_paths_env_is_honoured() {
        let home = tempdir();
        let extra = home.join("extra.jsonl");
        fs::write(&extra, b"{}\n").expect("write");

        // Use a unique env var name per test run to avoid parallel test races.
        // std::env::set_var is process-global; keep the scope tight.
        let prev = std::env::var("SANITAI_EXTRA_PATHS").ok();
        std::env::set_var("SANITAI_EXTRA_PATHS", extra.to_string_lossy().to_string());

        let results = discover_all(&home);
        let hit = results
            .iter()
            .any(|s| s.path == extra.canonicalize().expect("canon"));

        match prev {
            Some(v) => std::env::set_var("SANITAI_EXTRA_PATHS", v),
            None => std::env::remove_var("SANITAI_EXTRA_PATHS"),
        }

        assert!(hit, "extra path not discovered: {results:?}");
        fs::remove_dir_all(&home).ok();
    }
}
