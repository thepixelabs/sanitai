//! Resolve and spawn the user's preferred file viewer.
//!
//! Resolution priority (first hit wins):
//!   1. `$VISUAL` — the convention for "I want a real editor right now"
//!   2. `$EDITOR` — the lower-priority fallback
//!   3. **Probe well-known editors on `PATH`** (`code`, `code-insiders`,
//!      `cursor`, `subl`, `nvim`, `vim`, `nano`, in that order). The first
//!      binary we can find on the user's `PATH` is used.
//!   4. Platform default — picker-safe:
//!        - macOS:   plain `open <file>`. Opens with the default app for
//!          the extension when one is registered, or shows the system
//!          "Open With" picker when none is. Both outcomes are useful;
//!          failing to spawn (which `open -t` does on extensions Launch
//!          Services doesn't bind to a text editor — `.jsonl` is the
//!          canonical example) is not.
//!        - Linux:   `xdg-open <file>`
//!        - Windows: `cmd /c start "" <file>`
//!
//! For known editors we append a line-jump argument: `:LINE` for the VS
//! Code / Sublime / cursor family, `+LINE` for vim/nano.
//!
//! The returned vector is the full argv ready for `Command::new(argv[0])`
//! with `argv[1..]` as args. Tests build the vector and assert on its
//! contents without ever spawning a process.

use std::path::{Path, PathBuf};

/// Outcome of attempting to resolve a viewer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditorResolution {
    /// Run this argv with `Command::new(argv[0]).args(&argv[1..])`.
    Spawn(Vec<String>),
    /// No viewer could be resolved. Caller surfaces a tagline.
    NoEditor,
}

/// Editors we probe in `PATH` when neither `$VISUAL` nor `$EDITOR` is set.
/// Order matters — `code` (VS Code) ships on most modern dev machines and
/// gets us a real editor with line-jump support, so it leads. `nano` is
/// last because it is the lowest-common-denominator fallback.
const PROBED_EDITORS: &[&str] = &[
    "code",
    "code-insiders",
    "cursor",
    "subl",
    "nvim",
    "vim",
    "nano",
];

/// Build the argv for opening `file` at `line` (1-based).
///
/// `env` is parameterised so tests can inject `$VISUAL` / `$EDITOR` without
/// touching the real process environment (process-global env vars are not
/// safe to mutate from tests run in parallel). `which` is parameterised
/// for the same reason — production callers pass [`ProcessWhich`], tests
/// pass a fake whose decisions are explicit and deterministic.
pub fn resolve(
    file: &Path,
    line: usize,
    env: &dyn EnvLookup,
    which: &dyn Whichable,
) -> EditorResolution {
    // 1 + 2: $VISUAL then $EDITOR. Per `man 7 environ`, $VISUAL beats $EDITOR.
    for var in ["VISUAL", "EDITOR"] {
        if let Some(value) = env.get(var) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return EditorResolution::Spawn(build_argv(trimmed, file, line));
            }
        }
    }

    // 3: probe known editors on PATH. We use the binary's basename for
    // line-jump detection and pass the discovered absolute path as argv[0]
    // so we don't depend on the child re-resolving via PATH.
    for name in PROBED_EDITORS {
        if let Some(path) = which.locate(name) {
            let path_str = path.display().to_string();
            return EditorResolution::Spawn(build_argv(&path_str, file, line));
        }
    }

    // 4: platform default — picker-safe.
    platform_default(file)
        .map(EditorResolution::Spawn)
        .unwrap_or(EditorResolution::NoEditor)
}

/// Trait used to read environment variables in a test-friendly way.
pub trait EnvLookup {
    fn get(&self, key: &str) -> Option<String>;
}

/// Real-process env lookup. Production callers always use this.
pub struct ProcessEnv;
impl EnvLookup for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

/// Trait used to locate a binary on `PATH` in a test-friendly way.
///
/// The production implementation walks `PATH` itself instead of shelling
/// out to `which(1)` — every probe would otherwise fork a subprocess, and
/// the lookup is not portable to Windows. Walking `PATH` ourselves keeps
/// the probe to a handful of `stat` calls.
pub trait Whichable {
    /// Locate the absolute path of `name` on `PATH`, if any.
    fn locate(&self, name: &str) -> Option<PathBuf>;
}

/// Production `Whichable`: walks `$PATH` and returns the first executable
/// match. On Windows we additionally try common executable suffixes
/// (`.exe`, `.cmd`, `.bat`).
pub struct ProcessWhich;

impl Whichable for ProcessWhich {
    fn locate(&self, name: &str) -> Option<PathBuf> {
        let path_var = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path_var) {
            // Plain name first — covers macOS / Linux and bare names on Windows.
            let candidate = dir.join(name);
            if is_executable(&candidate) {
                return Some(candidate);
            }
            #[cfg(target_os = "windows")]
            for ext in [".exe", ".cmd", ".bat"] {
                let candidate = dir.join(format!("{name}{ext}"));
                if is_executable(&candidate) {
                    return Some(candidate);
                }
            }
        }
        None
    }
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && (meta.permissions().mode() & 0o111) != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    // On Windows the `mode` bits don't apply; we just check that the file
    // exists. Suffix discovery in `ProcessWhich::locate` covers `.exe` /
    // `.cmd` / `.bat` so a hit here is good enough.
    std::fs::metadata(path)
        .map(|m| m.is_file())
        .unwrap_or(false)
}

/// Tokenise the editor command and append a line-jump arg appropriate for
/// the editor family. We deliberately do **not** support quoted arguments
/// or shell metacharacters in `$VISUAL` / `$EDITOR` — splitting on
/// whitespace covers the 99% case and refusing to spawn a shell keeps an
/// obvious code-injection vector closed.
fn build_argv(cmd: &str, file: &Path, line: usize) -> Vec<String> {
    let mut parts: Vec<String> = cmd.split_whitespace().map(|s| s.to_owned()).collect();
    if parts.is_empty() {
        // Defensive — caller already trimmed, but keep the invariant tight.
        return vec![file.display().to_string()];
    }

    let bin = parts[0].clone();
    let bin_basename = Path::new(&bin)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(bin.as_str())
        .to_lowercase();
    // Strip a trailing `.exe` / `.cmd` / `.bat` so the basename matches
    // our family table on Windows too.
    let bin_basename = bin_basename
        .strip_suffix(".exe")
        .or_else(|| bin_basename.strip_suffix(".cmd"))
        .or_else(|| bin_basename.strip_suffix(".bat"))
        .map(|s| s.to_owned())
        .unwrap_or(bin_basename);
    let line_arg = line_jump_arg(&bin_basename, line);
    let file_str = file.display().to_string();
    let target = match line_arg {
        Some(LineJump::Vim(arg)) => {
            // vim wants `+LINE` BEFORE the file argument.
            parts.push(arg);
            parts.push(file_str);
            return parts;
        }
        Some(LineJump::Suffix(suffix)) => format!("{}{}", file_str, suffix),
        None => file_str,
    };
    parts.push(target);
    parts
}

enum LineJump {
    /// `+N` arg pushed onto argv before the file (vim family).
    Vim(String),
    /// `:N` (or other) suffix appended to the file path (VS Code family).
    Suffix(String),
}

fn line_jump_arg(bin_basename: &str, line: usize) -> Option<LineJump> {
    match bin_basename {
        // VS Code / Cursor / Sublime — accept FILE:LINE
        "code" | "code-insiders" | "cursor" | "subl" => Some(LineJump::Suffix(format!(":{line}"))),
        // Vim family — accept +LINE FILE
        "vim" | "nvim" | "vi" | "view" => Some(LineJump::Vim(format!("+{line}"))),
        // nano accepts +LINE
        "nano" => Some(LineJump::Vim(format!("+{line}"))),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn platform_default(file: &Path) -> Option<Vec<String>> {
    // Plain `open <file>` — opens with the default app for that extension
    // when one is registered, or shows the "Open With" picker when none is.
    // Both outcomes are useful; failing to spawn (which `open -t` does when
    // Launch Services can't resolve a text editor for an unregistered
    // extension like `.jsonl`) is not.
    Some(vec!["open".to_owned(), file.display().to_string()])
}

#[cfg(target_os = "linux")]
fn platform_default(file: &Path) -> Option<Vec<String>> {
    Some(vec!["xdg-open".to_owned(), file.display().to_string()])
}

#[cfg(target_os = "windows")]
fn platform_default(file: &Path) -> Option<Vec<String>> {
    // `cmd /c start "" <file>` — the empty quoted arg is the window title;
    // omitting it makes `start` interpret the file path as the title.
    Some(vec![
        "cmd".to_owned(),
        "/c".to_owned(),
        "start".to_owned(),
        "".to_owned(),
        file.display().to_string(),
    ])
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn platform_default(_file: &Path) -> Option<Vec<String>> {
    None
}

/// Spawn the resolved argv non-blocking. Errors propagate up so the caller
/// can update the tagline — we deliberately do not crash the TUI.
pub fn spawn(argv: &[String]) -> std::io::Result<()> {
    if argv.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty argv",
        ));
    }
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    // Detach stdin/stdout/stderr so the child does not contend with the TUI
    // for the terminal. The TUI is in alternate-screen mode; piping ensures
    // the child cannot accidentally write to it.
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    cmd.spawn()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;

    /// Map-backed EnvLookup so tests stay hermetic.
    struct FakeEnv(HashMap<String, String>);
    impl EnvLookup for FakeEnv {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    fn fake(pairs: &[(&str, &str)]) -> FakeEnv {
        FakeEnv(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
    }

    /// Whichable that returns `Some(/usr/bin/<name>)` for any name in its
    /// allow-list and `None` otherwise. Lets each test declare exactly
    /// which editors are "installed" without touching `PATH`.
    struct FakeWhich(HashSet<String>);
    impl FakeWhich {
        fn from(names: &[&str]) -> Self {
            FakeWhich(names.iter().map(|s| (*s).to_owned()).collect())
        }
        fn empty() -> Self {
            FakeWhich(HashSet::new())
        }
    }
    impl Whichable for FakeWhich {
        fn locate(&self, name: &str) -> Option<PathBuf> {
            if self.0.contains(name) {
                Some(PathBuf::from(format!("/usr/bin/{name}")))
            } else {
                None
            }
        }
    }

    #[test]
    fn visual_takes_priority_over_editor() {
        let env = fake(&[("VISUAL", "code"), ("EDITOR", "vim")]);
        let res = resolve(&PathBuf::from("/tmp/x.jsonl"), 5, &env, &FakeWhich::empty());
        match res {
            EditorResolution::Spawn(argv) => {
                assert_eq!(argv[0], "code");
                // VS Code: FILE:LINE suffix
                assert_eq!(argv.last().unwrap(), "/tmp/x.jsonl:5");
            }
            other => panic!("expected Spawn, got {other:?}"),
        }
    }

    #[test]
    fn editor_used_when_visual_unset() {
        let env = fake(&[("EDITOR", "vim")]);
        let res = resolve(
            &PathBuf::from("/tmp/x.jsonl"),
            12,
            &env,
            &FakeWhich::empty(),
        );
        match res {
            EditorResolution::Spawn(argv) => {
                // vim: +LINE arg BEFORE the file
                assert_eq!(argv[0], "vim");
                assert_eq!(argv[1], "+12");
                assert_eq!(argv[2], "/tmp/x.jsonl");
            }
            other => panic!("expected Spawn, got {other:?}"),
        }
    }

    #[test]
    fn empty_visual_falls_through_to_editor() {
        let env = fake(&[("VISUAL", "   "), ("EDITOR", "nano")]);
        let res = resolve(&PathBuf::from("/tmp/x"), 3, &env, &FakeWhich::empty());
        match res {
            EditorResolution::Spawn(argv) => {
                assert_eq!(argv[0], "nano");
                assert_eq!(argv[1], "+3");
            }
            other => panic!("expected Spawn, got {other:?}"),
        }
    }

    #[test]
    fn unknown_editor_gets_no_line_jump() {
        let env = fake(&[("EDITOR", "weirdtool")]);
        let res = resolve(
            &PathBuf::from("/tmp/x.jsonl"),
            99,
            &env,
            &FakeWhich::empty(),
        );
        match res {
            EditorResolution::Spawn(argv) => {
                assert_eq!(argv[0], "weirdtool");
                assert_eq!(argv.last().unwrap(), "/tmp/x.jsonl");
                assert_eq!(argv.len(), 2, "no extra line-jump arg expected");
            }
            other => panic!("expected Spawn, got {other:?}"),
        }
    }

    #[test]
    fn editor_with_args_preserves_args() {
        let env = fake(&[("EDITOR", "code --wait")]);
        let res = resolve(&PathBuf::from("/tmp/x"), 1, &env, &FakeWhich::empty());
        match res {
            EditorResolution::Spawn(argv) => {
                assert_eq!(argv[0], "code");
                assert_eq!(argv[1], "--wait");
                assert_eq!(argv[2], "/tmp/x:1");
            }
            other => panic!("expected Spawn, got {other:?}"),
        }
    }

    #[test]
    fn cursor_uses_colon_line() {
        let env = fake(&[("VISUAL", "cursor")]);
        let res = resolve(&PathBuf::from("/tmp/x.md"), 42, &env, &FakeWhich::empty());
        if let EditorResolution::Spawn(argv) = res {
            assert_eq!(argv.last().unwrap(), "/tmp/x.md:42");
        } else {
            panic!("expected Spawn");
        }
    }

    #[test]
    fn nvim_uses_plus_line() {
        let env = fake(&[("EDITOR", "nvim")]);
        let res = resolve(&PathBuf::from("/tmp/x.md"), 42, &env, &FakeWhich::empty());
        if let EditorResolution::Spawn(argv) = res {
            assert_eq!(argv[0], "nvim");
            assert_eq!(argv[1], "+42");
        } else {
            panic!("expected Spawn");
        }
    }

    #[test]
    fn editor_resolved_with_absolute_path() {
        let env = fake(&[("EDITOR", "/usr/local/bin/code")]);
        let res = resolve(&PathBuf::from("/tmp/x"), 7, &env, &FakeWhich::empty());
        if let EditorResolution::Spawn(argv) = res {
            assert_eq!(argv[0], "/usr/local/bin/code");
            // basename detection is case-insensitive, picks up "code"
            assert_eq!(argv.last().unwrap(), "/tmp/x:7");
        } else {
            panic!("expected Spawn");
        }
    }

    // ---------------- Editor probe (Change 5) -------------------------------

    #[test]
    fn probe_picks_code_when_only_code_on_path() {
        // No env vars set; only `code` is on PATH. Resolution must land on
        // the absolute path returned by the fake Whichable, with the line
        // suffix attached.
        let env = fake(&[]);
        let which = FakeWhich::from(&["code"]);
        let res = resolve(&PathBuf::from("/tmp/x.jsonl"), 47, &env, &which);
        match res {
            EditorResolution::Spawn(argv) => {
                assert_eq!(argv[0], "/usr/bin/code");
                assert_eq!(argv.last().unwrap(), "/tmp/x.jsonl:47");
            }
            other => panic!("expected Spawn, got {other:?}"),
        }
    }

    #[test]
    fn probe_respects_priority_order() {
        // Both `cursor` and `nano` are on PATH. The probe order in
        // PROBED_EDITORS puts `cursor` ahead of `nano`, so cursor wins.
        let env = fake(&[]);
        let which = FakeWhich::from(&["cursor", "nano"]);
        let res = resolve(&PathBuf::from("/tmp/x.md"), 12, &env, &which);
        match res {
            EditorResolution::Spawn(argv) => {
                assert_eq!(argv[0], "/usr/bin/cursor");
                assert_eq!(argv.last().unwrap(), "/tmp/x.md:12");
            }
            other => panic!("expected Spawn, got {other:?}"),
        }
    }

    #[test]
    fn visual_beats_probe() {
        // $VISUAL is set AND `code` is on PATH. $VISUAL still wins so the
        // user's explicit choice is honoured.
        let env = fake(&[("VISUAL", "vim")]);
        let which = FakeWhich::from(&["code"]);
        let res = resolve(&PathBuf::from("/tmp/x"), 5, &env, &which);
        match res {
            EditorResolution::Spawn(argv) => {
                assert_eq!(argv[0], "vim");
                assert_eq!(argv[1], "+5");
            }
            other => panic!("expected Spawn, got {other:?}"),
        }
    }

    // ---------------- Platform-default fallback -----------------------------

    #[test]
    fn no_env_no_editors_falls_to_platform_default() {
        let env = fake(&[]);
        let which = FakeWhich::empty();
        let res = resolve(&PathBuf::from("/tmp/x"), 1, &env, &which);
        match res {
            EditorResolution::Spawn(argv) => {
                #[cfg(target_os = "macos")]
                {
                    // Plain `open <file>` — opens default app or shows the
                    // picker. Earlier versions used `open -t` to suppress the
                    // picker, but that fails on extensions Launch Services
                    // doesn't bind to a text editor (e.g., `.jsonl`).
                    assert_eq!(argv[0], "open");
                    assert_eq!(argv[1], "/tmp/x");
                }
                #[cfg(target_os = "linux")]
                assert_eq!(argv[0], "xdg-open");
                #[cfg(target_os = "windows")]
                assert_eq!(argv[0], "cmd");
            }
            EditorResolution::NoEditor => {
                // Acceptable on platforms without a known default.
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_default_is_plain_open() {
        let env = fake(&[]);
        let which = FakeWhich::empty();
        let res = resolve(&PathBuf::from("/Users/me/conv.jsonl"), 1, &env, &which);
        match res {
            EditorResolution::Spawn(argv) => {
                assert_eq!(argv, vec!["open", "/Users/me/conv.jsonl"]);
            }
            other => panic!("expected Spawn(open ...), got {other:?}"),
        }
    }
}
