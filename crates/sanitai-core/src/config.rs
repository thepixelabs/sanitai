use crate::error::CoreError;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitaiConfig {
    pub schema_version: u32,
    pub scan: ScanConfig,
    pub redact: RedactConfig,
    pub policy: PolicyConfig,
    pub runtime: RuntimeConfig,
}

impl Default for SanitaiConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            scan: ScanConfig::default(),
            redact: RedactConfig::default(),
            policy: PolicyConfig::default(),
            runtime: RuntimeConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Sub-configs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Source paths to scan. `["auto"]` triggers auto-discovery.
    pub sources: Vec<String>,
    /// Detector IDs to enable. Empty = all enabled.
    pub detectors: Vec<String>,
    /// Findings below this confidence are suppressed.
    pub confidence_threshold: f32,
    /// Scanning profile affecting defaults.
    pub profile: Profile,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            sources: vec!["auto".to_string()],
            detectors: vec![],
            confidence_threshold: 0.85,
            profile: Profile::Dev,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Dev,        // precision-focused, threshold 0.85
    Compliance, // recall-focused, threshold 0.75
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactConfig {
    pub mode: RedactMode,
    pub preserve_structure: bool,
}

impl Default for RedactConfig {
    fn default() -> Self {
        Self {
            mode: RedactMode::Mask,
            preserve_structure: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RedactMode {
    Mask,
    Hash,
    Partial,
    VaultRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyConfig {
    /// Glob patterns for paths to skip.
    pub ignore_patterns: Vec<String>,
    /// Paths to custom rule YAML directories.
    pub extra_rules_dirs: Vec<String>,
    /// Detector IDs to disable entirely.
    pub disable_detectors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub max_memory: String,
    pub parallelism: String,
    pub sandbox: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_memory: "512M".to_string(),
            parallelism: "auto".to_string(),
            sandbox: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Load the active configuration, applying the full precedence chain:
///   built-in defaults
///   < $XDG_CONFIG_HOME/sanitai/config.toml
///   < ./sanitai.toml
///   < SANITAI_* env vars   (double-underscore for nesting)
///   < CLI overrides (passed as a serialized struct)
pub fn load_config() -> Result<SanitaiConfig, CoreError> {
    let xdg_config = std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| {
        dirs_next::home_dir()
            .map(|h| h.join(".config").to_string_lossy().to_string())
            .unwrap_or_default()
    });
    let global_config = format!("{}/sanitai/config.toml", xdg_config);

    let config: SanitaiConfig = Figment::from(Serialized::defaults(SanitaiConfig::default()))
        .merge(Toml::file(&global_config))
        .merge(Toml::file("sanitai.toml"))
        .merge(Env::prefixed("SANITAI_").split("__"))
        .extract()
        .map_err(|e| CoreError::Config(e.to_string()))?;

    if config.schema_version != 1 {
        return Err(CoreError::Config(format!(
            "unsupported schema_version {}; expected 1",
            config.schema_version
        )));
    }

    Ok(config)
}

/// Load configuration starting from an explicit TOML file path, bypassing
/// the auto-discovery chain. Still applies built-in defaults underneath and
/// `SANITAI_*` env overrides on top.
pub fn load_config_from(path: &std::path::Path) -> Result<SanitaiConfig, CoreError> {
    let config: SanitaiConfig = Figment::from(Serialized::defaults(SanitaiConfig::default()))
        .merge(Toml::file(path))
        .merge(Env::prefixed("SANITAI_").split("__"))
        .extract()
        .map_err(|e| CoreError::Config(e.to_string()))?;

    if config.schema_version != 1 {
        return Err(CoreError::Config(format!(
            "unsupported schema_version {}; expected 1",
            config.schema_version
        )));
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let cfg = SanitaiConfig::default();
        assert_eq!(cfg.schema_version, 1);
        assert_eq!(cfg.scan.profile, Profile::Dev);
        assert!((cfg.scan.confidence_threshold - 0.85).abs() < f32::EPSILON);
        assert!(cfg.runtime.sandbox);
    }
}

// ---------------------------------------------------------------------------
// Ignore patterns
// ---------------------------------------------------------------------------

/// Compiled form of `policy.ignore_patterns`: files whose absolute path
/// matches any pattern are skipped before parsing.
///
/// Pattern rules (kept deliberately forgiving — this is typed by hand or
/// added from the TUI):
/// * a leading `~/` expands to the home directory;
/// * `*` and `?` match across `/` (so `*/Copper/*` skips a whole project);
/// * a pattern with no glob metacharacters is a substring test —
///   `git-sanitai` skips every path containing it.
#[derive(Debug, Clone, Default)]
pub struct IgnoreMatcher {
    patterns: Vec<(String, glob::Pattern)>,
}

const IGNORE_MATCH_OPTIONS: glob::MatchOptions = glob::MatchOptions {
    case_sensitive: true,
    require_literal_separator: false,
    require_literal_leading_dot: false,
};

/// Normalise and compile one ignore pattern; see [`IgnoreMatcher`] for the
/// rules. Errors only on a malformed glob (unbalanced `[`).
pub fn compile_ignore_pattern(raw: &str) -> Result<glob::Pattern, CoreError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CoreError::Config("empty ignore pattern".to_owned()));
    }
    let mut expanded = trimmed.to_owned();
    if let Some(rest) = trimmed.strip_prefix("~/") {
        if let Some(home) = dirs_next::home_dir() {
            expanded = home.join(rest).to_string_lossy().into_owned();
        }
    }
    let has_meta = expanded.contains(['*', '?', '[']);
    let pattern = if has_meta {
        expanded
    } else {
        format!("*{}*", glob::Pattern::escape(&expanded))
    };
    glob::Pattern::new(&pattern)
        .map_err(|e| CoreError::Config(format!("invalid ignore pattern {raw:?}: {e}")))
}

impl IgnoreMatcher {
    /// Compile every pattern, warning about (and skipping) malformed ones so
    /// one typo in the config never disables scanning.
    pub fn new(patterns: &[String]) -> Self {
        let mut compiled = Vec::with_capacity(patterns.len());
        for raw in patterns {
            match compile_ignore_pattern(raw) {
                Ok(p) => compiled.push((raw.clone(), p)),
                Err(e) => tracing::warn!("{e}; pattern skipped"),
            }
        }
        Self { patterns: compiled }
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    pub fn is_ignored(&self, path: &Path) -> bool {
        if self.patterns.is_empty() {
            return false;
        }
        let text = path.to_string_lossy();
        self.patterns
            .iter()
            .any(|(_, p)| p.matches_with(&text, IGNORE_MATCH_OPTIONS))
    }

    /// Drop ignored paths in place; returns how many were removed.
    pub fn retain_allowed(&self, paths: &mut Vec<PathBuf>) -> usize {
        if self.patterns.is_empty() {
            return 0;
        }
        let before = paths.len();
        paths.retain(|p| !self.is_ignored(p));
        before - paths.len()
    }
}

impl PolicyConfig {
    pub fn ignore_matcher(&self) -> IgnoreMatcher {
        IgnoreMatcher::new(&self.ignore_patterns)
    }
}

/// `$XDG_CONFIG_HOME/sanitai/config.toml` — the global config file the
/// loader reads first and the TUI writes ignore patterns to.
pub fn global_config_path() -> Option<PathBuf> {
    let xdg = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs_next::home_dir().map(|h| h.join(".config")))?;
    Some(xdg.join("sanitai").join("config.toml"))
}

/// Append `pattern` to `policy.ignore_patterns` in the global config,
/// creating the file if needed and leaving everything else in it untouched
/// (comments included). Returns the file written and whether the pattern
/// was new.
pub fn add_ignore_pattern(pattern: &str) -> Result<(PathBuf, bool), CoreError> {
    let path = global_config_path()
        .ok_or_else(|| CoreError::Config("cannot resolve the config directory".to_owned()))?;
    let added = edit_ignore_patterns_in(&path, pattern, true)?;
    Ok((path, added))
}

/// Remove `pattern` from `policy.ignore_patterns` in the global config.
/// Returns the file written and whether anything was removed.
pub fn remove_ignore_pattern(pattern: &str) -> Result<(PathBuf, bool), CoreError> {
    let path = global_config_path()
        .ok_or_else(|| CoreError::Config("cannot resolve the config directory".to_owned()))?;
    let removed = edit_ignore_patterns_in(&path, pattern, false)?;
    Ok((path, removed))
}

/// Shared implementation of add/remove against an explicit file (so tests
/// never touch the real config).
pub fn edit_ignore_patterns_in(path: &Path, pattern: &str, add: bool) -> Result<bool, CoreError> {
    let pattern = pattern.trim();
    if add {
        compile_ignore_pattern(pattern)?;
    }
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(CoreError::Config(format!("read {}: {e}", path.display()))),
    };
    let mut doc: toml_edit::DocumentMut = existing
        .parse()
        .map_err(|e| CoreError::Config(format!("parse {}: {e}", path.display())))?;
    if !doc.contains_key("policy") {
        doc["policy"] = toml_edit::table();
    }
    let policy = doc["policy"]
        .as_table_mut()
        .ok_or_else(|| CoreError::Config("`policy` is not a table".to_owned()))?;
    if !policy.contains_key("ignore_patterns") {
        policy["ignore_patterns"] = toml_edit::value(toml_edit::Array::new());
    }
    let arr = policy["ignore_patterns"]
        .as_array_mut()
        .ok_or_else(|| CoreError::Config("`policy.ignore_patterns` is not an array".to_owned()))?;
    let idx = arr
        .iter()
        .position(|v| v.as_str().map(str::trim) == Some(pattern));
    let changed = match (add, idx) {
        (true, None) => {
            arr.push(pattern);
            true
        }
        (false, Some(i)) => {
            arr.remove(i);
            true
        }
        _ => false,
    };
    if changed {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| CoreError::Config(format!("create {}: {e}", dir.display())))?;
        }
        std::fs::write(path, doc.to_string())
            .map_err(|e| CoreError::Config(format!("write {}: {e}", path.display())))?;
    }
    Ok(changed)
}

#[cfg(test)]
mod ignore_tests {
    use super::*;

    #[test]
    fn substring_and_glob_patterns_match_full_paths() {
        let m = IgnoreMatcher::new(&[
            "git-sanitai".to_owned(),
            "*/Copper/*".to_owned(),
            "/Users/me/.claude/projects/-Users-me-git-old/*".to_owned(),
        ]);
        assert!(m.is_ignored(Path::new(
            "/Users/me/.claude/projects/-Users-me-Documents-git-sanitai/abc/agent-1.jsonl"
        )));
        assert!(m.is_ignored(Path::new("/Users/me/.claude/projects/x/Copper/s.jsonl")));
        assert!(m.is_ignored(Path::new(
            "/Users/me/.claude/projects/-Users-me-git-old/deep/er/file.jsonl"
        )));
        assert!(!m.is_ignored(Path::new(
            "/Users/me/.claude/projects/-Users-me-git-new/s.jsonl"
        )));
        let mut paths = vec![
            PathBuf::from("/a/Copper/x.jsonl"),
            PathBuf::from("/a/Brass/x.jsonl"),
        ];
        assert_eq!(m.retain_allowed(&mut paths), 1);
        assert_eq!(paths, vec![PathBuf::from("/a/Brass/x.jsonl")]);
    }

    #[test]
    fn malformed_pattern_is_skipped_not_fatal() {
        let m = IgnoreMatcher::new(&["[unclosed".to_owned(), "ok".to_owned()]);
        assert!(m.is_ignored(Path::new("/tmp/ok/file")));
        assert!(compile_ignore_pattern("").is_err());
    }

    #[test]
    fn edit_ignore_patterns_preserves_other_content() {
        let dir = std::env::temp_dir().join(format!("sanitai-ignore-{}", std::process::id()));
        let path = dir.join("nested").join("config.toml");
        let _ = std::fs::remove_dir_all(&dir);
        // Fresh file.
        assert!(edit_ignore_patterns_in(&path, "git-sanitai", true).unwrap());
        assert!(!edit_ignore_patterns_in(&path, "git-sanitai", true).unwrap());
        // Hand-written content with a comment survives a second edit.
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.insert_str(
            0,
            "# my config\nschema_version = 1\n\n[scan]\nconfidence_threshold = 0.5\n\n",
        );
        std::fs::write(&path, &text).unwrap();
        assert!(edit_ignore_patterns_in(&path, "*/Copper/*", true).unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# my config"));
        assert!(text.contains("confidence_threshold = 0.5"));
        assert!(text.contains("\"git-sanitai\""));
        assert!(text.contains("\"*/Copper/*\""));
        // Loads back through the real loader.
        let cfg = load_config_from(&path).unwrap();
        assert_eq!(
            cfg.policy.ignore_patterns,
            vec!["git-sanitai", "*/Copper/*"]
        );
        // Remove.
        assert!(edit_ignore_patterns_in(&path, "git-sanitai", false).unwrap());
        assert!(!edit_ignore_patterns_in(&path, "git-sanitai", false).unwrap());
        let cfg = load_config_from(&path).unwrap();
        assert_eq!(cfg.policy.ignore_patterns, vec!["*/Copper/*"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
