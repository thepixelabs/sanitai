//! User-managed list of suppressed finding fingerprints.
//!
//! A suppressed fingerprint is **not** filtered out of the Results view —
//! we still render the row with `Modifier::CROSSED_OUT` and a `[suppressed]`
//! tag so the user keeps a visible audit trail of what they have chosen to
//! ignore. The flag persists across sessions in
//! `~/.local/share/sanitai/suppressions.json` (XDG-style) so the user's
//! "I've seen this" decisions outlive the running TUI.
//!
//! Storage is intentionally trivial JSON. The schema is versioned so a
//! future move to e.g. a SQLite table can detect old files and migrate
//! them; today we only know how to read v1.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// On-disk schema. Sorted, deduped string set for human-readable diffs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SuppressionsFile {
    version: u32,
    suppressed_fingerprints: BTreeSet<String>,
}

/// In-memory representation. Holds the resolved on-disk path so callers can
/// surface it in error messages without recomputing it.
#[derive(Debug, Clone, Default)]
pub struct Suppressions {
    fingerprints: BTreeSet<String>,
    path: Option<PathBuf>,
}

impl Suppressions {
    /// Load from the canonical XDG path (or `~/.sanitai/suppressions.json`
    /// fallback). Missing files yield an empty store — that's the common
    /// case for first-run users. Malformed files yield an empty store and
    /// log a warning so we don't wipe the user's history on a parse error.
    pub fn load() -> Self {
        let path = match resolve_path() {
            Some(p) => p,
            None => return Self::default(),
        };
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Self {
                    fingerprints: BTreeSet::new(),
                    path: Some(path),
                };
            }
            Err(e) => {
                tracing::warn!("suppressions read failed: {e}");
                return Self {
                    fingerprints: BTreeSet::new(),
                    path: Some(path),
                };
            }
        };
        let parsed: SuppressionsFile = match serde_json::from_slice(&bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("suppressions parse failed: {e}; starting empty");
                SuppressionsFile::default()
            }
        };
        Self {
            fingerprints: parsed.suppressed_fingerprints,
            path: Some(path),
        }
    }

    /// Toggle suppression for `fingerprint_hex`. Returns the new state
    /// (`true` = now suppressed) so the caller can update its tagline.
    /// Persists to disk immediately — this is a low-frequency action and
    /// keeping the in-memory and on-disk views aligned avoids data loss
    /// if the TUI panics later in the session.
    pub fn toggle(&mut self, fingerprint_hex: &str) -> bool {
        let now_suppressed = if self.fingerprints.contains(fingerprint_hex) {
            self.fingerprints.remove(fingerprint_hex);
            false
        } else {
            self.fingerprints.insert(fingerprint_hex.to_owned());
            true
        };
        if let Err(e) = self.save() {
            tracing::warn!("suppressions save failed: {e}");
        }
        now_suppressed
    }

    pub fn is_suppressed(&self, fingerprint_hex: &str) -> bool {
        self.fingerprints.contains(fingerprint_hex)
    }

    /// Persist to the resolved path. No-op if no path could be resolved
    /// (e.g. headless container with no $HOME).
    pub fn save(&self) -> std::io::Result<()> {
        let Some(ref path) = self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = SuppressionsFile {
            version: 1,
            suppressed_fingerprints: self.fingerprints.clone(),
        };
        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    /// Load from a specific path. Used by tests; production code uses `load()`.
    #[cfg(test)]
    pub fn load_from(path: PathBuf) -> Self {
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => {
                return Self {
                    fingerprints: BTreeSet::new(),
                    path: Some(path),
                };
            }
        };
        let parsed: SuppressionsFile = serde_json::from_slice(&bytes).unwrap_or_default();
        Self {
            fingerprints: parsed.suppressed_fingerprints,
            path: Some(path),
        }
    }

    #[cfg(test)]
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            fingerprints: BTreeSet::new(),
            path: Some(path),
        }
    }
}

/// Resolve `~/.local/share/sanitai/suppressions.json` (or the OS equivalent
/// returned by `dirs_next::data_local_dir()`), falling back to
/// `~/.sanitai/suppressions.json` if neither is available. Returns `None`
/// only on very locked-down hosts where neither path can be derived.
fn resolve_path() -> Option<PathBuf> {
    if let Some(dir) = dirs_next::data_local_dir() {
        return Some(dir.join("sanitai").join("suppressions.json"));
    }
    let home = dirs_next::home_dir()?;
    Some(home.join(".sanitai").join("suppressions.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn toggle_inserts_and_removes() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("suppressions.json");
        let mut s = Suppressions::with_path(path.clone());

        assert!(!s.is_suppressed("a8f3c91e"));
        let now = s.toggle("a8f3c91e");
        assert!(now);
        assert!(s.is_suppressed("a8f3c91e"));

        let now2 = s.toggle("a8f3c91e");
        assert!(!now2);
        assert!(!s.is_suppressed("a8f3c91e"));
    }

    #[test]
    fn save_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("suppressions.json");

        let mut s = Suppressions::with_path(path.clone());
        s.toggle("a8f3c91e");
        s.toggle("deadbeef");
        s.toggle("12345678");
        // Toggle "deadbeef" off so we can also verify removal persists.
        s.toggle("deadbeef");
        s.save().unwrap();

        let loaded = Suppressions::load_from(path.clone());
        assert!(loaded.is_suppressed("a8f3c91e"));
        assert!(loaded.is_suppressed("12345678"));
        assert!(!loaded.is_suppressed("deadbeef"));

        // Verify the file is sorted JSON (BTreeSet iteration order).
        let raw = fs::read_to_string(&path).unwrap();
        let p1 = raw.find("12345678").unwrap();
        let p2 = raw.find("a8f3c91e").unwrap();
        assert!(p1 < p2, "fingerprints in file must be sorted");
    }

    #[test]
    fn missing_file_is_empty_not_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.json");
        let s = Suppressions::load_from(path);
        assert!(!s.is_suppressed("anything"));
    }

    #[test]
    fn malformed_file_does_not_panic() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bad.json");
        fs::write(&path, "this is not json").unwrap();
        let s = Suppressions::load_from(path);
        assert!(!s.is_suppressed("anything"));
    }
}
