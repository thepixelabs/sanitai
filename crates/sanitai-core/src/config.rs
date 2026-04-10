use crate::error::CoreError;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};

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
