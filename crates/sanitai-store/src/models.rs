//! Persistent record types for the scan history store.

/// A summary record written after each `sanitai scan` invocation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanRecord {
    /// ULID string — lexicographically sortable, globally unique.
    pub scan_id: String,
    /// Scan wall-clock start time as Unix nanoseconds.
    pub started_at_ns: i64,
    /// How long the scan took, in milliseconds.
    pub duration_ms: i64,
    /// Optional project name derived from the scanned path or config.
    pub project_name: Option<String>,
    /// Optional Claude account identifier from the export file metadata.
    pub claude_account: Option<String>,
    /// Number of distinct files processed.
    pub total_files: i64,
    /// Number of conversation turns processed.
    pub total_turns: i64,
    /// Output format used: "human", "json", or "sarif".
    pub format: String,
    /// Process exit code (0 = clean, 1 = findings, 2+ = error).
    pub exit_code: i32,
    /// Count of high-confidence findings.
    pub findings_high: i64,
    /// Count of medium-confidence findings.
    pub findings_medium: i64,
    /// Count of low-confidence findings.
    pub findings_low: i64,
}

/// A single finding captured during a scan.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FindingRecord {
    /// Foreign key to the parent `ScanRecord`.
    pub scan_id: String,
    /// Detector that produced this finding (e.g. `"aws_key"`).
    pub detector_id: String,
    /// Path of the file that contained the finding.
    pub file_path: String,
    /// Zero-based index of the conversation turn where this finding appeared.
    pub turn_idx: i64,
    /// Confidence level: "high", "medium", or "low".
    pub confidence: String,
    /// JSON array of transform names applied before detection (e.g. `["base64"]`).
    pub transforms: String,
    /// Whether this finding was produced by a synthetic/test fixture.
    pub synthetic: bool,
    /// Role of the source turn, if known ("user", "assistant", ...).
    pub role: Option<String>,
    /// Category of the firing rule ("credential", "secret", ...).
    pub category: Option<String>,
    /// Shannon entropy of the raw match at detection time.
    pub entropy_score: Option<f64>,
    /// Context classification ("unclassified", "real_paste", ...).
    pub context_class: Option<String>,
    /// HMAC-SHA256 of the secret value, keyed with the per-install key.
    /// Allows deduplication across scans without storing the raw secret.
    pub secret_hash: Option<String>,
}
