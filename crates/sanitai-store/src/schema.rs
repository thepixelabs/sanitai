//! SQL migration strings applied in order on every `Store::open_at` call.
//!
//! Every statement uses `IF NOT EXISTS` / `INSERT OR IGNORE` so they are
//! idempotent — safe to re-run against an already-initialized database.

/// Ordered list of DDL statements that constitute the full schema history.
/// Each entry is applied via `execute_batch` in a single call so SQLite
/// treats each statement as its own implicit transaction.
pub const MIGRATIONS: &[&str] = &[
    // v1 — initial schema
    "CREATE TABLE IF NOT EXISTS scans (
        scan_id         TEXT PRIMARY KEY,
        started_at_ns   INTEGER NOT NULL,
        duration_ms     INTEGER NOT NULL DEFAULT 0,
        project_name    TEXT,
        claude_account  TEXT,
        total_files     INTEGER NOT NULL DEFAULT 0,
        total_turns     INTEGER NOT NULL DEFAULT 0,
        format          TEXT NOT NULL DEFAULT 'human',
        exit_code       INTEGER NOT NULL DEFAULT 0,
        findings_high   INTEGER NOT NULL DEFAULT 0,
        findings_medium INTEGER NOT NULL DEFAULT 0,
        findings_low    INTEGER NOT NULL DEFAULT 0
    )",
    "CREATE TABLE IF NOT EXISTS scan_files (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id  TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
        path     TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS findings (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id     TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
        detector_id TEXT NOT NULL,
        file_path   TEXT NOT NULL,
        turn_idx    INTEGER NOT NULL DEFAULT 0,
        confidence  TEXT NOT NULL,
        transforms  TEXT NOT NULL DEFAULT '[]',
        synthetic   INTEGER NOT NULL DEFAULT 0
    )",
    "CREATE INDEX IF NOT EXISTS idx_scans_started     ON scans(started_at_ns DESC)",
    "CREATE INDEX IF NOT EXISTS idx_findings_scan     ON findings(scan_id)",
    "CREATE INDEX IF NOT EXISTS idx_scan_files_scan   ON scan_files(scan_id)",
    "CREATE INDEX IF NOT EXISTS idx_findings_detector ON findings(detector_id)",
    // schema_version tracks how many migrations have run
    "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
    "INSERT OR IGNORE INTO schema_version VALUES (1)",
    // v2 — enrich findings with role, category, entropy, context classification
    "ALTER TABLE findings ADD COLUMN role TEXT",
    "ALTER TABLE findings ADD COLUMN category TEXT",
    "ALTER TABLE findings ADD COLUMN entropy_score REAL",
    "ALTER TABLE findings ADD COLUMN context_class TEXT NOT NULL DEFAULT 'unclassified'",
    "ALTER TABLE findings ADD COLUMN secret_hash TEXT",
    "INSERT OR IGNORE INTO schema_version VALUES (2)",
];

/// Index (exclusive upper bound) of the last v1 migration entry in `MIGRATIONS`.
/// Entries `[0..MIGRATIONS_V1_END]` are v1; `[MIGRATIONS_V1_END..]` are v2.
/// v1 has 9 entries: 3 CREATE TABLE + 4 CREATE INDEX + CREATE schema_version + INSERT.
pub const MIGRATIONS_V1_END: usize = 9;
