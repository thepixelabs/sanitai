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
    // v3 — track in-progress vs finalized scans so force-killed runs surface
    // in History instead of silently disappearing. `complete=1` means the
    // scan reached `finalize_scan` (whether it ended cleanly or via the
    // recovery sweep on next launch). `cancelled=1` means the user asked
    // for it to stop OR the recovery sweep flipped it from `complete=0`.
    // Existing rows default to `complete=1, cancelled=0` because everything
    // written under the old single-shot path is, by definition, complete.
    "ALTER TABLE scans ADD COLUMN complete INTEGER NOT NULL DEFAULT 1",
    "ALTER TABLE scans ADD COLUMN cancelled INTEGER NOT NULL DEFAULT 0",
    // Make `(scan_id, path)` unique so per-file commits can be re-applied
    // idempotently — we INSERT OR IGNORE on commit_file so the TUI can
    // record progress with an empty-findings call and then top up findings
    // at finalize time without duplicating path rows.
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_files_scan_path ON scan_files(scan_id, path)",
    "INSERT OR IGNORE INTO schema_version VALUES (3)",
    // v4 — persist enough finding metadata for the History → Results reload
    // path to reconstruct an actionable display row. We deliberately do NOT
    // store `matched_raw` (the secret value) — only the byte range, line
    // number, redacted excerpt, and 8-char fingerprint. Existing v3 rows
    // simply hold NULL in these columns; the reload code tolerates that.
    "ALTER TABLE findings ADD COLUMN line_in_file INTEGER",
    "ALTER TABLE findings ADD COLUMN fingerprint TEXT",
    "ALTER TABLE findings ADD COLUMN byte_start INTEGER",
    "ALTER TABLE findings ADD COLUMN byte_end INTEGER",
    "ALTER TABLE findings ADD COLUMN excerpt TEXT",
    "INSERT OR IGNORE INTO schema_version VALUES (4)",
];

/// Index (exclusive upper bound) of the last v1 migration entry in `MIGRATIONS`.
/// Entries `[0..MIGRATIONS_V1_END]` are v1; `[MIGRATIONS_V1_END..MIGRATIONS_V2_END]`
/// are v2; `[MIGRATIONS_V2_END..MIGRATIONS_V3_END]` are v3;
/// `[MIGRATIONS_V3_END..MIGRATIONS_V4_END]` are v4.
/// v1 has 9 entries: 3 CREATE TABLE + 4 CREATE INDEX + CREATE schema_version + INSERT.
pub const MIGRATIONS_V1_END: usize = 9;
/// v2 has 6 entries: 5 ALTER TABLE + INSERT.
pub const MIGRATIONS_V2_END: usize = MIGRATIONS_V1_END + 6;
/// v3 has 4 entries: 2 ALTER TABLE + 1 CREATE UNIQUE INDEX + INSERT.
pub const MIGRATIONS_V3_END: usize = MIGRATIONS_V2_END + 4;
/// v4 has 6 entries: 5 ALTER TABLE + INSERT.
pub const MIGRATIONS_V4_END: usize = MIGRATIONS_V3_END + 6;
