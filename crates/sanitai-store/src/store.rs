//! SQLite-backed append-only scan history store.

use std::cell::RefCell;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use tracing::debug;

use crate::error::StoreError;
use crate::models::{FindingRecord, ScanRecord};
use crate::schema::{
    MIGRATIONS, MIGRATIONS_V1_END, MIGRATIONS_V2_END, MIGRATIONS_V3_END, MIGRATIONS_V4_END,
};

// ---------------------------------------------------------------------------
// Installation key & secret hashing
// ---------------------------------------------------------------------------

/// Load the 32-byte per-install HMAC key, generating it on first use.
/// Stored at `~/.local/share/sanitai/install.key` with mode 0600.
/// Returns an empty slice as a last-resort fallback so that hashing never
/// blocks scan recording — callers should treat failure to read the key as
/// a warning condition, not an error.
#[allow(dead_code)] // Wired for Phase 1 (secret_hash dedupe); infra lives here now.
fn load_or_create_install_key() -> Vec<u8> {
    let Some(data_dir) = dirs_next::data_local_dir() else {
        tracing::warn!("no data_local_dir available; secret_hash will be unkeyed");
        return Vec::new();
    };
    let dir = data_dir.join("sanitai");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!("create data dir failed: {e}");
        return Vec::new();
    }
    let key_path = dir.join("install.key");
    if let Ok(bytes) = std::fs::read(&key_path) {
        if bytes.len() == 32 {
            return bytes;
        }
    }
    let mut key = vec![0u8; 32];
    if let Err(e) = getrandom::getrandom(&mut key) {
        tracing::warn!("getrandom failed: {e}; secret_hash will be unkeyed");
        return Vec::new();
    }
    if let Err(e) = std::fs::write(&key_path, &key) {
        tracing::warn!("install.key write failed: {e}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }
    key
}

#[allow(dead_code)] // Wired for Phase 1 (secret_hash dedupe); infra lives here now.
fn compute_secret_hash(secret: &str, installation_key: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(installation_key).expect("HMAC accepts any key length");
    mac.update(secret.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Aggregate totals across all recorded scans.
#[derive(Debug, Clone)]
pub struct StoreTotals {
    /// Total number of scans ever recorded.
    pub total_scans: i64,
    /// Scans that produced zero findings at any severity.
    pub clean_scans: i64,
    /// Sum of high-confidence findings across all scans.
    pub total_findings_high: i64,
    /// Sum of medium-confidence findings across all scans.
    pub total_findings_medium: i64,
    /// Sum of low-confidence findings across all scans.
    pub total_findings_low: i64,
}

// ---------------------------------------------------------------------------
// Incremental-write inputs
// ---------------------------------------------------------------------------

/// Metadata captured at the start of a scan, before any files are processed.
///
/// Lets `begin_scan` write a placeholder row immediately so a force-kill in
/// the middle of the run doesn't lose the fact that a scan was attempted at
/// all. The "running totals" fields (`duration_ms`, `total_turns`, finding
/// counts, `exit_code`) are written by `finalize_scan` once the scan ends.
#[derive(Debug, Clone)]
pub struct BeginScanRecord {
    /// ULID string — lexicographically sortable, globally unique.
    pub scan_id: String,
    /// Wall-clock start time as Unix nanoseconds.
    pub started_at_ns: i64,
    /// Optional project name derived from the scanned path or config.
    pub project_name: Option<String>,
    /// Optional Claude account identifier from the export file metadata.
    pub claude_account: Option<String>,
    /// Number of files the scanner intends to process. May be exceeded if
    /// the scanner discovers new files mid-run; finalize updates the total.
    pub total_files: i64,
    /// Output format used: "human", "json", "sarif", or "tui".
    pub format: String,
}

/// Final values captured at scan end, regardless of whether the scan
/// completed cleanly or was cancelled by the user.
#[derive(Debug, Clone)]
pub struct FinalizeScanInput {
    /// Wall-clock duration in milliseconds.
    pub duration_ms: i64,
    /// Total conversation turns processed.
    pub total_turns: i64,
    /// Process exit code (0 = clean, 1 = findings, 2+ = error).
    pub exit_code: i32,
    /// True if the user asked to cancel mid-scan, or if the recovery sweep
    /// promoted an `complete=0` row (process was killed).
    pub cancelled: bool,
}

/// Append-only SQLite-backed store for scan history.
///
/// Uses `RefCell<Connection>` internally so that all public methods can take
/// `&self` — appropriate for a single-threaded CLI tool.  The type is therefore
/// `!Sync`; do not share it across threads.
pub struct Store {
    conn: RefCell<Connection>,
}

impl Store {
    /// Open (or create) the store at `~/.local/share/sanitai/history.db`.
    ///
    /// Creates the directory if it does not exist and applies all migrations.
    pub fn open() -> Result<Self, StoreError> {
        let data_dir = dirs_next::data_local_dir()
            .ok_or(StoreError::NoDataDir)?
            .join("sanitai");
        std::fs::create_dir_all(&data_dir)?;
        Self::open_at(&data_dir.join("history.db"))
    }

    /// Open at an explicit path — primarily useful for tests and tooling.
    ///
    /// Enables WAL mode and foreign-key enforcement, then runs every migration
    /// statement in `MIGRATIONS` via `execute_batch`. After migrations apply,
    /// runs a one-shot recovery sweep that promotes any `complete=0` rows
    /// (force-killed scans from a prior run) to `complete=1, cancelled=1` so
    /// they surface in History.
    pub fn open_at(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;

        // Enable WAL for better write concurrency and crash safety.
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;
        // Enforce referential integrity.
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;

        // v1 migrations use `IF NOT EXISTS` / `INSERT OR IGNORE` so they are
        // idempotent and can run unconditionally.
        for sql in &MIGRATIONS[..MIGRATIONS_V1_END] {
            debug!(sql = *sql, "applying migration (v1)");
            conn.execute_batch(sql)?;
        }

        // `ALTER TABLE ADD COLUMN` has no `IF NOT EXISTS` in SQLite, so we
        // gate v2 / v3 on the recorded schema version.
        let current_version: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if current_version < 2 {
            for sql in &MIGRATIONS[MIGRATIONS_V1_END..MIGRATIONS_V2_END] {
                debug!(sql = *sql, "applying migration (v2)");
                conn.execute_batch(sql)?;
            }
        }
        if current_version < 3 {
            for sql in &MIGRATIONS[MIGRATIONS_V2_END..MIGRATIONS_V3_END] {
                debug!(sql = *sql, "applying migration (v3)");
                conn.execute_batch(sql)?;
            }
        }
        if current_version < 4 {
            for sql in &MIGRATIONS[MIGRATIONS_V3_END..MIGRATIONS_V4_END] {
                debug!(sql = *sql, "applying migration (v4)");
                conn.execute_batch(sql)?;
            }
        }

        // Recovery sweep: any scan still flagged `complete=0` was written by
        // `begin_scan` (or by `commit_file`) but never finalized — i.e. the
        // host process died. Promote those to `complete=1, cancelled=1` and
        // backfill duration_ms from wall-clock so History renders something
        // sensible. Do this once on every open; subsequent opens are no-ops.
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        conn.execute(
            "UPDATE scans
                SET complete = 1,
                    cancelled = 1,
                    duration_ms = MAX(duration_ms, (?1 - started_at_ns) / 1000000)
                WHERE complete = 0",
            params![now_ns],
        )?;

        Ok(Self {
            conn: RefCell::new(conn),
        })
    }

    /// Insert a placeholder `scans` row so an in-flight scan is visible in
    /// History the moment work starts. The row is created with `complete=0,
    /// cancelled=0, duration_ms=0` and zero findings; `finalize_scan` updates
    /// those fields once the scan ends.
    ///
    /// Idempotent on `scan_id` — re-issuing for the same id is a no-op.
    pub fn begin_scan(&self, rec: &BeginScanRecord) -> Result<(), StoreError> {
        self.conn.borrow().execute(
            "INSERT OR IGNORE INTO scans (
                scan_id, started_at_ns, duration_ms, project_name,
                claude_account, total_files, total_turns, format,
                exit_code, findings_high, findings_medium, findings_low,
                complete, cancelled
            ) VALUES (?1,?2,0,?3,?4,?5,0,?6,0,0,0,0,0,0)",
            params![
                rec.scan_id,
                rec.started_at_ns,
                rec.project_name,
                rec.claude_account,
                rec.total_files,
                rec.format,
            ],
        )?;
        Ok(())
    }

    /// Append a single file's findings (and the file path itself) to a scan
    /// already opened by `begin_scan`. Each call is its own transaction so a
    /// force-kill mid-scan still leaves committed rows for everything before
    /// it.
    ///
    /// `findings` may be empty — that's the expected shape for a TUI progress
    /// callback that only knows the path so far. The path insert uses
    /// `INSERT OR IGNORE` so a follow-up call with the same path (e.g. a
    /// finalize-time pass that supplies the actual findings) does not
    /// duplicate scan_files rows.
    pub fn commit_file(
        &self,
        scan_id: &str,
        file_path: &str,
        findings: &[FindingRecord],
    ) -> Result<(), StoreError> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction()?;

        tx.execute(
            "INSERT OR IGNORE INTO scan_files (scan_id, path) VALUES (?1, ?2)",
            params![scan_id, file_path],
        )?;

        for finding in findings {
            tx.execute(
                "INSERT INTO findings (
                    scan_id, detector_id, file_path, turn_idx,
                    confidence, transforms, synthetic,
                    role, category, entropy_score, context_class, secret_hash,
                    line_in_file, fingerprint, byte_start, byte_end, excerpt
                ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![
                    finding.scan_id,
                    finding.detector_id,
                    finding.file_path,
                    finding.turn_idx,
                    finding.confidence,
                    finding.transforms,
                    finding.synthetic as i64,
                    finding.role,
                    finding.category,
                    finding.entropy_score,
                    finding
                        .context_class
                        .clone()
                        .unwrap_or_else(|| "unclassified".to_owned()),
                    finding.secret_hash,
                    finding.line_in_file,
                    finding.fingerprint,
                    finding.byte_start,
                    finding.byte_end,
                    finding.excerpt,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Mark a scan complete. Updates `duration_ms`, `total_turns`,
    /// `exit_code`, `cancelled`, and re-derives the finding totals from the
    /// `findings` table so they always agree with what's actually persisted.
    /// Sets `complete=1` so the recovery sweep on the next `Store::open`
    /// leaves the row alone.
    ///
    /// Idempotent — re-calling for the same `scan_id` re-derives the totals
    /// from whatever's currently in the findings table. Useful if the caller
    /// wants to commit additional findings before declaring the scan done.
    pub fn finalize_scan(&self, scan_id: &str, fin: &FinalizeScanInput) -> Result<(), StoreError> {
        let conn = self.conn.borrow();

        let (h, m, l): (i64, i64, i64) = conn.query_row(
            "SELECT
                COALESCE(SUM(CASE WHEN confidence = 'high'   THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN confidence = 'medium' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN confidence = 'low'    THEN 1 ELSE 0 END), 0)
             FROM findings WHERE scan_id = ?1",
            params![scan_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;

        // Recompute total_files from the scan_files table for the same reason
        // we recompute findings — `commit_file` is the source of truth.
        let total_files: i64 = conn.query_row(
            "SELECT COUNT(*) FROM scan_files WHERE scan_id = ?1",
            params![scan_id],
            |r| r.get(0),
        )?;

        conn.execute(
            "UPDATE scans
                SET duration_ms     = ?1,
                    total_turns     = ?2,
                    exit_code       = ?3,
                    findings_high   = ?4,
                    findings_medium = ?5,
                    findings_low    = ?6,
                    total_files     = ?7,
                    complete        = 1,
                    cancelled       = ?8
              WHERE scan_id = ?9",
            params![
                fin.duration_ms,
                fin.total_turns,
                fin.exit_code,
                h,
                m,
                l,
                total_files,
                fin.cancelled as i64,
                scan_id,
            ],
        )?;
        Ok(())
    }

    /// Persist a completed scan together with its file list and findings.
    ///
    /// Back-compat wrapper that stitches `begin_scan` → `commit_file` (per
    /// path) → `finalize_scan` so callers still on the old single-shot API
    /// keep working. Prefer the per-file API for any new code path —
    /// incremental commits make in-progress scans visible in History even
    /// if the host process is killed before the scan ends.
    #[deprecated(note = "use begin_scan + commit_file + finalize_scan for per-file persistence")]
    pub fn record_scan(
        &self,
        scan: &ScanRecord,
        files: &[String],
        findings: &[FindingRecord],
    ) -> Result<(), StoreError> {
        self.begin_scan(&BeginScanRecord {
            scan_id: scan.scan_id.clone(),
            started_at_ns: scan.started_at_ns,
            project_name: scan.project_name.clone(),
            claude_account: scan.claude_account.clone(),
            total_files: scan.total_files,
            format: scan.format.clone(),
        })?;

        // Group findings by file_path so each file gets one commit_file call.
        // Files that appeared in `files` but produced no findings still need
        // their path row, so we walk both inputs.
        let mut by_path: std::collections::HashMap<&str, Vec<FindingRecord>> =
            std::collections::HashMap::new();
        for f in findings {
            by_path
                .entry(f.file_path.as_str())
                .or_default()
                .push(f.clone());
        }
        for path in files {
            let bucket = by_path.remove(path.as_str()).unwrap_or_default();
            self.commit_file(&scan.scan_id, path, &bucket)?;
        }
        // Any findings whose file_path wasn't in `files` (shouldn't happen,
        // but be defensive) still need to be persisted.
        for (path, bucket) in by_path {
            self.commit_file(&scan.scan_id, path, &bucket)?;
        }

        self.finalize_scan(
            &scan.scan_id,
            &FinalizeScanInput {
                duration_ms: scan.duration_ms,
                total_turns: scan.total_turns,
                exit_code: scan.exit_code,
                cancelled: false,
            },
        )?;
        Ok(())
    }

    /// Return the most recent `limit` scans, newest first.
    pub fn recent_scans(&self, limit: usize) -> Result<Vec<ScanRecord>, StoreError> {
        let conn = self.conn.borrow();
        let mut stmt = conn.prepare(
            "SELECT scan_id, started_at_ns, duration_ms, project_name,
                    claude_account, total_files, total_turns, format,
                    exit_code, findings_high, findings_medium, findings_low,
                    complete, cancelled
             FROM scans
             ORDER BY started_at_ns DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(ScanRecord {
                scan_id: row.get(0)?,
                started_at_ns: row.get(1)?,
                duration_ms: row.get(2)?,
                project_name: row.get(3)?,
                claude_account: row.get(4)?,
                total_files: row.get(5)?,
                total_turns: row.get(6)?,
                format: row.get(7)?,
                exit_code: row.get(8)?,
                findings_high: row.get(9)?,
                findings_medium: row.get(10)?,
                findings_low: row.get(11)?,
                complete: row.get::<_, i64>(12)? != 0,
                cancelled: row.get::<_, i64>(13)? != 0,
            })
        })?;

        let mut scans = Vec::new();
        for row in rows {
            scans.push(row?);
        }
        Ok(scans)
    }

    /// Return every `FindingRecord` for a scan, ordered by `detector_id`
    /// then `turn_idx` so the History → Results reload always renders the
    /// rows in the same order. Old v3 rows have `None` in the v4 columns
    /// (`line_in_file`, `fingerprint`, `byte_start`, `byte_end`, `excerpt`).
    pub fn findings_for_scan(&self, scan_id: &str) -> Result<Vec<FindingRecord>, StoreError> {
        let conn = self.conn.borrow();
        let mut stmt = conn.prepare(
            "SELECT scan_id, detector_id, file_path, turn_idx,
                    confidence, transforms, synthetic,
                    role, category, entropy_score, context_class, secret_hash,
                    line_in_file, fingerprint, byte_start, byte_end, excerpt
             FROM findings
             WHERE scan_id = ?1
             ORDER BY detector_id, turn_idx",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            Ok(FindingRecord {
                scan_id: row.get(0)?,
                detector_id: row.get(1)?,
                file_path: row.get(2)?,
                turn_idx: row.get(3)?,
                confidence: row.get(4)?,
                transforms: row.get(5)?,
                synthetic: row.get::<_, i64>(6)? != 0,
                role: row.get(7)?,
                category: row.get(8)?,
                entropy_score: row.get(9)?,
                context_class: row.get(10)?,
                secret_hash: row.get(11)?,
                line_in_file: row.get(12)?,
                fingerprint: row.get(13)?,
                byte_start: row.get(14)?,
                byte_end: row.get(15)?,
                excerpt: row.get(16)?,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Compute aggregate totals across all recorded scans.
    pub fn totals(&self) -> Result<StoreTotals, StoreError> {
        let conn = self.conn.borrow();
        let totals = conn.query_row(
            "SELECT
                COUNT(*),
                SUM(CASE WHEN findings_high + findings_medium + findings_low = 0 THEN 1 ELSE 0 END),
                COALESCE(SUM(findings_high),   0),
                COALESCE(SUM(findings_medium), 0),
                COALESCE(SUM(findings_low),    0)
             FROM scans",
            [],
            |row| {
                Ok(StoreTotals {
                    total_scans: row.get(0)?,
                    clean_scans: row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                    total_findings_high: row.get(2)?,
                    total_findings_medium: row.get(3)?,
                    total_findings_low: row.get(4)?,
                })
            },
        )?;
        Ok(totals)
    }

    /// Delete all scan history — used by the "reset stats" action in settings.
    ///
    /// Cascading deletes on `findings` and `scan_files` are handled by the
    /// `ON DELETE CASCADE` foreign-key constraints defined in the schema.
    pub fn clear_all(&self) -> Result<(), StoreError> {
        self.conn.borrow().execute_batch("DELETE FROM scans;")?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(deprecated)] // the back-compat tests intentionally exercise record_scan
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// Open a store backed by a fresh temporary file.
    ///
    /// `NamedTempFile` keeps the file alive for the duration of the test.
    /// Both are returned so the caller keeps the file alive for the test's
    /// duration — dropping `_f` would delete the underlying file.
    fn open_temp() -> (Store, NamedTempFile) {
        let f = NamedTempFile::new().unwrap();
        let store = Store::open_at(f.path()).unwrap();
        (store, f)
    }

    /// Minimal `ScanRecord` with deterministic fields.  `findings_high`,
    /// `findings_medium`, and `findings_low` default to 1, 2, 0 so that
    /// tests which need custom counts pass their own values directly.
    fn make_scan(id: &str, started_at_ns: i64) -> ScanRecord {
        ScanRecord {
            scan_id: id.to_string(),
            started_at_ns,
            duration_ms: 123,
            project_name: Some("test-project".to_string()),
            claude_account: Some("alice@example.com".to_string()),
            total_files: 5,
            total_turns: 42,
            format: "json".to_string(),
            exit_code: 1,
            findings_high: 1,
            findings_medium: 2,
            findings_low: 0,
            complete: true,
            cancelled: false,
        }
    }

    fn make_finding(scan_id: &str) -> FindingRecord {
        FindingRecord {
            scan_id: scan_id.to_string(),
            detector_id: "aws_access_key".to_string(),
            file_path: "chat_export.json".to_string(),
            turn_idx: 3,
            confidence: "high".to_string(),
            transforms: "[]".to_string(),
            synthetic: false,
            role: None,
            category: None,
            entropy_score: None,
            context_class: None,
            secret_hash: None,
            line_in_file: None,
            fingerprint: None,
            byte_start: None,
            byte_end: None,
            excerpt: None,
        }
    }

    /// Count rows in an arbitrary table via a raw SQL query.
    ///
    /// Only used in tests; accesses `store.conn` directly because tests live
    /// in the same module as the implementation.
    fn raw_count(store: &Store, table: &str) -> i64 {
        store
            .conn
            .borrow()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    // -------------------------------------------------------------------------
    // Existing tests — reviewed and hardened
    // -------------------------------------------------------------------------

    /// Every field on `ScanRecord` survives a write/read cycle.
    /// All inserted findings and files land in their respective tables.
    #[test]
    fn round_trip_scan_record() {
        let (store, _f) = open_temp();
        let scan = make_scan("01HXYZ001", 1_700_000_000_000_000_000);
        let files = vec![
            "export_part1.json".to_string(),
            "export_part2.json".to_string(),
        ];
        let findings = vec![
            FindingRecord {
                file_path: "export_part1.json".to_string(),
                ..make_finding("01HXYZ001")
            },
            FindingRecord {
                scan_id: "01HXYZ001".to_string(),
                detector_id: "github_pat".to_string(),
                file_path: "export_part2.json".to_string(),
                turn_idx: 7,
                confidence: "medium".to_string(),
                transforms: r#"["base64"]"#.to_string(),
                synthetic: true,
                role: None,
                category: None,
                entropy_score: None,
                context_class: None,
                secret_hash: None,
                line_in_file: None,
                fingerprint: None,
                byte_start: None,
                byte_end: None,
                excerpt: None,
            },
            FindingRecord {
                scan_id: "01HXYZ001".to_string(),
                detector_id: "jwt_token".to_string(),
                file_path: "export_part1.json".to_string(),
                turn_idx: 1,
                confidence: "low".to_string(),
                transforms: "[]".to_string(),
                synthetic: false,
                role: None,
                category: None,
                entropy_score: None,
                context_class: None,
                secret_hash: None,
                line_in_file: None,
                fingerprint: None,
                byte_start: None,
                byte_end: None,
                excerpt: None,
            },
        ];

        store.record_scan(&scan, &files, &findings).unwrap();

        // Verify every ScanRecord field survived the round-trip.
        let results = store.recent_scans(10).unwrap();
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.scan_id, "01HXYZ001");
        assert_eq!(r.started_at_ns, 1_700_000_000_000_000_000);
        assert_eq!(r.duration_ms, 123);
        assert_eq!(r.project_name.as_deref(), Some("test-project"));
        assert_eq!(r.claude_account.as_deref(), Some("alice@example.com"));
        assert_eq!(r.total_files, 2, "recomputed from scan_files at finalize");
        assert_eq!(r.total_turns, 42);
        assert_eq!(r.format, "json");
        assert_eq!(r.exit_code, 1);
        assert_eq!(r.findings_high, 1);
        assert_eq!(r.findings_medium, 1, "1 medium finding committed");
        assert_eq!(r.findings_low, 1, "1 low finding committed");
        assert!(r.complete);
        assert!(!r.cancelled);

        // Verify all findings and files were actually persisted — `recent_scans`
        // does not return them, so we check the raw tables.
        assert_eq!(
            raw_count(&store, "findings"),
            3,
            "all 3 FindingRecords should be in the findings table"
        );
        assert_eq!(
            raw_count(&store, "scan_files"),
            2,
            "both file paths should be in the scan_files table"
        );
    }

    #[test]
    fn totals_empty_db_returns_zeros() {
        let (store, _f) = open_temp();
        let t = store.totals().unwrap();
        assert_eq!(t.total_scans, 0);
        assert_eq!(t.clean_scans, 0);
        assert_eq!(t.total_findings_high, 0);
        assert_eq!(t.total_findings_medium, 0);
        assert_eq!(t.total_findings_low, 0);
    }

    /// `clear_all` empties the scans table and, through ON DELETE CASCADE,
    /// also empties findings and scan_files.
    #[test]
    fn clear_all_removes_everything() {
        let (store, _f) = open_temp();

        let scan = make_scan("01HXYZ002", 1_700_000_001_000_000_000);
        let files = vec!["chat_export.json".to_string()];
        let findings = vec![make_finding("01HXYZ002")];
        store.record_scan(&scan, &files, &findings).unwrap();

        // Sanity-check that all three tables were written.
        assert_eq!(raw_count(&store, "scans"), 1);
        assert_eq!(raw_count(&store, "scan_files"), 1);
        assert_eq!(raw_count(&store, "findings"), 1);

        store.clear_all().unwrap();

        // scans must be empty.
        let after = store.totals().unwrap();
        assert_eq!(after.total_scans, 0);
        assert!(store.recent_scans(10).unwrap().is_empty());

        // Cascade must have removed child rows — if foreign_keys pragma were
        // absent, these rows would silently survive.
        assert_eq!(
            raw_count(&store, "scan_files"),
            0,
            "ON DELETE CASCADE should have removed scan_files rows"
        );
        assert_eq!(
            raw_count(&store, "findings"),
            0,
            "ON DELETE CASCADE should have removed findings rows"
        );
    }

    #[test]
    fn recent_scans_newest_first() {
        let (store, _f) = open_temp();

        // Insert three scans with deliberately out-of-order timestamps.
        let oldest = make_scan("01HXYZ003", 1_000_000_000);
        let middle = make_scan("01HXYZ004", 2_000_000_000);
        let newest = make_scan("01HXYZ005", 3_000_000_000);

        store.record_scan(&oldest, &[], &[]).unwrap();
        store.record_scan(&newest, &[], &[]).unwrap();
        store.record_scan(&middle, &[], &[]).unwrap();

        let results = store.recent_scans(10).unwrap();
        assert_eq!(results.len(), 3);

        // Should be sorted descending by started_at_ns.
        assert_eq!(results[0].scan_id, "01HXYZ005");
        assert_eq!(results[1].scan_id, "01HXYZ004");
        assert_eq!(results[2].scan_id, "01HXYZ003");

        // Verify the limit parameter is respected.
        let top_two = store.recent_scans(2).unwrap();
        assert_eq!(top_two.len(), 2);
        assert_eq!(top_two[0].scan_id, "01HXYZ005");
        assert_eq!(top_two[1].scan_id, "01HXYZ004");
    }

    // -------------------------------------------------------------------------
    // New tests
    // -------------------------------------------------------------------------

    /// `record_scan` with empty file and finding slices must succeed.
    ///
    /// This is the "clean scan" path — a valid scan that found nothing.
    /// It is a distinct code path from a scan with findings (the for-loops
    /// in `record_scan` are simply skipped).
    #[test]
    fn record_scan_with_no_files_and_no_findings() {
        let (store, _f) = open_temp();
        let scan = ScanRecord {
            scan_id: "01HXYZ010".to_string(),
            started_at_ns: 1_700_000_010_000_000_000,
            duration_ms: 50,
            project_name: None,
            claude_account: None,
            total_files: 0,
            total_turns: 0,
            format: "human".to_string(),
            exit_code: 0,
            findings_high: 0,
            findings_medium: 0,
            findings_low: 0,
            complete: true,
            cancelled: false,
        };

        store.record_scan(&scan, &[], &[]).unwrap();

        let results = store.recent_scans(10).unwrap();
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.scan_id, "01HXYZ010");
        assert_eq!(r.project_name, None);
        assert_eq!(r.claude_account, None);
        assert_eq!(r.exit_code, 0);
        assert_eq!(raw_count(&store, "scan_files"), 0);
        assert_eq!(raw_count(&store, "findings"), 0);
    }

    /// `totals()` aggregates correctly across scans with mixed finding counts.
    ///
    /// - scan A: 0 findings (clean)
    /// - scan B: 2 HIGH only
    /// - scan C: 1 HIGH + 3 MEDIUM + 1 LOW
    ///
    /// Expected: total_scans=3, clean_scans=1, high=3, medium=3, low=1.
    #[test]
    fn totals_with_mixed_scans() {
        let (store, _f) = open_temp();

        let clean = ScanRecord {
            findings_high: 0,
            findings_medium: 0,
            findings_low: 0,
            ..make_scan("01HXYZ020", 1_000)
        };
        let high_only = ScanRecord {
            findings_high: 2,
            findings_medium: 0,
            findings_low: 0,
            ..make_scan("01HXYZ021", 2_000)
        };
        let mixed = ScanRecord {
            findings_high: 1,
            findings_medium: 3,
            findings_low: 1,
            ..make_scan("01HXYZ022", 3_000)
        };

        // Build matching findings so finalize_scan recomputes the same totals.
        let mk = |scan_id: &str, conf: &str| FindingRecord {
            scan_id: scan_id.to_string(),
            detector_id: "d".to_string(),
            file_path: "f.json".to_string(),
            turn_idx: 0,
            confidence: conf.to_string(),
            transforms: "[]".to_string(),
            synthetic: false,
            role: None,
            category: None,
            entropy_score: None,
            context_class: None,
            secret_hash: None,
            line_in_file: None,
            fingerprint: None,
            byte_start: None,
            byte_end: None,
            excerpt: None,
        };

        store.record_scan(&clean, &[], &[]).unwrap();
        store
            .record_scan(
                &high_only,
                &["f.json".to_string()],
                &[mk("01HXYZ021", "high"), mk("01HXYZ021", "high")],
            )
            .unwrap();
        store
            .record_scan(
                &mixed,
                &["f.json".to_string()],
                &[
                    mk("01HXYZ022", "high"),
                    mk("01HXYZ022", "medium"),
                    mk("01HXYZ022", "medium"),
                    mk("01HXYZ022", "medium"),
                    mk("01HXYZ022", "low"),
                ],
            )
            .unwrap();

        let t = store.totals().unwrap();
        assert_eq!(t.total_scans, 3);
        assert_eq!(
            t.clean_scans, 1,
            "only the scan with all-zero findings is clean"
        );
        assert_eq!(t.total_findings_high, 3, "2 + 1");
        assert_eq!(t.total_findings_medium, 3, "0 + 3");
        assert_eq!(t.total_findings_low, 1, "0 + 1");
    }

    /// Opening the same path twice must not fail.
    ///
    /// All migrations use `CREATE TABLE IF NOT EXISTS` / `INSERT OR IGNORE`, so
    /// they are idempotent.  A second `open_at` against an already-initialized
    /// file must succeed and produce a fully functional store.
    #[test]
    fn open_at_creates_schema_idempotently() {
        let f = NamedTempFile::new().unwrap();

        // First open — initialises schema.
        let store1 = Store::open_at(f.path()).unwrap();
        let scan = make_scan("01HXYZ030", 1_000);
        store1.record_scan(&scan, &[], &[]).unwrap();
        drop(store1);

        // Second open against the same file — must not return an error.
        let store2 = Store::open_at(f.path())
            .expect("second open_at on an already-migrated DB must succeed");

        // The data written by store1 must still be readable.
        let results = store2.recent_scans(10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].scan_id, "01HXYZ030");
    }

    /// ON DELETE CASCADE must propagate from `scans` to both `findings` and
    /// `scan_files`.  This test verifies the cascade by counting raw rows in
    /// both child tables after `clear_all()`.
    ///
    /// If `PRAGMA foreign_keys = ON` were absent from `open_at`, the DELETE
    /// would succeed (SQLite ignores FK constraints by default) but the child
    /// rows would survive — this test catches exactly that regression.
    #[test]
    fn foreign_key_cascade_on_clear() {
        let (store, _f) = open_temp();

        let scan = make_scan("01HXYZ040", 1_700_000_040_000_000_000);
        let files = vec!["a.json".to_string(), "b.json".to_string()];
        let findings = vec![
            FindingRecord {
                file_path: "a.json".to_string(),
                ..make_finding("01HXYZ040")
            },
            FindingRecord {
                scan_id: "01HXYZ040".to_string(),
                detector_id: "github_pat".to_string(),
                file_path: "b.json".to_string(),
                turn_idx: 2,
                confidence: "medium".to_string(),
                transforms: "[]".to_string(),
                synthetic: false,
                role: None,
                category: None,
                entropy_score: None,
                context_class: None,
                secret_hash: None,
                line_in_file: None,
                fingerprint: None,
                byte_start: None,
                byte_end: None,
                excerpt: None,
            },
        ];
        store.record_scan(&scan, &files, &findings).unwrap();

        // Pre-condition: child rows exist.
        assert_eq!(raw_count(&store, "scan_files"), 2);
        assert_eq!(raw_count(&store, "findings"), 2);

        store.clear_all().unwrap();

        // Post-condition: cascade must have deleted all child rows.
        assert_eq!(
            raw_count(&store, "scan_files"),
            0,
            "scan_files rows must be removed by ON DELETE CASCADE"
        );
        assert_eq!(
            raw_count(&store, "findings"),
            0,
            "findings rows must be removed by ON DELETE CASCADE"
        );
    }

    #[test]
    fn v2_migration_applies_to_fresh_db() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let _store = Store::open_at(&db_path).expect("open fresh db");
        // Verify v2 columns exist by inserting a row that uses them.
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute(
            "INSERT INTO scans (scan_id, started_at_ns) VALUES ('s1', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO findings (scan_id, detector_id, file_path, turn_idx, confidence, transforms, synthetic, context_class) \
             VALUES ('s1','d1','f1',0,'high','[]',0,'real_paste')",
            [],
        )
        .expect("v2 column context_class must exist");
    }

    #[test]
    fn v2_migration_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        Store::open_at(&db_path).expect("first open");
        Store::open_at(&db_path).expect("second open must not fail");
    }

    // -------------------------------------------------------------------------
    // v3 migration / incremental-write tests
    // -------------------------------------------------------------------------

    /// v2 → v3 upgrade: a database initialised under v2 must accept the v3
    /// migrations cleanly. We simulate "v2 only" by creating a fresh DB and
    /// running just the v1+v2 statements, then opening it normally and
    /// verifying both new columns are present.
    #[test]
    fn v3_migration_applies_to_v2_db() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("v2.db");

        // Hand-roll a v2-only DB.
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
            for sql in &MIGRATIONS[..MIGRATIONS_V2_END] {
                conn.execute_batch(sql).unwrap();
            }
            // Insert a row in the v2 shape (no `complete`, no `cancelled`).
            conn.execute(
                "INSERT INTO scans (scan_id, started_at_ns) VALUES ('legacy', 1)",
                [],
            )
            .unwrap();
        }

        // Open normally — v3 migrations should apply on top of the v2 schema.
        let store = Store::open_at(&db_path).expect("v3 should apply to a v2 db");

        // Existing v2 row must default to complete=1, cancelled=0 per the
        // migration's NOT NULL DEFAULT.
        let recs = store.recent_scans(10).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].scan_id, "legacy");
        assert!(recs[0].complete, "legacy v2 rows default to complete=1");
        assert!(!recs[0].cancelled, "legacy v2 rows default to cancelled=0");
    }

    /// `commit_file` is independent: a force-drop of the Store after two
    /// commits — without a `finalize_scan` call — must leave both findings
    /// and both path rows readable from a fresh reopen of the DB.
    #[test]
    fn commit_file_persists_independently_across_drop() {
        let f = NamedTempFile::new().unwrap();
        let scan_id = "01HXYZ_KILLED".to_owned();

        // First "process" — begin + 2 commits, then drop without finalize.
        {
            let store = Store::open_at(f.path()).unwrap();
            store
                .begin_scan(&BeginScanRecord {
                    scan_id: scan_id.clone(),
                    started_at_ns: 100,
                    project_name: Some("p".to_owned()),
                    claude_account: None,
                    total_files: 2,
                    format: "tui".to_owned(),
                })
                .unwrap();

            let mk = |path: &str| FindingRecord {
                scan_id: scan_id.clone(),
                detector_id: "aws_key".to_string(),
                file_path: path.to_string(),
                turn_idx: 0,
                confidence: "high".to_string(),
                transforms: "[]".to_string(),
                synthetic: false,
                role: None,
                category: None,
                entropy_score: None,
                context_class: None,
                secret_hash: None,
                line_in_file: None,
                fingerprint: None,
                byte_start: None,
                byte_end: None,
                excerpt: None,
            };

            store
                .commit_file(&scan_id, "a.json", &[mk("a.json")])
                .unwrap();
            store
                .commit_file(&scan_id, "b.json", &[mk("b.json")])
                .unwrap();
            // No finalize_scan — simulates a force-kill.
            drop(store);
        }

        // Second "process" — reopen and verify everything committed survived.
        let store = Store::open_at(f.path()).unwrap();
        assert_eq!(raw_count(&store, "scan_files"), 2);
        assert_eq!(raw_count(&store, "findings"), 2);
    }

    /// The recovery sweep on `Store::open` must promote any `complete=0`
    /// row to `complete=1, cancelled=1` and backfill duration_ms from
    /// wall clock. This is the central recovery story for force-killed
    /// scans: the next launch surfaces them in History as cancelled.
    #[test]
    fn recovery_sweep_marks_killed_scans_cancelled() {
        let f = NamedTempFile::new().unwrap();
        let scan_id = "01HXYZ_RECOVER".to_owned();
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64
            - 5_000_000_000; // 5 seconds ago in ns

        // First "process": insert an in-progress scan with two committed
        // files, then drop the Store without finalizing.
        {
            let store = Store::open_at(f.path()).unwrap();
            store
                .begin_scan(&BeginScanRecord {
                    scan_id: scan_id.clone(),
                    started_at_ns: started,
                    project_name: Some("recover-me".to_owned()),
                    claude_account: None,
                    total_files: 9_999,
                    format: "tui".to_owned(),
                })
                .unwrap();

            let mk = |path: &str, conf: &str| FindingRecord {
                scan_id: scan_id.clone(),
                detector_id: "aws_key".to_string(),
                file_path: path.to_string(),
                turn_idx: 0,
                confidence: conf.to_string(),
                transforms: "[]".to_string(),
                synthetic: false,
                role: None,
                category: None,
                entropy_score: None,
                context_class: None,
                secret_hash: None,
                line_in_file: None,
                fingerprint: None,
                byte_start: None,
                byte_end: None,
                excerpt: None,
            };
            store
                .commit_file(&scan_id, "a.json", &[mk("a.json", "high")])
                .unwrap();
            store
                .commit_file(&scan_id, "b.json", &[mk("b.json", "medium")])
                .unwrap();
            drop(store);
        }

        // Second "process": reopen — the sweep should run.
        let store = Store::open_at(f.path()).unwrap();
        let recs = store.recent_scans(10).unwrap();
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.scan_id, scan_id);
        assert!(r.complete, "recovery sweep promotes complete=0 to 1");
        assert!(r.cancelled, "recovery sweep marks the row cancelled");
        assert!(
            r.duration_ms >= 4_000,
            "duration was backfilled from wall-clock (~5s); got {}",
            r.duration_ms
        );

        // The two committed findings + their path rows must still be queryable.
        assert_eq!(raw_count(&store, "findings"), 2);
        assert_eq!(raw_count(&store, "scan_files"), 2);
    }

    /// The recovery sweep must NOT touch already-finalized rows.
    #[test]
    fn recovery_sweep_leaves_finalized_rows_alone() {
        let f = NamedTempFile::new().unwrap();
        {
            let store = Store::open_at(f.path()).unwrap();
            store
                .begin_scan(&BeginScanRecord {
                    scan_id: "done".to_owned(),
                    started_at_ns: 1_000,
                    project_name: None,
                    claude_account: None,
                    total_files: 0,
                    format: "tui".to_owned(),
                })
                .unwrap();
            store
                .finalize_scan(
                    "done",
                    &FinalizeScanInput {
                        duration_ms: 42,
                        total_turns: 0,
                        exit_code: 0,
                        cancelled: false,
                    },
                )
                .unwrap();
        }

        let store = Store::open_at(f.path()).unwrap();
        let r = &store.recent_scans(10).unwrap()[0];
        assert!(r.complete);
        assert!(!r.cancelled, "finalized rows remain not-cancelled");
        assert_eq!(r.duration_ms, 42, "duration_ms preserved");
    }

    /// Calling `commit_file` twice for the same path with different findings
    /// must not duplicate the scan_files row, but both finding sets must be
    /// recorded. This is what lets the TUI record progress with empty
    /// findings on FileDone, then top up the findings at finalize time.
    #[test]
    fn commit_file_path_is_idempotent_findings_accumulate() {
        let (store, _f) = open_temp();
        store
            .begin_scan(&BeginScanRecord {
                scan_id: "s".to_owned(),
                started_at_ns: 0,
                project_name: None,
                claude_account: None,
                total_files: 1,
                format: "tui".to_owned(),
            })
            .unwrap();

        let mk = |conf: &str| FindingRecord {
            scan_id: "s".to_owned(),
            detector_id: "d".to_owned(),
            file_path: "p".to_owned(),
            turn_idx: 0,
            confidence: conf.to_owned(),
            transforms: "[]".to_owned(),
            synthetic: false,
            role: None,
            category: None,
            entropy_score: None,
            context_class: None,
            secret_hash: None,
            line_in_file: None,
            fingerprint: None,
            byte_start: None,
            byte_end: None,
            excerpt: None,
        };

        // First call records the path with no findings (simulating TUI
        // FileDone progress callback).
        store.commit_file("s", "p", &[]).unwrap();
        // Second call with findings (simulating TUI finalize-time top-up).
        store
            .commit_file("s", "p", &[mk("high"), mk("medium")])
            .unwrap();

        assert_eq!(
            raw_count(&store, "scan_files"),
            1,
            "path row not duplicated"
        );
        assert_eq!(raw_count(&store, "findings"), 2, "both findings recorded");
    }

    /// `finalize_scan` recomputes finding totals from the findings table.
    /// Anything already committed via `commit_file` must show up in the
    /// finalized record's high/medium/low counts.
    #[test]
    fn finalize_scan_recomputes_totals_from_committed_findings() {
        let (store, _f) = open_temp();
        store
            .begin_scan(&BeginScanRecord {
                scan_id: "s".to_owned(),
                started_at_ns: 0,
                project_name: None,
                claude_account: None,
                total_files: 1,
                format: "tui".to_owned(),
            })
            .unwrap();

        let mk = |conf: &str| FindingRecord {
            scan_id: "s".to_owned(),
            detector_id: "d".to_owned(),
            file_path: "p".to_owned(),
            turn_idx: 0,
            confidence: conf.to_owned(),
            transforms: "[]".to_owned(),
            synthetic: false,
            role: None,
            category: None,
            entropy_score: None,
            context_class: None,
            secret_hash: None,
            line_in_file: None,
            fingerprint: None,
            byte_start: None,
            byte_end: None,
            excerpt: None,
        };

        store
            .commit_file("s", "p", &[mk("high"), mk("high"), mk("medium"), mk("low")])
            .unwrap();
        store
            .finalize_scan(
                "s",
                &FinalizeScanInput {
                    duration_ms: 1,
                    total_turns: 0,
                    exit_code: 0,
                    cancelled: false,
                },
            )
            .unwrap();

        let r = &store.recent_scans(10).unwrap()[0];
        assert_eq!(r.findings_high, 2);
        assert_eq!(r.findings_medium, 1);
        assert_eq!(r.findings_low, 1);
        assert_eq!(r.total_files, 1);
        assert!(r.complete);
        assert!(!r.cancelled);
    }

    // -------------------------------------------------------------------------
    // v4 migration / new field plumbing tests
    // -------------------------------------------------------------------------

    /// Tuple shape for the five v4 columns the migration / round-trip
    /// tests query in one shot. Aliased so each query site doesn't trip
    /// clippy::type_complexity at the call expression.
    type V4Cols = (
        Option<i64>,
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<String>,
    );

    /// Opening a v3-only DB with `Store::open_at` must apply the v4 schema
    /// changes: every new findings column exists, and a row written under
    /// the v3 schema survives intact with NULLs in the v4 columns.
    #[test]
    fn v4_migration_applies_to_v3_db() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("v3.db");

        // Hand-roll a v3-only DB by running v1+v2+v3 migrations directly.
        // We seed one scans row and one findings row using the v3 column
        // set so we can prove the v4 ALTER doesn't disturb existing data.
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
            for sql in &MIGRATIONS[..MIGRATIONS_V3_END] {
                conn.execute_batch(sql).unwrap();
            }
            conn.execute(
                "INSERT INTO scans (scan_id, started_at_ns) VALUES ('legacy', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO findings (scan_id, detector_id, file_path, turn_idx, confidence, transforms, synthetic) \
                 VALUES ('legacy','d','f',0,'high','[]',0)",
                [],
            )
            .unwrap();
        }

        // Open via the public API — v4 should apply on top.
        let _store = Store::open_at(&db_path).expect("v4 should apply to a v3 db");

        // Reopen a raw connection so we can inspect PRAGMA table_info(findings)
        // and the legacy row's v4 columns.
        let conn = Connection::open(&db_path).unwrap();
        let mut stmt = conn.prepare("PRAGMA table_info(findings)").unwrap();
        let cols: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        for expected in [
            "line_in_file",
            "fingerprint",
            "byte_start",
            "byte_end",
            "excerpt",
        ] {
            assert!(
                cols.iter().any(|c| c == expected),
                "v4 column {expected} must exist after migration; got cols={cols:?}",
            );
        }

        // The legacy v3 row must still be there, with NULLs in the v4 columns.
        let (line, fp, bs, be, ex): V4Cols = conn
            .query_row(
                "SELECT line_in_file, fingerprint, byte_start, byte_end, excerpt
                 FROM findings WHERE scan_id = 'legacy'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert!(line.is_none(), "legacy v3 row has NULL line_in_file");
        assert!(fp.is_none(), "legacy v3 row has NULL fingerprint");
        assert!(bs.is_none(), "legacy v3 row has NULL byte_start");
        assert!(be.is_none(), "legacy v3 row has NULL byte_end");
        assert!(ex.is_none(), "legacy v3 row has NULL excerpt");
    }

    /// Round-trip every v4 column through `commit_file`. Build a record
    /// with all five new fields populated, commit it, and verify the
    /// values land verbatim by querying via raw SQL.
    #[test]
    fn commit_file_persists_v4_fields_round_trip() {
        let (store, _f) = open_temp();
        store
            .begin_scan(&BeginScanRecord {
                scan_id: "v4".to_owned(),
                started_at_ns: 0,
                project_name: None,
                claude_account: None,
                total_files: 1,
                format: "tui".to_owned(),
            })
            .unwrap();

        let rec = FindingRecord {
            scan_id: "v4".to_owned(),
            detector_id: "aws_access_key".to_owned(),
            file_path: "p".to_owned(),
            turn_idx: 7,
            confidence: "high".to_owned(),
            transforms: "[]".to_owned(),
            synthetic: false,
            role: Some("user".to_owned()),
            category: Some("secret".to_owned()),
            entropy_score: Some(4.5),
            context_class: Some("real_paste".to_owned()),
            secret_hash: None,
            line_in_file: Some(42),
            fingerprint: Some("deadbeef".to_owned()),
            byte_start: Some(12),
            byte_end: Some(32),
            excerpt: Some("before [FP:deadbeef] after".to_owned()),
        };

        store.commit_file("v4", "p", &[rec]).unwrap();

        let conn = store.conn.borrow();
        let (line, fp, bs, be, ex): V4Cols = conn
            .query_row(
                "SELECT line_in_file, fingerprint, byte_start, byte_end, excerpt
                 FROM findings WHERE scan_id = 'v4'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(line, Some(42));
        assert_eq!(fp.as_deref(), Some("deadbeef"));
        assert_eq!(bs, Some(12));
        assert_eq!(be, Some(32));
        assert_eq!(ex.as_deref(), Some("before [FP:deadbeef] after"));
    }

    /// `findings_for_scan` returns rows in stable order, sorted by
    /// `detector_id` then `turn_idx`, so the History reload renders
    /// the same way every time. We commit findings in deliberately
    /// scrambled insertion order and assert the read order is sorted.
    #[test]
    fn findings_for_scan_returns_stable_order() {
        let (store, _f) = open_temp();
        store
            .begin_scan(&BeginScanRecord {
                scan_id: "s".to_owned(),
                started_at_ns: 0,
                project_name: None,
                claude_account: None,
                total_files: 1,
                format: "tui".to_owned(),
            })
            .unwrap();

        let mk = |det: &str, turn: i64| FindingRecord {
            scan_id: "s".to_owned(),
            detector_id: det.to_owned(),
            file_path: "p".to_owned(),
            turn_idx: turn,
            confidence: "high".to_owned(),
            transforms: "[]".to_owned(),
            synthetic: false,
            role: None,
            category: None,
            entropy_score: None,
            context_class: None,
            secret_hash: None,
            line_in_file: None,
            fingerprint: None,
            byte_start: None,
            byte_end: None,
            excerpt: None,
        };

        // Scrambled insertion order across detector_ids and turn_idx.
        store
            .commit_file(
                "s",
                "p",
                &[
                    mk("zeta", 2),
                    mk("alpha", 5),
                    mk("alpha", 1),
                    mk("mu", 3),
                    mk("alpha", 3),
                ],
            )
            .unwrap();

        // Two consecutive reads must produce the same ordering.
        let first = store.findings_for_scan("s").unwrap();
        let second = store.findings_for_scan("s").unwrap();
        assert_eq!(first.len(), 5);
        let order: Vec<(String, i64)> = first
            .iter()
            .map(|r| (r.detector_id.clone(), r.turn_idx))
            .collect();
        assert_eq!(
            order,
            vec![
                ("alpha".to_owned(), 1),
                ("alpha".to_owned(), 3),
                ("alpha".to_owned(), 5),
                ("mu".to_owned(), 3),
                ("zeta".to_owned(), 2),
            ],
            "findings_for_scan must sort by detector_id then turn_idx",
        );
        let order2: Vec<(String, i64)> = second
            .iter()
            .map(|r| (r.detector_id.clone(), r.turn_idx))
            .collect();
        assert_eq!(order, order2, "ordering must be stable across calls");
    }
}
