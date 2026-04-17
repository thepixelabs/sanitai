//! SQLite-backed append-only scan history store.

use std::cell::RefCell;
use std::path::Path;

use rusqlite::{params, Connection};
use tracing::debug;

use crate::error::StoreError;
use crate::models::{FindingRecord, ScanRecord};
use crate::schema::{MIGRATIONS, MIGRATIONS_V1_END};

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
    /// statement in `MIGRATIONS` via `execute_batch`.
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
        // gate v2 on the recorded schema version.
        let current_version: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if current_version < 2 {
            for sql in &MIGRATIONS[MIGRATIONS_V1_END..] {
                debug!(sql = *sql, "applying migration (v2)");
                conn.execute_batch(sql)?;
            }
        }

        Ok(Self {
            conn: RefCell::new(conn),
        })
    }

    /// Persist a completed scan together with its file list and findings.
    ///
    /// All three writes happen inside a single transaction so the database
    /// is never left in a partially-written state.  The caller should treat
    /// a returned error as non-fatal and log it rather than aborting the
    /// scan result.
    pub fn record_scan(
        &self,
        scan: &ScanRecord,
        files: &[String],
        findings: &[FindingRecord],
    ) -> Result<(), StoreError> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction()?;

        tx.execute(
            "INSERT INTO scans (
                scan_id, started_at_ns, duration_ms, project_name,
                claude_account, total_files, total_turns, format,
                exit_code, findings_high, findings_medium, findings_low
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                scan.scan_id,
                scan.started_at_ns,
                scan.duration_ms,
                scan.project_name,
                scan.claude_account,
                scan.total_files,
                scan.total_turns,
                scan.format,
                scan.exit_code,
                scan.findings_high,
                scan.findings_medium,
                scan.findings_low,
            ],
        )?;

        for file in files {
            tx.execute(
                "INSERT INTO scan_files (scan_id, path) VALUES (?1, ?2)",
                params![scan.scan_id, file],
            )?;
        }

        for finding in findings {
            tx.execute(
                "INSERT INTO findings (
                    scan_id, detector_id, file_path, turn_idx,
                    confidence, transforms, synthetic,
                    role, category, entropy_score, context_class, secret_hash
                ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
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
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Return the most recent `limit` scans, newest first.
    pub fn recent_scans(&self, limit: usize) -> Result<Vec<ScanRecord>, StoreError> {
        let conn = self.conn.borrow();
        let mut stmt = conn.prepare(
            "SELECT scan_id, started_at_ns, duration_ms, project_name,
                    claude_account, total_files, total_turns, format,
                    exit_code, findings_high, findings_medium, findings_low
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
            })
        })?;

        let mut scans = Vec::new();
        for row in rows {
            scans.push(row?);
        }
        Ok(scans)
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
            make_finding("01HXYZ001"),
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
        assert_eq!(r.total_files, 5);
        assert_eq!(r.total_turns, 42);
        assert_eq!(r.format, "json");
        assert_eq!(r.exit_code, 1);
        assert_eq!(r.findings_high, 1);
        assert_eq!(r.findings_medium, 2);
        assert_eq!(r.findings_low, 0);

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
        let files = vec!["export.json".to_string()];
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

        store.record_scan(&clean, &[], &[]).unwrap();
        store.record_scan(&high_only, &[], &[]).unwrap();
        store.record_scan(&mixed, &[], &[]).unwrap();

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
            make_finding("01HXYZ040"),
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
}
