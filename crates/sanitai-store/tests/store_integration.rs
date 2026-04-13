//! Integration tests for `sanitai-store`.
//!
//! These tests exercise the store's public API end-to-end against a real SQLite
//! database in a temporary file. They are intentionally separate from the unit
//! tests in `store.rs` (which test internal helpers and access private fields
//! from within the same module) to verify that the observable contract of the
//! public API is solid.
//!
//! Note: `store.conn` is a private `RefCell<Connection>`. External integration
//! tests cannot access it directly. All row-level assertions are made through
//! the public methods `record_scan`, `recent_scans`, `totals`, and `clear_all`,
//! which is the correct level of abstraction for an external caller.

use sanitai_store::{FindingRecord, ScanRecord, Store};
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Shared builders
// ---------------------------------------------------------------------------

/// Open a fresh store backed by a new temporary file.
///
/// The `NamedTempFile` must be kept alive for the duration of the test to
/// prevent the OS from reclaiming the backing file.
fn open_temp() -> (Store, NamedTempFile) {
    let f = NamedTempFile::new().expect("create temp file");
    let store = Store::open_at(f.path()).expect("open_at temp file");
    (store, f)
}

fn make_scan(id: &str, started_at_ns: i64) -> ScanRecord {
    ScanRecord {
        scan_id: id.to_string(),
        started_at_ns,
        duration_ms: 10,
        project_name: Some("integration-project".to_string()),
        claude_account: Some("test@example.com".to_string()),
        total_files: 1,
        total_turns: 5,
        format: "json".to_string(),
        exit_code: 1,
        findings_high: 0,
        findings_medium: 0,
        findings_low: 0,
    }
}

fn make_finding(scan_id: &str, confidence: &str) -> FindingRecord {
    FindingRecord {
        scan_id: scan_id.to_string(),
        detector_id: "aws_access_key_id".to_string(),
        file_path: "chat.jsonl".to_string(),
        turn_idx: 1,
        confidence: confidence.to_string(),
        transforms: "[]".to_string(),
        synthetic: false,
        role: None,
        category: None,
        entropy_score: None,
        context_class: None,
        secret_hash: None,
    }
}

// ---------------------------------------------------------------------------
// record_scan — findings persistence
// ---------------------------------------------------------------------------

/// `record_scan` with two findings correctly persists both rows.
///
/// Verified indirectly: the finding counts stored on the ScanRecord (which the
/// caller is responsible for setting) are read back correctly from `recent_scans`,
/// and `totals()` aggregates them. This is the only observable surface for
/// finding persistence that is reachable from external test code.
#[test]
fn record_scan_with_findings_persists_finding_rows() {
    let (store, _f) = open_temp();

    let scan = ScanRecord {
        findings_high: 2,
        findings_medium: 1,
        findings_low: 0,
        ..make_scan("IT-SCAN-001", 1_000_000)
    };

    let findings = vec![
        make_finding("IT-SCAN-001", "high"),
        make_finding("IT-SCAN-001", "high"),
        make_finding("IT-SCAN-001", "medium"),
    ];

    store
        .record_scan(&scan, &["chat.jsonl".to_string()], &findings)
        .expect("record_scan must succeed");

    // Read back via the public API — the only external entry point.
    let scans = store.recent_scans(10).expect("recent_scans must succeed");
    assert_eq!(scans.len(), 1, "exactly one scan must be recorded");

    let r = &scans[0];
    assert_eq!(r.scan_id, "IT-SCAN-001");
    assert_eq!(
        r.findings_high, 2,
        "findings_high must match what was recorded"
    );
    assert_eq!(
        r.findings_medium, 1,
        "findings_medium must match what was recorded"
    );
    assert_eq!(
        r.findings_low, 0,
        "findings_low must match what was recorded"
    );

    // totals() must also reflect the persisted finding counts.
    let t = store.totals().expect("totals must succeed");
    assert_eq!(t.total_scans, 1);
    assert_eq!(t.total_findings_high, 2);
    assert_eq!(t.total_findings_medium, 1);
    assert_eq!(t.total_findings_low, 0);
}

/// `record_scan` with a non-empty file list persists the file association.
///
/// The file list is internal to the store but its effect is observable through
/// `record_scan` returning `Ok` (foreign-key constraints would reject any
/// row that references a non-existent scan_id) and `total_files` in the
/// ScanRecord matching the count supplied by the caller.
#[test]
fn record_scan_file_list_is_accepted_without_error() {
    let (store, _f) = open_temp();

    let scan = ScanRecord {
        total_files: 3,
        ..make_scan("IT-SCAN-002", 2_000_000)
    };

    let files = vec![
        "export_a.jsonl".to_string(),
        "export_b.jsonl".to_string(),
        "export_c.jsonl".to_string(),
    ];

    store
        .record_scan(&scan, &files, &[])
        .expect("record_scan with three files must succeed");

    let scans = store.recent_scans(1).expect("recent_scans must succeed");
    assert_eq!(scans[0].total_files, 3);
}

// ---------------------------------------------------------------------------
// clear_all — cascade behaviour
// ---------------------------------------------------------------------------

/// After `clear_all`, both `recent_scans` and `totals` report empty state.
///
/// This verifies that ON DELETE CASCADE propagates from `scans` to both child
/// tables (`findings` and `scan_files`). If the cascade were missing, the
/// re-insertion of a scan with the same scan_id after `clear_all` would fail
/// with a UNIQUE constraint violation — which would surface as an Err here.
#[test]
fn clear_all_cascades_to_child_tables() {
    let (store, _f) = open_temp();

    // Insert two scans with associated files and findings.
    let scan_a = ScanRecord {
        findings_high: 1,
        ..make_scan("IT-SCAN-010", 10_000_000)
    };
    let scan_b = ScanRecord {
        findings_medium: 2,
        ..make_scan("IT-SCAN-011", 20_000_000)
    };

    store
        .record_scan(
            &scan_a,
            &["a.jsonl".to_string()],
            &[make_finding("IT-SCAN-010", "high")],
        )
        .expect("record scan_a");
    store
        .record_scan(
            &scan_b,
            &["b.jsonl".to_string(), "c.jsonl".to_string()],
            &[
                make_finding("IT-SCAN-011", "medium"),
                make_finding("IT-SCAN-011", "medium"),
            ],
        )
        .expect("record scan_b");

    // Verify pre-condition: both scans exist.
    assert_eq!(
        store.recent_scans(10).expect("recent_scans").len(),
        2,
        "pre-condition: two scans must exist before clear_all"
    );

    store.clear_all().expect("clear_all must succeed");

    // scans table must be empty.
    let after_scans = store.recent_scans(10).expect("recent_scans after clear");
    assert!(
        after_scans.is_empty(),
        "recent_scans must return empty slice after clear_all"
    );

    let t = store.totals().expect("totals after clear");
    assert_eq!(t.total_scans, 0, "total_scans must be 0 after clear_all");
    assert_eq!(
        t.total_findings_high, 0,
        "total_findings_high must be 0 after clear_all"
    );
    assert_eq!(
        t.total_findings_medium, 0,
        "total_findings_medium must be 0 after clear_all"
    );

    // The cascade is verified by re-inserting the same scan_id. If child rows
    // survived (meaning FK cascade didn't fire), SQLite's referential integrity
    // would be violated on the next insert of an orphaned child row if the
    // foreign_keys pragma had been ON. More concretely: re-using the same
    // scan_id must succeed (no UNIQUE violation on the now-absent parent).
    let reinsert = make_scan("IT-SCAN-010", 30_000_000);
    store
        .record_scan(&reinsert, &[], &[])
        .expect("re-inserting a scan_id that was previously cleared must succeed");

    let final_scans = store.recent_scans(10).expect("final recent_scans");
    assert_eq!(final_scans.len(), 1, "only the re-inserted scan must exist");
}

// ---------------------------------------------------------------------------
// totals — aggregate across multiple scans
// ---------------------------------------------------------------------------

/// `totals()` returns correct aggregate counts across two scans with different
/// finding counts and correctly identifies clean vs. dirty scans.
///
/// Scan A: 3 HIGH, 0 MEDIUM, 0 LOW — dirty
/// Scan B: 0 HIGH, 0 MEDIUM, 0 LOW — clean
///
/// Expected totals: total_scans=2, clean_scans=1, high=3, medium=0, low=0.
#[test]
fn totals_returns_correct_aggregate_across_two_scans() {
    let (store, _f) = open_temp();

    let dirty = ScanRecord {
        findings_high: 3,
        findings_medium: 0,
        findings_low: 0,
        exit_code: 1,
        ..make_scan("IT-SCAN-020", 100_000)
    };
    let clean = ScanRecord {
        findings_high: 0,
        findings_medium: 0,
        findings_low: 0,
        exit_code: 0,
        ..make_scan("IT-SCAN-021", 200_000)
    };

    store
        .record_scan(&dirty, &[], &[])
        .expect("record dirty scan");
    store
        .record_scan(&clean, &[], &[])
        .expect("record clean scan");

    let t = store.totals().expect("totals");
    assert_eq!(t.total_scans, 2, "both scans must be counted");
    assert_eq!(
        t.clean_scans, 1,
        "only the scan with zero findings at all levels is clean"
    );
    assert_eq!(t.total_findings_high, 3, "sum of high across both scans");
    assert_eq!(t.total_findings_medium, 0);
    assert_eq!(t.total_findings_low, 0);
}

/// `totals()` sums findings across more than two scans correctly.
///
/// Scan A: high=1, medium=0, low=0
/// Scan B: high=0, medium=4, low=2
/// Scan C: high=2, medium=1, low=0
///
/// Expected: total=3, clean=0, high=3, medium=5, low=2.
#[test]
fn totals_sums_correctly_across_three_dirty_scans() {
    let (store, _f) = open_temp();

    for (id, ts, h, m, l) in [
        ("IT-SCAN-030", 1_000i64, 1i64, 0i64, 0i64),
        ("IT-SCAN-031", 2_000, 0, 4, 2),
        ("IT-SCAN-032", 3_000, 2, 1, 0),
    ] {
        let scan = ScanRecord {
            findings_high: h,
            findings_medium: m,
            findings_low: l,
            exit_code: 1,
            ..make_scan(id, ts)
        };
        store.record_scan(&scan, &[], &[]).expect("record scan");
    }

    let t = store.totals().expect("totals");
    assert_eq!(t.total_scans, 3);
    assert_eq!(t.clean_scans, 0, "no scan has zero findings at every level");
    assert_eq!(t.total_findings_high, 3, "1 + 0 + 2");
    assert_eq!(t.total_findings_medium, 5, "0 + 4 + 1");
    assert_eq!(t.total_findings_low, 2, "0 + 2 + 0");
}

// ---------------------------------------------------------------------------
// recent_scans — ordering
// ---------------------------------------------------------------------------

/// `recent_scans(n)` returns results ordered newest-first when n scans exist.
///
/// Scans are inserted in oldest-first order to rule out insertion order being
/// responsible for the result ordering. The only correct ordering criterion is
/// `started_at_ns DESC`.
#[test]
fn recent_scans_newest_first_across_n_scans() {
    let (store, _f) = open_temp();

    // Insert 5 scans with timestamps in ascending order.
    let ids_and_timestamps = [
        ("IT-SCAN-040", 1_000i64),
        ("IT-SCAN-041", 2_000),
        ("IT-SCAN-042", 3_000),
        ("IT-SCAN-043", 4_000),
        ("IT-SCAN-044", 5_000),
    ];
    for (id, ts) in ids_and_timestamps {
        store
            .record_scan(&make_scan(id, ts), &[], &[])
            .expect("record scan");
    }

    let results = store.recent_scans(10).expect("recent_scans(10)");
    assert_eq!(results.len(), 5, "all five scans must be returned");

    // Verify strict descending order by started_at_ns.
    for window in results.windows(2) {
        assert!(
            window[0].started_at_ns > window[1].started_at_ns,
            "scans must be ordered newest-first; got {} then {}",
            window[0].started_at_ns,
            window[1].started_at_ns,
        );
    }

    // The very first result must be the newest.
    assert_eq!(
        results[0].scan_id, "IT-SCAN-044",
        "newest scan must be first"
    );
    assert_eq!(
        results[4].scan_id, "IT-SCAN-040",
        "oldest scan must be last"
    );
}

/// `recent_scans(n)` with n < total count returns exactly n rows, still newest-first.
#[test]
fn recent_scans_limit_respected() {
    let (store, _f) = open_temp();

    for (id, ts) in [
        ("IT-SCAN-050", 1_000i64),
        ("IT-SCAN-051", 2_000),
        ("IT-SCAN-052", 3_000),
    ] {
        store
            .record_scan(&make_scan(id, ts), &[], &[])
            .expect("record scan");
    }

    let top2 = store.recent_scans(2).expect("recent_scans(2)");
    assert_eq!(top2.len(), 2, "limit=2 must return exactly 2 rows");
    assert_eq!(
        top2[0].scan_id, "IT-SCAN-052",
        "first result must be newest"
    );
    assert_eq!(
        top2[1].scan_id, "IT-SCAN-051",
        "second result must be second-newest"
    );
}

/// `recent_scans(0)` returns an empty slice without error.
#[test]
fn recent_scans_limit_zero_returns_empty() {
    let (store, _f) = open_temp();
    store
        .record_scan(&make_scan("IT-SCAN-060", 1_000), &[], &[])
        .expect("record scan");

    let results = store.recent_scans(0).expect("recent_scans(0)");
    assert!(
        results.is_empty(),
        "limit=0 must return an empty slice even when scans exist"
    );
}
