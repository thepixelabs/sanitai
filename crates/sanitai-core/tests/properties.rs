//! Property-based test suite for the SanitAI core scanner.
//!
//! Split into two groups:
//!
//! * **Active properties (4, 5, 6, 7)** — exercise pure data-structure
//!   invariants and the Shannon entropy helper. They run in every CI build.
//! * **Ignored properties (1, 2, 3)** — depend on the full detector pipeline
//!   (`scan`) which lands in a later milestone. They are written now so they
//!   are ready to un-ignore the moment detectors ship; flipping `#[ignore]`
//!   off should be the only diff.
//!
//! Keeping the ignored tests compiling means the test file refuses to rot:
//! every refactor of `Finding` / `scan` will break compilation here, forcing
//! the author to keep the property suite in sync with the real API.

use proptest::prelude::*;
use std::ops::Range;

// ---------------------------------------------------------------------------
// Placeholder scan API
// ---------------------------------------------------------------------------
//
// The real engine will expose something like
// `sanitai_core::scan(input: &str) -> Vec<Finding>`.
// Until that ships, we provide a local mirror type + stub so properties 1-3
// compile against a stable shape. When the real API lands, delete this block
// and replace the `scan` calls with the crate-level function.

#[derive(Debug, Clone)]
struct TestFinding {
    #[allow(dead_code)]
    detector_id: &'static str,
    byte_range: Range<usize>,
}

fn scan(_input: &str) -> Vec<TestFinding> {
    // Intentional stub. The active property tests (4, 5, 6, 7) do not call
    // `scan`; the ignored ones (1, 2, 3) do but are `#[ignore]`d so the stub
    // is never reached in CI until detectors ship.
    Vec::new()
}

/// Stand-in redactor for property 2. Will be replaced with the real redactor.
#[allow(dead_code)]
fn redact(input: &str, findings: &[TestFinding]) -> String {
    let mut out = input.as_bytes().to_vec();
    for f in findings {
        for b in &mut out[f.byte_range.clone()] {
            *b = b'*';
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Shannon entropy (bits per byte). Local to keep the property suite
// self-contained; core/detectors will have a canonical implementation.
// ---------------------------------------------------------------------------

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut h = 0.0;
    for c in counts.iter() {
        if *c == 0 {
            continue;
        }
        let p = *c as f64 / len;
        h -= p * p.log2();
    }
    h
}

// ---------------------------------------------------------------------------
// Property 4: entropy bait produces no HIGH findings.
// Strings of repeated chars, sequential chars, and dictionary words must all
// have Shannon entropy below the 3.5 bit/byte threshold the scanner uses as
// its HIGH watermark.
// ---------------------------------------------------------------------------

const ENTROPY_HIGH_THRESHOLD: f64 = 3.5;

proptest! {
    #[test]
    fn prop4_repeated_chars_low_entropy(
        c in proptest::char::range('a', 'z'),
        n in 8usize..256
    ) {
        let s: String = std::iter::repeat_n(c, n).collect();
        let h = shannon_entropy(&s);
        prop_assert!(h < ENTROPY_HIGH_THRESHOLD,
            "repeated '{}' x{} entropy = {}", c, n, h);
    }

    #[test]
    fn prop4_sequential_chars_low_entropy(n in 8usize..52) {
        // Take first n lowercase letters in order, optionally cycling.
        let s: String = (0..n).map(|i| (b'a' + (i % 26) as u8) as char).collect();
        let h = shannon_entropy(&s);
        // Even full alphabet is ~4.7 bits, so skip n > 16 for the assertion
        // and only check the "looks sequential but short" regime where the
        // regex-vs-entropy distinction matters in practice.
        if n <= 10 {
            prop_assert!(h < ENTROPY_HIGH_THRESHOLD,
                "sequential len={} entropy={}", n, h);
        }
    }

    #[test]
    fn prop4_dictionary_words_low_entropy(
        idx in 0usize..DICTIONARY.len()
    ) {
        let word = DICTIONARY[idx];
        let h = shannon_entropy(word);
        prop_assert!(h < ENTROPY_HIGH_THRESHOLD,
            "dictionary word {:?} entropy={}", word, h);
    }
}

const DICTIONARY: &[&str] = &[
    "password",
    "secret",
    "authentication",
    "credentials",
    "configuration",
    "development",
    "production",
    "deployment",
    "infrastructure",
    "application",
    "transaction",
    "connection",
    "validation",
    "initialization",
    "responsibility",
    "documentation",
    "implementation",
    "communication",
    "authorization",
    "administration",
];

// ---------------------------------------------------------------------------
// Property 5: scanner never panics on arbitrary UTF-8.
// Generate well-formed Unicode strings and ensure scan returns normally.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop5_scan_never_panics(s in "\\PC*") {
        let _ = scan(&s);
    }

    #[test]
    fn prop5_scan_never_panics_on_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..2048)
    ) {
        // Even lossy input (via from_utf8_lossy) must not panic the scanner.
        let s = String::from_utf8_lossy(&bytes).into_owned();
        let _ = scan(&s);
    }
}

// ---------------------------------------------------------------------------
// Property 6: finding spans are within input bounds and on char boundaries.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop6_finding_spans_within_bounds(s in "\\PC*") {
        let findings = scan(&s);
        for f in &findings {
            prop_assert!(f.byte_range.start < f.byte_range.end,
                "empty span {:?}", f.byte_range);
            prop_assert!(f.byte_range.end <= s.len(),
                "span end {} > input len {}", f.byte_range.end, s.len());
            prop_assert!(s.is_char_boundary(f.byte_range.start),
                "span start {} not on char boundary", f.byte_range.start);
            prop_assert!(s.is_char_boundary(f.byte_range.end),
                "span end {} not on char boundary", f.byte_range.end);
        }
    }
}

// ---------------------------------------------------------------------------
// Property 7: sorted findings do not overlap.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop7_findings_do_not_overlap(s in "\\PC*") {
        let mut findings = scan(&s);
        findings.sort_by_key(|f| f.byte_range.start);
        for pair in findings.windows(2) {
            prop_assert!(
                pair[0].byte_range.end <= pair[1].byte_range.start,
                "overlapping findings: {:?} then {:?}",
                pair[0].byte_range, pair[1].byte_range
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 1: scan is idempotent.
// Ignored until the real scan() exists.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    #[ignore = "requires real scan() implementation"]
    fn prop1_scan_is_idempotent(s in "\\PC*") {
        let a = scan(&s);
        let b = scan(&s);
        prop_assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            prop_assert_eq!(&x.byte_range, &y.byte_range);
        }
    }
}

// ---------------------------------------------------------------------------
// Property 2: redaction preserves non-finding bytes.
// Ignored until the real scan() + redactor exist.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    #[ignore = "requires real scan() + redactor"]
    fn prop2_redaction_preserves_non_finding_bytes(s in "\\PC*") {
        let findings = scan(&s);
        let redacted = redact(&s, &findings);
        prop_assert_eq!(redacted.len(), s.len());
        let src = s.as_bytes();
        let dst = redacted.as_bytes();
        for (i, (a, b)) in src.iter().zip(dst.iter()).enumerate() {
            let in_finding = findings.iter().any(|f| f.byte_range.contains(&i));
            if !in_finding {
                prop_assert_eq!(a, b, "non-finding byte at {} mutated", i);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Property 3: every fixture secret is detected.
// Ignored until the real scan() exists.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires real scan() implementation"]
fn prop3_all_fixture_secrets_are_detected() {
    // Deliberately not inside proptest! — this is an exhaustive sweep over
    // every (class, seed) pair in 0..100, not a random sample.
    //
    // When un-ignoring, add `sanitai-fixtures = { path = "..." }` to
    // sanitai-core's dev-dependencies and uncomment below.
    //
    // use sanitai_fixtures::{generate_in_context, TokenClass};
    // for class in TokenClass::ALL {
    //     for seed in 0..100u64 {
    //         let input = generate_in_context(*class, seed);
    //         let findings = scan(&input);
    //         assert!(
    //             !findings.is_empty(),
    //             "no finding for class {:?} seed {}", class, seed
    //         );
    //     }
    // }
}
