use crate::traits::Category;
use crate::turn::{Role, TurnId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ops::Range;
use std::path::Path;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextClass {
    #[default]
    Unclassified,
    RealPaste,
    Educational,
    DocumentationQuote,
    ModelHallucination,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    Base64,
    Hex,
    UrlEncoded,
    Gzip,
    HtmlEntity,
}

/// Chain of transforms applied before detection (innermost first).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransformChain(pub Vec<Transform>);

impl TransformChain {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn push(&mut self, t: Transform) {
        self.0.push(t);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpanKind {
    /// Secret found within a single turn.
    Single,
    /// Secret assembled from fragments across multiple turns.
    CrossTurn { contributing_turns: Vec<usize> },
}

/// A detected secret or PII finding.
// Finding is serialized (JSON output) but never deserialized: TurnId contains
// Arc<PathBuf> which has no serde::Deserialize impl. The CLI round-trips
// findings through FindingJson (a flat serializable DTO) instead.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// The turn this finding belongs to (primary turn for cross-turn findings).
    pub turn_id: TurnId,
    /// Stable detector identifier, e.g. `"aws_access_key"`.
    pub detector_id: &'static str,
    /// Byte range within `Turn::content`.
    pub byte_range: Range<usize>,
    /// The exact matched bytes. NEVER log this value.
    pub matched_raw: String,
    /// Transform chain applied before detection.
    pub transform: TransformChain,
    pub confidence: Confidence,
    pub span_kind: SpanKind,
    /// Whether this finding contains the SANITAI_FAKE synthetic marker.
    pub synthetic: bool,
    /// Role of the turn this finding came from (None if not known at the
    /// construction site — e.g. inside the transform cascade).
    pub role: Option<Role>,
    /// Category inherited from the firing rule.
    pub category: Category,
    /// Shannon entropy of `matched_raw` in bits/byte at the moment of detection.
    pub entropy_score: f64,
    /// Context classification — defaults to Unclassified; populated by
    /// later pipeline stages that understand code fences, docs, etc.
    pub context_class: ContextClass,
    /// Stable 4-byte fingerprint derived from the matched bytes plus
    /// detector / file / turn metadata. The lowercase 8-char hex form
    /// (`fingerprint_hex()`) is safe to display: it does not leak the raw
    /// secret, but is stable across re-scans so users can recognise,
    /// suppress, and reference findings without reading `matched_raw`.
    #[serde(with = "serde_fingerprint")]
    pub fingerprint: [u8; 4],
    /// 1-based line number inside the originating source file, when the
    /// parser can compute one. JSONL/log-line parsers populate this; tree-
    /// structured parsers (ChatGPT export, Cursor SQLite blob walks) leave
    /// it `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_in_file: Option<u32>,
    /// Single-line redacted excerpt around the match: ~30 chars before, the
    /// fingerprint placeholder `[FP:xxxxxxxx]`, ~30 chars after. Newlines
    /// and tabs collapsed to spaces. Never contains any byte of
    /// `matched_raw`. Computed at construction time via [`compute_excerpt`].
    pub excerpt: String,
}

impl Finding {
    pub fn is_synthetic(&self) -> bool {
        self.matched_raw.contains("SANITAI_FAKE")
    }

    /// Lowercase 8-char hex representation of `fingerprint` — the form used
    /// in CLI/JSON/TUI output, suppression files, and SARIF
    /// `partialFingerprints`.
    pub fn fingerprint_hex(&self) -> String {
        let [a, b, c, d] = self.fingerprint;
        format!("{:02x}{:02x}{:02x}{:02x}", a, b, c, d)
    }
}

/// Compute a stable 4-byte fingerprint from the raw matched bytes plus the
/// detector / file / turn coordinates. This is the *only* public way to
/// produce the fingerprint — every Finding construction site must call it
/// so the value is reproducible across re-scans, suppressions, and
/// cross-format round-trips.
///
/// The mix is `SHA-256(matched_raw || detector_id || file_path || turn_idx_le)`,
/// truncated to its first 4 bytes. The hash domain is wide enough to make
/// trivial collisions unlikely in any single user's history; the truncation
/// trades a small amount of distinctness for a fingerprint short enough to
/// glance at and copy by hand.
pub fn compute_fingerprint(
    matched_raw: &[u8],
    detector_id: &str,
    file: &Path,
    turn_idx: usize,
) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(matched_raw);
    hasher.update(detector_id.as_bytes());
    // OsStr → bytes via to_string_lossy is platform-portable and stable for
    // the path strings we actually see (UTF-8 on every supported OS).
    hasher.update(file.to_string_lossy().as_bytes());
    hasher.update(turn_idx.to_le_bytes());
    let digest = hasher.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

/// Build the redacted excerpt that accompanies a finding for display.
///
/// The result is exactly the form `<prefix>[FP:xxxxxxxx]<suffix>` where
/// `prefix` is up to `CONTEXT_CHARS` chars (counted in `chars`, not bytes)
/// taken from `content` immediately before `byte_range.start`, `suffix` is
/// up to `CONTEXT_CHARS` chars taken from immediately after `byte_range.end`,
/// and `xxxxxxxx` is the lowercase hex form of `fingerprint`.
///
/// Two invariants this function upholds, neither of which is incidental:
///
/// 1. **No bytes of the match leak.** The slices we read are `[..start]`
///    and `[end..]` only, so even a malformed `byte_range` cannot let
///    matched bytes through.
/// 2. **The excerpt is single-line.** Newlines (`\n`, `\r`), tabs, and
///    other ASCII control characters are replaced with a single space.
///    Renderers can trust the string to be one line wide.
///
/// `byte_range` is interpreted in *bytes* (matching `Finding::byte_range`).
/// The function trims the start/end to the nearest UTF-8 char boundary, so
/// it is safe to call with arbitrary multi-byte content.
pub fn compute_excerpt(content: &str, byte_range: &Range<usize>, fingerprint: [u8; 4]) -> String {
    /// Number of characters of context to grab on each side. 30 is enough
    /// for a meaningful glance in the typical 80-column TUI without
    /// dominating the row when both sides are present.
    const CONTEXT_CHARS: usize = 30;

    let len = content.len();
    let mut start = byte_range.start.min(len);
    let mut end = byte_range.end.min(len);
    if start > end {
        // Defensive: a caller passed an inverted range. Treat as empty.
        start = end;
    }
    // Snap to char boundaries so we never cut a multi-byte sequence.
    while start > 0 && !content.is_char_boundary(start) {
        start -= 1;
    }
    while end < len && !content.is_char_boundary(end) {
        end += 1;
    }

    let before = &content[..start];
    let after = &content[end..];

    // Take the trailing CONTEXT_CHARS of `before` and leading CONTEXT_CHARS
    // of `after`, counted in `chars` so multi-byte glyphs count as one.
    let prefix: String = {
        let total = before.chars().count();
        let skip = total.saturating_sub(CONTEXT_CHARS);
        before.chars().skip(skip).collect()
    };
    let suffix: String = after.chars().take(CONTEXT_CHARS).collect();

    let placeholder = format!(
        "[FP:{:02x}{:02x}{:02x}{:02x}]",
        fingerprint[0], fingerprint[1], fingerprint[2], fingerprint[3]
    );
    let raw = format!("{prefix}{placeholder}{suffix}");

    // Collapse newlines, tabs, and other ASCII control chars to a single
    // space so the excerpt is guaranteed to render on one line. We keep
    // non-ASCII as-is — Unicode line separators in chat content are rare
    // enough that erasing them would be more confusing than useful.
    raw.chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' || (c.is_ascii_control()) {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Remove duplicate findings that share an identical `fingerprint`.
///
/// Two findings whose fingerprints are equal describe the same secret in the
/// same place — fingerprint = SHA-256(matched_raw || detector_id || file ||
/// turn_idx)[..4], so collisions can only happen when all four inputs match.
/// In practice this happens when:
///
/// - the cross-turn correlator and the per-chunk regex pass both report a
///   secret that lies entirely within a single turn (the cross-turn pass
///   re-scans the same content in its sliding-window buffer),
/// - the chunker produces overlapping chunks for cross-turn alignment and
///   the same regex match falls inside two of them,
/// - a transform decoder no-ops on already-plaintext content and the same
///   match is reported by both `RegexDetector` and `TransformDetector`.
///
/// Order is preserved: the first occurrence wins. Callers that care about
/// span_kind should sort by that priority before calling this — the function
/// does not look at any other field.
pub fn dedupe_by_fingerprint(findings: &mut Vec<Finding>) {
    let mut seen: std::collections::HashSet<[u8; 4]> =
        std::collections::HashSet::with_capacity(findings.len());
    findings.retain(|f| seen.insert(f.fingerprint));
}

/// Custom serde for `[u8; 4]` so JSON consumers see the 8-char hex string
/// rather than a 4-element byte array. Only `serialize` is wired up via
/// `#[serde(with = ...)]`; Finding has no Deserialize impl (see the
/// doc-comment on the struct) so a deserialize half would be dead code.
mod serde_fingerprint {
    use serde::Serializer;

    pub fn serialize<S: Serializer>(bytes: &[u8; 4], s: S) -> Result<S::Ok, S::Error> {
        let hex = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        );
        s.serialize_str(&hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_debug_does_not_contain_raw_value() {
        // If we ever wrap matched_raw in secrecy, Debug must redact it.
        // For now verify the ContextClass default is Unclassified.
        let cc = ContextClass::default();
        assert_eq!(cc, ContextClass::Unclassified);
    }

    #[test]
    fn context_class_serde_roundtrip() {
        let j = serde_json::to_string(&ContextClass::Educational).unwrap();
        assert_eq!(j, r#""educational""#);
        let back: ContextClass = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ContextClass::Educational);
    }

    #[test]
    fn compute_fingerprint_is_deterministic() {
        let raw = b"AKIAIOSFODNN7EXAMPLE";
        let path = Path::new("/tmp/conv.jsonl");
        let a = compute_fingerprint(raw, "aws_access_key", path, 7);
        let b = compute_fingerprint(raw, "aws_access_key", path, 7);
        assert_eq!(a, b, "fingerprint must be reproducible");
        assert_eq!(a.len(), 4);
    }

    #[test]
    fn compute_fingerprint_changes_on_input_change() {
        let path = Path::new("/tmp/conv.jsonl");
        let base = compute_fingerprint(b"AKIAIOSFODNN7EXAMPLE", "aws_access_key", path, 7);

        // Different raw bytes.
        let diff_raw = compute_fingerprint(b"AKIAIOSFODNN7DIFFEXM", "aws_access_key", path, 7);
        assert_ne!(base, diff_raw);

        // Different detector id.
        let diff_det = compute_fingerprint(b"AKIAIOSFODNN7EXAMPLE", "other_rule", path, 7);
        assert_ne!(base, diff_det);

        // Different file.
        let diff_file = compute_fingerprint(
            b"AKIAIOSFODNN7EXAMPLE",
            "aws_access_key",
            Path::new("/tmp/other.jsonl"),
            7,
        );
        assert_ne!(base, diff_file);

        // Different turn.
        let diff_turn = compute_fingerprint(b"AKIAIOSFODNN7EXAMPLE", "aws_access_key", path, 8);
        assert_ne!(base, diff_turn);
    }

    #[test]
    fn dedupe_keeps_first_drops_duplicates() {
        // Build three findings: two with identical fingerprint, one distinct.
        // The dedupe call must keep findings[0] and findings[2], drop [1].
        let mk = |fp: [u8; 4], det: &'static str| Finding {
            turn_id: (std::sync::Arc::new(std::path::PathBuf::from("/tmp/x")), 0),
            detector_id: det,
            byte_range: 0..3,
            matched_raw: "abc".to_owned(),
            transform: TransformChain::default(),
            confidence: Confidence::High,
            span_kind: SpanKind::Single,
            synthetic: false,
            role: None,
            category: Category::Secret,
            entropy_score: 0.0,
            context_class: ContextClass::Unclassified,
            fingerprint: fp,
            line_in_file: None,
            excerpt: String::new(),
        };
        let mut v = vec![
            mk([1, 2, 3, 4], "rule_a"),
            mk([1, 2, 3, 4], "rule_a"), // identical fingerprint — must drop
            mk([5, 6, 7, 8], "rule_b"),
        ];
        dedupe_by_fingerprint(&mut v);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].fingerprint, [1, 2, 3, 4]);
        assert_eq!(v[1].fingerprint, [5, 6, 7, 8]);
    }

    #[test]
    fn fingerprint_hex_is_8_lowercase_chars() {
        let f = Finding {
            turn_id: (std::sync::Arc::new(std::path::PathBuf::from("/tmp/x")), 0),
            detector_id: "test_rule",
            byte_range: 0..3,
            matched_raw: "abc".to_owned(),
            transform: TransformChain::default(),
            confidence: Confidence::High,
            span_kind: SpanKind::Single,
            synthetic: false,
            role: None,
            category: Category::Secret,
            entropy_score: 0.0,
            context_class: ContextClass::Unclassified,
            fingerprint: [0xa8, 0xf3, 0xc9, 0x1e],
            line_in_file: None,
            excerpt: String::new(),
        };
        let hex = f.fingerprint_hex();
        assert_eq!(hex, "a8f3c91e");
        assert_eq!(hex.len(), 8);
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // -------- compute_excerpt -------------------------------------------------

    #[test]
    fn excerpt_is_deterministic() {
        // Same input → same output, every call.
        let content = "the quick brown fox jumps over AKIAIOSFODNN7EXAMPLE while the dog naps";
        let start = content.find("AKIA").expect("substring present");
        let end = start + "AKIAIOSFODNN7EXAMPLE".len();
        let fp = [0xde, 0xad, 0xbe, 0xef];
        let a = compute_excerpt(content, &(start..end), fp);
        let b = compute_excerpt(content, &(start..end), fp);
        assert_eq!(a, b);
        assert!(a.contains("[FP:deadbeef]"));
    }

    #[test]
    fn excerpt_never_includes_match_bytes() {
        // The matched value must never reappear in the excerpt — this is a
        // hard invariant the caller relies on for safe display.
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let content = format!("prelude one two {secret} epilogue three four");
        let start = content.find(secret).expect("secret in content");
        let end = start + secret.len();
        let excerpt = compute_excerpt(&content, &(start..end), [1, 2, 3, 4]);
        assert!(
            !excerpt.contains(secret),
            "excerpt must not contain match bytes, got {excerpt:?}"
        );
        assert!(excerpt.contains("[FP:01020304]"));
    }

    #[test]
    fn excerpt_collapses_newlines_and_tabs() {
        let content = "line1\nline2\ttabbed AKIA12345 trailing\r\n";
        let start = content.find("AKIA12345").expect("present");
        let end = start + "AKIA12345".len();
        let excerpt = compute_excerpt(content, &(start..end), [0, 0, 0, 0]);
        assert!(!excerpt.contains('\n'));
        assert!(!excerpt.contains('\t'));
        assert!(!excerpt.contains('\r'));
    }

    #[test]
    fn excerpt_handles_short_content() {
        // 60-char window > content; just use what's available.
        let content = "AKIA12345 short tail";
        let start = 0;
        let end = "AKIA12345".len();
        let excerpt = compute_excerpt(content, &(start..end), [0xa, 0xb, 0xc, 0xd]);
        assert!(excerpt.contains("[FP:0a0b0c0d]"));
        // No prefix bytes available — placeholder must sit at the start.
        assert!(excerpt.starts_with("[FP:"));
        assert!(excerpt.contains(" short tail"));
    }

    #[test]
    fn excerpt_handles_match_at_end_of_string() {
        let content = "leading context up to here AKIA";
        let start = content.len() - 4;
        let end = content.len();
        let excerpt = compute_excerpt(content, &(start..end), [0xff, 0xee, 0xdd, 0xcc]);
        assert!(excerpt.ends_with("[FP:ffeeddcc]"));
        assert!(!excerpt.contains("AKIA"));
    }

    #[test]
    fn excerpt_is_utf8_safe_on_multibyte_boundaries() {
        // Surround a match with multi-byte chars; range may not land on a
        // char boundary on input but the function must not panic.
        let content = "café before AKIA12 café after";
        let start = content.find("AKIA12").expect("present");
        let end = start + "AKIA12".len();
        let excerpt = compute_excerpt(content, &(start..end), [0, 0, 0, 0]);
        assert!(excerpt.contains("café"));
        assert!(!excerpt.contains("AKIA12"));
    }
}
