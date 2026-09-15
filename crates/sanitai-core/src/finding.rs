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
    /// A value published as a test/example by its own vendor or standard:
    /// Stripe's `4242 4242 4242 4242`, the ISO IBAN sample `GB82 WEST …`,
    /// AWS's `AKIAIOSFODNN7EXAMPLE`, the Bitcoin genesis address. Format-
    /// valid by construction, secret to nobody. Hidden by default.
    TestValue,
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

/// A display-safe rendering of a matched value: first and last few
/// characters with the middle replaced by bullets, so a reader can recognise
/// `4242••••••••4242` or `AKIA••••••••••••MPLE` without the report carrying
/// a usable secret. Follows the PCI/"last four" convention: up to 4 chars
/// each side for values of 12+ chars, 2 each side for 8–11, all bullets
/// below that.
pub fn mask_secret(raw: &str) -> String {
    // `scheme://user:pass@host…`: keep user and host, mask the password.
    if let Some((scheme, rest)) = raw.split_once("://") {
        if let Some((userinfo, host)) = rest.rsplit_once('@') {
            if let Some((user, pass)) = userinfo.split_once(':') {
                // User and host already identify the credential; the
                // password's edges add nothing, so hide it entirely.
                let bullets = "\u{2022}".repeat(pass.chars().count().min(12));
                return format!("{scheme}://{user}:{bullets}@{host}");
            }
        }
    }
    // `KEY=value` / `key: 'value'`: keep the key, mask the value.
    if let Some(sep) = raw.find(['=', ':']) {
        let (key, value) = raw.split_at(sep + 1);
        let key_ok = key[..sep]
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'));
        let lead = value.len() - value.trim_start().len();
        let value = &value[lead..];
        let quote = value
            .chars()
            .next()
            .filter(|c| matches!(c, '\'' | '"' | '`'));
        let inner = if quote.is_some() { &value[1..] } else { value };
        if key_ok && !inner.is_empty() {
            return format!(
                "{key}{}{}{}",
                &raw[sep + 1..sep + 1 + lead],
                quote.map(String::from).unwrap_or_default(),
                mask_value(inner)
            );
        }
    }
    mask_value(raw)
}

/// Edge-only rendering of a bare secret value: 4 chars each side from 16
/// chars (the PCI "first/last four"), 2 from 12, nothing below that.
fn mask_value(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let n = chars.len();
    let keep = if n >= 16 {
        4
    } else if n >= 12 {
        2
    } else {
        0
    };
    let head: String = chars[..keep].iter().collect();
    let tail: String = chars[n - keep..].iter().collect();
    let hidden = (n - 2 * keep).min(12);
    format!("{head}{}{tail}", "\u{2022}".repeat(hidden))
}

/// One distinct secret and every place it was seen.
///
/// Conversation exports repeat themselves: an assistant that reads a `.env`
/// file, edits it, and reads it back produces the same `DATABASE_URL` line
/// dozens of times in one session. Fingerprints are per occurrence (they mix
/// in the turn index), so the raw findings list has no notion of "one secret,
/// 48 places". Grouping by `(detector_id, matched_raw)` restores it for the
/// human-facing views; JSON/SARIF stay per occurrence.
#[derive(Debug)]
pub struct FindingGroup<'a> {
    /// The first occurrence in input order. Its fingerprint, excerpt and
    /// location are what a row/line displays.
    pub representative: &'a Finding,
    /// Every occurrence, including `representative`, in input order.
    pub occurrences: Vec<&'a Finding>,
}

impl FindingGroup<'_> {
    pub fn count(&self) -> usize {
        self.occurrences.len()
    }

    /// Number of distinct source files the secret appears in.
    pub fn file_count(&self) -> usize {
        let mut files: Vec<&Path> = self
            .occurrences
            .iter()
            .map(|f| f.turn_id.0.as_path())
            .collect();
        files.sort_unstable();
        files.dedup();
        files.len()
    }

    /// Highest confidence across the occurrences. Occurrences share a
    /// detector and value so this is normally uniform, but a validator that
    /// looks at context could in principle grade two occurrences differently.
    pub fn confidence(&self) -> Confidence {
        let rank = |c: &Confidence| match c {
            Confidence::High => 2u8,
            Confidence::Medium => 1,
            Confidence::Low => 0,
        };
        self.occurrences
            .iter()
            .map(|f| &f.confidence)
            .max_by_key(|c| rank(c))
            .cloned()
            .unwrap_or_else(|| self.representative.confidence.clone())
    }
}

/// Group findings by `(detector_id, matched_raw)`, preserving the input
/// order of first occurrence. Callers that want severity ordering should sort
/// the result by [`FindingGroup::confidence`].
///
/// A finding with an empty `matched_raw` (one reloaded from the history
/// store, which never persists secret values) has no known value to group
/// on, so it is keyed on its own fingerprint and always forms a group of one.
/// Without that rule every historical finding from the same detector would
/// collapse into a single `×N` row — and `f` would suppress all of them.
pub fn group_by_secret<'a, I>(findings: I) -> Vec<FindingGroup<'a>>
where
    I: IntoIterator<Item = &'a Finding>,
{
    let mut index: std::collections::HashMap<(&'static str, &'a str, Option<[u8; 4]>), usize> =
        std::collections::HashMap::new();
    let mut groups: Vec<FindingGroup<'a>> = Vec::new();
    for f in findings {
        let key = if f.matched_raw.is_empty() {
            (f.detector_id, "", Some(f.fingerprint))
        } else {
            (f.detector_id, f.matched_raw.as_str(), None)
        };
        match index.entry(key) {
            std::collections::hash_map::Entry::Occupied(e) => {
                groups[*e.get()].occurrences.push(f);
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(groups.len());
                groups.push(FindingGroup {
                    representative: f,
                    occurrences: vec![f],
                });
            }
        }
    }
    groups
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
    fn mask_secret_keeps_edges_only() {
        let b = |n: usize| "\u{2022}".repeat(n);
        assert_eq!(mask_secret("4242424242424242"), format!("4242{}4242", b(8)));
        assert_eq!(
            mask_secret("AKIAIOSFODNN7EXAMPLE"),
            format!("AKIA{}MPLE", b(12))
        );
        // 12–15 chars: two each side; under 12: nothing.
        assert_eq!(mask_secret("hunter2abcde"), format!("hu{}de", b(8)));
        assert_eq!(mask_secret("hunter2abc"), b(10));
        assert_eq!(mask_secret("short"), b(5));
        // Long values never reveal more than 8 chars and never grow unbounded.
        let long = "x".repeat(200);
        assert_eq!(mask_secret(&long).chars().count(), 4 + 12 + 4);
    }

    #[test]
    fn mask_secret_keeps_key_and_host_masks_value() {
        let b = |n: usize| "\u{2022}".repeat(n);
        // Assignment: the key stays, a short value shows nothing.
        assert_eq!(
            mask_secret("PASSWORD=hunter22"),
            format!("PASSWORD={}", b(8))
        );
        assert_eq!(
            mask_secret("api_key: 'Xa7pQ9vR2mK4nL8zT5jB3hC6d"),
            format!("api_key: 'Xa7p{}hC6d", b(12))
        );
        // URL: user and host stay, the password is masked entirely.
        assert_eq!(
            mask_secret("postgres://app:Xq9vR2mK4nL8@db.corp.net:5432/app"),
            format!("postgres://app:{}@db.corp.net:5432/app", b(12))
        );
        // Multi-byte input is handled per char, not per byte.
        assert_eq!(mask_secret("pässwörd=ünïcödé!!").chars().count(), 9 + 9);
    }

    #[test]
    fn group_by_secret_merges_same_value_keeps_first_order() {
        let mk = |file: &str, turn: usize, det: &'static str, raw: &str| Finding {
            turn_id: (std::sync::Arc::new(std::path::PathBuf::from(file)), turn),
            detector_id: det,
            byte_range: 0..raw.len(),
            matched_raw: raw.to_owned(),
            transform: TransformChain::default(),
            confidence: Confidence::High,
            span_kind: SpanKind::Single,
            synthetic: false,
            role: None,
            category: Category::Secret,
            entropy_score: 0.0,
            context_class: ContextClass::Unclassified,
            fingerprint: [turn as u8, 0, 0, 0],
            line_in_file: Some(turn as u32),
            excerpt: String::new(),
        };
        let v = vec![
            mk("/a.jsonl", 1, "postgres_url", "postgres://u:p@h/db"),
            mk(
                "/a.jsonl",
                2,
                "generic_password_assignment",
                "password=hunter22",
            ),
            mk("/a.jsonl", 3, "postgres_url", "postgres://u:p@h/db"),
            mk("/b.jsonl", 4, "postgres_url", "postgres://u:p@h/db"),
            // Same value, different detector: a separate group.
            mk("/b.jsonl", 5, "redis_url", "postgres://u:p@h/db"),
        ];
        let groups = group_by_secret(&v);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].representative.fingerprint, [1, 0, 0, 0]);
        assert_eq!(groups[0].count(), 3);
        assert_eq!(groups[0].file_count(), 2);
        assert_eq!(groups[1].count(), 1);
        assert_eq!(groups[2].representative.detector_id, "redis_url");
        // Total occurrences are conserved.
        assert_eq!(groups.iter().map(|g| g.count()).sum::<usize>(), v.len());
    }

    /// Findings reloaded from the history store never carry `matched_raw`
    /// (the value is deliberately not persisted). Two such findings from
    /// the same detector are *not* known to be the same secret, so they
    /// must stay separate rows rather than collapsing into one `×N` group.
    #[test]
    fn group_by_secret_does_not_merge_findings_with_empty_matched_raw() {
        let mk = |turn: usize, fp: u8| Finding {
            turn_id: (
                std::sync::Arc::new(std::path::PathBuf::from("/h.jsonl")),
                turn,
            ),
            detector_id: "aws_access_key",
            byte_range: 0..0,
            matched_raw: String::new(),
            transform: TransformChain::default(),
            confidence: Confidence::High,
            span_kind: SpanKind::Single,
            synthetic: false,
            role: None,
            category: Category::Secret,
            entropy_score: 0.0,
            context_class: ContextClass::Unclassified,
            fingerprint: [fp, 0, 0, 0],
            line_in_file: None,
            excerpt: String::new(),
        };
        let v = vec![mk(0, 1), mk(1, 2), mk(2, 3)];
        let groups = group_by_secret(&v);
        assert_eq!(
            groups.len(),
            3,
            "historical findings (empty matched_raw) must not collapse into one group"
        );
        assert!(groups.iter().all(|g| g.count() == 1));
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
