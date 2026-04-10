//! Policy-driven redactor.
//!
//! Given a text blob and a list of `Finding`s that point at byte ranges inside
//! it, produce a new string where every finding has been replaced according to
//! the active `RedactMode`. The redactor is intentionally stateless across
//! calls except for two things that must persist between chunks of the same
//! process run:
//!
//! 1. `session_salt` — random bytes generated at construction, mixed into the
//!    HMAC used by `RedactMode::Hash`. Never persisted to disk.
//! 2. `vault_counters` — monotonically-increasing per-detector counter used by
//!    `RedactMode::VaultRef` so each finding gets a unique `${VAULT:*}` ref.
//!
//! Invariants the implementation must hold:
//!
//! - Output is always valid UTF-8. Span boundaries are snapped to char
//!   boundaries before slicing.
//! - Overlapping findings are merged into a single replacement span. We
//!   sort by `start` then walk forward coalescing anything whose start
//!   falls inside the current running span's end.
//! - `redact(content, &[])` is a zero-op that returns an exact copy of the
//!   input. (Tested below.)
//! - `matched_raw` from a `Finding` is only used as input to the HMAC or
//!   as a source of the first N bytes for `Partial`. It is never logged.

#![deny(clippy::unwrap_used)]

use std::collections::HashMap;
use std::ops::Range;

use hmac::{Hmac, Mac};
use sanitai_core::{config::RedactMode, finding::Finding};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub struct Redactor {
    pub mode: RedactMode,
    vault_counters: HashMap<String, usize>,
    /// Random per-process salt. 32 bytes is enough for HMAC-SHA256 and
    /// matches the common NIST recommendation for symmetric keys.
    session_salt: [u8; 32],
}

impl Redactor {
    /// Build a redactor with a freshly generated session salt.
    ///
    /// If `getrandom` somehow fails (sandbox issues, /dev/urandom missing)
    /// we fall back to a salt derived from the process ID and wall clock.
    /// That fallback is non-cryptographic but it keeps the CLI usable in
    /// pathological environments; callers that need real entropy should
    /// check `getrandom` health separately before invoking us.
    pub fn new(mode: RedactMode) -> Self {
        let mut salt = [0u8; 32];
        if getrandom::getrandom(&mut salt).is_err() {
            tracing::warn!("getrandom failed; using fallback salt (NOT cryptographically secure)");
            let pid = std::process::id();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let seed = (pid as u64)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(now);
            for (i, b) in salt.iter_mut().enumerate() {
                *b = ((seed >> ((i % 8) * 8)) & 0xff) as u8;
            }
        }
        Self {
            mode,
            vault_counters: HashMap::new(),
            session_salt: salt,
        }
    }

    /// Replace every finding in `content` according to `self.mode` and return
    /// a new `String`. `findings` may be in any order and may overlap; this
    /// function handles sorting and coalescing internally.
    pub fn redact(&mut self, content: &str, findings: &[Finding]) -> String {
        if findings.is_empty() {
            return content.to_string();
        }

        // 1. Copy references to findings and sort by start.
        let mut ordered: Vec<&Finding> = findings.iter().collect();
        ordered.sort_by_key(|f| f.byte_range.start);

        // 2. Merge overlapping spans. Each merged entry keeps a list of
        //    contributing findings so we can still emit counters / HMAC
        //    replacements for the first finding in the group.
        let merged = merge_spans(&ordered, content);

        // 3. Walk content, emitting unchanged bytes between spans and the
        //    replacement at each span. Everything is pushed into a single
        //    output buffer to minimize allocations.
        let mut out = String::with_capacity(content.len());
        let mut cursor: usize = 0;
        for group in merged {
            // Emit the gap before this group.
            if group.range.start > cursor {
                out.push_str(&content[cursor..group.range.start]);
            }
            // Emit the replacement.
            let raw_slice = &content[group.range.clone()];
            let leader = group
                .findings
                .first()
                .expect("merge_spans always produces non-empty groups");
            let replacement = self.replacement_for(leader, raw_slice);
            out.push_str(&replacement);
            cursor = group.range.end;
        }
        if cursor < content.len() {
            out.push_str(&content[cursor..]);
        }
        out
    }

    fn replacement_for(&mut self, finding: &Finding, matched: &str) -> String {
        match self.mode {
            RedactMode::Mask => "[REDACTED]".to_string(),
            RedactMode::Hash => {
                // HMAC-SHA256 over the matched bytes with the session salt as
                // the key. We expose the first 4 bytes (8 hex chars) as a
                // short, stable identifier — enough for deduping inside one
                // process run, not enough to brute-force the original value.
                let mut mac = HmacSha256::new_from_slice(&self.session_salt)
                    .expect("HMAC-SHA256 accepts any key length");
                mac.update(matched.as_bytes());
                let digest = mac.finalize().into_bytes();
                let mut hex = String::with_capacity(8);
                for b in &digest[..4] {
                    hex.push_str(&format!("{:02x}", b));
                }
                format!("[sha256:{hex}]")
            }
            RedactMode::Partial => {
                // Preserve a short prefix of the original for operator triage
                // while still hiding the full secret. Snap the prefix length
                // down to a char boundary so we never produce invalid UTF-8.
                let prefix_bytes = snap_down(matched, matched.len().min(6));
                let prefix = &matched[..prefix_bytes];
                format!("{prefix}[REDACTED]")
            }
            RedactMode::VaultRef => {
                let counter = self
                    .vault_counters
                    .entry(finding.detector_id.to_string())
                    .and_modify(|n| *n += 1)
                    .or_insert(1);
                format!("${{VAULT:{}_{}}}", finding.detector_id, counter)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Span merging
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct MergedSpan<'a> {
    range: Range<usize>,
    findings: Vec<&'a Finding>,
}

fn merge_spans<'a>(sorted: &[&'a Finding], content: &str) -> Vec<MergedSpan<'a>> {
    let mut out: Vec<MergedSpan<'a>> = Vec::new();
    for f in sorted {
        // Snap span boundaries to char boundaries defensively. Upstream
        // detectors should already emit aligned ranges, but if they don't
        // we'd rather silently widen than produce invalid UTF-8.
        let start = snap_down(content, f.byte_range.start.min(content.len()));
        let end_raw = f.byte_range.end.min(content.len());
        let end = snap_up(content, end_raw);

        if let Some(last) = out.last_mut() {
            if start < last.range.end {
                // Overlap. Extend the running span to cover the union.
                if end > last.range.end {
                    last.range.end = end;
                }
                last.findings.push(f);
                continue;
            }
        }
        out.push(MergedSpan {
            range: start..end,
            findings: vec![f],
        });
    }
    out
}

fn snap_down(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn snap_up(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sanitai_core::finding::{Confidence, SpanKind, TransformChain};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn make_finding(detector_id: &'static str, start: usize, end: usize, raw: &str) -> Finding {
        Finding {
            turn_id: (Arc::new(PathBuf::from("/tmp/t")), 0),
            detector_id,
            byte_range: start..end,
            matched_raw: raw.to_string(),
            transform: TransformChain::default(),
            confidence: Confidence::High,
            span_kind: SpanKind::Single,
            synthetic: false,
        }
    }

    #[test]
    fn empty_findings_returns_unchanged() {
        let mut r = Redactor::new(RedactMode::Mask);
        let input = "hello world";
        assert_eq!(r.redact(input, &[]), input);
    }

    #[test]
    fn mask_replaces_span() {
        let mut r = Redactor::new(RedactMode::Mask);
        let input = "my key is sk-ant-secret and that's all";
        let f = make_finding("claude_api_key", 10, 23, "sk-ant-secret");
        let out = r.redact(input, &[f]);
        assert_eq!(out, "my key is [REDACTED] and that's all");
    }

    #[test]
    fn overlapping_findings_produce_one_span() {
        let mut r = Redactor::new(RedactMode::Mask);
        let input = "abcdefghij";
        let a = make_finding("d1", 2, 6, "cdef");
        let b = make_finding("d2", 4, 8, "efgh");
        let out = r.redact(input, &[a, b]);
        // Expect the union [2,8) replaced once, not twice.
        assert_eq!(out, "ab[REDACTED]ij");
    }

    #[test]
    fn vault_counter_increments_per_detector() {
        let mut r = Redactor::new(RedactMode::VaultRef);
        let input = "AAA BBB CCC";
        let a = make_finding("aws_key", 0, 3, "AAA");
        let b = make_finding("aws_key", 4, 7, "BBB");
        let c = make_finding("gcp_key", 8, 11, "CCC");
        let out = r.redact(input, &[a, b, c]);
        assert!(out.contains("${VAULT:aws_key_1}"));
        assert!(out.contains("${VAULT:aws_key_2}"));
        assert!(out.contains("${VAULT:gcp_key_1}"));
    }

    #[test]
    fn hash_mode_produces_stable_prefix() {
        let mut r = Redactor::new(RedactMode::Hash);
        let input = "hello secret world";
        let f = make_finding("d", 6, 12, "secret");
        let out = r.redact(input, &[f]);
        // Shape check: "[sha256:XXXXXXXX]" inserted at position 6.
        assert!(out.starts_with("hello "));
        assert!(out.contains("[sha256:"));
        assert!(out.ends_with(" world"));
    }

    #[test]
    fn partial_mode_preserves_prefix() {
        let mut r = Redactor::new(RedactMode::Partial);
        let input = "token=abcdefghij tail";
        let f = make_finding("d", 6, 16, "abcdefghij");
        let out = r.redact(input, &[f]);
        assert!(out.contains("abcdef[REDACTED]"));
        assert!(out.ends_with(" tail"));
    }

    #[test]
    fn output_is_always_valid_utf8_with_multibyte_content() {
        let mut r = Redactor::new(RedactMode::Mask);
        let input = "héllo 🔥 world"; // multi-byte chars
                                      // Redact "🔥" — its byte range in the source. The fire emoji is 4 bytes.
        let start = input.find('🔥').expect("emoji present");
        let end = start + '🔥'.len_utf8();
        let f = make_finding("d", start, end, "🔥");
        let out = r.redact(input, &[f]);
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
        assert!(out.contains("[REDACTED]"));
        assert!(out.starts_with("héllo "));
    }

    #[test]
    fn ranges_outside_content_are_clamped() {
        let mut r = Redactor::new(RedactMode::Mask);
        let input = "short";
        let f = make_finding("d", 0, 999, "short");
        let out = r.redact(input, &[f]);
        assert_eq!(out, "[REDACTED]");
    }

    #[test]
    fn unsorted_findings_are_handled() {
        let mut r = Redactor::new(RedactMode::Mask);
        let input = "one two three four";
        let a = make_finding("d", 14, 18, "four");
        let b = make_finding("d", 0, 3, "one");
        let out = r.redact(input, &[a, b]);
        assert_eq!(out, "[REDACTED] two three [REDACTED]");
    }
}
