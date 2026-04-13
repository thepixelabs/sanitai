//! Transform-aware cascading detector.
//!
//! Wraps a [`RegexDetector`] and additionally attempts to decode embedded
//! base64, hex, URL-encoded, and gzip content before re-scanning. Findings
//! surfaced from a decoded payload carry a [`TransformChain`] describing the
//! encodings that had to be peeled back to reach the secret.
//!
//! Security invariants:
//! - **Decode budget**: the total number of bytes produced by decoders is
//!   bounded by [`TransformConfig::max_decode_bytes`]. Once the budget is
//!   exhausted for a chunk the cascade stops and logs a warning (no raw
//!   content ever goes into the warning).
//! - **Depth cap**: recursion is bounded by [`TransformConfig::max_depth`]
//!   (default 2). This prevents a malicious payload from exhausting the
//!   stack via layered encodings.
//! - **Cycle detection**: an `xxhash64` of every decoded blob is recorded
//!   in a per-chunk set. A repeated hash short-circuits further decoding.
//! - **Zero allocation of raw secrets into logs**: no `tracing` call here
//!   takes untrusted content as an argument.

use crate::regex_detector::RegexDetector;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use flate2::read::GzDecoder;
use regex::Regex;
use sanitai_core::{
    chunk::{Chunk, DetectorScratch},
    finding::{Finding, Transform, TransformChain},
    traits::{Category, Detector},
};
use std::hash::Hasher;
use std::io::Read;
use std::sync::{Arc, OnceLock};
use twox_hash::XxHash64;

fn hash64(bytes: &[u8]) -> u64 {
    let mut h = XxHash64::with_seed(0);
    h.write(bytes);
    h.finish()
}

#[derive(Debug, Clone)]
pub struct TransformConfig {
    pub max_depth: u8,
    pub max_decode_bytes: usize,
}

impl Default for TransformConfig {
    fn default() -> Self {
        Self {
            max_depth: 2,
            max_decode_bytes: 65_536,
        }
    }
}

pub struct TransformDetector {
    inner: Arc<RegexDetector>,
    config: TransformConfig,
}

impl TransformDetector {
    pub fn new(inner: Arc<RegexDetector>, config: TransformConfig) -> Self {
        Self { inner, config }
    }

    pub fn with_defaults(inner: Arc<RegexDetector>) -> Self {
        Self::new(inner, TransformConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

fn base64_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").expect("static regex must compile"))
}

fn hex_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[0-9a-fA-F]{32,}").expect("static regex must compile"))
}

fn percent_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"%[0-9A-Fa-f]{2}").expect("static regex must compile"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn shannon_entropy_bytes(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

const GZIP_LIMIT: usize = 10 * 1024 * 1024; // 10 MB absolute ceiling

fn decode_gzip(src: &[u8]) -> Option<Vec<u8>> {
    if src.len() < 2 || src[0] != 0x1f || src[1] != 0x8b {
        return None;
    }
    let mut dec = GzDecoder::new(src);
    let mut out = Vec::new();
    // Manual take-limited read to guarantee we never exceed GZIP_LIMIT even
    // on adversarial streams that would otherwise expand enormously.
    let mut buf = [0u8; 8192];
    loop {
        match dec.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() + n > GZIP_LIMIT {
                    tracing::warn!("gzip decode aborted: exceeded {} bytes", GZIP_LIMIT);
                    return None;
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(_) => return None,
        }
    }
    Some(out)
}

fn try_decode_base64(tok: &str) -> Option<Vec<u8>> {
    // Must be divisible by 4 (with or without padding padded up).
    let mut t = tok.to_string();
    let rem = t.len() % 4;
    if rem != 0 {
        // Pad if it looks paddable.
        if rem == 2 {
            t.push_str("==");
        } else if rem == 3 {
            t.push('=');
        } else {
            return None;
        }
    }
    STANDARD.decode(t.as_bytes()).ok()
}

fn try_decode_hex(tok: &str) -> Option<Vec<u8>> {
    if tok.len() % 2 != 0 {
        return None;
    }
    hex::decode(tok).ok()
}

fn try_url_decode(region: &str) -> Option<Vec<u8>> {
    // Only decode if we see at least 3 percent-escapes in any 50-char window.
    let bytes = region.as_bytes();
    let mut window_hits = 0usize;
    let mut seen = false;
    for i in 0..bytes.len() {
        if i >= 2 && bytes[i - 2] == b'%' {
            window_hits += 1;
        }
        if i >= 50 && bytes[i - 50] == b'%' {
            window_hits = window_hits.saturating_sub(1);
        }
        if window_hits >= 3 {
            seen = true;
            break;
        }
    }
    // Fallback: simple regex count.
    if !seen && percent_re().find_iter(region).count() < 3 {
        return None;
    }
    let decoded: Vec<u8> = percent_encoding::percent_decode_str(region).collect();
    Some(decoded)
}

// ---------------------------------------------------------------------------
// Cascade
// ---------------------------------------------------------------------------

struct CascadeCtx<'a> {
    inner: &'a RegexDetector,
    config: &'a TransformConfig,
    turn_id: &'a sanitai_core::turn::TurnId,
    /// Role is unknown inside the transform cascade (we operate on decoded
    /// payloads, not original turns) — always `None`.
    role: Option<sanitai_core::turn::Role>,
    out: &'a mut Vec<Finding>,
    scratch: &'a mut DetectorScratch,
}

impl<'a> CascadeCtx<'a> {
    fn note(&mut self, bytes: &[u8]) -> bool {
        let h = hash64(bytes);
        if !self.scratch.decode_seen.insert(h) {
            return false;
        }
        if self.scratch.decode_bytes_used + bytes.len() > self.config.max_decode_bytes {
            tracing::warn!(
                used = self.scratch.decode_bytes_used,
                limit = self.config.max_decode_bytes,
                "transform decode budget exhausted for chunk"
            );
            return false;
        }
        self.scratch.decode_bytes_used += bytes.len();
        true
    }

    fn rescan(&mut self, decoded: &[u8], chain: &TransformChain, depth: u8) {
        if let Ok(s) = std::str::from_utf8(decoded) {
            self.inner
                .scan_str(s, self.turn_id, self.role.clone(), 0, chain, self.out);
            if depth < self.config.max_depth {
                self.cascade(s, chain, depth + 1);
            }
        }
    }

    fn cascade(&mut self, hay: &str, chain: &TransformChain, depth: u8) {
        if depth > self.config.max_depth {
            return;
        }

        // ---------------- base64 ----------------
        let matches: Vec<(usize, usize)> = base64_re()
            .find_iter(hay)
            .map(|m| (m.start(), m.end()))
            .collect();
        for (s, e) in matches {
            let tok = &hay[s..e];
            if let Some(decoded) = try_decode_base64(tok) {
                if shannon_entropy_bytes(&decoded) < 3.5 {
                    continue;
                }
                if !self.note(&decoded) {
                    continue;
                }
                let mut new_chain = chain.clone();
                new_chain.push(Transform::Base64);
                self.rescan(&decoded, &new_chain, depth);
            }
        }

        // ---------------- hex ----------------
        let matches: Vec<(usize, usize)> = hex_re()
            .find_iter(hay)
            .map(|m| (m.start(), m.end()))
            .collect();
        for (s, e) in matches {
            let tok = &hay[s..e];
            if let Some(decoded) = try_decode_hex(tok) {
                if !self.note(&decoded) {
                    continue;
                }
                let mut new_chain = chain.clone();
                new_chain.push(Transform::Hex);
                self.rescan(&decoded, &new_chain, depth);
            }
        }

        // ---------------- URL percent-encoding ----------------
        if let Some(decoded) = try_url_decode(hay) {
            if decoded.as_slice() != hay.as_bytes() && self.note(&decoded) {
                let mut new_chain = chain.clone();
                new_chain.push(Transform::UrlEncoded);
                self.rescan(&decoded, &new_chain, depth);
            }
        }

        // ---------------- gzip ----------------
        // Try the whole haystack as raw bytes — gzip magic is rarely
        // embedded in the middle of a textual region.
        if let Some(decoded) = decode_gzip(hay.as_bytes()) {
            if self.note(&decoded) {
                let mut new_chain = chain.clone();
                new_chain.push(Transform::Gzip);
                self.rescan(&decoded, &new_chain, depth);
            }
        }
    }
}

impl Detector for TransformDetector {
    fn id(&self) -> &'static str {
        "transform"
    }

    fn categories(&self) -> &'static [Category] {
        &[
            Category::Secret,
            Category::Credential,
            Category::Pii,
            Category::Pci,
            Category::HighEntropy,
        ]
    }

    fn scan<'c>(&self, chunk: &Chunk<'c>, scratch: &mut DetectorScratch, out: &mut Vec<Finding>) {
        // First let the underlying regex detector run on the raw chunk.
        self.inner.scan(chunk, scratch, out);

        let hay = match std::str::from_utf8(chunk.bytes) {
            Ok(s) => s,
            Err(_) => return,
        };

        // Reset the decode budget and cycle-detection set for this chunk.
        scratch.reset_for_chunk();
        let mut ctx = CascadeCtx {
            inner: &self.inner,
            config: &self.config,
            turn_id: &chunk.turn_id,
            role: None,
            out,
            scratch,
        };
        let base_chain = TransformChain::default();
        ctx.cascade(hay, &base_chain, 1);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sanitai_core::chunk::OffsetMap;
    use std::path::PathBuf;

    fn tid() -> sanitai_core::turn::TurnId {
        (Arc::new(PathBuf::from("/tmp/t")), 0)
    }

    #[test]
    fn base64_wrapped_aws_key_detected() {
        let plaintext = "AKIAIOSFODNN7EXAMPLE and some more words for entropy";
        let encoded = STANDARD.encode(plaintext.as_bytes());
        let input = format!("payload: {}", encoded);
        let det = TransformDetector::with_defaults(Arc::new(RegexDetector::new()));
        let chunk = Chunk {
            bytes: input.as_bytes(),
            offset_map: OffsetMap::new_linear(0),
            is_message_start: true,
            turn_id: tid(),
        };
        let mut scratch = DetectorScratch::default();
        let mut out = Vec::new();
        det.scan(&chunk, &mut scratch, &mut out);
        assert!(
            out.iter()
                .any(|f| f.detector_id == "aws_access_key_id" && !f.transform.is_empty()),
            "expected base64-transformed AWS key finding"
        );
    }

    #[test]
    fn url_encoded_github_pat_detected() {
        let raw = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        // Percent-encode a few underscores to force at least 3 hits.
        let encoded = raw
            .replace('_', "%5F")
            .replace('a', "%61")
            .replace('b', "%62");
        let input = format!("x={}", encoded);
        let det = TransformDetector::with_defaults(Arc::new(RegexDetector::new()));
        let chunk = Chunk {
            bytes: input.as_bytes(),
            offset_map: OffsetMap::new_linear(0),
            is_message_start: true,
            turn_id: tid(),
        };
        let mut scratch = DetectorScratch::default();
        let mut out = Vec::new();
        det.scan(&chunk, &mut scratch, &mut out);
        assert!(out.iter().any(|f| f.detector_id == "github_pat_classic"));
    }

    #[test]
    fn budget_halts_runaway_decoding() {
        // Build a giant base64 blob that decodes to high-entropy junk, and
        // set a tiny budget.
        let junk: Vec<u8> = (0..4096).map(|i| (i as u8).wrapping_mul(37)).collect();
        let encoded = STANDARD.encode(&junk);
        let det = TransformDetector::new(
            Arc::new(RegexDetector::new()),
            TransformConfig {
                max_depth: 2,
                max_decode_bytes: 128,
            },
        );
        let chunk = Chunk {
            bytes: encoded.as_bytes(),
            offset_map: OffsetMap::new_linear(0),
            is_message_start: true,
            turn_id: tid(),
        };
        let mut scratch = DetectorScratch::default();
        let mut out = Vec::new();
        det.scan(&chunk, &mut scratch, &mut out);
        // No crash, no runaway. May or may not contain findings — we
        // only assert graceful completion.
    }
}
