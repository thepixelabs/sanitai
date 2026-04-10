//! Regex-based detector ruleset.
//!
//! Implements the [`Detector`] trait with a broad set of high-signal regex
//! patterns for cloud credentials, SCM tokens, API keys, private key PEM
//! blocks, database URLs, and generic password-assignment heuristics.
//!
//! Rules that are prone to false-positives (e.g. 40-character AWS secret
//! keys, Bitcoin addresses, generic `password=` assignments) are
//! entropy-gated. Credit-card and IBAN matches are algorithmically validated
//! via Luhn and mod-97 respectively.
//!
//! Security rules for this module:
//! - `Finding::matched_raw` is populated from `chunk.bytes`, but is NEVER
//!   logged, printed, or included in errors. All diagnostics use redacted
//!   summaries (length, detector id).
//! - Regex compilation happens once via `once_cell::sync::Lazy` equivalents
//!   (we use `std::sync::OnceLock`) so scanning is allocation-free on the
//!   hot path aside from the per-finding `String`.

use fancy_regex::Regex as FancyRegex;
use regex::Regex;
use sanitai_core::{
    chunk::{Chunk, DetectorScratch},
    finding::{Confidence, Finding, SpanKind, TransformChain},
    traits::{Category, Detector},
};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Entropy, Luhn, IBAN helpers
// ---------------------------------------------------------------------------

/// Shannon entropy in bits/byte. Range: 0.0 .. 8.0.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.as_bytes() {
        counts[*b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

/// Luhn checksum validation for PAN-like numeric strings. Ignores spaces/dashes.
pub fn luhn_valid(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 12 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for d in digits.iter().rev() {
        let mut v = *d;
        if alt {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        alt = !alt;
    }
    sum % 10 == 0
}

/// IBAN mod-97 validation per ISO 13616.
pub fn iban_valid(s: &str) -> bool {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.len() < 15 || cleaned.len() > 34 {
        return false;
    }
    if !cleaned.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    // Move first four chars to the end.
    let (head, tail) = cleaned.split_at(4);
    let rearranged: String = format!("{tail}{head}");
    // Convert letters A..Z -> 10..35.
    let mut numeric = String::with_capacity(rearranged.len() * 2);
    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            numeric.push(c);
        } else if c.is_ascii_uppercase() {
            let v = (c as u8 - b'A' + 10) as u32;
            numeric.push_str(&v.to_string());
        } else {
            return false;
        }
    }
    // Compute mod 97 in chunks to avoid u128 overflow on long strings.
    let mut rem: u32 = 0;
    for ch in numeric.chars() {
        let d = match ch.to_digit(10) {
            Some(x) => x,
            None => return false,
        };
        rem = (rem * 10 + d) % 97;
    }
    rem == 1
}

// ---------------------------------------------------------------------------
// Rule model
// ---------------------------------------------------------------------------

/// A compiled rule. `validate` is an optional post-match validator
/// (entropy threshold, Luhn, etc.). `confidence` is the default; validators
/// can demote.
#[allow(dead_code)]
struct Rule {
    id: &'static str,
    category: Category,
    base_confidence: Confidence,
    matcher: Matcher,
    validate: Option<fn(&str) -> Option<Confidence>>,
}

/// We use both `regex` (fast, no backrefs) and `fancy_regex` (lookaround) as
/// needed. Most patterns stick to `regex`.
enum Matcher {
    Plain(Regex),
    /// `(regex, capture_group_to_report)`. If `capture_group` > 0, the
    /// finding is the contents of that capture group instead of the full match.
    PlainCap(Regex, usize),
    Fancy(FancyRegex),
}

impl Matcher {
    fn find_iter<'h>(&self, hay: &'h str, out: &mut Vec<(usize, usize, &'h str)>) {
        match self {
            Matcher::Plain(re) => {
                for m in re.find_iter(hay) {
                    out.push((m.start(), m.end(), &hay[m.start()..m.end()]));
                }
            }
            Matcher::PlainCap(re, idx) => {
                for caps in re.captures_iter(hay) {
                    if let Some(g) = caps.get(*idx) {
                        out.push((g.start(), g.end(), &hay[g.start()..g.end()]));
                    }
                }
            }
            Matcher::Fancy(re) => {
                let mut pos = 0usize;
                while pos <= hay.len() {
                    match re.find_from_pos(hay, pos) {
                        Ok(Some(m)) => {
                            out.push((m.start(), m.end(), &hay[m.start()..m.end()]));
                            pos = if m.end() == m.start() {
                                m.end() + 1
                            } else {
                                m.end()
                            };
                        }
                        _ => break,
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

fn entropy_gate_3_5(s: &str) -> Option<Confidence> {
    if shannon_entropy(s) >= 3.5 {
        Some(Confidence::High)
    } else {
        None
    }
}

fn entropy_gate_4_0(s: &str) -> Option<Confidence> {
    if shannon_entropy(s) >= 4.0 {
        Some(Confidence::High)
    } else {
        None
    }
}

fn luhn_gate(s: &str) -> Option<Confidence> {
    if luhn_valid(s) {
        Some(Confidence::High)
    } else {
        None
    }
}

fn iban_gate(s: &str) -> Option<Confidence> {
    if iban_valid(s) {
        Some(Confidence::High)
    } else {
        None
    }
}

/// Generic assignment heuristic: the captured value is only a secret if it
/// has enough entropy — otherwise it might just be `password=changeme`.
fn generic_assign_gate(s: &str) -> Option<Confidence> {
    // The match text begins with the literal key prefix (e.g. "password=")
    // so we check entropy of the whole match. A high threshold prevents
    // noise like `password=password` or `secret=changeme`.
    let e = shannon_entropy(s);
    if e >= 4.2 {
        Some(Confidence::Medium)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Ruleset construction
// ---------------------------------------------------------------------------

fn build_rules() -> Vec<Rule> {
    // We `expect` during construction behind a OnceLock — a panic at
    // static init is acceptable because it is caught by our unit tests
    // and indicates a developer error, not untrusted input.
    let plain = |s: &str| Regex::new(s).expect("static regex must compile");
    let plain_cap = |s: &str, i: usize| (Regex::new(s).expect("static regex must compile"), i);
    let fancy = |s: &str| FancyRegex::new(s).expect("static fancy regex must compile");

    vec![
        // ---------------- AWS ----------------
        Rule {
            id: "aws_access_key_id",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bAKIA[0-9A-Z]{16}\b")),
            validate: None,
        },
        Rule {
            id: "aws_sts_access_key_id",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bASIA[0-9A-Z]{16}\b")),
            validate: None,
        },
        // AWS secret: 40-char base64-ish. Only emit if entropy is high AND
        // it is near an `aws` context. We capture the value of the assignment.
        Rule {
            id: "aws_secret_access_key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: {
                let (re, idx) = plain_cap(
                    r#"(?i)aws[_\- ]?(?:secret|sec)[_\- ]?(?:access[_\- ]?)?key[^A-Za-z0-9]{1,5}['"]?([A-Za-z0-9/+=]{40})\b"#,
                    1,
                );
                Matcher::PlainCap(re, idx)
            },
            validate: Some(entropy_gate_4_0),
        },
        // ---------------- GitHub ----------------
        Rule {
            id: "github_pat_classic",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bghp_[A-Za-z0-9]{36}\b")),
            validate: None,
        },
        Rule {
            id: "github_pat_fine_grained",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b")),
            validate: None,
        },
        Rule {
            id: "github_server_token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bghs_[A-Za-z0-9]{36}\b")),
            validate: None,
        },
        Rule {
            id: "github_oauth_token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bgho_[A-Za-z0-9]{36}\b")),
            validate: None,
        },
        Rule {
            id: "github_refresh_token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bghr_[A-Za-z0-9]{36}\b")),
            validate: None,
        },
        // ---------------- OpenAI / Anthropic ----------------
        Rule {
            id: "openai_api_key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bsk-[A-Za-z0-9]{48}\b")),
            validate: None,
        },
        Rule {
            id: "openai_project_key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bsk-proj-[A-Za-z0-9\-_]{100,150}\b")),
            validate: None,
        },
        Rule {
            id: "anthropic_api_key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bsk-ant-(?:api03-)?[A-Za-z0-9\-_]{93,}\b")),
            validate: None,
        },
        // ---------------- Stripe ----------------
        Rule {
            id: "stripe_live_secret_key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bsk_live_[A-Za-z0-9]{24,}\b")),
            validate: None,
        },
        Rule {
            id: "stripe_test_secret_key",
            category: Category::Credential,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\bsk_test_[A-Za-z0-9]{24,}\b")),
            validate: None,
        },
        Rule {
            id: "stripe_restricted_key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\brk_live_[A-Za-z0-9]{24,}\b")),
            validate: None,
        },
        Rule {
            id: "stripe_webhook_secret",
            category: Category::Secret,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bwhsec_[A-Za-z0-9]{32,}\b")),
            validate: None,
        },
        // ---------------- Slack ----------------
        Rule {
            id: "slack_token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bxox[baprs]-[0-9]{9,13}-[A-Za-z0-9-]{24,}\b")),
            validate: None,
        },
        // ---------------- JWT ----------------
        Rule {
            id: "jwt",
            category: Category::Credential,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(
                r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
            )),
            validate: None,
        },
        // ---------------- Private key PEM ----------------
        Rule {
            id: "private_key_pem",
            category: Category::Secret,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----",
            )),
            validate: None,
        },
        // ---------------- Database URLs ----------------
        Rule {
            id: "postgres_url",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"postgres(?:ql)?://[^\s:@/]+:[^\s@/]+@[^\s/]+")),
            validate: None,
        },
        Rule {
            id: "mysql_url",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"mysql://[^\s:@/]+:[^\s@/]+@[^\s/]+")),
            validate: None,
        },
        Rule {
            id: "mongodb_srv_url",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"mongodb(?:\+srv)?://[^\s:@/]+:[^\s@/]+@[^\s/]+")),
            validate: None,
        },
        Rule {
            id: "redis_url",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"redis(?:s)?://(?:[^\s:@/]+:)?[^\s@/]+@[^\s/]+")),
            validate: None,
        },
        // ---------------- Credit cards (Luhn validated) ----------------
        Rule {
            id: "credit_card_visa",
            category: Category::Pci,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\b4[0-9]{12}(?:[0-9]{3})?\b")),
            validate: Some(luhn_gate),
        },
        Rule {
            id: "credit_card_mastercard",
            category: Category::Pci,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(
                r"\b(?:5[1-5][0-9]{14}|2(?:2[2-9][0-9]{12}|[3-6][0-9]{13}|7[01][0-9]{12}|720[0-9]{12}))\b",
            )),
            validate: Some(luhn_gate),
        },
        Rule {
            id: "credit_card_amex",
            category: Category::Pci,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\b3[47][0-9]{13}\b")),
            validate: Some(luhn_gate),
        },
        // ---------------- IBAN (mod-97 validated) ----------------
        Rule {
            id: "iban",
            category: Category::Pii,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b")),
            validate: Some(iban_gate),
        },
        // ---------------- GCP ----------------
        Rule {
            id: "gcp_api_key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
            validate: None,
        },
        Rule {
            id: "gcp_service_account_private_key_id",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r#""private_key_id"\s*:\s*"[0-9a-f]{40}""#)),
            validate: None,
        },
        // ---------------- Azure ----------------
        Rule {
            id: "azure_storage_account_key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: {
                let (re, idx) = plain_cap(r"AccountKey=([A-Za-z0-9+/]{86}==)", 1);
                Matcher::PlainCap(re, idx)
            },
            validate: Some(entropy_gate_4_0),
        },
        Rule {
            id: "azure_sas_token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(
                r"sv=\d{4}-\d{2}-\d{2}&[A-Za-z0-9%=&_\-]+sig=[A-Za-z0-9%]+",
            )),
            validate: None,
        },
        // ---------------- Package registries ----------------
        Rule {
            id: "npm_token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bnpm_[0-9A-Za-z]{36}\b")),
            validate: None,
        },
        Rule {
            id: "pypi_token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bpypi-[0-9A-Za-z\-_]{32,}\b")),
            validate: None,
        },
        Rule {
            id: "rubygems_token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\brubygems_[0-9a-f]{48}\b")),
            validate: None,
        },
        // ---------------- HashiCorp Vault ----------------
        Rule {
            id: "vault_service_token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bhvs\.[A-Za-z0-9_\-]{24,}\b")),
            validate: None,
        },
        Rule {
            id: "vault_batch_token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bhvb\.[A-Za-z0-9_\-]{24,}\b")),
            validate: None,
        },
        Rule {
            id: "vault_recovery_token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bhvr\.[A-Za-z0-9_\-]{24,}\b")),
            validate: None,
        },
        Rule {
            id: "vault_legacy_token",
            category: Category::Credential,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\bs\.[0-9A-Za-z]{24,}\b")),
            validate: None,
        },
        // ---------------- Crypto ----------------
        Rule {
            id: "bitcoin_address",
            category: Category::HighEntropy,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\b1[0-9A-HJ-NP-Za-km-z]{25,34}\b")),
            validate: Some(entropy_gate_3_5),
        },
        Rule {
            id: "ethereum_address",
            category: Category::HighEntropy,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\b0x[0-9a-fA-F]{40}\b")),
            validate: None,
        },
        Rule {
            id: "bitcoin_wif_private_key",
            category: Category::Secret,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\b[5KL][0-9A-HJ-NP-Za-km-z]{50,51}\b")),
            validate: Some(entropy_gate_4_0),
        },
        // ---------------- Generic assignment heuristic ----------------
        Rule {
            id: "generic_password_assignment",
            category: Category::Secret,
            base_confidence: Confidence::Low,
            matcher: {
                let re = fancy(
                    r#"(?i)(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*['"]?([^\s'"]{8,256})"#,
                );
                Matcher::Fancy(re)
            },
            validate: Some(generic_assign_gate),
        },
    ]
}

// ---------------------------------------------------------------------------
// RegexDetector
// ---------------------------------------------------------------------------

/// A `Detector` backed by the static rule table in this module.
pub struct RegexDetector {
    rules: &'static [Rule],
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(build_rules).as_slice()
}

impl Default for RegexDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RegexDetector {
    pub fn new() -> Self {
        Self { rules: rules() }
    }

    /// Scan a plain `&str` and append findings to `out`. Used by both the
    /// `Detector` impl and by the transform-aware cascade in `transform.rs`.
    pub(crate) fn scan_str(
        &self,
        hay: &str,
        turn_id: &sanitai_core::turn::TurnId,
        offset_base: usize,
        transform: &TransformChain,
        out: &mut Vec<Finding>,
    ) {
        // Reuse a scratch vec. Allocating here is fine — the transform path
        // calls us per decoded blob, not per chunk.
        let mut matches: Vec<(usize, usize, &str)> = Vec::new();
        for rule in self.rules {
            matches.clear();
            rule.matcher.find_iter(hay, &mut matches);
            for (start, end, raw) in matches.drain(..) {
                let confidence = match rule.validate {
                    Some(f) => match f(raw) {
                        Some(c) => c,
                        None => continue,
                    },
                    None => rule.base_confidence.clone(),
                };
                out.push(Finding {
                    turn_id: turn_id.clone(),
                    detector_id: rule.id,
                    byte_range: (offset_base + start)..(offset_base + end),
                    matched_raw: raw.to_owned(),
                    transform: TransformChain(transform.0.clone()),
                    confidence,
                    span_kind: SpanKind::Single,
                    synthetic: raw.contains("SANITAI_FAKE"),
                });
            }
            // Log count only — never raw value.
            tracing::trace!(detector = rule.id, "scan complete");
        }
    }
}

impl Detector for RegexDetector {
    fn id(&self) -> &'static str {
        "regex"
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

    fn scan<'c>(&self, chunk: &Chunk<'c>, _scratch: &mut DetectorScratch, out: &mut Vec<Finding>) {
        // Chunks are documented as "always valid UTF-8".
        let hay = match std::str::from_utf8(chunk.bytes) {
            Ok(s) => s,
            Err(_) => {
                tracing::warn!("regex_detector: chunk was not valid UTF-8, skipping");
                return;
            }
        };
        let empty = TransformChain::default();
        self.scan_str(hay, &chunk.turn_id, 0, &empty, out);
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
    use std::sync::Arc;

    fn tid() -> sanitai_core::turn::TurnId {
        (Arc::new(PathBuf::from("/tmp/test")), 0)
    }

    fn scan_for(input: &str) -> Vec<Finding> {
        let det = RegexDetector::new();
        let chunk = Chunk {
            bytes: input.as_bytes(),
            offset_map: OffsetMap::new_linear(0),
            is_message_start: true,
            turn_id: tid(),
        };
        let mut scratch = DetectorScratch::default();
        let mut out = Vec::new();
        det.scan(&chunk, &mut scratch, &mut out);
        out
    }

    #[test]
    fn shannon_entropy_basic() {
        assert!(shannon_entropy("") < 0.001);
        assert!(shannon_entropy("aaaaaaaa") < 0.001);
        // Random-ish string should have higher entropy.
        assert!(shannon_entropy("abcdefghijklmnopqrstuvwxyz") > 4.0);
    }

    #[test]
    fn luhn_valid_known_cards() {
        // Stripe test card 4242 4242 4242 4242.
        assert!(luhn_valid("4242424242424242"));
        // With dashes and spaces.
        assert!(luhn_valid("4242-4242-4242-4242"));
        // Amex test card.
        assert!(luhn_valid("378282246310005"));
        // Invalid checksum.
        assert!(!luhn_valid("4242424242424243"));
    }

    #[test]
    fn iban_valid_known() {
        // Canonical IBAN example from ISO 13616.
        assert!(iban_valid("GB82WEST12345698765432"));
        assert!(!iban_valid("GB82WEST12345698765431"));
        // DE example.
        assert!(iban_valid("DE89370400440532013000"));
    }

    #[test]
    fn detects_aws_access_key() {
        let f = scan_for("here is the key: AKIAIOSFODNN7EXAMPLE stuff");
        assert!(f.iter().any(|f| f.detector_id == "aws_access_key_id"));
    }

    #[test]
    fn detects_github_pat() {
        let f = scan_for("token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 x");
        assert!(f.iter().any(|f| f.detector_id == "github_pat_classic"));
    }

    #[test]
    fn detects_openai_key() {
        let key: String = "sk-".to_string() + &"A".repeat(48);
        let f = scan_for(&format!("key = {}", key));
        assert!(f.iter().any(|f| f.detector_id == "openai_api_key"));
    }

    #[test]
    fn detects_jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9FYR50DAVcWiU";
        let f = scan_for(jwt);
        assert!(f.iter().any(|f| f.detector_id == "jwt"));
    }

    #[test]
    fn detects_pem_header() {
        let f = scan_for("-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
        assert!(f.iter().any(|f| f.detector_id == "private_key_pem"));
    }

    #[test]
    fn detects_postgres_url() {
        let f = scan_for("DB=postgres://user:hunter2@db.example.com/app");
        assert!(f.iter().any(|f| f.detector_id == "postgres_url"));
    }

    #[test]
    fn credit_card_requires_luhn() {
        let valid = scan_for("card: 4242424242424242");
        assert!(valid.iter().any(|f| f.detector_id == "credit_card_visa"));
        let invalid = scan_for("card: 4242424242424243");
        assert!(!invalid.iter().any(|f| f.detector_id == "credit_card_visa"));
    }

    #[test]
    fn iban_requires_mod97() {
        let valid = scan_for("IBAN GB82WEST12345698765432");
        assert!(valid.iter().any(|f| f.detector_id == "iban"));
    }

    #[test]
    fn gcp_api_key_detected() {
        // GCP API keys are AIza + exactly 35 [0-9A-Za-z\-_] chars (39 chars total)
        let f = scan_for("key=AIzaSyA-1234567890abcdefghijklmnopqrstu");
        assert!(f.iter().any(|f| f.detector_id == "gcp_api_key"));
    }

    #[test]
    fn generic_assignment_requires_entropy() {
        let low = scan_for("password=password");
        assert!(!low
            .iter()
            .any(|f| f.detector_id == "generic_password_assignment"));
        // High entropy passes.
        let high = scan_for("password = 'Xa7!pQ9vR2mK4nL8zT5jB3hC6d'");
        assert!(high
            .iter()
            .any(|f| f.detector_id == "generic_password_assignment"));
    }

    #[test]
    fn never_panics_on_empty() {
        let _ = scan_for("");
    }
}
