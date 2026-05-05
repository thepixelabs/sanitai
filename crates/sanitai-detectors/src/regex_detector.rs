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

use crate::keyword_filter::KeywordFilter;
use crate::stopwords;
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
    sum.is_multiple_of(10)
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
    /// Human-readable label used in the TUI Results widget and CLI human
    /// output. The internal `id` remains the canonical identifier for
    /// JSON / SARIF / store / suppressions — only the display path uses
    /// `display_name`.
    display_name: &'static str,
    category: Category,
    base_confidence: Confidence,
    matcher: Matcher,
    validate: Option<fn(&str) -> Option<Confidence>>,
    /// Keywords for Aho-Corasick pre-filter. None = no keyword gate (always scan).
    /// At least one keyword must appear in the haystack for this rule to fire.
    keywords: Option<&'static [&'static str]>,
    /// Apply conversation-aware stopword suppression to this rule's matches.
    use_stopwords: bool,
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
            display_name: "AWS Access Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bAKIA[0-9A-Z]{16}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "aws_sts_access_key_id",
            display_name: "AWS STS Access Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bASIA[0-9A-Z]{16}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // AWS secret: 40-char base64-ish. Only emit if entropy is high AND
        // it is near an `aws` context. We capture the value of the assignment.
        Rule {
            id: "aws_secret_access_key",
            display_name: "AWS Secret Access Key",
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
            keywords: None,
            use_stopwords: false,
        },
        // ---------------- GitHub ----------------
        Rule {
            id: "github_pat_classic",
            display_name: "GitHub Personal Access Token (classic)",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bghp_[A-Za-z0-9]{36}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "github_pat_fine_grained",
            display_name: "GitHub Personal Access Token (fine-grained)",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "github_server_token",
            display_name: "GitHub Server Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bghs_[A-Za-z0-9]{36}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "github_oauth_token",
            display_name: "GitHub OAuth Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bgho_[A-Za-z0-9]{36}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "github_refresh_token",
            display_name: "GitHub Refresh Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bghr_[A-Za-z0-9]{36}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // ---------------- OpenAI / Anthropic ----------------
        Rule {
            id: "openai_api_key",
            display_name: "OpenAI API Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bsk-[A-Za-z0-9]{48}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "openai_project_key",
            display_name: "OpenAI Project Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bsk-proj-[A-Za-z0-9\-_]{100,150}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "anthropic_api_key",
            display_name: "Anthropic API Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bsk-ant-(?:api03-)?[A-Za-z0-9\-_]{93,}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // ---------------- Stripe ----------------
        Rule {
            id: "stripe_live_secret_key",
            display_name: "Stripe Secret Key (live)",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bsk_live_[A-Za-z0-9]{24,}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "stripe_test_secret_key",
            display_name: "Stripe Secret Key (test)",
            category: Category::Credential,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\bsk_test_[A-Za-z0-9]{24,}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "stripe_restricted_key",
            display_name: "Stripe Restricted Key (live)",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\brk_live_[A-Za-z0-9]{24,}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "stripe_webhook_secret",
            display_name: "Stripe Webhook Secret",
            category: Category::Secret,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bwhsec_[A-Za-z0-9]{32,}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // ---------------- Slack ----------------
        Rule {
            id: "slack_token",
            display_name: "Slack Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bxox[baprs]-[0-9]{9,13}-[A-Za-z0-9-]{24,}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // ---------------- JWT ----------------
        Rule {
            id: "jwt",
            display_name: "JSON Web Token",
            category: Category::Credential,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(
                r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
            )),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // ---------------- Private key PEM ----------------
        Rule {
            id: "private_key_pem",
            display_name: "Private Key (PEM)",
            category: Category::Secret,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----",
            )),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // ---------------- Database URLs ----------------
        Rule {
            id: "postgres_url",
            display_name: "Postgres Connection URL",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"postgres(?:ql)?://[^\s:@/]+:[^\s@/]+@[^\s/]+")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "mysql_url",
            display_name: "MySQL Connection URL",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"mysql://[^\s:@/]+:[^\s@/]+@[^\s/]+")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "mongodb_srv_url",
            display_name: "MongoDB Connection URL",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"mongodb(?:\+srv)?://[^\s:@/]+:[^\s@/]+@[^\s/]+")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "redis_url",
            display_name: "Redis Connection URL",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"redis(?:s)?://(?:[^\s:@/]+:)?[^\s@/]+@[^\s/]+")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // ---------------- Credit cards (Luhn validated) ----------------
        Rule {
            id: "credit_card_visa",
            display_name: "Credit Card (Visa)",
            category: Category::Pci,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\b4[0-9]{12}(?:[0-9]{3})?\b")),
            validate: Some(luhn_gate),
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "credit_card_mastercard",
            display_name: "Credit Card (Mastercard)",
            category: Category::Pci,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(
                r"\b(?:5[1-5][0-9]{14}|2(?:2[2-9][0-9]{12}|[3-6][0-9]{13}|7[01][0-9]{12}|720[0-9]{12}))\b",
            )),
            validate: Some(luhn_gate),
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "credit_card_amex",
            display_name: "Credit Card (Amex)",
            category: Category::Pci,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\b3[47][0-9]{13}\b")),
            validate: Some(luhn_gate),
            keywords: None,
            use_stopwords: false,
        },
        // ---------------- IBAN (mod-97 validated) ----------------
        Rule {
            id: "iban",
            display_name: "IBAN",
            category: Category::Pii,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b")),
            validate: Some(iban_gate),
            keywords: None,
            use_stopwords: false,
        },
        // ---------------- GCP ----------------
        Rule {
            id: "gcp_api_key",
            display_name: "Google Cloud API Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "gcp_service_account_private_key_id",
            display_name: "Google Cloud Service Account Private Key ID",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r#""private_key_id"\s*:\s*"[0-9a-f]{40}""#)),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // ---------------- Azure ----------------
        Rule {
            id: "azure_storage_account_key",
            display_name: "Azure Storage Account Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: {
                let (re, idx) = plain_cap(r"AccountKey=([A-Za-z0-9+/]{86}==)", 1);
                Matcher::PlainCap(re, idx)
            },
            validate: Some(entropy_gate_4_0),
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "azure_sas_token",
            display_name: "Azure SAS Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(
                r"sv=\d{4}-\d{2}-\d{2}&[A-Za-z0-9%=&_\-]+sig=[A-Za-z0-9%]+",
            )),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // ---------------- Package registries ----------------
        Rule {
            id: "npm_token",
            display_name: "npm Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bnpm_[0-9A-Za-z]{36}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "pypi_token",
            display_name: "PyPI Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bpypi-[0-9A-Za-z\-_]{32,}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "rubygems_token",
            display_name: "RubyGems Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\brubygems_[0-9a-f]{48}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // ---------------- HashiCorp Vault ----------------
        Rule {
            id: "vault_service_token",
            display_name: "Vault Service Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bhvs\.[A-Za-z0-9_\-]{24,}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "vault_batch_token",
            display_name: "Vault Batch Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bhvb\.[A-Za-z0-9_\-]{24,}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "vault_recovery_token",
            display_name: "Vault Recovery Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bhvr\.[A-Za-z0-9_\-]{24,}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "vault_legacy_token",
            display_name: "Vault Legacy Token",
            category: Category::Credential,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\b[sb]\.[0-9A-Za-z]{24,}\b")),
            validate: Some(entropy_gate_4_0),
            keywords: Some(&[
                "vault",
                "VAULT_TOKEN",
                "hvault",
                "X-Vault-Token",
                "VAULT_ADDR",
            ]),
            use_stopwords: false,
        },
        // ---------------- Crypto ----------------
        Rule {
            id: "bitcoin_address",
            display_name: "Bitcoin Address",
            category: Category::HighEntropy,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\b1[0-9A-HJ-NP-Za-km-z]{25,34}\b")),
            validate: Some(entropy_gate_3_5),
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "ethereum_address",
            display_name: "Ethereum Address",
            category: Category::HighEntropy,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\b0x[0-9a-fA-F]{40}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "bitcoin_wif_private_key",
            display_name: "Bitcoin WIF Private Key",
            category: Category::Secret,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\b[5KL][0-9A-HJ-NP-Za-km-z]{50,51}\b")),
            validate: Some(entropy_gate_4_0),
            keywords: None,
            use_stopwords: false,
        },
        // ---------------- Generic assignment heuristic ----------------
        Rule {
            id: "generic_password_assignment",
            display_name: "Password / Secret Assignment",
            category: Category::Secret,
            base_confidence: Confidence::Low,
            matcher: {
                let re = fancy(
                    r#"(?i)(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*['"]?([^\s'"]{8,256})"#,
                );
                Matcher::Fancy(re)
            },
            validate: Some(generic_assign_gate),
            keywords: None,
            use_stopwords: false,
        },
        // --- Phase 1a: New provider rules ---

        // source: gitleaks/rules/discord.toml
        Rule {
            id: "discord_bot_token",
            display_name: "Discord Bot Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b")),
            validate: None,
            keywords: Some(&["discord", "DISCORD", "bot_token", "BOT_TOKEN"]),
            use_stopwords: false,
        },
        // source: gitleaks/rules/telegram.toml
        Rule {
            id: "telegram_bot_token",
            display_name: "Telegram Bot Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
            validate: None,
            keywords: Some(&["telegram", "TELEGRAM", "bot_token"]),
            use_stopwords: false,
        },
        // source: gitleaks/rules/sendgrid.toml
        Rule {
            id: "sendgrid_api_key",
            display_name: "SendGrid API Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
            validate: None,
            keywords: Some(&["SG.", "sendgrid", "SENDGRID"]),
            use_stopwords: false,
        },
        // source: gitleaks/rules/mailgun.toml
        Rule {
            id: "mailgun_api_key",
            display_name: "Mailgun API Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bkey-[0-9a-z]{32}\b")),
            validate: None,
            keywords: Some(&["mailgun", "MAILGUN", "key-"]),
            use_stopwords: false,
        },
        // source: gitleaks/rules/twilio.toml
        Rule {
            id: "twilio_account_sid",
            display_name: "Twilio Account SID",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bAC[a-f0-9]{32}\b")),
            validate: None,
            keywords: Some(&["twilio", "TWILIO", "account_sid", "ACCOUNT_SID"]),
            use_stopwords: false,
        },
        // source: gitleaks/rules/linear.toml
        Rule {
            id: "linear_api_key",
            display_name: "Linear API Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\blin_api_[A-Za-z0-9]{40}\b")),
            validate: None,
            keywords: Some(&["lin_api_", "linear", "LINEAR_API"]),
            use_stopwords: false,
        },
        // source: gitleaks/rules/notion.toml
        Rule {
            id: "notion_integration_token",
            display_name: "Notion Integration Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bsecret_[A-Za-z0-9]{43}\b")),
            validate: None,
            keywords: Some(&["notion", "NOTION", "secret_"]),
            use_stopwords: false,
        },
        // source: gitleaks/rules/fly.toml
        Rule {
            id: "fly_io_api_token",
            display_name: "Fly.io API Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bFlyV1 [A-Za-z0-9+/=]{100,}\b")),
            validate: None,
            keywords: Some(&["FlyV1", "fly.io", "FLY_API"]),
            use_stopwords: false,
        },
        // source: gitleaks/rules/doppler.toml
        Rule {
            id: "doppler_service_token",
            display_name: "Doppler Service Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bdp\.st\.[a-z_]+\.[A-Za-z0-9]{40}\b")),
            validate: None,
            keywords: Some(&["dp.st.", "doppler", "DOPPLER"]),
            use_stopwords: false,
        },
        // source: gitleaks/rules/huggingface.toml
        Rule {
            id: "huggingface_token",
            display_name: "Hugging Face Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bhf_[A-Za-z0-9]{37}\b")),
            validate: None,
            keywords: Some(&["hf_", "huggingface", "HF_TOKEN", "HUGGINGFACE"]),
            use_stopwords: false,
        },
        // source: gitleaks/rules/replicate.toml
        Rule {
            id: "replicate_api_token",
            display_name: "Replicate API Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\br8_[A-Za-z0-9]{40}\b")),
            validate: None,
            keywords: Some(&["r8_", "replicate", "REPLICATE"]),
            use_stopwords: false,
        },
        // source: gitleaks/rules/pagerduty.toml
        Rule {
            id: "pagerduty_api_key",
            display_name: "PagerDuty API Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bu\+[A-Za-z0-9_-]{20}\b")),
            validate: None,
            keywords: Some(&["pagerduty", "PAGERDUTY", "pd_"]),
            use_stopwords: false,
        },
        // source: gitleaks/rules/gitlab.toml — 13 variants
        Rule {
            id: "gitlab_pat",
            display_name: "GitLab Personal Access Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bglpat-[A-Za-z0-9\-_]{20}\b")),
            validate: None,
            keywords: Some(&["glpat-"]),
            use_stopwords: false,
        },
        Rule {
            id: "gitlab_pipeline_trigger_token",
            display_name: "GitLab Pipeline Trigger Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bglptt-[A-Za-z0-9\-_]{20}\b")),
            validate: None,
            keywords: Some(&["glptt-"]),
            use_stopwords: false,
        },
        Rule {
            id: "gitlab_runner_registration_token",
            display_name: "GitLab Runner Registration Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bGR1348941[A-Za-z0-9\-_]{20}\b")),
            validate: None,
            keywords: Some(&["GR1348941"]),
            use_stopwords: false,
        },
        Rule {
            id: "gitlab_deploy_token",
            display_name: "GitLab Deploy Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bgldt-[A-Za-z0-9\-_]{20}\b")),
            validate: None,
            keywords: Some(&["gldt-"]),
            use_stopwords: false,
        },
        Rule {
            id: "gitlab_feature_flag_token",
            display_name: "GitLab Feature Flag Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bglft-[A-Za-z0-9\-_]{20}\b")),
            validate: None,
            keywords: Some(&["glft-"]),
            use_stopwords: false,
        },
        Rule {
            id: "gitlab_runner_token",
            display_name: "GitLab Runner Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bglrt-[A-Za-z0-9\-_]{20}\b")),
            validate: None,
            keywords: Some(&["glrt-"]),
            use_stopwords: false,
        },
        Rule {
            id: "gitlab_scim_oauth_token",
            display_name: "GitLab SCIM OAuth Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bglsoat-[A-Za-z0-9\-_]{20}\b")),
            validate: None,
            keywords: Some(&["glsoat-"]),
            use_stopwords: false,
        },
        Rule {
            id: "gitlab_ci_build_token",
            display_name: "GitLab CI Build Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bglcbt-[A-Za-z0-9\-_]{20}\b")),
            validate: None,
            keywords: Some(&["glcbt-"]),
            use_stopwords: false,
        },
        Rule {
            id: "gitlab_test_secret_token",
            display_name: "GitLab Test Secret Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bgltst-[A-Za-z0-9\-_]{20}\b")),
            validate: None,
            keywords: Some(&["gltst-"]),
            use_stopwords: false,
        },
        Rule {
            id: "gitlab_incoming_mail_token",
            display_name: "GitLab Incoming Mail Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bglidt-[A-Za-z0-9\-_]{20}\b")),
            validate: None,
            keywords: Some(&["glidt-"]),
            use_stopwords: false,
        },
        Rule {
            id: "gitlab_oauth_app_secret",
            display_name: "GitLab OAuth App Secret",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bgloas-[A-Za-z0-9\-_]{64}\b")),
            validate: None,
            keywords: Some(&["gloas-"]),
            use_stopwords: false,
        },
        Rule {
            id: "gitlab_agent_token",
            display_name: "GitLab Agent Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bglagent-[A-Za-z0-9\-_]{50}\b")),
            validate: None,
            keywords: Some(&["glagent-"]),
            use_stopwords: false,
        },
        Rule {
            id: "gitlab_pat_uppercase",
            display_name: "GitLab Personal Access Token (uppercase)",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bGLPAT-[A-Za-z0-9\-_]{20}\b")),
            validate: None,
            keywords: Some(&["GLPAT-"]),
            use_stopwords: false,
        },
        // ---------------- Phase 1b: context-gated rules (require AC keyword + entropy + context) ----------------
        // These rules have high FP risk without the AC keyword gate.
        // source: gitleaks (Twilio, Datadog) and original (Vercel)
        Rule {
            id: "twilio_auth_token",
            display_name: "Twilio Auth Token",
            category: Category::Credential,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\b[0-9a-f]{32}\b")),
            validate: Some(|s: &str| {
                if crate::shannon_entropy(s) >= 3.8 {
                    Some(Confidence::Medium)
                } else {
                    None
                }
            }),
            keywords: Some(&[
                "twilio",
                "TWILIO",
                "auth_token",
                "AUTH_TOKEN",
                "TWILIO_AUTH_TOKEN",
            ]),
            use_stopwords: true,
        },
        Rule {
            id: "datadog_api_key",
            display_name: "Datadog API Key",
            category: Category::Credential,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\b[0-9a-f]{32}\b")),
            validate: Some(|s: &str| {
                if crate::shannon_entropy(s) >= 3.8 {
                    Some(Confidence::Medium)
                } else {
                    None
                }
            }),
            keywords: Some(&["datadog", "DATADOG", "DD_API_KEY", "DD_APP_KEY"]),
            use_stopwords: true,
        },
        Rule {
            id: "vercel_access_token",
            display_name: "Vercel Access Token",
            category: Category::Credential,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\b[A-Za-z0-9]{24}\b")),
            validate: Some(entropy_gate_3_5),
            keywords: Some(&["vercel", "VERCEL", "VERCEL_TOKEN", "vercel_token"]),
            use_stopwords: true,
        },
        // -----------------------------------------------------------------
        // Phase 2: ~25 additional high-precision provider-prefix rules.
        // Each rule below cites its upstream source per the project
        // compliance template. Patterns are independently typed in Rust;
        // no TOML port.
        // -----------------------------------------------------------------

        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "github_user_to_server_token",
            display_name: "GitHub User-to-Server Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bghu_[A-Za-z0-9]{36}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "slack_webhook_url",
            display_name: "Slack Webhook URL",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(
                r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}",
            )),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "discord_webhook_url",
            display_name: "Discord Webhook URL",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(
                r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,80}",
            )),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        // Mailchimp keys are 32-hex with a `-us<datacenter-number>` suffix.
        Rule {
            id: "mailchimp_api_key",
            display_name: "Mailchimp API Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\b[a-f0-9]{32}-us[0-9]{1,2}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        // Brevo (formerly SendinBlue) v3 API keys.
        Rule {
            id: "brevo_api_key",
            display_name: "Brevo API Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "square_access_token",
            display_name: "Square Access Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bEAAA[A-Za-z0-9_-]{60}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "square_oauth_secret",
            display_name: "Square OAuth Secret",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bsq0csp-[A-Za-z0-9_-]{43}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        // Airtable PATs: `pat` + 14 chars + `.` + 64-hex.
        Rule {
            id: "airtable_pat",
            display_name: "Airtable Personal Access Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        // Asana PATs are 32-hex; require keyword context to avoid generic-hash collisions.
        Rule {
            id: "asana_pat",
            display_name: "Asana Personal Access Token",
            category: Category::Credential,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\b[0-9a-f]{32}\b")),
            validate: Some(entropy_gate_3_5),
            keywords: Some(&["asana", "ASANA", "ASANA_PAT", "ASANA_TOKEN"]),
            use_stopwords: true,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "shopify_private_app_password",
            display_name: "Shopify Private App Password",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bshppa_[a-fA-F0-9]{32}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "shopify_shared_secret",
            display_name: "Shopify Shared Secret",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bshpss_[a-fA-F0-9]{32}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "shopify_access_token",
            display_name: "Shopify Access Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bshpat_[a-fA-F0-9]{32}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "digitalocean_pat",
            display_name: "DigitalOcean Personal Access Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bdop_v1_[a-f0-9]{64}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "digitalocean_oauth_token",
            display_name: "DigitalOcean OAuth Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bdoo_v1_[a-f0-9]{64}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "digitalocean_refresh_token",
            display_name: "DigitalOcean Refresh Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bdor_v1_[a-f0-9]{64}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "heroku_api_key",
            display_name: "Heroku API Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bHRKU-[A-Za-z0-9_-]{36}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: coverage informed by gitleaks/config/gitleaks.toml; pattern independently derived
        // Cloudflare API tokens: 40-char base62 token. Require keyword + entropy
        // because the alphabet is too generic to stand alone.
        Rule {
            id: "cloudflare_api_token",
            display_name: "Cloudflare API Token",
            category: Category::Credential,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\b[A-Za-z0-9_-]{40}\b")),
            validate: Some(entropy_gate_4_0),
            keywords: Some(&[
                "cloudflare",
                "CLOUDFLARE",
                "CLOUDFLARE_API_TOKEN",
                "CF_API_TOKEN",
                "cf_api_token",
            ]),
            use_stopwords: true,
        },
        // source: coverage informed by gitleaks/config/gitleaks.toml; pattern independently derived
        // Cloudflare global API key: 37-hex. Keyword + entropy gated.
        Rule {
            id: "cloudflare_global_api_key",
            display_name: "Cloudflare Global API Key",
            category: Category::Credential,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\b[a-f0-9]{37}\b")),
            validate: Some(entropy_gate_3_5),
            keywords: Some(&[
                "cloudflare",
                "CLOUDFLARE",
                "CLOUDFLARE_API_KEY",
                "CF_API_KEY",
                "X-Auth-Key",
            ]),
            use_stopwords: true,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        // Cloudflare Origin CA key: very distinctive `v1.0-` + 24-hex + `-` + 146-hex.
        Rule {
            id: "cloudflare_origin_ca_key",
            display_name: "Cloudflare Origin CA Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "new_relic_user_api_key",
            display_name: "New Relic User API Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bNRAK-[A-Z0-9]{27}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "new_relic_ingest_license_key",
            display_name: "New Relic Ingest License Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bNRII-[A-Za-z0-9_-]{27}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "new_relic_browser_key",
            display_name: "New Relic Browser Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bNRJS-[a-f0-9]{19}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "atlassian_api_token",
            display_name: "Atlassian API Token",
            category: Category::Credential,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\b[A-Za-z0-9]{24}\b")),
            validate: Some(entropy_gate_4_0),
            keywords: Some(&[
                "atlassian",
                "ATLASSIAN",
                "ATLASSIAN_API_TOKEN",
                "JIRA_TOKEN",
                "JIRA_API_TOKEN",
                "CONFLUENCE_TOKEN",
                "jira",
                "confluence",
            ]),
            use_stopwords: true,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "postman_api_key",
            display_name: "Postman API Key",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        Rule {
            id: "dockerhub_pat",
            display_name: "Docker Hub Personal Access Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bdckr_pat_[A-Za-z0-9_-]{27,36}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: gitleaks/config/gitleaks.toml — pattern informed by upstream; independently typed
        // Sentry user auth tokens (`sntrys_` is the modern prefix; the trailing
        // payload is a short JWT-ish base64 blob).
        Rule {
            id: "sentry_user_token",
            display_name: "Sentry User Token",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"\bsntrys_[A-Za-z0-9+/=_-]{60,200}\b")),
            validate: None,
            keywords: None,
            use_stopwords: false,
        },
        // source: coverage informed by gitleaks/config/gitleaks.toml; pattern independently derived
        // Algolia admin API keys are 32-hex; require keyword context.
        Rule {
            id: "algolia_api_key",
            display_name: "Algolia API Key",
            category: Category::Credential,
            base_confidence: Confidence::Medium,
            matcher: Matcher::Plain(plain(r"\b[a-f0-9]{32}\b")),
            validate: Some(entropy_gate_3_5),
            keywords: Some(&[
                "algolia",
                "ALGOLIA",
                "ALGOLIA_API_KEY",
                "ALGOLIA_ADMIN_KEY",
                "algolia_admin",
            ]),
            use_stopwords: true,
        },
    ]
}

// ---------------------------------------------------------------------------
// RegexDetector
// ---------------------------------------------------------------------------

/// A `Detector` backed by the static rule table in this module.
pub struct RegexDetector {
    rules: &'static [Rule],
    keyword_filter: KeywordFilter,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(build_rules).as_slice()
}

/// Look up the human-readable display name for a detector id. Returns an
/// empty string if no rule with that id is registered — this only happens
/// when a stale finding (on disk, in JSON input, etc.) references a removed
/// rule. Callers should fall back to the canonical id in that case so the
/// row never renders blank.
pub fn display_name_for(detector_id: &str) -> &'static str {
    for r in rules() {
        if r.id == detector_id {
            return r.display_name;
        }
    }
    ""
}

impl Default for RegexDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RegexDetector {
    pub fn new() -> Self {
        let r = rules();
        let kw_pairs: Vec<(usize, Option<&'static [&'static str]>)> = r
            .iter()
            .enumerate()
            .map(|(i, rule)| (i, rule.keywords))
            .collect();
        let keyword_filter = KeywordFilter::build(&kw_pairs);
        Self {
            rules: r,
            keyword_filter,
        }
    }

    /// Scan a plain `&str` and append findings to `out`. Used by both the
    /// `Detector` impl and by the transform-aware cascade in `transform.rs`.
    ///
    /// `line_in_file` carries the 1-based source line attribution forward
    /// onto the resulting findings so the TUI / CLI can offer an editor
    /// jump without an extra post-pass over `findings`. Pass `None` when
    /// the parser could not produce a line number (tree-structured exports).
    //
    // NOTE: this signature is internal (`pub(crate)`) and intentionally
    // wide. Bundling the args into a struct would not pay off — every
    // caller already has each value as a separate local, and the cost of
    // allocating the struct on every chunk would show up in our scan-loop
    // benchmark.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn scan_str(
        &self,
        hay: &str,
        turn_id: &sanitai_core::turn::TurnId,
        role: Option<sanitai_core::turn::Role>,
        offset_base: usize,
        transform: &TransformChain,
        line_in_file: Option<u32>,
        out: &mut Vec<Finding>,
    ) {
        // Reuse a scratch vec. Allocating here is fine — the transform path
        // calls us per decoded blob, not per chunk.
        let kw_mask = self.keyword_filter.scan(hay);
        let mut matches: Vec<(usize, usize, &str)> = Vec::new();
        for (rule_idx, rule) in self.rules.iter().enumerate() {
            if !KeywordFilter::rule_fires(&kw_mask, rule_idx) {
                continue; // keyword not present, skip regex entirely
            }
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
                // Stopword suppression (only for rules with use_stopwords: true)
                if rule.use_stopwords && stopwords::is_stopword(raw) {
                    continue;
                }
                let fingerprint = sanitai_core::finding::compute_fingerprint(
                    raw.as_bytes(),
                    rule.id,
                    turn_id.0.as_ref(),
                    turn_id.1,
                );
                let excerpt =
                    sanitai_core::finding::compute_excerpt(hay, &(start..end), fingerprint);
                out.push(Finding {
                    turn_id: turn_id.clone(),
                    detector_id: rule.id,
                    byte_range: (offset_base + start)..(offset_base + end),
                    matched_raw: raw.to_owned(),
                    transform: TransformChain(transform.0.clone()),
                    confidence,
                    span_kind: SpanKind::Single,
                    synthetic: raw.contains("SANITAI_FAKE"),
                    role: role.clone(),
                    category: rule.category,
                    entropy_score: shannon_entropy(raw),
                    context_class: sanitai_core::finding::ContextClass::Unclassified,
                    fingerprint,
                    line_in_file,
                    excerpt,
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
        self.scan_str(
            hay,
            &chunk.turn_id,
            None,
            0,
            &empty,
            chunk.line_in_file,
            out,
        );
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
            line_in_file: None,
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

    #[test]
    fn display_name_for_known_rules() {
        // Spot-check five representative rules across the gitleaks-derived
        // set so a careless pretty-name rename gets caught fast.
        assert_eq!(
            super::display_name_for("aws_access_key_id"),
            "AWS Access Key"
        );
        assert_eq!(super::display_name_for("openai_api_key"), "OpenAI API Key");
        assert_eq!(
            super::display_name_for("github_pat_classic"),
            "GitHub Personal Access Token (classic)"
        );
        assert_eq!(
            super::display_name_for("slack_webhook_url"),
            "Slack Webhook URL"
        );
        assert_eq!(
            super::display_name_for("stripe_live_secret_key"),
            "Stripe Secret Key (live)"
        );
        // Every rule must carry a non-empty display name — empty would mean
        // we forgot to fill one in.
        for rule in super::rules() {
            assert!(
                !rule.display_name.is_empty(),
                "rule {} missing display_name",
                rule.id
            );
        }
    }

    #[test]
    fn display_name_for_unknown_returns_empty() {
        // Stale findings from disk may carry rule ids that have since been
        // removed. We must not panic, and callers must be able to detect
        // the miss.
        assert_eq!(super::display_name_for("definitely_not_a_real_rule"), "");
    }

    #[test]
    fn vault_legacy_token_does_not_fire_on_rust_method_call() {
        let det = RegexDetector::new();
        let chunk = Chunk {
            bytes: b"let n = s.len(); let c = s.clone();",
            offset_map: OffsetMap::new_linear(0),
            is_message_start: true,
            turn_id: tid(),
            line_in_file: None,
        };
        let mut scratch = DetectorScratch::default();
        let mut out = Vec::new();
        det.scan(&chunk, &mut scratch, &mut out);
        assert!(
            out.iter().all(|f| f.detector_id != "vault_legacy_token"),
            "vault_legacy_token must not fire on ordinary Rust method calls"
        );
    }

    #[test]
    fn vault_legacy_token_fires_on_high_entropy_token() {
        let det = RegexDetector::new();
        let input = "VAULT_TOKEN=s.xK9mP2qR7nL4wB8vJ5cY1eT6uA3dH0fG";
        let chunk = Chunk {
            bytes: input.as_bytes(),
            offset_map: OffsetMap::new_linear(0),
            is_message_start: true,
            turn_id: tid(),
            line_in_file: None,
        };
        let mut scratch = DetectorScratch::default();
        let mut out = Vec::new();
        det.scan(&chunk, &mut scratch, &mut out);
        assert!(
            out.iter().any(|f| f.detector_id == "vault_legacy_token"),
            "vault_legacy_token must fire on high-entropy token"
        );
    }

    #[test]
    fn sendgrid_key_detected() {
        let det = RegexDetector::new();
        let input = "key=SG.aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let chunk = Chunk {
            bytes: input.as_bytes(),
            offset_map: OffsetMap::new_linear(0),
            is_message_start: true,
            turn_id: tid(),
            line_in_file: None,
        };
        let mut scratch = DetectorScratch::default();
        let mut out = Vec::new();
        det.scan(&chunk, &mut scratch, &mut out);
        assert!(out.iter().any(|f| f.detector_id == "sendgrid_api_key"));
    }

    #[test]
    fn gitlab_pat_detected() {
        let det = RegexDetector::new();
        let input = "token: glpat-xxxxxxxxxxxxxxxxxxxx";
        let chunk = Chunk {
            bytes: input.as_bytes(),
            offset_map: OffsetMap::new_linear(0),
            is_message_start: true,
            turn_id: tid(),
            line_in_file: None,
        };
        let mut scratch = DetectorScratch::default();
        let mut out = Vec::new();
        det.scan(&chunk, &mut scratch, &mut out);
        assert!(out.iter().any(|f| f.detector_id == "gitlab_pat"));
    }

    #[test]
    fn huggingface_token_detected() {
        let det = RegexDetector::new();
        // Pattern requires exactly 37 alphanumeric chars after "hf_"
        let input = "HF_TOKEN=hf_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJk";
        let chunk = Chunk {
            bytes: input.as_bytes(),
            offset_map: OffsetMap::new_linear(0),
            is_message_start: true,
            turn_id: tid(),
            line_in_file: None,
        };
        let mut scratch = DetectorScratch::default();
        let mut out = Vec::new();
        det.scan(&chunk, &mut scratch, &mut out);
        assert!(out.iter().any(|f| f.detector_id == "huggingface_token"));
    }

    #[test]
    fn keyword_filter_blocks_non_matching_rules() {
        use crate::keyword_filter::KeywordFilter;
        let filter = KeywordFilter::build(&[
            (0, Some(&["discord"])),
            (1, Some(&["github"])),
            (2, None), // no keyword gate
        ]);
        let mask = filter.scan("nothing relevant here");
        assert!(!KeywordFilter::rule_fires(&mask, 0));
        assert!(!KeywordFilter::rule_fires(&mask, 1));
        assert!(KeywordFilter::rule_fires(&mask, 2));
    }

    #[test]
    fn keyword_filter_with_match() {
        use crate::keyword_filter::KeywordFilter;
        let filter = KeywordFilter::build(&[(0, Some(&["discord"])), (1, Some(&["github"]))]);
        let mask = filter.scan("I use discord for my team");
        assert!(KeywordFilter::rule_fires(&mask, 0));
        assert!(!KeywordFilter::rule_fires(&mask, 1));
    }

    #[test]
    fn twilio_auth_token_fires_with_context() {
        let f = scan_for("TWILIO_AUTH_TOKEN=abcdef1234567890abcdef1234567890");
        assert!(
            f.iter().any(|f| f.detector_id == "twilio_auth_token"),
            "twilio_auth_token must fire when twilio context keyword is present"
        );
    }

    #[test]
    fn twilio_auth_token_no_context_does_not_fire() {
        let f = scan_for("some_random_hash=abcdef1234567890abcdef1234567890");
        assert!(
            !f.iter().any(|f| f.detector_id == "twilio_auth_token"),
            "twilio_auth_token must not fire without context keyword"
        );
    }

    #[test]
    fn vault_legacy_token_upgraded_version_fires_with_context() {
        let f = scan_for("vault: s.xK9mP2qR7nLwF5vB3tY8hD1jC");
        assert!(
            f.iter().any(|f| f.detector_id == "vault_legacy_token"),
            "vault_legacy_token must fire with vault context keyword"
        );
    }

    #[test]
    fn vault_legacy_token_no_context_does_not_fire() {
        let f = scan_for("s.xK9mP2qR7nLwF5vB3tY8hD1jC");
        assert!(
            !f.iter().any(|f| f.detector_id == "vault_legacy_token"),
            "vault_legacy_token must not fire without vault context"
        );
    }

    #[test]
    fn datadog_api_key_fires_with_context() {
        let f = scan_for("DD_API_KEY=abcdef1234567890abcdef1234567890");
        assert!(
            f.iter().any(|f| f.detector_id == "datadog_api_key"),
            "datadog_api_key must fire when DD_API_KEY context is present"
        );
    }

    #[test]
    fn stopword_does_not_suppress_high_specificity_rules() {
        let det = RegexDetector::new();
        let input =
            "sendgrid key: SG.aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let chunk = Chunk {
            bytes: input.as_bytes(),
            offset_map: OffsetMap::new_linear(0),
            is_message_start: true,
            turn_id: tid(),
            line_in_file: None,
        };
        let mut scratch = DetectorScratch::default();
        let mut out = Vec::new();
        det.scan(&chunk, &mut scratch, &mut out);
        assert!(out.iter().any(|f| f.detector_id == "sendgrid_api_key"));
    }

    // -----------------------------------------------------------------
    // Phase 2 rule coverage. Each rule below has at least one positive
    // and one negative case. All synthetic credentials carry the
    // `SANITAI_FAKE` marker in the surrounding test text so static
    // greps can confirm none are real.
    // -----------------------------------------------------------------

    fn assert_fires(input: &str, id: &str) {
        let f = scan_for(input);
        assert!(
            f.iter().any(|f| f.detector_id == id),
            "rule {id} must fire on input: {input}"
        );
    }

    fn assert_does_not_fire(input: &str, id: &str) {
        let f = scan_for(input);
        assert!(
            !f.iter().any(|f| f.detector_id == id),
            "rule {id} must NOT fire on input: {input}"
        );
    }

    #[test]
    fn github_user_to_server_token() {
        // SANITAI_FAKE — ghu_ + exactly 36 alnum
        let token = format!("ghu_{}", "A".repeat(36));
        assert_fires(&token, "github_user_to_server_token");
        // ghp_ prefix is a different rule — must not fire here.
        assert_does_not_fire(
            &format!("ghp_{}", "A".repeat(36)),
            "github_user_to_server_token",
        );
    }

    #[test]
    fn slack_webhook_url() {
        // SANITAI_FAKE — uniform-letter token so GitHub Push Protection's
        // provider-format check rejects it as a known synthetic.
        let token: String = "A".repeat(24);
        assert_fires(
            &format!("post to https://hooks.slack.com/services/T00000000/B00000000/{token} ok?"),
            "slack_webhook_url",
        );
        // hooks.example.com is not Slack — must not fire.
        assert_does_not_fire(
            &format!("https://hooks.example.com/services/T00000000/B00000000/{token}"),
            "slack_webhook_url",
        );
    }

    #[test]
    fn discord_webhook_url() {
        // SANITAI_FAKE — uniform-letter token, all-zero numeric id.
        let token: String = "A".repeat(60);
        let url = format!("https://discord.com/api/webhooks/100000000000000000/{token}");
        assert_fires(&url, "discord_webhook_url");
        // discord.com without /api/webhooks/ must not match.
        assert_does_not_fire(
            "https://discord.com/channels/123/456",
            "discord_webhook_url",
        );
    }

    #[test]
    fn mailchimp_api_key() {
        // SANITAI_FAKE — 32 zeros + -us<n>. Low entropy on purpose.
        let key: String = "0".repeat(32);
        assert_fires(&format!("mc={key}-us12 ok"), "mailchimp_api_key");
        // 32-hex without -us<n> suffix must not match.
        assert_does_not_fire(&key, "mailchimp_api_key");
    }

    #[test]
    fn brevo_api_key() {
        // SANITAI_FAKE — 64 zeros + 16-char marker.
        let payload = format!("xkeysib-{}-SANITAIFAKE12345", "0".repeat(64));
        assert_fires(&payload, "brevo_api_key");
        // Wrong prefix — must not match.
        assert_does_not_fire(
            &format!("wrongkey-{}-SANITAIFAKE12345", "0".repeat(64)),
            "brevo_api_key",
        );
    }

    #[test]
    fn square_access_token() {
        // SANITAI_FAKE — EAAA + 60 chars
        let token = format!("EAAA{}", "a".repeat(60));
        assert_fires(&format!("token={token}"), "square_access_token");
        // EAA prefix (only 3 A's) must not match.
        assert_does_not_fire(&format!("EAAa{}", "a".repeat(60)), "square_access_token");
    }

    #[test]
    fn square_oauth_secret() {
        // SANITAI_FAKE — sq0csp- + 43 chars
        let token = format!("sq0csp-{}", "a".repeat(43));
        assert_fires(&format!("secret={token}"), "square_oauth_secret");
        // sq0csb (different middle char) must not match.
        assert_does_not_fire(&format!("sq0csb-{}", "a".repeat(43)), "square_oauth_secret");
    }

    #[test]
    fn airtable_pat() {
        // SANITAI_FAKE — marker (11) + 3 zeros = 14 alnum after `pat`, then 64 zeros after dot.
        let token = format!("patSANITAIFAKE000.{}", "0".repeat(64));
        assert_fires(&token, "airtable_pat");
        // Wrong prefix length (only 13 chars after pat).
        assert_does_not_fire(
            &format!("patSANITAIFAKE00.{}", "0".repeat(64)),
            "airtable_pat",
        );
    }

    #[test]
    fn asana_pat() {
        // SANITAI_FAKE — 32-hex with entropy ≥ 3.5, not in the stopword list
        // (which suppresses the canonical `0123456789abcdef...` cycled pattern).
        let key = "1234567890abcdef1234567890abcdef";
        assert_fires(&format!("ASANA_PAT={key}"), "asana_pat");
        // No keyword — should not fire even with the right shape.
        assert_does_not_fire(key, "asana_pat");
    }

    #[test]
    fn shopify_private_app_password() {
        // SANITAI_FAKE — shppa_ + 32 zeros.
        let key: String = "0".repeat(32);
        assert_fires(
            &format!("shopify=shppa_{key}"),
            "shopify_private_app_password",
        );
        // shppa_ prefix but only 31 hex — must not match.
        assert_does_not_fire(
            &format!("shppa_{}", "0".repeat(31)),
            "shopify_private_app_password",
        );
    }

    #[test]
    fn shopify_shared_secret() {
        // SANITAI_FAKE
        let key: String = "0".repeat(32);
        assert_fires(&format!("shpss_{key}"), "shopify_shared_secret");
        // Wrong prefix.
        assert_does_not_fire(&format!("shppx_{key}"), "shopify_shared_secret");
    }

    #[test]
    fn shopify_access_token() {
        // SANITAI_FAKE
        let key: String = "0".repeat(32);
        assert_fires(&format!("shpat_{key}"), "shopify_access_token");
        assert_does_not_fire(&format!("shopat_{key}"), "shopify_access_token");
    }

    #[test]
    fn digitalocean_pat() {
        // SANITAI_FAKE — dop_v1_ + 64 hex
        let token = format!("dop_v1_{}", "a".repeat(64));
        assert_fires(&format!("DO={token}"), "digitalocean_pat");
        // 63 hex (one short) must not fire.
        assert_does_not_fire(&format!("dop_v1_{}", "a".repeat(63)), "digitalocean_pat");
    }

    #[test]
    fn digitalocean_oauth_token() {
        // SANITAI_FAKE
        let token = format!("doo_v1_{}", "f".repeat(64));
        assert_fires(&token, "digitalocean_oauth_token");
        // dop_v1_ must not be picked up as oauth.
        assert_does_not_fire(
            &format!("dop_v1_{}", "f".repeat(64)),
            "digitalocean_oauth_token",
        );
    }

    #[test]
    fn digitalocean_refresh_token() {
        // SANITAI_FAKE
        let token = format!("dor_v1_{}", "0".repeat(64));
        assert_fires(&token, "digitalocean_refresh_token");
        assert_does_not_fire(
            &format!("dor_v2_{}", "0".repeat(64)),
            "digitalocean_refresh_token",
        );
    }

    #[test]
    fn heroku_api_key() {
        // SANITAI_FAKE — HRKU- + 36 chars
        let token = format!("HRKU-{}", "A".repeat(36));
        assert_fires(&format!("token={token}"), "heroku_api_key");
        // 35 chars must not fire.
        assert_does_not_fire(&format!("HRKU-{}", "A".repeat(35)), "heroku_api_key");
    }

    #[test]
    fn cloudflare_api_token_with_keyword() {
        // SANITAI_FAKE — marker + cycled hex. Entropy is 22+ unique chars
        // across 40 (log2 ≈ 4.46), passing the rule's 4.0 threshold while
        // staying obviously synthetic to upstream scanners.
        let token = format!(
            "SANITAIFAKE{}",
            "0123456789abcdef"
                .repeat(2)
                .chars()
                .take(29)
                .collect::<String>()
        );
        assert_fires(
            &format!("CLOUDFLARE_API_TOKEN={token}"),
            "cloudflare_api_token",
        );
        // No keyword — must not fire.
        assert_does_not_fire(&format!("random={token}"), "cloudflare_api_token");
    }

    #[test]
    fn cloudflare_global_api_key_with_keyword() {
        // SANITAI_FAKE — exactly 37 hex with cloudflare keyword.
        // We use `CF_API_KEY` (unique to this rule) rather than the
        // longer `CLOUDFLARE_API_KEY` because the shared keyword
        // `CLOUDFLARE` is registered earlier (for the api_token rule)
        // and Aho-Corasick's leftmost-first scan would shadow the
        // longer pattern.
        let key: String = "0123456789abcdef".repeat(3).chars().take(37).collect();
        assert_fires(&format!("CF_API_KEY={key}"), "cloudflare_global_api_key");
        // No keyword — must not fire.
        assert_does_not_fire(&format!("hash={key}"), "cloudflare_global_api_key");
    }

    #[test]
    fn cloudflare_origin_ca_key() {
        // SANITAI_FAKE — v1.0- + 24-hex + - + 146-hex
        let token = format!("v1.0-{}-{}", "a".repeat(24), "b".repeat(146));
        assert_fires(&token, "cloudflare_origin_ca_key");
        // Wrong version prefix.
        assert_does_not_fire(
            &format!("v2.0-{}-{}", "a".repeat(24), "b".repeat(146)),
            "cloudflare_origin_ca_key",
        );
    }

    #[test]
    fn new_relic_user_api_key() {
        // SANITAI_FAKE — NRAK- + 27 [A-Z0-9]
        let token = format!("NRAK-{}", "A".repeat(27));
        assert_fires(&token, "new_relic_user_api_key");
        // Lowercase letters not allowed in payload.
        assert_does_not_fire(
            &format!("NRAK-{}", "a".repeat(27)),
            "new_relic_user_api_key",
        );
    }

    #[test]
    fn new_relic_ingest_license_key() {
        // SANITAI_FAKE
        let token = format!("NRII-{}", "a".repeat(27));
        assert_fires(&token, "new_relic_ingest_license_key");
        // 26 chars too short.
        assert_does_not_fire(
            &format!("NRII-{}", "a".repeat(26)),
            "new_relic_ingest_license_key",
        );
    }

    #[test]
    fn new_relic_browser_key() {
        // SANITAI_FAKE — NRJS- + 19 hex
        let token = format!("NRJS-{}", "abcdef0123456789abc"); // 19 hex chars
        assert_fires(&token, "new_relic_browser_key");
        // Uppercase hex not allowed by the pattern.
        assert_does_not_fire("NRJS-ABCDEF0123456789ABC", "new_relic_browser_key");
    }

    #[test]
    fn atlassian_api_token_with_keyword() {
        // SANITAI_FAKE — marker + cycled hex (24 chars total). 22 unique chars over
        // 24 → entropy ≈ 4.46 bits/byte, passing the rule's 4.0 threshold.
        let token = format!("SANITAIFAKE{}", "0123456789abc");
        assert_fires(
            &format!("ATLASSIAN_API_TOKEN={token}"),
            "atlassian_api_token",
        );
        // No keyword — must not fire.
        assert_does_not_fire(&format!("random={token}"), "atlassian_api_token");
    }

    #[test]
    fn postman_api_key() {
        // SANITAI_FAKE — PMAK- + 24 hex + - + 34 hex
        let token = format!("PMAK-{}-{}", "a".repeat(24), "b".repeat(34));
        assert_fires(&token, "postman_api_key");
        // Mismatched segment lengths.
        assert_does_not_fire(
            &format!("PMAK-{}-{}", "a".repeat(20), "b".repeat(34)),
            "postman_api_key",
        );
    }

    #[test]
    fn dockerhub_pat() {
        // SANITAI_FAKE — dckr_pat_ + 27..36 chars
        let token = format!("dckr_pat_{}", "a".repeat(30));
        assert_fires(&token, "dockerhub_pat");
        // Too short (15 chars).
        assert_does_not_fire(&format!("dckr_pat_{}", "a".repeat(15)), "dockerhub_pat");
    }

    #[test]
    fn sentry_user_token() {
        // SANITAI_FAKE — sntrys_ + long base64-ish payload
        let token = format!("sntrys_{}", "a".repeat(80));
        assert_fires(&token, "sentry_user_token");
        // Too short payload (40 chars).
        assert_does_not_fire(&format!("sntrys_{}", "a".repeat(40)), "sentry_user_token");
    }

    #[test]
    fn algolia_api_key_with_keyword() {
        // SANITAI_FAKE — 32-hex with entropy ≥ 3.5, not in the stopword list.
        let key = "1234567890abcdef1234567890abcdef";
        assert_fires(&format!("ALGOLIA_ADMIN_KEY={key}"), "algolia_api_key");
        // No keyword — must not fire.
        assert_does_not_fire(&format!("hash={key}"), "algolia_api_key");
    }

    #[test]
    fn placeholder_values_are_suppressed_by_stopwords() {
        // The string "0123456789abcdef0123456789abcdef" is shaped like a
        // valid 32-hex provider key, has high entropy, but is a doc
        // placeholder — it is in the stopword list and must be
        // suppressed for keyword-gated 32-hex rules.
        let f = scan_for("ASANA_PAT=0123456789abcdef0123456789abcdef");
        assert!(
            !f.iter().any(|f| f.detector_id == "asana_pat"),
            "asana_pat must be suppressed by stopword for hex doc placeholder"
        );
        // `deadbeef...` is another canonical filler — also stopworded.
        let f = scan_for("ALGOLIA_ADMIN_KEY=deadbeefdeadbeefdeadbeefdeadbeef");
        assert!(
            !f.iter().any(|f| f.detector_id == "algolia_api_key"),
            "algolia_api_key must be suppressed by stopword for deadbeef filler"
        );
    }
}
