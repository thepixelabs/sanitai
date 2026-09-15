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
use sha2::{Digest, Sha256};
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
/// IBAN length by country code, per the SWIFT IBAN Registry. An IBAN whose
/// country is not in the registry, or whose length is wrong for it, is not
/// an IBAN no matter what mod-97 says — 1 in 97 random alphanumerics pass
/// the checksum, and trademark ids (`US50…`), VINs and tracking numbers
/// were doing exactly that.
pub fn iban_length_for(country: &str) -> Option<usize> {
    Some(match country {
        "AL" => 28,
        "AD" => 24,
        "AT" => 20,
        "AZ" => 28,
        "BH" => 22,
        "BY" => 28,
        "BE" => 16,
        "BA" => 20,
        "BR" => 29,
        "BG" => 22,
        "BI" => 27,
        "CR" => 22,
        "HR" => 21,
        "CY" => 28,
        "CZ" => 24,
        "DK" => 18,
        "DJ" => 27,
        "DO" => 28,
        "EG" => 29,
        "SV" => 28,
        "EE" => 20,
        "FK" => 18,
        "FO" => 18,
        "FI" => 18,
        "FR" => 27,
        "GE" => 22,
        "DE" => 22,
        "GI" => 23,
        "GR" => 27,
        "GL" => 18,
        "GT" => 28,
        "VA" => 22,
        "HU" => 28,
        "IS" => 26,
        "IQ" => 23,
        "IE" => 22,
        "IL" => 23,
        "IT" => 27,
        "JO" => 30,
        "KZ" => 20,
        "XK" => 20,
        "KW" => 30,
        "LV" => 21,
        "LB" => 28,
        "LY" => 25,
        "LI" => 21,
        "LT" => 20,
        "LU" => 20,
        "MT" => 31,
        "MR" => 27,
        "MU" => 30,
        "MD" => 24,
        "MC" => 27,
        "MN" => 20,
        "ME" => 22,
        "NL" => 18,
        "NI" => 28,
        "MK" => 19,
        "NO" => 15,
        "OM" => 23,
        "PK" => 24,
        "PS" => 29,
        "PL" => 28,
        "PT" => 25,
        "QA" => 29,
        "RO" => 24,
        "RU" => 33,
        "LC" => 32,
        "SM" => 27,
        "ST" => 25,
        "SA" => 24,
        "RS" => 22,
        "SC" => 31,
        "SK" => 24,
        "SI" => 19,
        "SO" => 23,
        "ES" => 24,
        "SD" => 18,
        "SE" => 24,
        "CH" => 21,
        "TL" => 23,
        "TN" => 24,
        "TR" => 26,
        "UA" => 29,
        "AE" => 23,
        "GB" => 22,
        "VG" => 24,
        "YE" => 30,
        _ => return None,
    })
}

pub fn iban_valid(s: &str) -> bool {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.len() < 15 || cleaned.len() > 34 {
        return false;
    }
    if iban_length_for(&cleaned[..2]) != Some(cleaned.len()) {
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

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58Check validation for a Bitcoin P2PKH address (version byte `0x00`,
/// the `1…` form). True only if the string decodes to exactly 25 bytes whose
/// trailing 4 bytes equal the first 4 bytes of SHA256(SHA256(first 21 bytes)).
///
/// A random base58-looking run (hex hash, base64 fragment, opaque id) passes
/// with probability ~2^-32, which is why this replaces the entropy heuristic:
/// hex and base64 are high-entropy by construction, so entropy cannot tell a
/// wallet address from an MD5 sum.
///
/// Out of scope: P2SH `3…` (version `0x05`) and bech32/bech32m `bc1…` addresses
/// use different prefixes/checksums and are not matched by the `1…` rule.
pub fn base58check_p2pkh_valid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 26 || bytes.len() > 35 {
        return false;
    }
    // Big-number decode into little-endian base-256 limbs (u128 would overflow
    // at 34 chars).
    let mut limbs: Vec<u8> = Vec::with_capacity(25);
    for &c in bytes {
        let mut carry = match BASE58_ALPHABET.iter().position(|&a| a == c) {
            Some(v) => v as u32,
            None => return false,
        };
        for limb in limbs.iter_mut() {
            carry += u32::from(*limb) * 58;
            *limb = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            limbs.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Each leading '1' encodes a single 0x00 byte that the big-number decode
    // cannot represent.
    let leading_ones = bytes.iter().take_while(|&&c| c == b'1').count();
    let mut decoded = vec![0u8; leading_ones];
    decoded.extend(limbs.iter().rev());
    if decoded.len() != 25 || decoded[0] != 0x00 {
        return false;
    }
    let (payload, checksum) = decoded.split_at(21);
    let double_sha = Sha256::digest(Sha256::digest(payload));
    double_sha[..4] == *checksum
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

/// A Bitcoin address is a public identifier: a valid checksum earns the rule's
/// Medium, never a promotion to High (that is reserved for the WIF private key).
fn base58check_gate(s: &str) -> Option<Confidence> {
    if base58check_p2pkh_valid(s) {
        Some(Confidence::Medium)
    } else {
        None
    }
}

/// Google API keys that are public by design and published in Google's own
/// docs or shipped inside YouTube's web/mobile clients. They pass the
/// `AIza…` format check but are nobody's secret; a scanner that reports the
/// key from every `youtubei/v1/player?key=` URL trains people to ignore it.
const PUBLIC_GOOGLE_API_KEYS: &[&str] = &[
    // Example key in developers.google.com credential docs.
    "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe",
    // YouTube InnerTube: web client.
    "AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8",
    // YouTube InnerTube: Android client.
    "AIzaSyA8eiZmM1FaDVjRy-df2KTyQ_vz_yYM39w",
];

fn gcp_api_key_gate(s: &str) -> Option<Confidence> {
    if PUBLIC_GOOGLE_API_KEYS.contains(&s) {
        None
    } else {
        Some(Confidence::High)
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
/// The value part of a `key = value` match: everything after the first
/// `=`/`:` separator, minus surrounding whitespace and an opening quote.
fn assignment_value(s: &str) -> &str {
    let sep = s.find(['=', ':']).map(|i| i + 1).unwrap_or(0);
    s[sep..].trim_start().trim_start_matches(['\'', '"', '`'])
}

/// True when an assignment's right-hand side is not a literal secret: a
/// reference to one (`process.env.X`, `${X}`, `!secret x`), a type
/// annotation (`password: string,`), a call (`token = randomBytes(32)`) or
/// a placeholder (`<your-key>`, `changeme`, `sk-...`). In a corpus of
/// developer transcripts these were more than two thirds of the generic
/// assignment hits — code that *handles* a secret is not a leak of one.
fn is_non_literal_value(v: &str) -> bool {
    if v.is_empty() {
        return true;
    }
    // Templates and placeholders by their first character(s). `$` is only a
    // reference when it looks like one — `${DB_PASS}`, `$(cmd)`, `$DB_PASS` —
    // so a password that merely starts with `$` or `!` still counts.
    if v.starts_with(['<', '[', '{', '('])
        || v.starts_with("...")
        || v.starts_with("***")
        || v.starts_with("${")
        || v.starts_with("$(")
        || (v.starts_with('%') && v.ends_with('%'))
        || (v.starts_with('$')
            && v.len() > 1
            && v[1..]
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
    {
        return true;
    }
    // A call (`randomBytes(32)`, `os.getenv("X")`) or index expression.
    if let Some(paren) = v.find('(') {
        let callee = &v[..paren];
        if !callee.is_empty()
            && callee
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':')
        {
            return true;
        }
    }
    if v.contains("[\"") || v.contains("['") {
        return true;
    }
    // Dotted access rooted in a well-known runtime/config object. Rooting on
    // a known name (rather than "anything dotted") keeps JWTs and dotted
    // tokens intact.
    const ROOTS: &[&str] = &[
        "process",
        "os",
        "env",
        "ENV",
        "environ",
        "System",
        "Deno",
        "Bun",
        "import",
        "config",
        "configs",
        "cfg",
        "conf",
        "settings",
        "this",
        "self",
        "ctx",
        "context",
        "req",
        "request",
        "res",
        "params",
        "options",
        "opts",
        "args",
        "props",
        "state",
        "data",
        "secrets",
        "secret",
        "vars",
        "var",
        "local",
        "module",
        "credentials",
        "creds",
        "keychain",
        "vault",
        "window",
        "globalThis",
        "global",
        "app",
        "Rails",
        "django",
        "flask",
        "std",
        "crate",
        "super",
    ];
    if let Some((root, rest)) = v.split_once(['.', ':']) {
        if !rest.is_empty()
            && ROOTS.contains(&root)
            && rest.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_' || c == ':')
        {
            return true;
        }
    }
    // Type annotations in signatures / interfaces / SQL DDL.
    const TYPES: &[&str] = &[
        "string",
        "String",
        "str",
        "&str",
        "bool",
        "boolean",
        "number",
        "int",
        "integer",
        "float",
        "Option",
        "Vec",
        "Box",
        "Secret",
        "SecretString",
        "varchar",
        "VARCHAR",
        "nvarchar",
        "text",
        "TEXT",
        "char",
        "CHAR",
        "Text",
        "bytes",
        "Bytes",
        "any",
        "unknown",
        "object",
    ];
    let type_end = v
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '&'))
        .unwrap_or(v.len());
    if TYPES.contains(&&v[..type_end]) {
        return true;
    }
    // Placeholder vocabulary: some words disqualify anywhere in the value,
    // others only as a prefix (a real password may contain "todo").
    let lower = v.to_ascii_lowercase();
    const ANYWHERE: &[&str] = &[
        "your",
        "xxx",
        "placeholder",
        "changeme",
        "change-me",
        "change_me",
        "redacted",
        "<",
        "...",
    ];
    const PREFIX: &[&str] = &[
        "example", "insert", "replace", "todo", "fixme", "sample", "dummy", "fake",
    ];
    if ANYWHERE.iter().any(|p| lower.contains(p)) || PREFIX.iter().any(|p| lower.starts_with(p)) {
        return true;
    }
    // `null`, `none`, `undefined`, `true`, `false` and friends.
    matches!(
        lower.trim_end_matches([',', ';', ')']),
        "null" | "none" | "nil" | "undefined" | "true" | "false" | "required" | "optional"
    )
}

fn generic_assign_gate(s: &str) -> Option<Confidence> {
    if is_non_literal_value(assignment_value(s)) {
        return None;
    }
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

/// Grade a `scheme://user:pass@host…` connection URL by what the credential
/// is actually worth.
///
/// * Placeholder password (`<password>`, `${DB_PASS}`, `PASSWORD`, `xxx`) →
///   not a finding.
/// * Local/dev host (`localhost`, loopback, `host.docker.internal`, a bare
///   compose/k8s service name) with a trivial password (equal to the user,
///   or `postgres`/`root`/`secret`/…) → Low. Every `docker-compose.yml` in
///   the world has one of these; reporting them as High buries the real
///   ones.
/// * Local host, non-trivial password → Medium.
/// * Anything else → High.
fn db_url_gate(s: &str) -> Option<Confidence> {
    let rest = s.split_once("://")?.1;
    let (userinfo, host) = rest.rsplit_once('@')?;
    let (user, pass) = match userinfo.split_once(':') {
        Some((u, p)) => (u, p),
        None => ("", userinfo),
    };
    // `[2001:db8::1]:5432` — a bracketed IPv6 literal contains `:`, so
    // take the bracket body before falling back to the port/path split.
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(v6),
        None => host.split([':', '/', '?']).next().unwrap_or(host),
    };
    if pass.is_empty() || is_placeholder_password(pass) {
        return None;
    }
    if is_local_host(host) {
        if is_trivial_password(pass, user) {
            Some(Confidence::Low)
        } else {
            Some(Confidence::Medium)
        }
    } else {
        Some(Confidence::High)
    }
}

fn is_placeholder_password(pass: &str) -> bool {
    if pass.starts_with(['<', '{', '[', '*', '.']) || (pass.starts_with('%') && pass.ends_with('%'))
    {
        return true;
    }
    // `$` is a reference only when it looks like one — `${DB_PASS}`,
    // `$(cmd)`, `$DB_PASS` — so a password that merely starts with `$`
    // still counts (same rule as `is_non_literal_value`).
    if pass.starts_with("${")
        || pass.starts_with("$(")
        || (pass.starts_with('$')
            && pass[1..]
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
    {
        return true;
    }
    let lower = pass.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "password"
            | "pass"
            | "passwd"
            | "pwd"
            | "secret"
            | "xxx"
            | "xxxx"
            | "changeme"
            | "redacted"
    ) || lower.starts_with("your")
        || lower.contains("example")
        || lower.contains("placeholder")
}

fn is_trivial_password(pass: &str, user: &str) -> bool {
    if pass.len() < 4 || (!user.is_empty() && pass.eq_ignore_ascii_case(user)) {
        return true;
    }
    matches!(
        pass.to_ascii_lowercase().as_str(),
        "postgres"
            | "postgresql"
            | "mysql"
            | "mongo"
            | "mongodb"
            | "redis"
            | "root"
            | "admin"
            | "test"
            | "dev"
            | "guest"
            | "1234"
            | "12345"
            | "123456"
            | "12345678"
            | "password123"
            | "devpassword"
    )
}

/// `localhost`, loopback, docker's host alias, `*.local`, or a single-label
/// name such as `db` / `postgres-postgresql` (a compose or k8s service —
/// unreachable from outside the stack).
fn is_local_host(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if h.is_empty() {
        return false;
    }
    if matches!(
        h,
        "localhost" | "127.0.0.1" | "::1" | "0.0.0.0" | "host.docker.internal"
    ) || h.starts_with("127.")
        || h.ends_with(".local")
        || h.ends_with(".localhost")
        || h.ends_with(".internal")
    {
        return true;
    }
    // Single label, not an IP: `db`, `postgres`, `redis-master`.
    !h.contains('.') && !h.contains(':') && !h.chars().all(|c| c.is_ascii_digit())
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
            validate: Some(db_url_gate),
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
            validate: Some(db_url_gate),
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "redis_url",
            display_name: "Redis Connection URL",
            category: Category::Credential,
            base_confidence: Confidence::High,
            matcher: Matcher::Plain(plain(r"redis(?:s)?://(?:[^\s:@/]+:)?[^\s@/]+@[^\s/]+")),
            validate: Some(db_url_gate),
            keywords: None,
            use_stopwords: false,
        },
        // ---------------- Credit cards (Luhn validated) ----------------
        // `\b` treats `.` and `/` as boundaries, so without the lookarounds the
        // fractional digits of a float (`0.4545454680919647`) and numeric ids in
        // URL paths (`/hc/en-us/articles/4409472300051`) match as standalone
        // PANs — and Luhn passes 1 in 10 of them. `(?<![./])` rejects exactly
        // those two shapes; `(?!\.[0-9])` rejects the integer part of a float.
        // Deliberately NOT excluded: `=`, `&`, `?`, `#`, `-` — `card=4111…` and
        // `?cc=4111…` are the canonical leak shapes.
        Rule {
            id: "credit_card_visa",
            display_name: "Credit Card (Visa)",
            category: Category::Pci,
            base_confidence: Confidence::High,
            // 16 digits only: 13-digit Visa PANs have not been issued in decades
            // and the legacy alternative contributed half the false positives.
            matcher: Matcher::Fancy(fancy(r"(?<![./])\b4[0-9]{15}\b(?!\.[0-9])")),
            validate: Some(luhn_gate),
            keywords: None,
            use_stopwords: false,
        },
        Rule {
            id: "credit_card_mastercard",
            display_name: "Credit Card (Mastercard)",
            category: Category::Pci,
            base_confidence: Confidence::High,
            // 51–55 and the 2221–2720 BIN range; every alternative is 16 digits.
            matcher: Matcher::Fancy(fancy(
                r"(?<![./])\b(?:5[1-5][0-9]{14}|2(?:2[2-9][0-9]{13}|[3-6][0-9]{14}|7[01][0-9]{13}|720[0-9]{12}))\b(?!\.[0-9])",
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
            matcher: Matcher::Fancy(fancy(r"(?<![./])\b3[47][0-9]{13}\b(?!\.[0-9])")),
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
            validate: Some(gcp_api_key_gate),
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
            // Every PyPI API token is a macaroon whose base64 body opens with
            // the `pypi.org` location, i.e. the literal `pypi-AgEIcHlwaS5vcmc`
            // (`pypi-AgENdGVzdC5weXBpLm9yZw` for test.pypi.org). Anchoring on
            // it stops URL slugs like `…-npm-pypi-supply-chain-…`.
            matcher: Matcher::Plain(plain(
                r"\bpypi-(?:AgEIcHlwaS5vcmc|AgENdGVzdC5weXBpLm9yZw)[0-9A-Za-z\-_]{30,}\b",
            )),
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
            // Exact Base58 alphabet (no 0/O/I/l) as a cheap prefilter; the
            // checksum gate does the real work, so hex hashes and base64
            // fragments that happen to start with `1` are rejected.
            matcher: Matcher::Plain(plain(r"\b1[1-9A-HJ-NP-Za-km-z]{25,34}\b")),
            validate: Some(base58check_gate),
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
            // 24 alphanumerics is not distinctive on its own (Turnstile site
            // keys, build ids, …), so the token must sit right after a
            // `VERCEL_TOKEN=` / `vercel token:` / `--token` context. The
            // keyword gate below is only a prefilter.
            matcher: {
                let (re, idx) = plain_cap(
                    r#"(?i)(?:vercel[\w .-]{0,24}?token|\bvercel_token|--token)["'`]?\s*[=:]?\s*["'`]?([A-Za-z0-9]{24})\b"#,
                    1,
                );
                Matcher::PlainCap(re, idx)
            },
            validate: Some(entropy_gate_3_5),
            keywords: Some(&["vercel", "Vercel", "VERCEL", "VERCEL_TOKEN", "vercel_token"]),
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
            // Any 40-char run in a chunk that merely *mentions* Cloudflare
            // (a link to community.cloudflare.com, say) used to fire: URL
            // slugs, challenge cookies, `google-site-verification=…`. The
            // token must now follow an assignment or bearer context. The
            // keyword gate still requires a Cloudflare mention in the chunk,
            // which is what lets the bare `api_token =` of a Terraform
            // `provider "cloudflare" { … }` block count as context. The
            // optional quote after the key admits `"CLOUDFLARE_API_TOKEN": "…"`.
            matcher: {
                let (re, idx) = plain_cap(
                    r#"(?i)(?:cloudflare[\w .-]{0,24}?(?:token|key)|\bcf_api_token|\bcf_token|\bapi_token|authorization:\s*bearer)["'`]?\s*[=:]?\s*["'`]?([A-Za-z0-9_-]{40})\b"#,
                    1,
                );
                Matcher::PlainCap(re, idx)
            },
            validate: Some(entropy_gate_4_0),
            keywords: Some(&[
                "cloudflare",
                "Cloudflare",
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

    fn has_card(findings: &[Finding]) -> bool {
        findings
            .iter()
            .any(|f| f.detector_id.starts_with("credit_card_"))
    }

    #[test]
    fn credit_card_float_fraction_not_a_card() {
        // Synth-parameter dump: the fractional digits are Luhn-valid by chance.
        assert!(luhn_valid("4545454680919647"));
        assert!(!has_card(&scan_for(
            "\"OSC.level\": {\"min\": 0.4545454680919647, \"max\": 0.75}"
        )));
        // Mastercard-shaped fraction and Amex-shaped fraction.
        assert!(!has_card(&scan_for("(0.5454545454545454, 1)")));
        assert!(!has_card(&scan_for("np.float64(1.378282246310005)")));
        // Integer part of a float is not a card either.
        assert!(!has_card(&scan_for("x = 4242424242424242.5")));
    }

    #[test]
    fn credit_card_url_path_id_not_a_card() {
        // Zendesk article id (13 digits) and a 16-digit path segment.
        assert!(!has_card(&scan_for(
            "https://support.example.com/hc/en-us/articles/4409472300051-Complete-Access-Hub-FAQ",
        )));
        assert!(!has_card(&scan_for(
            "https://example.com/orders/4242424242424242/receipt"
        )));
    }

    #[test]
    fn credit_card_leak_shapes_still_detected() {
        // The shapes a card actually leaks in: assignment, query string, JSON,
        // end of sentence, CSV.
        for input in [
            "card=4242424242424242",
            "export CARD=4242424242424242; exp=12/29",
            "https://pay.example.com/?cc=4242424242424242&cvv=123",
            r#"{"pan":"4242424242424242"}"#,
            "my number is 4242424242424242.",
            "name,4242424242424242,12/29",
        ] {
            assert!(
                has_card(&scan_for(input)),
                "expected a card finding in {input:?}"
            );
        }
    }

    #[test]
    fn visa_legacy_13_digit_not_matched() {
        // 13-digit Visa PANs have not been issued in decades; this one is a
        // Luhn-valid Zendesk id that used to fire.
        assert!(luhn_valid("4409472300051"));
        assert!(!has_card(&scan_for(
            "article 4409472300051 | More solutions"
        )));
    }

    #[test]
    fn mastercard_2_series_is_16_digits() {
        // Real 2221–2720 range card (16 digits, Luhn-valid) must fire…
        assert!(luhn_valid("2221000000000009"));
        let f = scan_for("card 2221000000000009");
        assert!(f.iter().any(|f| f.detector_id == "credit_card_mastercard"));
        // …while the 15-digit shape the old pattern accepted must not.
        assert!(luhn_valid("222100000000000"));
        assert!(!has_card(&scan_for("id 222100000000000 x")));
        // Facebook group id shape (15 digits, Luhn-valid) from the corpus.
        assert!(!has_card(&scan_for(
            "https://www.facebook.com/groups/222914377916832/"
        )));
    }

    #[test]
    fn base58check_known_vectors() {
        // Genesis block coinbase address.
        assert!(base58check_p2pkh_valid(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        ));
        // 21 leading zero bytes — exercises the leading-'1' handling.
        assert!(base58check_p2pkh_valid("1111111111111111111114oLvT2"));
        // Single-character corruption breaks the checksum.
        assert!(!base58check_p2pkh_valid(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"
        ));
        // Non-alphabet character.
        assert!(!base58check_p2pkh_valid(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf0a"
        ));
        // Wrong length.
        assert!(!base58check_p2pkh_valid("1A1zP1eP5QGefi2DMPTfTL5SLmv7"));
    }

    #[test]
    fn bitcoin_requires_base58check() {
        let btc = |input: &str| {
            scan_for(input)
                .into_iter()
                .find(|f| f.detector_id == "bitcoin_address")
        };
        // Bare and inside a URL path.
        let f = btc("send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").expect("genesis address");
        assert_eq!(
            f.confidence,
            Confidence::Medium,
            "an address is public: Medium, not High"
        );
        assert!(btc("https://blockchain.com/address/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").is_some());
        assert!(btc("1111111111111111111114oLvT2").is_some());
        // Corrupted checksum.
        assert!(btc("send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb").is_none());
        // 32-char hex hash starting with 1 (MD5 shape, no 0/O/I/l).
        assert!(btc("sid=1a2b3c4d5e6f7a8b9c1d2e3f4a5b6c7d").is_none());
        // Base64 fragment split at '/' — high entropy, but not an address.
        assert!(
            btc("AKguiHoA/CiCTkvhItjE0GJu5uv8L/1sv9ALefFcchYszJwPfgFv0HGRpXaVW5M5++B8D").is_none()
        );
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

    fn has(findings: &[Finding], det: &str) -> bool {
        findings.iter().any(|f| f.detector_id == det)
    }

    fn conf_of(findings: &[Finding], det: &str) -> Option<Confidence> {
        findings
            .iter()
            .find(|f| f.detector_id == det)
            .map(|f| f.confidence.clone())
    }

    #[test]
    fn generic_assignment_ignores_references_types_and_placeholders() {
        const DET: &str = "generic_password_assignment";
        // Code that *handles* a secret is not a leak of one.
        for input in [
            "password: process.env.DB_PASSWORD || 'sa',",
            "clientSecret: process.env.ARM_CLIENT_SECRET,",
            "api_key = os.environ[\"OPENAI_API_KEY\"]",
            "apiKey: import.meta.env.VITE_SUPABASE_KEY",
            "password: ${DB_PASSWORD_FROM_VAULT}",
            "token: !secret home_assistant_token",
            "secret = settings.SECRET_KEY_FALLBACK",
            "password: string; confirmPassword: string;",
            "token = randomBytes(32).toString('base64url')",
            "token = mx.zeros((batch, prompt_len))",
            "JWT_SECRET=<generate-with-openssl-rand>",
            "API_KEY=your-api-key-goes-here-1234",
            "password=...&next=/dashboard",
            "token: string }> {",
        ] {
            assert!(!has(&scan_for(input), DET), "should not fire on {input:?}");
        }
        // Literal values still fire — including ones that start with `$`,
        // `!` or `@`, or contain parentheses.
        for input in [
            "password = 'Xa7!pQ9vR2mK4nL8zT5jB3hC6d'",
            "INTERNAL_API_KEY: \"7D4pQ9vR2mK4nL8zT5jB3hC6dXa7WqZ1\"",
            "DB_PASSWORD=DevPassMon123!Xq9",
            "password=$ecretXq9vR2mK4nL8",
            "password=!Xq9vR2mK4nL8zT5j",
            "password=@Xq9vR2mK4nL8zT5j",
            "password=P@ss(Xq9vR2mK4)nL8",
        ] {
            assert!(has(&scan_for(input), DET), "should fire on {input:?}");
        }
    }

    #[test]
    fn db_url_grades_local_defaults_low_and_remote_high() {
        const DET: &str = "postgres_url";
        // compose / k8s defaults: password == user, local host.
        assert_eq!(
            conf_of(
                &scan_for("DATABASE_URL=postgres://cookday:cookday@localhost:5433/cookday"),
                DET
            ),
            Some(Confidence::Low)
        );
        assert_eq!(
            conf_of(
                &scan_for("postgresql://postgres:postgres@postgres-postgresql:5432/app"),
                DET
            ),
            Some(Confidence::Low)
        );
        // Local host but a real-looking password: worth a look.
        assert_eq!(
            conf_of(
                &scan_for("postgres://app:Xq9!vR2mK4nL8zT5@localhost:5432/app"),
                DET
            ),
            Some(Confidence::Medium)
        );
        // Remote host: High regardless of how weak the password is.
        assert_eq!(
            conf_of(
                &scan_for("postgres://postgres:postgres@db.prod.example.net:5432/app"),
                DET
            ),
            Some(Confidence::High)
        );
        assert_eq!(
            conf_of(
                &scan_for("DB=postgres://user:hunter2@db.example.com/app"),
                DET
            ),
            Some(Confidence::High)
        );
        // Placeholders are not findings.
        for input in [
            "postgres://USER:PASSWORD@HOST:PORT/DB",
            "postgres://medusa:***@localhost:5432/medusa",
            "postgres://app:${DB_PASSWORD}@db.internal/app",
            "postgres://app:<password>@db.example.com/app",
        ] {
            assert!(!has(&scan_for(input), DET), "should not fire on {input:?}");
        }
        // A password that merely *starts* with `$` is a literal, not a
        // `${VAR}` / `$VAR` reference — same rule as the generic gate.
        assert_eq!(
            conf_of(
                &scan_for("postgres://app:$uperS3cret9@db.example.com:5432/app"),
                DET
            ),
            Some(Confidence::High)
        );
        for input in [
            "postgres://app:$DB_PASSWORD@db.example.com/app",
            "postgres://app:$(cat pw)@db.example.com/app",
        ] {
            assert!(!has(&scan_for(input), DET), "should not fire on {input:?}");
        }
        // Bracketed IPv6 hosts: loopback is local, a global address is not.
        assert_eq!(
            conf_of(
                &scan_for("postgres://app:Xq9vR2mK4nL8zT5@[::1]:5432/app"),
                DET
            ),
            Some(Confidence::Medium)
        );
        assert_eq!(
            conf_of(
                &scan_for("postgres://app:Xq9vR2mK4nL8zT5@[fd12:3456::10]:5432/app"),
                DET
            ),
            Some(Confidence::High)
        );
        // Same gate on the sibling rules.
        assert_eq!(
            conf_of(&scan_for("redis://:redis@redis:6379/0"), "redis_url"),
            Some(Confidence::Low)
        );
        assert_eq!(
            conf_of(
                &scan_for("mongodb+srv://svc:Zk8!qP2mR4tY7wE1@cluster0.abc.mongodb.net/db"),
                "mongodb_srv_url"
            ),
            Some(Confidence::High)
        );
    }

    #[test]
    fn cloudflare_token_needs_assignment_context() {
        const DET: &str = "cloudflare_api_token";
        let token = format!(
            "SANITAIFAKE{}",
            "0123456789abcdef"
                .repeat(2)
                .chars()
                .take(29)
                .collect::<String>()
        );
        // A chunk that merely mentions Cloudflare no longer turns every
        // 40-char run into a token: URL slug, challenge cookie, verification tag.
        for input in [
            format!("see https://community.cloudflare.com/t/{token}-rule-cannot-activate/884843"),
            format!("cloudflare cf_chl_opt = {{cH: '{token}.Tw-1788200171-1.2.1.1'}}"),
            format!("cloudflare zone: \"google-site-verification={token}\""),
        ] {
            assert!(!has(&scan_for(&input), DET), "should not fire on {input:?}");
        }
        for input in [
            format!("CLOUDFLARE_API_TOKEN={token}"),
            format!("cloudflare_api_token = \"{token}\""),
            format!("Cloudflare API token: {token}"),
            format!("# cloudflare\ncurl -H 'Authorization: Bearer {token}' https://api.cloudflare.com/client/v4/zones"),
            // Terraform provider block: the key is a bare `api_token`.
            format!("provider \"cloudflare\" {{\n  api_token = \"{token}\"\n}}"),
            // JSON / quoted-YAML key.
            format!("{{\"CLOUDFLARE_API_TOKEN\": \"{token}\"}}"),
            format!("'CLOUDFLARE_API_TOKEN': '{token}'"),
        ] {
            assert!(has(&scan_for(&input), DET), "should fire on {input:?}");
        }
    }

    #[test]
    fn vercel_token_needs_assignment_context() {
        const DET: &str = "vercel_access_token";
        let token = "Xq9vR2mK4nL8zT5jB3hC6dWa";
        assert!(!has(
            &scan_for(&format!("| Turnstile site key (vercel) | `{token}` |")),
            DET
        ));
        assert!(has(&scan_for(&format!("VERCEL_TOKEN={token}")), DET));
        assert!(has(
            &scan_for(&format!("vercel deploy --token {token}")),
            DET
        ));
        assert!(has(
            &scan_for(&format!("{{\"VERCEL_TOKEN\": \"{token}\"}}")),
            DET
        ));
    }

    #[test]
    fn pypi_token_is_anchored_on_macaroon_prefix() {
        const DET: &str = "pypi_token";
        // URL slug that used to match.
        assert!(!has(
            &scan_for(
                "https://socket.dev/blog/large-scale-npm-pypi-supply-chain-attack-uncovered-2025"
            ),
            DET
        ));
        // Real shape: `pypi-AgEIcHlwaS5vcmc` + long base64 body.
        let token = format!(
            "pypi-AgEIcHlwaS5vcmc{}",
            "AiQxMjM0NTY3OC1hYmNkLWVmZ2gtaWprbC1tbm9wcXJzdHV2AAIqWzMsIjEyMzQ1Njc4LWFiY2QiXQAABiB"
                .repeat(2)
        );
        assert!(has(&scan_for(&format!("password = {token}")), DET));
        // test.pypi.org issues macaroons located at `test.pypi.org`.
        let test_token = format!(
            "pypi-AgENdGVzdC5weXBpLm9yZw{}",
            "IkMTIzNDU2NzgtYWJjZC1lZmdoLWlqa2wtbW5vcHFyc3R1dgACJFszLCIxMjM0NTY3OC1hYmNkIl0AAAYg"
                .repeat(2)
        );
        assert!(has(&scan_for(&format!("TWINE_PASSWORD={test_token}")), DET));
        // Other `pypi-` prefixed strings (an unrelated token, a slug) do not.
        assert!(!has(
            &scan_for("pypi-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnop"),
            DET
        ));
    }

    #[test]
    fn iban_requires_registry_country_and_length() {
        // A WIPO ST13 trademark id: two letters, digits, passes mod-97 by
        // chance, but `US` issues no IBANs.
        assert!(!has(&scan_for(r#"{"ST13":"US502024123456789"}"#), "iban"));
        assert!(!iban_valid("US50202412345678"));
        // Right country, wrong length.
        assert!(!iban_valid("GB82WEST123456987654321"));
        // Registry entries still validate.
        assert!(iban_valid("GB82WEST12345698765432"));
        assert!(iban_valid("DE89370400440532013000"));
        assert_eq!(iban_length_for("GB"), Some(22));
        assert_eq!(iban_length_for("US"), None);
    }

    #[test]
    fn gcp_api_key_skips_well_known_public_keys() {
        const DET: &str = "gcp_api_key";
        assert!(!has(
            &scan_for("curl 'https://www.youtube.com/youtubei/v1/player?key=AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8'"),
            DET
        ));
        assert!(!has(
            &scan_for("example: AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"),
            DET
        ));
        // Any other well-formed key still fires.
        assert!(has(
            &scan_for("key=AIzaSyA-1234567890abcdefghijklmnopqrstu"),
            DET
        ));
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
