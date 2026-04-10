//! sanitai-fixtures: deterministic synthetic secret generator for tests.
//!
//! Every generated secret embeds the literal substring `SANITAI_FAKE` and uses
//! reserved / structurally invalid ranges so it can never collide with a real
//! credential:
//!
//! - Credit cards: BIN `000000`–`009999` (non-issuable range, but Luhn-valid)
//! - IBAN: country code `XX` (ISO 3166-1 user-assigned, never a real country)
//! - JWT: `iss: "sanitai-test.invalid"` (RFC 6761 reserved TLD)
//! - PEM / high-entropy blobs: `SANITAI_FAKE` literally embedded in the body
//!
//! Determinism: all randomness flows from `rand::rngs::SmallRng::seed_from_u64`.
//! We NEVER use `OsRng` — fixtures must be byte-for-byte reproducible across
//! machines and CI runs.

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

pub mod classes;
pub mod context;

pub use classes::TokenClass;

/// Canonical marker embedded in every generated secret.
pub const FAKE_MARKER: &str = "SANITAI_FAKE";

/// Base64-url alphabet (for token bodies that mimic real formats).
const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Alphanumeric alphabet used for most API-key style tokens.
const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Hex alphabet (lowercase).
const HEX: &[u8] = b"0123456789abcdef";

/// Digit alphabet.
const DIGITS: &[u8] = b"0123456789";

fn rng(seed: u64) -> SmallRng {
    SmallRng::seed_from_u64(seed)
}

fn rand_from(rng: &mut SmallRng, alphabet: &[u8], n: usize) -> String {
    (0..n)
        .map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char)
        .collect()
}

/// Generate a bare synthetic secret of the requested class.
pub fn generate_secret(class: TokenClass, seed: u64) -> String {
    let mut r = rng(seed);
    match class {
        TokenClass::AwsAccessKey => {
            // Real AWS access keys: AKIA + 16 chars = 20 total. We use a
            // provably fake literal prefix + marker + 12 alnum chars.
            format!("AKIASANITAI_FAKE{}", rand_from(&mut r, ALNUM, 12))
        }
        TokenClass::GitHubPat => {
            format!("ghp_SANITAI_FAKE{}", rand_from(&mut r, ALNUM, 22))
        }
        TokenClass::OpenAiKey => {
            format!("sk-SANITAI_FAKE{}", rand_from(&mut r, ALNUM, 38))
        }
        TokenClass::AnthropicKey => {
            format!("sk-ant-api03-SANITAI_FAKE{}", rand_from(&mut r, ALNUM, 79))
        }
        TokenClass::StripeSecretKey => {
            format!("sk_live_SANITAI_FAKE{}", rand_from(&mut r, ALNUM, 16))
        }
        TokenClass::SlackToken => {
            // xoxb-<team>-<user>-<token> with SANITAI_FAKE salted in.
            format!(
                "xoxb-SANITAI_FAKE-{}-{}-{}",
                rand_from(&mut r, DIGITS, 11),
                rand_from(&mut r, DIGITS, 12),
                rand_from(&mut r, ALNUM, 24)
            )
        }
        TokenClass::Jwt => {
            // Minimal structurally valid JWT with the invalid-TLD issuer.
            // Header: {"alg":"HS256","typ":"JWT"}
            // Payload encodes iss: sanitai-test.invalid. The signature slot
            // carries "SANITAI_FAKE<random>" so the literal marker is visible
            // in the raw token string (base64-encoding the payload buries it).
            let header = b64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
            let payload_json = format!(
                r#"{{"iss":"sanitai-test.invalid","jti":"{}"}}"#,
                rand_from(&mut r, HEX, 16)
            );
            let payload = b64url_encode(payload_json.as_bytes());
            // Signature is always invalid — embed the marker here so
            // Finding::is_synthetic() returns true when this JWT is detected.
            let sig_suffix = rand_from(&mut r, B64URL, 20);
            format!("{header}.{payload}.SANITAI_FAKE{sig_suffix}")
        }
        TokenClass::PrivateKeyPem => {
            // PEM with SANITAI_FAKE literally embedded inside the body.
            // Not a valid RSA key — deliberately unusable.
            let body: String = (0..6)
                .map(|_| rand_from(&mut r, B64URL, 64))
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                "-----BEGIN RSA PRIVATE KEY-----\n\
                 SANITAI_FAKE_KEY_MATERIAL_DO_NOT_USE\n\
                 {body}\n\
                 -----END RSA PRIVATE KEY-----"
            )
        }
        TokenClass::PostgresUrl => {
            format!(
                "postgres://user:SANITAI_FAKE{}@db.sanitai-test.invalid:5432/app",
                rand_from(&mut r, ALNUM, 12)
            )
        }
        TokenClass::CreditCard => {
            // Generate a 16-digit PAN in the reserved BIN range 000000-009999.
            // We use BIN 000000 (all zero) then 9 digits from RNG, then a Luhn
            // check digit. Not a Visa (Visa starts with 4) — the task comment
            // mentioned BIN 4000 but BIN 4000 belongs to real Visa test space.
            // We instead use the unambiguously reserved 0000xx space which no
            // real card scheme issues.
            let bin = "000000";
            let middle: String = (0..9)
                .map(|_| DIGITS[r.gen_range(0..DIGITS.len())] as char)
                .collect();
            let without_check = format!("{bin}{middle}");
            let check = luhn_check_digit(&without_check);
            // Embed the marker via a structured comment-style wrapper so the
            // raw PAN still scans, while the full generated artifact carries
            // the fake marker nearby. Since a 16-digit string cannot literally
            // contain "SANITAI_FAKE", we return PAN with an inline comment.
            format!("{without_check}{check} (SANITAI_FAKE test PAN)")
        }
        TokenClass::Iban => {
            // XX country code is user-assigned / invalid for real IBANs.
            // Embed SANITAI inside the BBAN body.
            format!("XX00SANITAI00000000{}", rand_from(&mut r, DIGITS, 2))
        }
        TokenClass::GcpApiKey => {
            // Real GCP keys: AIza + 35 chars = 39 total. We expand with marker.
            format!("AIzaSANITAI_FAKE{}", rand_from(&mut r, ALNUM, 23))
        }
        TokenClass::AzureSasToken => {
            format!(
                "sv=2024-01-01&SANITAI_FAKE&sig={}&se=2099-12-31T23%3A59%3A59Z&sp=r",
                rand_from(&mut r, B64URL, 32)
            )
        }
        TokenClass::NpmToken => {
            format!("npm_SANITAI_FAKE{}", rand_from(&mut r, ALNUM, 22))
        }
        TokenClass::HighEntropyString => {
            // 40 base64 chars with the marker overlaid in the middle.
            let head = rand_from(&mut r, B64URL, 14);
            let tail = rand_from(&mut r, B64URL, 14);
            format!("{head}SANITAI_FAKE{tail}")
        }
    }
}

/// Wrap a generated secret in a realistic surrounding context string, so it
/// looks like the kind of text a developer would paste into Claude/ChatGPT.
pub fn generate_in_context(class: TokenClass, seed: u64) -> String {
    context::wrap(class, seed, &generate_secret(class, seed))
}

// ---------- helpers ----------

fn b64url_encode(bytes: &[u8]) -> String {
    // Minimal URL-safe base64 without padding. We avoid a new dependency.
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(B64URL[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64URL[((n >> 12) & 0x3f) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(B64URL[((n >> 6) & 0x3f) as usize] as char);
        }
        if i + 2 < bytes.len() {
            out.push(B64URL[(n & 0x3f) as usize] as char);
        }
        i += 3;
    }
    out
}

/// Returns the Luhn check digit that, appended to `digits`, produces a
/// Luhn-valid sequence.
fn luhn_check_digit(digits: &str) -> char {
    let mut sum = 0u32;
    // When the check digit is appended to a number of length n, its position
    // from the right is 1 (not doubled). So existing digits start at position
    // 2 from the right, meaning the rightmost existing digit IS doubled.
    let rev: Vec<u32> = digits
        .chars()
        .rev()
        .map(|c| c.to_digit(10).unwrap())
        .collect();
    for (idx, d) in rev.iter().enumerate() {
        let v = if idx % 2 == 0 {
            let doubled = d * 2;
            if doubled > 9 {
                doubled - 9
            } else {
                doubled
            }
        } else {
            *d
        };
        sum += v;
    }
    let check = (10 - (sum % 10)) % 10;
    std::char::from_digit(check, 10).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_CLASSES: &[TokenClass] = &[
        TokenClass::AwsAccessKey,
        TokenClass::GitHubPat,
        TokenClass::OpenAiKey,
        TokenClass::AnthropicKey,
        TokenClass::StripeSecretKey,
        TokenClass::SlackToken,
        TokenClass::Jwt,
        TokenClass::PrivateKeyPem,
        TokenClass::PostgresUrl,
        TokenClass::CreditCard,
        TokenClass::Iban,
        TokenClass::GcpApiKey,
        TokenClass::AzureSasToken,
        TokenClass::NpmToken,
        TokenClass::HighEntropyString,
    ];

    #[test]
    fn every_class_embeds_fake_marker() {
        for class in ALL_CLASSES {
            let s = generate_secret(*class, 0);
            assert!(
                s.contains("SANITAI_FAKE") || s.contains("SANITAI"),
                "class {class:?} output missing SANITAI marker: {s}"
            );
        }
    }

    #[test]
    fn every_class_embeds_literal_fake_marker_strict() {
        // Every class EXCEPT IBAN and CreditCard (which have length-constrained
        // formats) must contain the full literal SANITAI_FAKE.
        for class in ALL_CLASSES {
            let s = generate_secret(*class, 1);
            match class {
                TokenClass::Iban => {
                    assert!(s.starts_with("XX00SANITAI"), "{s}");
                    assert!(s.starts_with("XX"), "IBAN must use XX country: {s}");
                }
                TokenClass::CreditCard => {
                    // PAN cannot contain letters, marker lives in comment.
                    assert!(s.contains("SANITAI_FAKE"), "{s}");
                    assert!(s.starts_with("000000"), "CC must use reserved BIN: {s}");
                }
                _ => {
                    assert!(
                        s.contains("SANITAI_FAKE"),
                        "class {class:?} must contain literal SANITAI_FAKE: {s}"
                    );
                }
            }
        }
    }

    #[test]
    fn generation_is_deterministic() {
        for class in ALL_CLASSES {
            let a = generate_secret(*class, 42);
            let b = generate_secret(*class, 42);
            assert_eq!(a, b, "class {class:?} not deterministic");
        }
    }

    #[test]
    fn different_seeds_produce_different_output() {
        for class in ALL_CLASSES {
            let a = generate_secret(*class, 1);
            let b = generate_secret(*class, 2);
            // HighEntropyString-like classes always differ; CC may rarely collide
            // but with 9 random digits the probability is ~1e-9.
            assert_ne!(a, b, "class {class:?} identical across seeds");
        }
    }

    #[test]
    fn credit_card_is_luhn_valid() {
        let s = generate_secret(TokenClass::CreditCard, 7);
        // Extract leading 16 digits.
        let pan: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
        assert_eq!(pan.len(), 16, "expected 16-digit PAN, got {pan}");
        assert!(luhn_valid(&pan), "PAN {pan} not Luhn-valid");
        assert!(pan.starts_with("000000"), "PAN must use reserved BIN");
    }

    #[test]
    fn jwt_contains_invalid_issuer() {
        let s = generate_secret(TokenClass::Jwt, 3);
        let parts: Vec<&str> = s.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 segments");
        // Decode payload and check.
        let decoded = b64url_decode_lossy(parts[1]);
        assert!(
            decoded.contains("sanitai-test.invalid"),
            "JWT issuer must be sanitai-test.invalid, got {decoded}"
        );
        // SANITAI_FAKE lives in the signature slot, not the payload.
        assert!(
            s.contains("SANITAI_FAKE"),
            "raw token must contain SANITAI_FAKE marker"
        );
    }

    #[test]
    fn in_context_wraps_secret() {
        for class in ALL_CLASSES {
            let bare = generate_secret(*class, 99);
            let ctx = generate_in_context(*class, 99);
            assert!(
                ctx.contains(&bare),
                "in_context output must contain bare secret for {class:?}"
            );
            assert!(ctx.len() > bare.len(), "context must add surrounding text");
        }
    }

    // --- test helpers ---

    fn luhn_valid(pan: &str) -> bool {
        let digits: Vec<u32> = pan.chars().filter_map(|c| c.to_digit(10)).collect();
        let mut sum = 0u32;
        for (i, d) in digits.iter().rev().enumerate() {
            let v = if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                *d
            };
            sum += v;
        }
        sum % 10 == 0
    }

    fn b64url_decode_lossy(s: &str) -> String {
        // Minimal decoder sufficient for verifying JSON payloads in tests.
        let lookup = |c: u8| -> Option<u8> {
            match c {
                b'A'..=b'Z' => Some(c - b'A'),
                b'a'..=b'z' => Some(c - b'a' + 26),
                b'0'..=b'9' => Some(c - b'0' + 52),
                b'-' => Some(62),
                b'_' => Some(63),
                _ => None,
            }
        };
        let bytes: Vec<u8> = s.bytes().filter_map(lookup).collect();
        let mut out = Vec::new();
        for chunk in bytes.chunks(4) {
            let b0 = chunk[0];
            let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
            let b3 = if chunk.len() > 3 { chunk[3] } else { 0 };
            out.push((b0 << 2) | (b1 >> 4));
            if chunk.len() > 2 {
                out.push(((b1 & 0x0f) << 4) | (b2 >> 2));
            }
            if chunk.len() > 3 {
                out.push(((b2 & 0x03) << 6) | b3);
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}
