//! Conversation-aware stopword list.
//!
//! Applied only to low-specificity rules (those with `use_stopwords: true`).
//! High-precision rules (ghp_, sk-ant-, SG., etc.) never use stopwords.
//!
//! Unlike gitleaks' source-code stopwords, this list is curated for AI
//! conversation content. Words like "changeme" and "password" are kept as
//! suppressors only when they are unlikely to be real secrets in conversation
//! context.

use std::collections::HashSet;
use std::sync::OnceLock;

static STOPWORDS: OnceLock<HashSet<&'static str>> = OnceLock::new();

pub fn stopwords() -> &'static HashSet<&'static str> {
    STOPWORDS.get_or_init(|| {
        let words: &[&str] = &[
            // Generic placeholder strings safe to suppress
            "placeholder",
            "your_api_key",
            "your_secret",
            "your_token",
            "YOUR_API_KEY",
            "YOUR_SECRET_KEY",
            "YOUR_TOKEN",
            "YOUR_PASSWORD",
            "<YOUR_API_KEY>",
            "<API_KEY>",
            "<TOKEN>",
            "<SECRET>",
            "INSERT_YOUR_KEY_HERE",
            "REPLACE_WITH_YOUR_KEY",
            "example_key",
            "sample_key",
            "test_key",
            "dummy_key",
            "fake_key",
            "my_api_key",
            "api_key_here",
            // Common example values safe to suppress
            "xxxxxxxxxxxxxxxxxxxx",
            "XXXXXXXXXXXXXXXXXXXX",
            "yyyyyyyyyyy",
            "YYYYYYYYYYY",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            // Provider-doc placeholder fills — extend as needed.
            // These are exact-match suppressors for low-specificity rules
            // (anything with `use_stopwords: true`).
            "00000000000000000000000000000000",
            "11111111111111111111111111111111",
            "ffffffffffffffffffffffffffffffff",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "deadbeefdeadbeefdeadbeefdeadbeef",
            "0123456789abcdef0123456789abcdef",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",         // 32 x's
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",         // 32 X's
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",    // 37 x's (Cloudflare global key shape)
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", // 40 x's (Cloudflare token shape)
            "xxxxxxxxxxxxxxxxxxxxxxxx",                 // 24 x's (Atlassian/Vercel shape)
            "your_cloudflare_api_token_here_xxxxxxxxx",
            "<YOUR_CLOUDFLARE_API_TOKEN>",
            "<YOUR_ATLASSIAN_TOKEN>",
            "<YOUR_ALGOLIA_API_KEY>",
            "<YOUR_ASANA_TOKEN>",
            // Gitleaks stopwords appropriate for conversations
            "adafruit",
            "documentation",
            "example.com",
        ];
        words.iter().copied().collect()
    })
}

/// Returns true if the matched string is a known stopword and should be suppressed.
pub fn is_stopword(matched: &str) -> bool {
    stopwords().contains(matched)
}
