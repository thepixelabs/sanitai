//! Realistic surrounding-text wrappers for generated secrets.
//!
//! The purpose is to mimic the kind of text users paste into Claude/ChatGPT:
//! shell exports, config snippets, error messages, code blocks. This makes
//! corpora stress both the regex layer and any contextual heuristics.

use crate::classes::TokenClass;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

/// Wrap a bare secret in a realistic context string. Deterministic given the
/// (class, seed) pair.
pub fn wrap(class: TokenClass, seed: u64, secret: &str) -> String {
    let mut r = SmallRng::seed_from_u64(seed ^ 0xC0FFEE);
    let templates: &[&str] = templates_for(class);
    let tpl = templates[r.gen_range(0..templates.len())];
    tpl.replace("{SECRET}", secret)
}

fn templates_for(class: TokenClass) -> &'static [&'static str] {
    match class {
        TokenClass::AwsAccessKey => &[
            "Here's the AWS key I used: {SECRET}\nCan you help me rotate it?",
            "export AWS_ACCESS_KEY_ID={SECRET}\nexport AWS_SECRET_ACCESS_KEY=...",
            "I got this error:\n```\nAuthFailure: The AWS Access Key Id {SECRET} is invalid\n```",
        ],
        TokenClass::GitHubPat => &[
            "My token is {SECRET} — is that the right format?",
            "git clone https://{SECRET}@github.com/acme/repo.git",
            "```\nerror: Bad credentials (token: {SECRET})\n```",
        ],
        TokenClass::OpenAiKey => &[
            "I set OPENAI_API_KEY={SECRET} but the SDK says it's invalid.",
            "```python\nopenai.api_key = \"{SECRET}\"\nopenai.ChatCompletion.create(...)\n```",
            "curl https://api.openai.com/v1/models -H 'Authorization: Bearer {SECRET}'",
        ],
        TokenClass::AnthropicKey => &[
            "ANTHROPIC_API_KEY={SECRET}\n\nWhy am I getting a 401?",
            "```ts\nconst client = new Anthropic({ apiKey: \"{SECRET}\" });\n```",
        ],
        TokenClass::StripeSecretKey => &[
            "Stripe is rejecting my key: {SECRET}",
            "```\nSTRIPE_SECRET_KEY={SECRET}\n```",
        ],
        TokenClass::SlackToken => &[
            "I'm setting SLACK_BOT_TOKEN={SECRET} in my .env — does that look right?",
            "```\nxoxb token received: {SECRET}\n```",
        ],
        TokenClass::Jwt => &[
            "Decoded my JWT and the payload looks off: {SECRET}",
            "Authorization: Bearer {SECRET}",
            "```\ntoken: {SECRET}\n```",
        ],
        TokenClass::PrivateKeyPem => &[
            "Here's the key file I was given:\n{SECRET}\nHow do I convert it to ssh format?",
            "My ~/.ssh/id_rsa contains:\n{SECRET}",
        ],
        TokenClass::PostgresUrl => &[
            "DATABASE_URL={SECRET}\n\npsql can't connect — what am I missing?",
            "```\nexport DATABASE_URL=\"{SECRET}\"\n```",
        ],
        TokenClass::CreditCard => &[
            "I need to store this card in our vault: {SECRET}",
            "Customer called about charge on card ending in {SECRET}",
        ],
        TokenClass::Iban => &[
            "My bank account is {SECRET} — transfer to this IBAN.",
            "IBAN: {SECRET}\nBIC: SANIXX22",
        ],
        TokenClass::GcpApiKey => &[
            "My Google Maps key {SECRET} stopped working.",
            "```\nGOOGLE_API_KEY={SECRET}\n```",
        ],
        TokenClass::AzureSasToken => &[
            "Uploading with this SAS URL: https://acct.blob.core.windows.net/c?{SECRET}",
            "SAS query string: {SECRET}",
        ],
        TokenClass::NpmToken => &[
            "//registry.npmjs.org/:_authToken={SECRET}",
            "I put {SECRET} in my .npmrc but publish still fails.",
        ],
        TokenClass::HighEntropyString => &[
            "Found this blob in the logs: {SECRET}\nAny idea what it is?",
            "The session cookie was {SECRET} — could that be the leak?",
        ],
    }
}
