//! Token class taxonomy. Each variant maps to a distinct synthetic generator
//! in `lib.rs::generate_secret`.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenClass {
    AwsAccessKey,
    GitHubPat,
    OpenAiKey,
    AnthropicKey,
    StripeSecretKey,
    SlackToken,
    Jwt,
    PrivateKeyPem,
    PostgresUrl,
    CreditCard,
    Iban,
    GcpApiKey,
    AzureSasToken,
    NpmToken,
    HighEntropyString,
}

impl TokenClass {
    /// Stable snake_case identifier for corpora, reports, and CLI args.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AwsAccessKey => "aws_access_key",
            Self::GitHubPat => "github_pat",
            Self::OpenAiKey => "openai_key",
            Self::AnthropicKey => "anthropic_key",
            Self::StripeSecretKey => "stripe_secret_key",
            Self::SlackToken => "slack_token",
            Self::Jwt => "jwt",
            Self::PrivateKeyPem => "private_key_pem",
            Self::PostgresUrl => "postgres_url",
            Self::CreditCard => "credit_card",
            Self::Iban => "iban",
            Self::GcpApiKey => "gcp_api_key",
            Self::AzureSasToken => "azure_sas_token",
            Self::NpmToken => "npm_token",
            Self::HighEntropyString => "high_entropy_string",
        }
    }

    pub const ALL: &'static [TokenClass] = &[
        Self::AwsAccessKey,
        Self::GitHubPat,
        Self::OpenAiKey,
        Self::AnthropicKey,
        Self::StripeSecretKey,
        Self::SlackToken,
        Self::Jwt,
        Self::PrivateKeyPem,
        Self::PostgresUrl,
        Self::CreditCard,
        Self::Iban,
        Self::GcpApiKey,
        Self::AzureSasToken,
        Self::NpmToken,
        Self::HighEntropyString,
    ];
}
