<img src="docs/nix-float.svg" align="right" width="200" alt="Nix the Raccoon — SanitAI mascot"/>

# SanitAI

**Find secrets in your LLM chat history before someone else does.**

SanitAI scans your Claude and ChatGPT conversation exports for leaked API keys, credentials, and personal data — entirely on your machine. No network calls. No cloud. No copies of your data leave the device.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform: Linux macOS](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](#install)

---

## The problem

You paste a `.env` file into Claude to debug a config issue. You ask ChatGPT to review a script that contains a database URL. Six months later, you export your conversation history and realise those secrets have been sitting in plain text inside a JSON file on your laptop — and in every backup, sync, and export you've made since.

SanitAI finds them. In seconds.

---

## Install

**Homebrew (macOS and Linux)**

```sh
brew install sanitai/tap/sanitai
```

**curl installer (Linux and macOS)**

```sh
curl -fsSL https://releases.sanitai.dev/install.sh | sh
```

Verify the binary signature before running anything (see [Trust model](#trust-model)).

**Cargo (build from source)**

```sh
cargo install sanitai
```

Requires Rust 1.78 or later.

---

## Your first scan

```sh
sanitai scan ~/Downloads/claude_export.zip
```

```
SanitAI v0.1.0 — local scan, no network
Parsing: claude_export.zip (Claude format)

Scanning 1,842 messages across 94 conversations...

FINDINGS (4)
────────────────────────────────────────────────────────────────
 HIGH  AWS Access Key        conversation_47.json:line 312
       AKIA[REDACTED]        matched: aws_access_key_id pattern

 HIGH  Generic API Key       conversation_12.json:line 88
       sk-[REDACTED]         matched: high-entropy bearer token

 MED   Email address         conversation_91.json:line 201
       j****@example.com     matched: RFC 5322 address heuristic

 LOW   Internal hostname     conversation_03.json:line 44
       db.internal.corp      matched: internal TLD heuristic
────────────────────────────────────────────────────────────────
4 findings in 1,842 messages (0.8 s)

Run `sanitai redact` to remove findings from a copy of the export.
```

No finding left the machine. The original file was not modified.

---

## Supported sources

| Source | Export format | Parser |
|---|---|---|
| Claude (claude.ai) | `conversations.json` ZIP export | Built-in |
| ChatGPT (chat.openai.com) | `conversations.json` ZIP export | Built-in |

Additional parsers are planned for future releases. The parser is separate from the detector — adding a new source does not change detection logic.

---

## Detection capabilities

| Category | Examples | Method |
|---|---|---|
| Cloud provider keys | AWS, GCP, Azure, Stripe, Twilio | Regex against known prefixes |
| Generic secrets | High-entropy strings in key=value context | Shannon entropy + heuristic |
| Bearer tokens | `Authorization:` headers, `sk-` prefixes | Regex + context heuristic |
| Database URLs | `postgres://`, `mysql://`, `mongodb+srv://` | Regex |
| Private keys | PEM blocks (`BEGIN RSA PRIVATE KEY`, etc.) | Regex |
| Email addresses | RFC 5322 addresses | Heuristic |
| Phone numbers | E.164 and regional formats | Regex + heuristic |
| Custom patterns | User-defined YAML rules | Regex + optional entropy |

Detectors run locally in process. No pattern or matched text is sent anywhere.

---

## Redaction modes

```sh
# Write a redacted copy alongside the original (default)
sanitai redact ~/Downloads/claude_export.zip

# Redact in place (replaces the original — use with caution)
sanitai redact --in-place ~/Downloads/claude_export.zip

# Replace matched text with a fixed mask
sanitai redact --mask "***REDACTED***" ~/Downloads/claude_export.zip

# Replace matched text with the finding type label
sanitai redact --mask-with-type ~/Downloads/claude_export.zip
# e.g. "[AWS_ACCESS_KEY]", "[EMAIL_ADDRESS]"
```

---

## Configuration

SanitAI reads `~/.config/sanitai/config.toml` (XDG-compliant). All fields are optional.

```toml
# ~/.config/sanitai/config.toml

[scan]
min_severity = "low"   # "low" | "medium" | "high"
disable_detectors = []

[redact]
mask = "[REDACTED]"
mask_with_type = false

[rules]
extra_rules_dirs = ["~/.config/sanitai/rules"]
```

Validate your config:

```sh
sanitai config validate
```

---

## Custom rules

```yaml
# ~/.config/sanitai/rules/acme-api-key.yaml
id: acme_api_key
name: "ACME Corp API Key"
severity: high
pattern: "acme_[a-zA-Z0-9]{32}"
min_entropy: 3.5
context_keywords: ["api_key", "apikey", "token"]
```

See [docs/custom-rules.md](docs/custom-rules.md) for the complete schema and examples.

---

## How it works

```
1. PARSE                  2. DETECT                  3. REPORT
─────────────             ─────────────              ─────────────
Read export ZIP     →     For each message:    →     Print findings
Identify format           run regex detectors         by severity
Extract message           run entropy scorer
text per turn             run heuristics
                          apply custom rules
```

Everything happens in a single local process. No state is persisted between runs.

---

## Trust model

**Offline by design.** SanitAI makes zero network connections at runtime. Verify:

```sh
# Linux
strace -e trace=network sanitai scan /path/to/export.zip 2>&1 | grep -v "^strace"

# macOS
sudo fs_usage -w -f network sanitai
```

A clean scan produces no output from either command.

**No telemetry.** No analytics, no crash reporting, no usage pinging.

**Signed binaries.** Release binaries are signed with [cosign](https://docs.sigstore.dev/cosign/overview/).

```sh
cosign verify-blob \
  --certificate sanitai-linux-amd64.cert \
  --signature sanitai-linux-amd64.sig \
  --certificate-identity \
    "https://github.com/sanitai/sanitai/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  sanitai-linux-amd64
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security vulnerabilities: see [SECURITY.md](SECURITY.md).

---

## License

MIT — see [LICENSE](LICENSE).
