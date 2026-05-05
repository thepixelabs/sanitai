# [SanitAI](https://sanitai.pixelabs.net)

<a href="https://sanitai.pixelabs.net"><img src="docs/nix-float.svg" align="right" width="200" alt="Nix the Raccoon — SanitAI mascot"/></a>

**Find secrets in your LLM chat history before someone else does.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform: Linux macOS](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](#install)
[![CI](https://github.com/thepixelabs/sanitai/actions/workflows/ci.yml/badge.svg)](https://github.com/thepixelabs/sanitai/actions)

SanitAI scans your Claude and ChatGPT conversation exports for leaked API keys, credentials, and personal data — entirely on your machine. No network calls. No cloud. No copies of your data leave the device.

---

## Why SanitAI

You paste a `.env` file into Claude to debug a config issue. You ask ChatGPT to review a script that contains a database URL. Six months later, you export your conversation history and realise those secrets have been sitting in plain text inside a JSON file on your laptop — and in every backup, sync, and export you've made since.

- **Your chat history is now a sensitive corpus.** Months of debugging sessions, code reviews, and "look at this error" pastes pile up secrets you forgot you ever shared. Treat the export the way you'd treat a backup of `~/.aws/`.
- **Cloud scanners are the wrong tool.** Uploading conversation exports to a SaaS scanner trades one leak for another. SanitAI never opens a socket — verify with `strace` if you don't trust us.
- **Detection beats deletion.** Knowing *which* conversation leaked which key tells you whose key to rotate, where, and when. A blanket "delete everything" doesn't.
- **Bring your own rules.** Cloud-provider key formats are covered out of the box; internal tokens, customer IDs, and project-specific secrets are one YAML file away.

SanitAI finds them. In seconds.

---

## Install

**Homebrew (macOS and Linux)**

```sh
brew install thepixelabs/tap/sanitai
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

**Requirements:** Rust 1.78+ if building from source. No runtime dependencies for the released binary.

---

## Quick start

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

### What to try next

- `sanitai redact <export>` — produce a redacted copy alongside the original
- `sanitai redact --in-place <export>` — replace the original (use carefully)
- `sanitai redact --mask-with-type <export>` — replace each match with its type label, e.g. `[AWS_ACCESS_KEY]`
- `sanitai config validate` — lint your config before scheduling automated scans
- Drop a YAML file into `~/.config/sanitai/rules/` to add a custom detector

---

## Features

| Feature | What it means |
|---|---|
| **Offline by design** | Zero network connections at runtime. Verifiable with `strace` (Linux) or `fs_usage` (macOS). |
| **Multi-source parsing** | Claude (claude.ai) and ChatGPT (chat.openai.com) `conversations.json` ZIP exports out of the box. Parser is pluggable from detection logic — adding a source doesn't change matching. |
| **Layered detection** | Regex against known cloud-provider prefixes, Shannon-entropy scoring for high-entropy strings, context-keyword heuristics, and PEM-block matching. |
| **Custom rules** | YAML files in `~/.config/sanitai/rules/` add detectors with regex + optional minimum entropy + context keywords. |
| **Three redaction modes** | Copy-then-redact (default), in-place redact, or mask-with-type for human-readable output. |
| **Severity-tiered output** | `HIGH` / `MED` / `LOW` so you can grep, pipe, and gate on what matters. Configurable `min_severity` floor. |
| **No telemetry** | No analytics, no crash reporting, no usage pinging. |
| **Signed binaries** | Release binaries are signed with [cosign](https://docs.sigstore.dev/cosign/overview/). |
| **XDG-compliant config** | `~/.config/sanitai/config.toml` — every field optional. |

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

  ~/.config/sanitai/config.toml      severity floor, redaction defaults, rule paths
  ~/.config/sanitai/rules/*.yaml     custom detectors (optional)
  $PWD/<export>.redacted.zip          default redaction output (mode: copy)
```

Everything happens in a single local process. No state is persisted between runs. The parser identifies the export format, walks each conversation's message turns, and hands the text to the detection layer. The detector runs every enabled rule against each message and emits findings tagged with file, line, and severity. The reporter formats by severity tier; the redactor (if invoked) re-emits the export with matched ranges replaced.

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

| Key | Default | Description |
|---|---|---|
| `scan.min_severity` | `"low"` | Floor for findings printed and counted. `low` shows everything. |
| `scan.disable_detectors` | `[]` | Detector IDs to skip. Useful for noisy heuristics in specific corpora. |
| `redact.mask` | `"[REDACTED]"` | String written in place of each match when `mask_with_type` is `false`. |
| `redact.mask_with_type` | `false` | When `true`, replace each match with its type label, e.g. `[AWS_ACCESS_KEY]`. |
| `rules.extra_rules_dirs` | `["~/.config/sanitai/rules"]` | Additional directories scanned for custom-rule YAML files. |

Validate your config:

```sh
sanitai config validate
```

---

## Commands

| Command | What it does |
|---|---|
| `sanitai scan <path>` | Scan an export file (ZIP) and print findings |
| `sanitai redact <path>` | Write a redacted copy of the export alongside the original |
| `sanitai redact --in-place <path>` | Redact and overwrite the original (use with caution) |
| `sanitai redact --mask <str> <path>` | Replace matched text with a fixed mask |
| `sanitai redact --mask-with-type <path>` | Replace matched text with the finding type label |
| `sanitai config validate` | Lint `~/.config/sanitai/config.toml` and any custom rule files |
| `sanitai --help` | Show help |
| `sanitai --version` | Show version |

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

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

SanitAI's detection rules were written from scratch, but the [gitleaks](https://github.com/gitleaks/gitleaks) project (MIT license) served as a reference for which credential formats exist and how to structure a keyword-gated, entropy-filtered ruleset. Where a pattern in `crates/sanitai-detectors/src/regex_detector.rs` was informed by a specific gitleaks rule file, the source is noted in an inline comment. We are grateful to the gitleaks contributors for their public work in this space.

---

> [sanitai.pixelabs.net](https://sanitai.pixelabs.net) · [thepixelabs/sanitai](https://github.com/thepixelabs/sanitai) · an independent project by [Pixelabs](https://pixelabs.net)
