# Custom Detection Rules

Version: v0.1.x  
Last reviewed: 2026-04-10

---

## Overview

SanitAI's built-in detectors cover common patterns. For internal secret formats, organisation-specific prefixes, or domain-specific PII, write custom rules in YAML and drop them in a directory SanitAI knows about.

---

## Configuring the rules directory

```toml
# ~/.config/sanitai/config.toml
[rules]
extra_rules_dirs = ["~/.config/sanitai/rules", "/etc/sanitai/rules"]
```

Or inline:

```sh
sanitai scan --rules-dir ./my-rules ~/Downloads/export.zip
```

---

## Rule schema

```yaml
# Required
id: string              # snake_case, unique across all rules
name: string            # human-readable display name
severity: "low" | "medium" | "high"
pattern: string         # Rust regex syntax

# Optional
min_entropy: float      # Shannon entropy floor (bits/char). Default: not applied.
context_keywords: [string]  # match only if one of these appears within 200 chars
description: string     # shown with --verbose
references: [string]    # informational URLs
```

Unknown fields produce a warning at startup. Unknown top-level fields are a hard error.

**YAML escape note:** Regex backslash sequences must be double-escaped in YAML strings: `\\d`, `\\w`, `\\s`.

---

## Example 1 — Custom API key format

```yaml
id: acme_api_key
name: "ACME Platform API Key"
severity: high
description: >
  ACME internal platform keys. Rotate at https://developer.acme.internal/keys

pattern: "acmk_(?:live|test)_[0-9a-f]{32}"
min_entropy: 3.5

references:
  - "https://developer.acme.internal/docs/authentication"
```

Test before deploying:

```sh
# Should find a finding
echo 'key: acmk_live_a3f1c9e2b8d047f6a1e3c5b7d9f02e4a' \
  | sanitai scan --rules-dir ./rules --stdin

# Should NOT (entropy too low)
echo 'key: acmk_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  | sanitai scan --rules-dir ./rules --stdin
```

---

## Example 2 — Internal secret prefix

```yaml
id: vault_encrypted_secret
name: "HashiCorp Vault Encrypted Value"
severity: medium
description: >
  Vault transit-encrypted values. Their presence in an LLM export indicates
  encrypted secrets are being pasted into prompts — a workflow control failure.

pattern: "vault:v\\d+:[A-Za-z0-9+/]+=*"

references:
  - "https://developer.hashicorp.com/vault/docs/secrets/transit"
```

---

## Example 3 — Specific PII pattern

```yaml
id: internal_user_id
name: "Internal User ID"
severity: low
description: >
  Internal user identifiers — pseudonymous personal data under GDPR Art. 4(5).
  Flag for review before sharing exports externally.

pattern: "usr_(?:prod|stg|dev)_[0-9A-Z]{26}"
context_keywords: ["user_id", "userid", "uid", "account", "profile"]
```

---

## Rule loading order and conflicts

1. Built-in detectors (compiled in)
2. `extra_rules_dirs` (config file order)
3. `--rules-dir` (CLI flag order)

Duplicate `id` values are a hard error at startup.

Disable a built-in detector:

```toml
[scan]
disable_detectors = ["email_address", "phone_number"]
```

List all loaded detectors:

```sh
sanitai scan --list-detectors
```

---

## Validating rules

```sh
sanitai config validate --rules-dir ./my-rules
```

Loads all rules, reports schema errors, prints loaded detector IDs. Does not scan any files.

---

## Regex reference

SanitAI uses the Rust `regex` crate. Key differences from PCRE:
- No lookahead or lookbehind assertions
- No backreferences
- `\b`, `\d`, `\w`, `\s` supported (double-escape in YAML: `\\d`)
- Unicode character properties supported: `\p{Lu}`, `\p{Letter}`

Full syntax: https://docs.rs/regex/latest/regex/#syntax
