# Security Policy

Version: v0.1.x  
Last reviewed: 2026-04-10

---

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (current) | Yes — security fixes backported |
| < 0.1.0 | No |

---

## Scope

### In scope

- Vulnerabilities in detection logic that cause systematic failure to detect a known-bad pattern class
- Vulnerabilities allowing a malformed input file to execute arbitrary code or escape the process sandbox
- Issues with the release pipeline that allow a tampered binary to pass signature verification
- Logic errors in redaction output that cause unredacted secrets to appear in redacted files
- Supply chain issues in direct Cargo dependencies

### Out of scope

- False negatives on novel secret formats not covered by any built-in or user-supplied rule
- Performance issues
- Vulnerabilities requiring physical access to the machine
- Security issues in third-party LLM providers

---

## Reporting a vulnerability

Do **not** open a public GitHub issue for security vulnerabilities.

Send a report to: **security@sanitai.dev**

Include:
- Description of the vulnerability and potential impact
- Steps to reproduce, with a minimal input file if applicable (use synthetic data, no real credentials)
- SanitAI version (`sanitai --version`)
- OS and architecture

**Response SLA:**

| Severity | Acknowledgement | Initial assessment | Target patch |
|---|---|---|---|
| Critical | 1 business day | 3 calendar days | 14 calendar days |
| High | 2 business days | 7 calendar days | 30 calendar days |
| Medium | 2 business days | 7 calendar days | 90 calendar days |
| Low | 5 business days | 14 calendar days | Next minor release |

---

## Trust model

SanitAI is offline-only. At runtime it makes no network connections. No conversation content, findings, or metadata leave the device. This is enforced by design — there is no setting that enables network access.

---

## Verifying release signatures

All release binaries are signed using cosign in keyless mode via GitHub Actions OIDC.

```sh
cosign verify-blob \
  --certificate sanitai-<platform>.cert \
  --signature sanitai-<platform>.sig \
  --certificate-identity \
    "https://github.com/sanitai/sanitai/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer \
    "https://token.actions.githubusercontent.com" \
  sanitai-<platform>
```

Expected output: `Verified OK`

| Platform | Suffix |
|---|---|
| Linux x86-64 | `linux-amd64` |
| Linux ARM64 | `linux-arm64` |
| macOS x86-64 | `darwin-amd64` |
| macOS ARM64 | `darwin-arm64` |

---

## Coordinated disclosure

We follow coordinated disclosure. We ask reporters to give us reasonable time before public disclosure. We will not pursue legal action against researchers who report in good faith, follow this policy, and avoid accessing data they do not own.
