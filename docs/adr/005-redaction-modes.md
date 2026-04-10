# ADR-005: Redaction Modes

**Status:** Accepted  
**Date:** 2026-04-10  
**Deciders:** CTO, Product Manager

## Context

Users need different redaction behaviors depending on their use case: sharing an export with a colleague (needs full redaction), debugging a CI pipeline (needs a stable reference), enterprise vault integration (needs a lookup key).

## Decision

Four redaction modes, user-selectable via `--mask` / `--mask-with-type` flags or config:

| Mode | Output | Use case |
|---|---|---|
| `mask` (default) | `[REDACTED]` | Sharing exports; removes all trace |
| `mask-with-type` | `[AWS_ACCESS_KEY]` | Debugging; shows what was found |
| `hash` | `[sha256:a3f1c9e2]` (first 8 hex chars of HMAC-SHA256) | Stable reference; deduplicate without revealing value |
| `vault-ref` | `${VAULT:aws_access_key_1}` | Enterprise; maps to a secrets manager lookup |

## Hash mode details

The hash uses HMAC-SHA256 with a per-session salt generated from `getrandom` at startup. The salt is held in memory for the duration of the run and never persisted. This means:
- Two runs of the same file produce different hashes (no cross-run linkability by default)
- Within a single run, the same secret always produces the same hash (deduplication works)
- The hash cannot be reversed to recover the original secret

If a stable cross-run hash is needed (e.g., for audit correlation), users can provide `--hash-key <hex>` to fix the salt. This is an advanced option not shown in basic help.

## Vault-ref mode details

References are numbered per detector class within a run: `aws_access_key_1`, `aws_access_key_2`, etc. The mapping from reference name to original value is printed to stderr (not stdout) at end of run, allowing piped output to be clean while the mapping is captured separately.

## Consequences

- The default (`mask`) is maximally safe and requires no configuration.
- `vault-ref` mode requires downstream tooling to consume the reference mapping; this is an enterprise feature.
- Partial redaction mode (keep first N chars) was considered but rejected for v0.1 — showing any part of a secret in output defeats the purpose for the primary use case.
