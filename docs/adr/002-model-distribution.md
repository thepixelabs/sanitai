# ADR-002: ML Model Distribution Strategy

**Status:** Deferred (v0.2)  
**Date:** 2026-04-10  
**Deciders:** CTO, Chief Architect

## Context

Future ML-based PII detection (BERT-tiny INT8 ONNX, ~15MB) requires distributing a model file. Options: embed in binary vs. post-install download.

## Decision

**Deferred to v0.2.** v0.1 ships with regex + entropy + heuristic detectors only. No ONNX model in v0.1.

## Planned decision for v0.2

Post-install download with compile-time hash pin:
- The expected SHA-256 of the model file is embedded in the binary at compile time via `build.rs` reading `models/model.sha256` (committed to the repo).
- First run fetches the model over HTTPS, verifies the hash before loading, rejects on mismatch.
- `--offline-install <path>` flag accepts a local model file for air-gapped environments.
- `sanitai install-models` is the explicit install command; the model is never downloaded silently.

## Why not embed in binary

- 15MB model makes the binary ~20MB compressed. npm installs over 30MB attract user complaints.
- Two-binary strategy (sanitai-lite / sanitai) mitigates this but adds distribution complexity.
- Post-install with a pinned hash achieves the same trust guarantee as embedding.

## Consequences

- v0.1 users get regex+entropy only. PII (names, addresses) detection waits for v0.2.
- The `sanitai install-models` CLI command exists in v0.1 but prints "no models available" — it is not removed, to avoid breaking scripts that check for the subcommand.
