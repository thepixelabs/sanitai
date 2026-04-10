# ADR-007: Two-Binary Split (sanitai vs sanitai-lite)

**Status:** Accepted (planned for v0.2 when ONNX ships)  
**Date:** 2026-04-10  
**Deciders:** CTO, DevOps

## Context

When ONNX ML models ship in v0.2, the binary size will increase by ~15-20MB. Homebrew formulae over 20MB attract scrutiny; npm packages over 30MB get bad press. The "single static binary" pitch becomes harder to make.

## Decision

Ship two binary artifacts when ONNX ships:

| Binary | Size | Detectors | Target audience |
|---|---|---|---|
| `sanitai` | ~35MB | regex + entropy + heuristic + ONNX NLP | Default for Homebrew, direct download |
| `sanitai-lite` | ~8MB | regex + entropy + heuristic | npm default, CI pipelines, minimal installs |

`sanitai-lite` uses `sanitai install-models` to fetch the ONNX model post-install (hash-pinned, see ADR-002).

## In v0.1

Only one binary exists (`sanitai`, ~4MB with no ONNX). The `sanitai-lite` Homebrew formula and npm `postinstall` path are scaffolded but point to the same binary. This avoids a breaking distribution change when ONNX ships.

## Naming convention

Binary artifact filenames:
- `sanitai-<version>-<target>.tar.gz` — full binary
- `sanitai-lite-<version>-<target>.tar.gz` — lite binary (v0.2+)

## Consequences

- Two release artifacts to build, sign, and publish per target from v0.2 onward.
- Users who install via Homebrew get the full binary automatically.
- Users who install via npm get lite by default — they can opt into full via `sanitai install-models`.
- The feature set difference (NLP PII detection) must be clearly documented in the README.
