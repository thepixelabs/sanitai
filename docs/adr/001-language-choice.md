# ADR-001: Language Choice — Rust

**Status:** Accepted  
**Date:** 2026-04-10  
**Deciders:** CTO, Chief Architect

## Context

SanitAI needs to: (1) scan potentially large files without memory errors, (2) zeroize secret-bearing memory reliably, (3) ship as a single static binary with no runtime, (4) integrate with ONNX runtime for future ML detectors.

## Decision

Use **Rust** as the sole implementation language.

## Rationale

- **Memory safety without GC:** The `zeroize` crate guarantees secrets are overwritten on drop. Go's GC may move or copy heap allocations before zeroing, making reliable secret erasure difficult.
- **Single static binary:** `cargo build --target x86_64-unknown-linux-musl` produces a fully self-contained binary with no dynamic linking. Critical for the "no-install" developer experience.
- **`unsafe` is auditable:** All `unsafe` blocks in the codebase are explicitly justified and grep-able. Go's CGo is harder to audit.
- **ONNX integration:** The `ort` crate provides first-class Rust bindings to ONNX Runtime for future ML detector support.
- **`cargo-vet` + `cargo-deny`:** Supply chain controls are mature in the Rust ecosystem.

## Alternatives considered

- **Go:** Excellent static binaries, but GC complicates memory zeroization. No equivalent of the `zeroize` crate with Drop guarantees.
- **C/C++:** Maximum control but unacceptable CVE risk surface for a security tool. No memory-safe standard.
- **Python:** Unsuitable — interpreter dependency, no static binary, memory model incompatible with secret erasure.

## Consequences

- All contributors need Rust knowledge.
- Compile times are longer than Go; mitigated by `sccache` in CI.
- `unsafe` usage is permitted only in `sanitai-sandbox` (for `mlock`/seccomp syscalls) and `sanitai-core::secure` (for `mlock`), with a mandatory `// SAFETY:` comment on every block.
