# ADR-003: Process Sandbox Approach

**Status:** Accepted  
**Date:** 2026-04-10  
**Deciders:** CTO, Security Engineer

## Context

SanitAI's "no network calls, ever" claim must be provable, not just promised. If a malicious transitive dependency attempts a syscall, the sandbox should kill the process.

## Decision

**In-process sandbox** applied before scanning begins:
- **Linux:** `seccomp-bpf` allowlist via the `seccompiler` crate, with argument-level restrictions. `SECCOMP_RET_KILL_PROCESS` on any non-allowlisted syscall.
- **macOS:** `sandbox_init()` with a Seatbelt profile that denies all `network*` operations.

Two-phase install:
1. **Phase 1 (permissive):** Applied at startup. Allows `mmap`/`mprotect` with `PROT_EXEC` for ONNX Runtime and dynamic linker initialization.
2. **Phase 2 (strict):** Applied before the first file is opened. Removes `PROT_EXEC` from `mprotect`, restricts `write` to fd 1 and 2 only, denies all socket/network syscalls.

## Alternatives considered

- **Fork/exec worker process:** Cleaner blast radius, but adds IPC complexity (a channel protocol, two binaries). Deferred as `sanitai-sandbox-worker` for v0.3 if needed.
- **Landlock (Linux 5.13+):** Filesystem access control, complements seccomp but does not cover network. Added as a stretch goal for v0.2.
- **No sandbox (trust `cargo-deny`):** `cargo-deny` prevents known-network crates from entering the dep tree, but cannot prevent a zero-day in an existing dep. Insufficient alone.

## Consequences

- seccomp-bpf requires Linux kernel ≥ 3.5. All supported targets meet this.
- `sandbox_init()` is deprecated SPI on macOS 12+. We use it for v0.1 and track the migration to App Sandbox entitlements for the notarized `.app` distribution path.
- The `--no-sandbox` flag exists for debugging but prints a visible warning to stderr and is not documented in the main help text.
