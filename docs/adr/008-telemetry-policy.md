# ADR-008: Telemetry Policy

**Status:** Accepted  
**Date:** 2026-04-10  
**Deciders:** CEO, CTO

## Context

Many CLI tools add opt-in telemetry for usage analytics. SanitAI's core value proposition is "never phones home." These are in direct tension.

## Decision

**No telemetry in v0.1. Not even opt-in.**

## Rationale

1. **Brand integrity:** "100% local, zero network" is our #1 trust differentiator. Adding an opt-in telemetry toggle weakens the claim even if the implementation is honest — users cannot verify that "opt-in" is truly opt-in from the binary alone.
2. **Provable guarantee:** The seccomp-bpf sandbox (ADR-003) blocks all network syscalls. Any telemetry code would be dead code and would confuse auditors.
3. **Alternative signal:** GitHub star count, release download counts, and Homebrew install counts provide sufficient product signal at this stage.
4. **Future enterprise tier:** Centralised audit logging is a paid-tier feature. If we add telemetry to the OSS core, we undermine the enterprise differentiation.

## What this means for product decisions

- No crash reporting. Bugs are reported via GitHub issues.
- No feature flag system tied to a remote service.
- No "phone home on first run" license activation.
- No anonymous usage counters.

## Revisit trigger

Revisit this decision if: (a) we cannot diagnose critical bugs without remote crash data AND (b) we can implement crash reporting in a way that is provably sandboxed (i.e., crash reports go to a local file the user explicitly sends). A local crash dump + opt-in email submission is the only acceptable pattern.

## Consequences

- We will not have automatic insight into what detectors are most used or what error conditions are most common.
- The QA team must build a comprehensive fixture corpus (see task #32) to compensate.
- Documentation must be clear about how to report bugs (GitHub issues, with sanitized output).
