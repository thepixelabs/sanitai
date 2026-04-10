# ADR-004: Distribution Strategy

**Status:** Accepted  
**Date:** 2026-04-10  
**Deciders:** CTO, DevOps

## Context

SanitAI targets developers on macOS and Linux. Installation friction is the #1 reason developer tools fail to reach critical mass.

## Decision

Ship via four channels in order of priority:

| Priority | Channel | Target audience |
|---|---|---|
| T1 | Homebrew tap (`brew install sanitai/tap/sanitai`) | macOS and Linux (Homebrew) |
| T1 | GitHub Releases binary download (6 targets) | All platforms, CI pipelines |
| T2 | `cargo install sanitai` | Rust developers |
| T2 | npm wrapper (`npm i -g sanitai`) | JS ecosystem developers |

## Build toolchain

- Cross-compilation via `cargo-zigbuild` for all Linux targets (avoids glibc version matrix)
- Native macOS runner for darwin targets (required for notarization)
- Targets: `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`

## Signing and provenance

- Binaries signed with cosign keyless (Sigstore public-good instance, OIDC from GitHub Actions)
- SLSA Level 2 provenance in v0.1 (build on GitHub-hosted runners); Level 3 deferred to v0.2
- SBOM generated via `cargo-cyclonedx` in CycloneDX format

## Deferred

- Windows support (v0.2 — requires separate sandbox implementation using Job Objects)
- APT/YUM repos, Nix flake, AUR, Scoop (v0.2 after confirming demand)
- Docker image (v0.2)

## Consequences

- Homebrew is macOS/Linux only; Windows users must download the binary manually in v0.1.
- npm wrapper adds Node.js as a runtime dependency for JS users — acceptable because it's optional.
- `cargo install` requires users to have a Rust toolchain; not suitable for end-user distribution.
