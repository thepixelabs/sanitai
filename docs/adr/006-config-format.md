# ADR-006: Configuration Format

**Status:** Accepted  
**Date:** 2026-04-10  
**Deciders:** CTO

## Context

SanitAI needs a configuration system that supports: layered precedence (CLI > env > local > global), schema validation, editor tooling (JSON schema), and a stable format across v0.x releases.

## Decision

**TOML** as the configuration file format, with `figment` for layered loading and `schemars` for JSON schema generation.

Config file locations (in precedence order, lowest to highest):
1. Built-in defaults (compiled in)
2. `$XDG_CONFIG_HOME/sanitai/config.toml` (global, typically `~/.config/sanitai/config.toml`)
3. `./sanitai.toml` (project-local)
4. `SANITAI_*` environment variables
5. CLI flags

## Schema versioning

`schema_version = 1` is a required top-level field. Unknown keys at the top level are a **hard error** in v0.1 (not a warning). This catches typos early. We can soften to a warning in v0.2 once the schema is stable.

## Why TOML over alternatives

- **TOML:** Human-friendly, no indentation sensitivity, good Rust support (`toml` crate). Chosen.
- **YAML:** Footguns (Norway problem, implicit typing, anchors). Rejected.
- **JSON:** No comments. Rejected for a config file.
- **DHALL/CUE:** Too exotic for a developer tool config. Rejected.

## JSON Schema

`sanitai config schema` prints a JSON Schema (draft 7) for the config file, generated at compile time via `schemars`. This enables editor autocompletion via the VSCode TOML extension or similar. The schema is also published at `https://sanitai.dev/config-schema/v1.json`.

## Consequences

- `figment` adds a dependency but saves ~300 lines of manual layering code.
- The `schema_version` field means old config files will error on major version bumps — acceptable, with a migration guide.
- Environment variable names are `SANITAI_SCAN__CONFIDENCE_THRESHOLD` (double underscore for nesting), matching figment's env provider convention.
