# Changelog

All notable changes to SanitAI are listed here. Versions follow [SemVer](https://semver.org);
entries are generated from conventional commit subjects on each release.

<!-- version list -->

## v0.5.0 (2026-09-16)

### Features

- **scan**: Ignore patterns via config, --ignore, and the TUI
  ([`e036d18`](https://github.com/thepixelabs/sanitai/commit/e036d188621cc0a4a26a74282da6870a3a8b3ae4))


## v0.4.3 (2026-09-15)

### Bug Fixes

- **scanner**: Hide vendor test values, mask matches, explain findings
  ([`daa8aa7`](https://github.com/thepixelabs/sanitai/commit/daa8aa7f51fc56149abdf14ac73d69728439293b))


## v0.4.2 (2026-09-15)

### Bug Fixes

- **detectors**: Cut false positives and group repeated findings
  ([`059119b`](https://github.com/thepixelabs/sanitai/commit/059119b805aba733eec37bfb37d29cb87219cdf6))


## v0.4.1 (2026-09-14)

- Baseline of the current codebase: offline scanner for Claude Code, Claude Desktop and Cursor
  histories with 90+ detectors, interactive TUI, redaction, signed multi-platform binaries and a
  Homebrew tap. Earlier 0.x versions were internal iterations.
