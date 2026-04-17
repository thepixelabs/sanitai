# CHANGELOG


## v0.2.1 (2026-04-17)

### Bug Fixes

- **ci**: Resolve fmt, clippy, and release build failures
  ([`372771f`](https://github.com/thepixelabs/sanitai/commit/372771f3526aad87d085bdbb503b625b67c54d7e))

- Apply cargo fmt across workspace (rustfmt 1.87.0) - Fix clippy --all-targets -D warnings:
  derivable_impls on ContextClass, new_without_default on Menu, manual_flatten in scan_runner,
  if_same_then_else in settings, unnecessary_map_or in redact_screen, redundant `use sanitai_tui`,
  and allow expect/unwrap inside sarif tests module - Annotate unused Theme palette scaffolding with
  dead_code allow - Regenerate Cargo.lock (adds missing context-eval entry; bumps workspace members
  from 0.1.0 to 0.1.2 to match Cargo.toml workspace.package.version) - Pin cargo-zigbuild to ^0.21
  in reproducible-verify and build-release workflows. Zigbuild 0.22 requires rustc 1.88; we pin to
  1.87.0 via rust-toolchain.toml. Bump together if the rustc pin ever moves. - Add build_command =
  "cargo update --workspace" to semantic-release config so Cargo.lock gets refreshed on version
  bumps; install the pinned rust toolchain in release.yml so that command has a stable cargo
  available.

The v0.2.0 build-release workflow failed because Cargo.lock on tag v0.2.0 was stale
  (semantic-release only updated Cargo.toml). That tag cannot be retroactively rebuilt; v0.2.1 (cut
  by this fix commit) will be the first release with a correct Cargo.lock and green build-release
  pipeline.


## v0.2.0 (2026-04-17)

### Bug Fixes

- Improve mobile/iPad hero layout and responsive breakpoints
  ([`f626e41`](https://github.com/thepixelabs/sanitai/commit/f626e41527f0dcb77ced625822b07fb69d61ebb9))

- Resolve post-merge compile errors and test failures
  ([`a0e36b7`](https://github.com/thepixelabs/sanitai/commit/a0e36b78f212733ccb283585597a6bdab86560db))

- Cargo.toml: remove duplicate rusqlite workspace dep (introduced by merge) - sanitai-tui/app.rs:
  populate new FindingRecord fields (role, category, entropy_score, context_class, secret_hash) in
  TUI scan history writer - sanitai-cli/sarif.rs: add missing Finding fields to test helper
  mk_finding - sanitai-detectors/regex_detector.rs: fix huggingface_token test — token was 39 chars
  but pattern requires exactly 37

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

### Documentation

- Add floating Nix hero to README
  ([`a27c701`](https://github.com/thepixelabs/sanitai/commit/a27c701b546b61b9a7ff8d49ec2b605f42a4b7f5))

Embeds a CSS-animated floating Nix mascot (hero pose, 280px wide) in the README via a self-contained
  SVG with a base64 PNG payload. GitHub renders SVG animations via <img>, no external URL needed.
  Also whitelist nix-readme.png and nix-float.svg in .gitignore.

- Fix landing page — replace zip/export fiction with actual local file discovery
  ([`505208f`](https://github.com/thepixelabs/sanitai/commit/505208f23e47495bc5472543f5ec72bfba947be0))

The site claimed SanitAI scanned ZIP exports downloaded from Claude.ai and OpenAI. That's wrong.
  SanitAI auto-discovers local session files on disk: Claude Code JSONL sessions
  (~/.claude/projects/), Claude Desktop JSON files, and Cursor SQLite workspace databases. No
  export, no download, no zip involved.

- Title, meta, OG, and Twitter tags updated to say "conversation history" - JSON-LD FAQ corrects
  supported sources - Terminal demo now shows `sanitai scan` with real output format (turn= bytes=)
  - "How it works" Step 01 changed from "Export (download a ZIP)" to "Install" - Step 02 uses
  `sanitai scan` with auto-discovery description - Supported sources table now shows Claude Code,
  Claude Desktop, Cursor - FAQ answer corrected to describe actual auto-discovery behaviour

- Link title and Nix mascot to homepage
  ([`4fc64c3`](https://github.com/thepixelabs/sanitai/commit/4fc64c375d2a5c5c29c9aaa17fe1561af05d32eb))

- Move Nix float img below h1 to avoid GitHub border-bottom overlap
  ([`f15688a`](https://github.com/thepixelabs/sanitai/commit/f15688ae61dd9ab919498073b364d40765f75d54))

### Features

- **phase-0**: Enrich Finding data model, schema v2 migration, vault_legacy_token entropy gate
  ([`6c463ff`](https://github.com/thepixelabs/sanitai/commit/6c463ff1e861438af39d6a7f060403e1f95b232c))

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- **phase-1b+4b**: Context-gated detector rules, TUI ResultsFilter, --show-all flag
  ([`526a36f`](https://github.com/thepixelabs/sanitai/commit/526a36fde428da13e4acb877c7db5cb1bdd66fb7))

- Upgrade vault_legacy_token: improved [sb]. pattern + AC keyword gate - Add twilio_auth_token,
  datadog_api_key, vercel_access_token rules (all gated) - Add sanitai-tui crate: full TUI with
  ResultsFilter, keyboard bindings, confidence filter (0/1/2/3 keys), context toggle (f/Tab), 6
  screens - Add --show-all CLI flag: suppresses Educational/DocumentationQuote by default - Add
  pipe_mode and tui_smoke integration tests with fixtures

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- **phase-2+1a**: Aho-corasick keyword pre-filter, stopwords, 25 new detector rules
  ([`4a0cccb`](https://github.com/thepixelabs/sanitai/commit/4a0cccb563e047afed55b7a71933188b258853bc))

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- **phase-3+4a**: Cursor/copilot/gemini parsers, SARIF output, discover subcommand
  ([`96a2a1d`](https://github.com/thepixelabs/sanitai/commit/96a2a1d2e471e666f4a29e54d646dad812cc864d))

- Add CursorParser: reads VS Code SQLite state.vscdb, platform-aware paths - Add CopilotParser:
  reads Copilot Chat .log files line-by-line - Add GeminiParser: reads Google Takeout
  MyActivity.json - Update discovery.rs: adds discover_copilot, discover_gemini - Add sarif.rs:
  hand-rolled SARIF 2.1.0 serialiser (no external crate) - Add --format sarif to CLI output options
  - Add `sanitai discover` subcommand for auto-discovery - Add test fixtures and integration tests
  for new parsers

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- **phase-5**: Heuristic context classifier, evaluation corpus, precision/recall tool
  ([`02a53bd`](https://github.com/thepixelabs/sanitai/commit/02a53bdda981fa200a3fed5f02d06471b0c1ce6e))

- Add ContextClassifier: heuristics-only (no LLM), signals include code-fence detection, inline
  code, educational keywords, doc URL proximity, hallucination patterns, cross-turn span - Add
  corpora/context/ with 25 labeled examples (real_paste/educational/
  documentation_quote/model_hallucination/unclassified) + schema + guidelines - Add
  tools/context-eval: precision/recall evaluator, exits 1 if gates fail - Export ContextClassifier
  and ContextClassifierConfig from sanitai-detectors

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>


## v0.1.2 (2026-04-12)

### Bug Fixes

- Move landing page to docs/ for GitHub Pages
  ([`b2b0581`](https://github.com/thepixelabs/sanitai/commit/b2b058175f5f6e6cd9e754a23eb1e57792aab05a))


## v0.1.1 (2026-04-12)

### Bug Fixes

- Rename landing.html to index.html for GitHub Pages
  ([`4c35f9f`](https://github.com/thepixelabs/sanitai/commit/4c35f9f71a5c34f3b1df45a11c898c9b0defe240))


## v0.1.0 (2026-04-12)

### Features

- Add landing page with Nix mascot, carousel, and features
  ([`7c46089`](https://github.com/thepixelabs/sanitai/commit/7c4608921be9f79af4913f9b9d54c414d5c30e03))
