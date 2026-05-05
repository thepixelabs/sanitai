# CHANGELOG


## v0.3.2 (2026-05-05)

### Bug Fixes

- Remove co-author footers from CHANGELOG and fix pre-push hook bash compat
  ([`f1f6474`](https://github.com/thepixelabs/sanitai/commit/f1f64743b5deb71051fee92226350a56ef79a927))

Replace mapfile (bash 4+) with while-read loop so the pre-push hook works on macOS system bash 3.
  Strip Co-Authored-By trailer lines from CHANGELOG.md.

- **hooks**: Pass paths as positional args to sanitai scan, not --file flags
  ([`42a813e`](https://github.com/thepixelabs/sanitai/commit/42a813edded0f1af8798091331652a65eb1fcc3c))


## v0.3.1 (2026-05-05)

### Bug Fixes

- Regenerate Cargo.lock to match workspace v0.3.0
  ([`83e8418`](https://github.com/thepixelabs/sanitai/commit/83e8418d087a0f9ff68c903d9adb5b13635221b2))


## v0.3.0 (2026-05-05)

### Bug Fixes

- Improve mobile/iPad hero layout and responsive breakpoints
  ([`d262665`](https://github.com/thepixelabs/sanitai/commit/d262665ed122137541f2aac6c01ba998c1f9a7ab))

- Move landing page to docs/ for GitHub Pages
  ([`a4dda4f`](https://github.com/thepixelabs/sanitai/commit/a4dda4f36c8dbc1a3319d60974fff14c4e08f64b))

- Rename landing.html to index.html for GitHub Pages
  ([`b93a608`](https://github.com/thepixelabs/sanitai/commit/b93a60800143891d36e3d58edd067f7a1a8e0df8))

- Replace unmaintained atty crate with std::io::IsTerminal
  ([`57ab85e`](https://github.com/thepixelabs/sanitai/commit/57ab85e7eab18f02f505ec93df5bbd9368840f46))

Drops the `atty` dependency in favour of the stdlib `IsTerminal` trait (stable since Rust 1.70).
  Closes RUSTSEC-2024-0375 (crate unmaintained) and RUSTSEC-2021-0145 (potential unaligned read on
  Windows + custom allocator). Removes both advisories from the cargo-deny ignore list. No behavior
  change: TTY detection on stdin/stdout is preserved byte-for-byte.

- Resolve post-merge compile errors and test failures
  ([`1f5b961`](https://github.com/thepixelabs/sanitai/commit/1f5b9618b44cfc8e6973006633d06cdebfe74201))

- Cargo.toml: remove duplicate rusqlite workspace dep (introduced by merge) - sanitai-tui/app.rs:
  populate new FindingRecord fields (role, category, entropy_score, context_class, secret_hash) in
  TUI scan history writer - sanitai-cli/sarif.rs: add missing Finding fields to test helper
  mk_finding - sanitai-detectors/regex_detector.rs: fix huggingface_token test — token was 39 chars
  but pattern requires exactly 37

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- **ci**: Fix sandbox clippy errors (Linux-only dead code + private interface) and auto-commit
  Cargo.lock on release
  ([`420dc45`](https://github.com/thepixelabs/sanitai/commit/420dc453a0fab978a0cdd4e0fc566a780b49accf))

- sanitai-sandbox: mark SockFilter as pub(crate) to satisfy private_interfaces (build_filter returns
  Vec<SockFilter>), and allow dead_code on BPF_JSET and the non-selected AUDIT_ARCH_* constant.
  These only surface on Linux where the seccomp module compiles — my local macOS clippy run did not
  catch them in the previous commit. - pyproject.toml: append `git add Cargo.lock` to build_command
  so the refreshed lockfile actually rides along in the version-bump commit. python-semantic-release
  does not stage build_command side-effects automatically, which is why v0.2.1's tag ended up with a
  stale Cargo.lock even though `cargo update --workspace` ran successfully.

- **ci**: Ignore correct RUSTSEC ids for atty and paste
  ([`6bdedd8`](https://github.com/thepixelabs/sanitai/commit/6bdedd82e24e73f5274ca301cfd03ae3c5e4f8df))

The ids in the previous commit were wrong (copy-paste from a stale list). The advisories actually
  flagged by cargo-deny 0.19.2 are:

RUSTSEC-2021-0145 — atty unaligned read (Windows + custom allocator only) RUSTSEC-2024-0436 — paste
  proc-macro unmaintained (transitive via ratatui)

Neither is reachable in our build. Replace the placeholder ids with the real ones so cargo-deny
  stops emitting "no crate matched advisory criteria" and advisory errors.

- **ci**: Ignore remaining unmaintained/unsound advisories
  ([`3d0b0c5`](https://github.com/thepixelabs/sanitai/commit/3d0b0c530a3198967fff7d21f4f8552702fc1148))

cargo-deny surfaced three more advisories after the previous ignore-list update:

RUSTSEC-2024-0375 — atty unmaintained (separate from 2021-0145 unsound) RUSTSEC-2026-0097 — rand
  custom-logger unsoundness (not reachable)

Both atty advisories are mitigated by switching to std::io::IsTerminal in a follow-up; neither
  applies to our runtime today. rand 2026-0097 is only triggered by a custom log::Logger that calls
  rand::rng() — we don't install one.

- **ci**: Make build-release idempotent with pre-existing tag and skip cargo-deny on macOS
  ([`bf590f9`](https://github.com/thepixelabs/sanitai/commit/bf590f9b1ef068fbce70950b91b503f9a2174ff7))

- build-release: the `release` job ran `gh release create` but the release already exists
  (semantic-release creates it via upload_to_release). Probe with `gh release view` and only create
  when missing, so the upload step is reachable and idempotent across retries. - build-release:
  disable SLSA `upload-assets`. Uploading to the release from within the SLSA call races against the
  release job — the release does not exist yet at that point, so upload-assets failed with "not
  include valid file", which cascaded into the SLSA final gate failing and skipping the release job
  entirely. Provenance is still produced as a workflow artifact; the release job downloads and
  uploads *.intoto.jsonl alongside tarballs/sigs/SBOM. - ci: guard `cargo-deny` with `if: runner.os
  == 'Linux'`. The cargo-deny-action is Docker-based and fails on macOS runners with "Container
  action is only supported on Linux". One Linux run per push is enough for supply-chain checks; the
  macOS matrix is there for platform-specific test coverage.

Also manually uploaded the existing v0.2.2 build artifacts (tarballs, sha256, sigs, certs, SBOM)
  from workflow run 24557160984 to the v0.2.2 GitHub Release, which was previously empty. Future
  releases will do this automatically once this commit lands.

- **ci**: Make homebrew-tap bump formula audit-strict compliant
  ([`ac5851a`](https://github.com/thepixelabs/sanitai/commit/ac5851a57986527383d0f966b524af20a92a5cf7))

Replace the old sed-based formula patcher with a Python script that: - Strips any explicit `version`
  stanza (Homebrew parses version from the archive filename; an explicit stanza alongside a
  parseable URL triggers "version X.Y.Z is redundant with version scanned from URL" which fails brew
  audit --strict and blocks the auto-merge gate). - Rewrites the old version token in every URL
  segment — handles both the original #{version} Ruby interpolation form and hardcoded semver from a
  previous bump, so the script is idempotent regardless of formula state. - Preserves the existing
  sha256-update logic unchanged.

- **ci**: Migrate cargo-deny config to v2 schema and mark workspace private
  ([`66bc5aa`](https://github.com/thepixelabs/sanitai/commit/66bc5aa0f91982110e5d3282c3d6d1e74d414adc))

cargo-deny 0.19.2 (bundled in cargo-deny-action v2.0.17) enforces the new schema strictly: every
  advisory key now fails rather than warns, and the old `[licenses] unlicensed/copyleft/deny` keys
  were removed. Without these fixes the advisory-db check errors on:

- workspace crates reporting "unlicensed" (no license field in Cargo.toml and not marked private) -
  internal path deps flagged as wildcard (version = "*") - unmaintained/unsound advisories for atty,
  rand, rand_core

Changes: - Cargo.toml: add `publish = false` and `license = "MIT"` to [workspace.package] so every
  member inherits the repo-root MIT LICENSE and is recognised by cargo-deny as private. - All
  crates/*/Cargo.toml and tools/*/Cargo.toml: inherit publish and license from the workspace via
  `.workspace = true`. - deny.toml: set `[licenses.private] ignore = true` and `[bans]
  allow-wildcard-paths = true`. Ignore three RUSTSEC advisories that are not reachable in our call
  graph (atty deprecation, rand custom-logger unsoundness, rand_core unaligned-read corner case).
  Follow-up: drop `atty` in favour of `std::io::IsTerminal`.

- **ci**: Prevent rust-toolchain component conflict in release build_command
  ([`4ce8bbe`](https://github.com/thepixelabs/sanitai/commit/4ce8bbe82413d27d63ed24212c758d49305c6d0a))

v0.2.3's release job silently swallowed a cargo update failure because the || fallback hid the
  error. Root cause:

dtolnay/rust-toolchain@stable installs a 1.87.0 toolchain with only the default components, then the
  first `cargo update` invocation triggers rust-toolchain.toml which asks for
  rustfmt/clippy/rust-src. The auto-install races against the already-installed toolchain and fails
  with "detected conflict: bin/cargo-clippy". With the previous `|| cargo update --workspace`
  fallback plus no `set -e`, the whole build_command returned 0 but Cargo.lock was never updated, so
  v0.2.3 shipped a stale lockfile and every --locked build on that tag broke.

Fixes:

- release.yml: pass `components: rustfmt, clippy, rust-src` to the rust-toolchain action so it
  installs everything rust-toolchain.toml asks for up front. No auto-install, no conflict. -
  pyproject.toml build_command: drop the `|| cargo update --workspace` fallback and add `set -e`. If
  `cargo update` fails, the release must fail loudly rather than silently producing a broken tag.

Known: v0.2.3 is a broken tag (release exists but no binaries attached because all five platform
  builds failed on the stale lockfile). The next release will be v0.2.4 and should be fully green
  end-to-end.

- **ci**: Release job must not block on SLSA final reporter exit 27
  ([`dc632d6`](https://github.com/thepixelabs/sanitai/commit/dc632d60537f742e96feb2b7e9475addec8cbd16))

The slsa-github-generator v2.0.0 "final" reporter step exits 27 whenever upload-assets=false,
  because its SUCCESS flag is only set when the upload-assets child job runs and succeeds. That
  makes the whole SLSA workflow "fail" from the caller's perspective, which blocks the release job
  and leaves every tag without binaries attached.

We gate the release job with `if: always() && build/sign/sbom == success` instead of needing
  `provenance`. Provenance is still generated and signed by the upstream SLSA workflow; only the
  cosmetic final reporter is non-fatal now. This unblocks end-to-end v0.2.x publishing.

Upgrading to slsa-github-generator v2.1+ or using their direct upload mode would be the cleaner fix
  later, but this is the smallest change that makes release delivery reliable today.

- **ci**: Resolve fmt, clippy, and release build failures
  ([`8f7a2cc`](https://github.com/thepixelabs/sanitai/commit/8f7a2cc8dc705352a38f5f00d4b1f2061f3eb4b8))

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

- **ci**: Unblock homebrew-tap bump job from transitive SLSA failure
  ([`b19cb81`](https://github.com/thepixelabs/sanitai/commit/b19cb81ca88d1f0c0b239e0ad4a9986bf8e09e6f))

The release job runs with `if: always() && ...` so it publishes even when SLSA's final-reporter step
  exits 27. Without the same `always()` guard on bump-tap, GitHub marks it skipped because a
  transitive upstream (SLSA provenance/final) failed — so homebrew-tap has never received a
  version-bump PR.

Match the release job's gate so bump-tap runs whenever the release was actually published,
  regardless of the SLSA reporter quirk.

- **ci**: Upgrade cargo-deny-action to v2.0.17 for CVSS 4.0 support
  ([`5fe4696`](https://github.com/thepixelabs/sanitai/commit/5fe46960c05505c494347baeeadef29513e6fecc))

The old action (v1 / cargo-deny 0.14.21) could not parse newer RUSTSEC advisories that use CVSS
  v4.0, producing:

failed to load advisory database: parse error: ... unsupported CVSS version: 4.0

Bump to EmbarkStudios/cargo-deny-action@v2.0.17, which bundles cargo-deny 0.19.2 with CVSS 4.0
  support, and migrate deny.toml to the v2 schema:

- [advisories]: drop removed keys (vulnerability, notice). Vulnerability advisories always error;
  warnings are promoted via `version = 2`. - [licenses]: drop removed keys (unlicensed, copyleft,
  deny). Anything not in `allow` is rejected by default, so copyleft licenses stay out implicitly.

### Documentation

- Add floating Nix hero to README
  ([`93ca8fe`](https://github.com/thepixelabs/sanitai/commit/93ca8fe9a211d080c8ed5dc09f04ea0b87a6e245))

Embeds a CSS-animated floating Nix mascot (hero pose, 280px wide) in the README via a self-contained
  SVG with a base64 PNG payload. GitHub renders SVG animations via <img>, no external URL needed.
  Also whitelist nix-readme.png and nix-float.svg in .gitignore.

- Fix landing page — replace zip/export fiction with actual local file discovery
  ([`9810a4a`](https://github.com/thepixelabs/sanitai/commit/9810a4a4ce55f73980ccdc6ab93c550bdabf79be))

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
  ([`b7086f6`](https://github.com/thepixelabs/sanitai/commit/b7086f6bd682c87d6903e6de0e8d647bc1f107f5))

- Move Nix float img below h1 to avoid GitHub border-bottom overlap
  ([`220665c`](https://github.com/thepixelabs/sanitai/commit/220665ce1652e3c5efc3c51a96735f0ae25044b6))

### Features

- Scan progress UI, History reload, redact-from-Results, +27 detectors
  ([`7288086`](https://github.com/thepixelabs/sanitai/commit/7288086e8a38d2b191b6cffe6fa81d1286686e3a))

## Summary

- Scan progress UI with animated status - History screen with reload support - Redact-from-Results
  workflow - Open-in-editor integration - Suppressions management screen - +27 new detectors

## Notes

Feature work recovered and rebased cleanly onto main. `docs/planning/` has been removed from history
  and added to `.gitignore`.

- **phase-0**: Enrich Finding data model, schema v2 migration, vault_legacy_token entropy gate
  ([`d4ba83f`](https://github.com/thepixelabs/sanitai/commit/d4ba83f371c17db9729f1cc94c374996e7824edb))

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- **phase-1b+4b**: Context-gated detector rules, TUI ResultsFilter, --show-all flag
  ([`91554b9`](https://github.com/thepixelabs/sanitai/commit/91554b9c158ac52347578a3685fbd14a4a23e49a))

- Upgrade vault_legacy_token: improved [sb]. pattern + AC keyword gate - Add twilio_auth_token,
  datadog_api_key, vercel_access_token rules (all gated) - Add sanitai-tui crate: full TUI with
  ResultsFilter, keyboard bindings, confidence filter (0/1/2/3 keys), context toggle (f/Tab), 6
  screens - Add --show-all CLI flag: suppresses Educational/DocumentationQuote by default - Add
  pipe_mode and tui_smoke integration tests with fixtures

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- **phase-2+1a**: Aho-corasick keyword pre-filter, stopwords, 25 new detector rules
  ([`f4c1eee`](https://github.com/thepixelabs/sanitai/commit/f4c1eee9e6a491ef19feff81cd5d63d95bbc35fc))

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- **phase-3+4a**: Cursor/copilot/gemini parsers, SARIF output, discover subcommand
  ([`993b075`](https://github.com/thepixelabs/sanitai/commit/993b07584b0bdf659adff242f2c596b8a5bd625d))

- Add CursorParser: reads VS Code SQLite state.vscdb, platform-aware paths - Add CopilotParser:
  reads Copilot Chat .log files line-by-line - Add GeminiParser: reads Google Takeout
  MyActivity.json - Update discovery.rs: adds discover_copilot, discover_gemini - Add sarif.rs:
  hand-rolled SARIF 2.1.0 serialiser (no external crate) - Add --format sarif to CLI output options
  - Add `sanitai discover` subcommand for auto-discovery - Add test fixtures and integration tests
  for new parsers

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- **phase-5**: Heuristic context classifier, evaluation corpus, precision/recall tool
  ([`0823332`](https://github.com/thepixelabs/sanitai/commit/08233323a70c71e5984daf23e772108974de6f2b))

- Add ContextClassifier: heuristics-only (no LLM), signals include code-fence detection, inline
  code, educational keywords, doc URL proximity, hallucination patterns, cross-turn span - Add
  corpora/context/ with 25 labeled examples (real_paste/educational/
  documentation_quote/model_hallucination/unclassified) + schema + guidelines - Add
  tools/context-eval: precision/recall evaluator, exits 1 if gates fail - Export ContextClassifier
  and ContextClassifierConfig from sanitai-detectors

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>


## v0.1.0 (2026-04-12)

### Features

- Add landing page with Nix mascot, carousel, and features
  ([`7c46089`](https://github.com/thepixelabs/sanitai/commit/7c4608921be9f79af4913f9b9d54c414d5c30e03))
