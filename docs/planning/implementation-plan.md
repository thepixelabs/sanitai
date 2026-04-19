# SanitAI — Competitive Parity Implementation Plan
> Version: 0.2 | Status: Reviewed (CTO + Staff Engineer) | Date: 2026-04-13

## Context

SanitAI is a local-first secret scanner for AI conversation exports (Claude, ChatGPT, Cursor, Copilot, Gemini). It uniquely handles cross-turn reassembly, transform cascades, and conversation-aware parsing.

**Competitive gap summary:**
- gitleaks: ~200 rules, Aho-Corasick pre-filter, global stopword list, no verification
- TruffleHog v3: ~860 detectors, live verification (AWS STS, GitHub, Stripe, Slack)
- SanitAI today: ~30 rules, no AC pre-filter, no verification, no contextual FP suppression

**Unique SanitAI advantages (must be preserved):**
- Cross-turn secret reassembly (3-turn sliding window, ZeroizeOnDrop)
- Transform cascade (base64/hex/URL/gzip decode before rescan)
- Conversation-aware role/source attribution (User vs Assistant vs System vs Tool)
- AI-chat-native: can distinguish "tutorial explanation" from "real paste" — TruffleHog cannot

---

## Recommended Execution Order

```
Pre-work (immediate hot fix)
→ Phase 0  (data model — prerequisite for everything)
→ Phase 4a (SARIF output — unblock enterprise pilots early)
→ Phase 3  (parsers — real user data to test against)
→ Phase 2  (AC pre-filter — performance + gating for noisy rules)
→ Phase 1a (safe rules — high-precision provider prefixes, no FP risk)
→ Phase 5  (contextual triage — THE MOAT, with corpus baseline first)
→ Phase 1b (gated rules — vault, twilio_auth, datadog; blocked on Phase 5)
→ Phase 4b (TUI filtering on context_class — blocked on Phase 5)
→ Phase 6  (live verification — optional, v2 consideration only)
```

**Rationale for this order:**
- Phase 4a (SARIF only, not TUI filtering) unblocks enterprise/SAST integration immediately
- Phase 3 moves before Phase 2/1 so real user conversations feed Phase 5 corpus collection
- Phase 1 is split: 1a = zero FP-risk rules (ghp_, sk-ant-, hf_, SG., lin_api_, etc.) ship early;
  1b = context-dependent rules (vault_legacy, twilio_auth_token) wait for Phase 5 FP suppressor
- Phase 6 is deferred and optional — it duplicates TruffleHog, conflicts with "local-first" positioning,
  and adds a network-capable subprocess to a security tool. Cut from v1.

---

## Pre-work — Immediate Hot Fix (before any Phase begins)
> `vault_legacy_token` is already live in `regex_detector.rs:529-535` with no entropy gate and no
> keyword gate. The pattern `\bs\.[0-9A-Za-z]{24,}\b` fires on `s.len()`, `s.clone()`, markdown
> sentences ending in `s.`, and thousands of ordinary Rust snippets in AI chats.

- **Add entropy gate immediately** to the existing `vault_legacy_token` rule:
  ```rust
  validate: Some(|m: &str| {
      if shannon_entropy(m.as_bytes()) >= 4.0 { Some(Confidence::Medium) } else { None }
  }),
  ```
- This is safe to ship without Phase 2. The AC keyword gate (Phase 2.5) is the full fix; this is
  the interim noise reducer.
- File: `crates/sanitai-detectors/src/regex_detector.rs` — vault_legacy_token rule (~line 529)

---

## Phase 0 — Data Model Foundation
**Prerequisite for all other phases.**

### 0.1 — Enrich `Finding` fields
Add to `Finding` in `crates/sanitai-core/src/finding.rs`:
```rust
pub role: Option<Role>,           // None for findings from sources without role info
pub category: Category,           // already on Detector trait, thread through
pub entropy_score: f64,           // shannon_entropy(matched_raw.as_bytes()) — computed at construction
pub context_class: ContextClass,  // default: Unclassified; Phase 5 fills this
// NOTE: verified field is deferred to Phase 6 (optional)
```

Add new types:
```rust
pub enum ContextClass {
    Unclassified,
    RealPaste,
    Educational,
    DocumentationQuote,
    ModelHallucination,
}
```

**Important:** `matched_raw` must be wrapped in `secrecy::Secret<String>` (already in `Cargo.toml:31`).
`secrecy::Secret` implements `Display` as `[REDACTED]` and `Debug` as `[REDACTED]`. This makes
accidental log inclusion safe by type rather than by convention alone. Update all access sites
to use `.expose_secret()` explicitly.

### 0.2 — Thread `role` into findings
- `Turn` already has `role: Role` in `sanitai-core/src/turn.rs`
- `scan_str` signature in `regex_detector.rs` takes `turn_id: &TurnId` — extend to also take
  `role: Option<Role>` as an explicit parameter (not via a new `ScanContext` abstraction, which
  does not currently exist anywhere in the codebase)
- All `scan_str` call sites pass the role from the enclosing `Turn` or `None` if unavailable

### 0.3 — SQLite schema migration (v1 → v2)
**Use the existing migration system, not Diesel.** The codebase uses `rusqlite` directly
(`Cargo.toml:67`). `sanitai-store` has a `const MIGRATIONS: &[&str]` array in `schema.rs`
applied via `execute_batch` in `open_at`. Extend this array with a v2 migration entry.

New columns (all nullable — allows schema cleanup if a phase is later descoped):
```sql
ALTER TABLE findings ADD COLUMN role TEXT;
ALTER TABLE findings ADD COLUMN category TEXT;
ALTER TABLE findings ADD COLUMN entropy_score REAL;
ALTER TABLE findings ADD COLUMN context_class TEXT;
ALTER TABLE findings ADD COLUMN secret_hash TEXT;
-- secret_hash for cross-scan correlation uses a per-installation key (see 0.4)
```

Migration guard:
```rust
// In open_at(), before executing v2 migration:
let version: i64 = conn.query_row(
    "SELECT version FROM schema_version WHERE version = 2",
    [], |r| r.get(0)
).unwrap_or(0);
if version < 2 {
    conn.execute_batch(MIGRATIONS[1])?;
    conn.execute("INSERT OR IGNORE INTO schema_version VALUES(2)", [])?;
}
```

### 0.4 — `secret_hash` computation
**Location: `sanitai-store` crate only** — not a public method on `Finding` (would allow CLI/TUI
crates to call it and route the output anywhere, including logs).

Two distinct purposes require two distinct keys:
- **Within-scan dedup**: no hash needed — key is `(file_path, turn_idx, detector_id, span_kind_discriminant)`
- **Cross-scan "seen before"**: HMAC-SHA256 with a per-installation key stored in the OS keychain
  (macOS: `security` keychain API; Linux: `libsecret`/`secret-tool`; fallback: `~/.sanitai/keyring`)
  This is explicitly **not** a per-scan salt — per-scan salt makes cross-scan correlation impossible.

```rust
// crates/sanitai-store/src/store.rs (internal only, not pub)
fn secret_hash(secret: &str, installation_key: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(installation_key).expect("HMAC can handle any key size");
    mac.update(secret.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
```

### 0.5 — Deduplication key
Within-scan: `(file_path, turn_idx, detector_id, span_kind_discriminant)` — no hash needed
Cross-scan: additionally `secret_hash` using the per-installation key (§0.4)

`span_kind_discriminant`: `"single"` or `"cross_turn"` — preserves audit trail per turn boundary.
Do NOT deduplicate by secret alone (collapses same secret appearing in different turns).

### 0.6 — `VerifiedStatus` enum (reserved for Phase 6, but define type now for schema stability)
If Phase 6 is ever added, the column already exists. For now:
```rust
pub enum VerifiedStatus {
    Unverified,
    Live,
    Revoked,
    Invalid,
    // No Error(String) variant — raw HTTP error strings can contain secret fragments.
    // Use: Error { code: u16, kind: VerifyErrorKind }
    Error { code: u16, kind: VerifyErrorKind },
}

pub enum VerifyErrorKind { NetworkTimeout, TlsError, RateLimited, Unknown }
```

### 0.7 — CI: mechanical enforcement of no-log-secrets invariant
Add `tools/security-lint/check_no_log_secrets.sh`:
```bash
#!/usr/bin/env bash
# Fails CI if any tracing macro references matched_raw (or expose_secret)
if git grep -n 'tracing::.*matched_raw\|tracing::.*expose_secret' -- '*.rs'; then
  echo "FAIL: secret value passed to tracing macro"
  exit 1
fi
```
Wire into CI (`.github/workflows/ci.yml`) as a pre-build step. One afternoon of work, prevents a
permanent audit failure forever.

### 0.8 — Existing users migration story
On first open after upgrade: run `PRAGMA integrity_check` then apply v2 migration. New columns are
nullable so existing rows remain valid. Display `"legacy"` for `context_class` on pre-migration
findings in the TUI. Do not backfill `entropy_score` for existing findings — compute on re-scan only.

### 0.9 — Tests for Phase 0
- `secrecy::Secret<String>` audit: confirm `format!("{:?}", finding)` outputs `[REDACTED]` not
  the actual secret value
- `secret_hash` determinism: same installation key + same secret → same hash
- `secret_hash` isolation: different installation keys → different hashes
- Within-scan dedup: same detector fires twice on same turn → single finding in output
- Cross-scan dedup: re-scan same file with installation key → no new findings for known secrets
- Migration: apply v2 on empty DB, verify schema; apply v2 on v1 DB with existing rows, verify rows intact
- `scan_str` role threading: confirm `finding.role` matches the Turn role passed at call site

---

## Phase 1a — Safe Rule Expansion (runs before Phase 5)
**High-precision rules with distinctive prefixes — zero FP risk, no context-gating needed.**

Rules follow: `Rule { id, category, base_confidence, keywords: &[&str], pattern, entropy_gate, validate }`
Source attribution required per rule: `// source: gitleaks/rules/<file>.toml @ <commit>` or `// source: trufflehog/pkg/detectors/<name>.go @ <commit>` or `// original`.

| Rule ID | Pattern | Keywords | Notes |
|---|---|---|---|
| `discord_bot_token` | `[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}` | `["discord", "bot_token"]` | source: gitleaks |
| `telegram_bot_token` | `\d{8,10}:[A-Za-z0-9_-]{35}` | `["telegram", "bot"]` | source: gitleaks |
| `sendgrid_api_key` | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` | `["sendgrid", "SG."]` | source: gitleaks |
| `mailgun_api_key` | `key-[0-9a-z]{32}` | `["mailgun"]` | source: gitleaks |
| `twilio_account_sid` | `AC[a-f0-9]{32}` | `["twilio", "AC"]` | SID only (low FP) |
| `linear_api_key` | `lin_api_[A-Za-z0-9]{40}` | `["linear", "lin_api_"]` | source: gitleaks |
| `notion_integration_token` | `secret_[A-Za-z0-9]{43}` | `["notion", "secret_"]` | source: gitleaks |
| `fly_io_api_token` | `FlyV1 [A-Za-z0-9+/=]{100,}` | `["fly", "FlyV1"]` | source: gitleaks |
| `doppler_service_token` | `dp\.st\.[a-z_]+\.[A-Za-z0-9]{40}` | `["doppler", "dp.st."]` | source: gitleaks |
| `huggingface_token` | `hf_[A-Za-z0-9]{37}` | `["huggingface", "hf_"]` | source: gitleaks |
| `replicate_api_token` | `r8_[A-Za-z0-9]{40}` | `["replicate", "r8_"]` | source: gitleaks |
| `pagerduty_api_key` | `u\+[A-Za-z0-9_-]{20}` | `["pagerduty"]` | source: gitleaks |

### 1a.1 — GitLab PAT variants (13 patterns matching gitleaks)
`glpat-`, `gldt-`, `glft-`, `glrt-`, `GR1348941`, `glsoat-`, `glcbt-`, `gltst-`, `glptt-`,
`GLPAT-`, `gloas-`, `glptt-2`, `glidt-`

### 1a.2 — CI gates
- `tools/differential` gates: precision ≥ 0.98, recall ≥ 0.95 on labeled corpus
- One true positive + one hard negative test per new rule in corpus

---

## Phase 1b — Context-gated Rule Expansion (runs after Phase 5)
**Rules with high FP risk without contextual suppression. Blocked on Phase 5.**

| Rule ID | Pattern | FP Risk | Gate Required |
|---|---|---|---|
| `vault_legacy_token` | `[sb]\.[A-Za-z0-9]{24,}` | Very high (matches `s.len()`) | AC keywords + entropy ≥ 4.0 + Phase 5 context gate |
| `twilio_auth_token` | 32 hex chars | High (any 32-hex token) | AC keyword `["twilio", "TWILIO_AUTH"]` + entropy ≥ 3.8 |
| `datadog_api_key` | 32 hex chars | High | AC keyword `["datadog", "DD_API"]` + entropy ≥ 3.8 |
| `vercel_access_token` | 24 alphanumeric | High | AC keyword `["vercel", "VERCEL_TOKEN"]` |

---

## Phase 2 — Aho-Corasick Keyword Pre-filter
**Prerequisite for Phase 1b rules and for performance at scale.**

### 2.1 — `KeywordFilter` struct
Location: `crates/sanitai-detectors/src/keyword_filter.rs`

```rust
pub struct KeywordFilter {
    ac: AhoCorasick,
    /// Maps AC pattern index → rule index. u16 supports up to 65,535 rules.
    pattern_to_rule: Vec<u16>,
    rule_count: usize,
}

impl KeywordFilter {
    pub fn new(rules_keywords: &[&[&str]]) -> Self { ... }
    /// Returns bitmask: bit N set ↔ rule N has a keyword match.
    /// [u64; 4] = 256 rule slots, zero heap allocation per call.
    pub fn scan(&self, hay: &str) -> [u64; 4] { ... }
}
```

**Why `[u64; 4]` not `u128`:** 256 rule slots from day one, avoids a breaking threshold when
Phase 1a + 1b + future rules exceed 128. Four words on the stack.

**Why `u16` not `u8` for `pattern_to_rule`:** `u8` caps at 255, would overflow silently
(wrong rule fires). `u16` supports 65,535 rules — no foreseeable ceiling.

### 2.2 — Stable rule indices
`RegexDetector::build_rules()` must assign each `Rule` a stable `index: usize` field set at
construction time. The `KeywordFilter` is built from the same `rules()` slice and derives bitmask
positions from those indices. **Never hardcode bitmask positions in separate locations** — if a rule
is inserted in the middle of `build_rules()`, positions must stay consistent with the slice.

```rust
// In RegexDetector::scan():
let keyword_mask = self.keyword_filter.scan(hay);
for rule in &self.rules {
    let bucket = rule.index / 64;
    let bit = rule.index % 64;
    if rule.keywords.len() > 0 && keyword_mask[bucket] & (1u64 << bit) == 0 {
        continue; // keyword not present, skip rule
    }
    // ... proceed with regex match
}
```

### 2.3 — Stopword list (conversation-aware, NOT a verbatim port of gitleaks)
**Important:** gitleaks' stopword list is designed for source code. Applied to AI conversations,
it suppresses real secrets. For example, `EXAMPLE` and `changeme` are on the gitleaks list — in
a git commit they're placeholders, but in a user's pasted config they may be real.

Strategy:
- Apply stopwords **only to low-specificity rules** (generic password assignment, high-entropy
  generic patterns). High-specificity rules with distinctive prefixes (ghp_, sk-ant-, SG., etc.)
  do NOT use stopword filtering — they're already precise.
- Curate a conversation-aware list: gitleaks entries minus words that appear in real production
  configs (e.g., keep `EXAMPLE`, `placeholder`, `your_api_key` as suppressors, but NOT
  `changeme`, `password`, `secret` when they appear as values rather than keys)
- Location: `crates/sanitai-detectors/src/stopwords.rs` with per-rule opt-in via
  `Rule { ..., use_stopwords: bool }`

### 2.4 — Entropy post-filter
- Per-rule `entropy_gate: f64` field (0.0 = disabled)
- Applied after regex match, before validation: `if shannon_entropy(matched) < rule.entropy_gate { continue }`
- Gated rules: `vault_legacy_token` ≥ 4.0, `twilio_auth_token` ≥ 3.8, `datadog_api_key` ≥ 3.8

### 2.5 — Wire `vault_legacy_token` through AC gate (completes Phase 1b prerequisite)

### 2.6 — Tests for Phase 2
- `KeywordFilter::scan()` returns correct `[u64; 4]` bitmask for known keyword/haystack pairs
- Zero-keyword rule always fires (all bits set for that rule's slot)
- Stopword suppression: applies only to rules with `use_stopwords: true`
- `changeme` in a user-pasted config is NOT suppressed by a `use_stopwords: true` rule
  (verify the stopword list is curated, not the gitleaks full list)
- Entropy gate: sub-threshold match discarded; above-threshold match kept
- Stable indices: insert a rule in the middle of `build_rules()`, verify no other rule fires incorrectly
- Benchmark (criterion): keyword filter throughput on 1MB synthetic conversation corpus

---

## Phase 3 — Parser Coverage
**Moved earlier than original plan — real user data is needed for Phase 5 corpus collection.**
**Depends on Phase 0 (role threading).**

### 3.1 — ChatGPT export JSON
- Format: `{"conversations": [{"mapping": {"node_id": {"message": {"role": ..., "content": ...}}}}]}`
- DAG structure — topological traversal to preserve turn order
- Parser location: `crates/sanitai-parsers/src/chatgpt.rs`

### 3.2 — Cursor SQLite conversations
- **Correct paths (platform-aware, not hardcoded):**
  - macOS: `~/Library/Application Support/Cursor/User/workspaceStorage/**/state.vscdb`
  - Linux: `~/.config/Cursor/User/workspaceStorage/**/state.vscdb`
  - Windows: `%APPDATA%\Cursor\User\workspaceStorage\**\state.vscdb`
- Use `dirs_next::data_dir()` (already in `Cargo.toml`)
- Glob must be recursive (`**/state.vscdb`), not single-level (`*/state.vscdb`)
- Parser: `crates/sanitai-parsers/src/cursor.rs`

### 3.3 — Copilot/VS Code extension logs
- Path: `{data_dir}/Code/logs/**/GitHub Copilot Chat.log`
- Format: structured log lines with JSON payloads
- Parser: `crates/sanitai-parsers/src/copilot.rs`

### 3.4 — Gemini export
- Google Takeout format: `Takeout/Gemini/MyActivity.json`
- Parser: `crates/sanitai-parsers/src/gemini.rs`

### 3.5 — Parser auto-discovery (`sanitai discover` subcommand)
- Lists candidate paths found on disk, shows user what was found
- Does NOT auto-scan without confirmation
- `sanitai scan` still requires explicit path argument
- This is the safest UX for a security tool — never scan user dirs silently

### 3.6 — Tests for Phase 3
- Each parser: minimal fixture file (real-format sample, fully sanitized with synthetic secrets)
  → verify turn extraction (role, content, index, conversation ordering)
- Multi-turn fixture per format to verify DAG/ordering correctness
- Malformed input: truncated JSON, missing fields — must not panic, must return `Err`, not `Ok([])`
- `sanitai discover` on a fixture dir with planted files → correct path list returned
- Platform path resolution: mock `dirs_next::data_dir()` for each OS variant

---

## Phase 4a — SARIF Output (early, unblocks enterprise pilots)
**No dependency on Phase 5 — ships `context_class: "unclassified"` until Phase 5 lands.**

### 4a.1 — SARIF 2.1.0 serializer
- Location: `crates/sanitai-cli/src/sarif.rs`
- Maps `Finding` → SARIF `result` with `ruleId`, `level`, `locations`, `properties`
- `context_class` surfaced in `properties` (value `"unclassified"` until Phase 5)
- Output via `--format sarif` CLI flag
- Schema version: 2.1.0 (current; GitHub Code Scanning, Sonar, every modern DAST/SAST)

### 4a.2 — Tests for Phase 4a
- SARIF serializer: golden file test (known findings → expected SARIF JSON, validated against
  SARIF 2.1.0 JSON schema)
- CLI `--format sarif` end-to-end with fixture conversation file
- SARIF output contains `ruleId`, `level`, `locations[0].physicalLocation`

---

## Phase 5 — Contextual False-Positive Suppression
**THE MOAT. The single architectural advantage TruffleHog cannot replicate.**
> Without Phase 5, SanitAI produces 60-80% FP noise from tutorial/assistant-explanation content.
> With Phase 5, SanitAI has something that requires understanding conversation context — a problem
> TruffleHog cannot solve by pointing at the same directory.

### 5.0 — Corpus collection + baseline measurement (FIRST, before writing classifier)
Before writing any classifier code, collect 200+ real AI conversation snippets (from
own exports, public datasets, or synthetic generation) and measure current FP rates:

```
tools/context-eval/ baseline run: what % of current findings are educational/docs/hallucinations?
```

If baseline FP rate is < 10%: heuristics may be overkill, proceed carefully.
If baseline FP rate is > 50%: Phase 5 is blocking — do not ship Phase 1b without it.

**Gate thresholds (precision ≥ 0.90, recall ≥ 0.85 on RealPaste) are tentative until baseline
is measured.** If heuristics achieve 0.95+ trivially, raise the bar. If 0.85 recall is
unreachable without an LLM, scope the problem more narrowly.

### 5.1 — Labeled corpus
Location: `corpora/context/` at workspace root (NOT inside `sanitai-fixtures` — this is a
dataset with its own curation lifecycle, not test data):

```
corpora/context/
  index.jsonl          # one entry per snippet: { id, expected_class, source, turns, finding_turn_idx }
  schema.json          # jsonschema for index.jsonl entries
  README.md            # labeling guidelines, contribution process
```

Minimum 500 labeled entries (after baseline phase proves gates are achievable):
- Labels: `{RealPaste, Educational, DocumentationQuote, ModelHallucination}`
- Balanced: User-role and Assistant-role turns, multiple providers, multiple secret types
- Contributions treated like code review (PR with label rationale)

### 5.2 — `ContextClassifier` struct
Location: `crates/sanitai-detectors/src/context_classifier.rs`

```rust
pub struct ContextClassifier {
    config: ContextClassifierConfig,
}

pub struct ContextClassifierConfig {
    pub window_turns: usize,                   // default: 3
    pub educational_keyword_threshold: usize,  // default: 2
}

impl ContextClassifier {
    /// Classify a finding given the full turn slice for its file.
    /// `turns` must be the complete ordered turn slice for `finding.turn_id.0` (the file path).
    /// Multi-file safety: callers must filter turns to the correct file before passing.
    pub fn classify(
        &self,
        finding: &Finding,
        file_turns: &[Turn],  // pre-filtered to finding.turn_id.0
    ) -> ContextClass { ... }
}
```

**Signature note:** `turns: &[Turn]` not `turns: &HashMap<..., Vec<Turn>>` — callers must
pre-filter to the correct file. This keeps the classifier stateless and testable.

### 5.3 — Heuristic signals (v1, no LLM)

**Push toward `Educational`:**
- Finding is in an `Assistant`-role turn
- Surrounding prose contains: `"example"`, `"format"`, `"looks like"`, `"such as"`, `"e.g."`,
  `"placeholder"`, `"replace with"`, `"your_"`, `"<YOUR_"`, `"YOUR_API_KEY"`, `"REDACTED"`
- Finding is inside a markdown code block (surrounded by ` ``` ` or ` ` ` `)
- Finding immediately follows `"Here's an example"`, `"For example"`, `"like this"`, `"such as"`

**Push toward `RealPaste`:**
- Finding is in a `User`-role turn
- No educational signals in surrounding N turns
- High entropy (> 4.5 bits/byte) of `matched_raw`
- Finding also triggers cross-turn reassembly (strongly suggests real leak)

**Push toward `ModelHallucination`:**
- Finding is in `Assistant`-role turn AND pattern matches a known hallucination signature
  (e.g., `AKIAIOSFODNN7EXAMPLE`, `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, any pattern containing
  only repeated chars or incrementing sequences)

**Push toward `DocumentationQuote`:**
- Surrounding turns contain URLs matching `docs.`, `developer.`, `api.` subdomains
- Finding appears in backtick inline code within explanatory prose

**No LLM tier in v1.** If corpus eval shows heuristics cannot reach target recall, the answer
is better heuristics or more labeled data — not llama.cpp. A local LLM is a 50MB download, adds
30s startup latency, and changes the "runs in 2 seconds" story fundamentally. If warranted, it
ships as `sanitai-classify-llm` as a completely separate opt-in crate in v2+.

### 5.4 — CI gate
`tools/context-eval/src/main.rs`: runs classifier against `corpora/context/index.jsonl`
- Gate: precision ≥ 0.90 on `RealPaste`
- Gate: recall ≥ 0.85 on `RealPaste`
- These numbers are confirmed after Phase 5.0 baseline measurement

### 5.5 — Tests for Phase 5
- Classifier: known educational snippet (assistant explains key format) → `Educational`
- Classifier: known real paste (user turn, no surrounding prose signals) → `RealPaste`
- Classifier: assistant code example with ` ``` ` fence → `Educational`
- Classifier: cross-turn finding → `RealPaste` (cross-turn strongly implies real)
- Multi-file: confirm classifier uses only turns from the correct file (pass turns from a
  different file, verify result is not `RealPaste` on a finding that should be `Educational`)
- `tools/context-eval` produces precision/recall report and exits non-zero if gates fail

---

## Phase 4b — TUI Filtering (runs after Phase 5)
**Blocked on Phase 5 because `context_class` must be meaningful before filtering on it.**

### 4b.1 — TUI filter bar
- Filter by `confidence`, `category`, `context_class`, `verified` (verified column shows
  "unverified" until Phase 6 if ever)
- Default view: hide `Educational` + `DocumentationQuote` findings
- `--show-all` flag bypasses default filter

### 4b.2 — Tests for Phase 4b
- Filter logic unit tests (no terminal required — test filter predicate functions directly)
- `--show-all` produces more findings than default on a fixture with educational content

---

## Phase 6 — Live Credential Verification (deferred, optional, v2+)
**Cut from v1.** Rationale:
- Duplicates TruffleHog — no competitive moat
- Outbound HTTPS conflicts with "local-first" positioning (trust break for the exact users who
  chose SanitAI over cloud scanners)
- Network-capable subprocess in a security tool = large attack surface
- Constant maintenance drag as provider APIs change

**If Phase 6 is ever added:**
- Separate `sanitai-verifier` binary (not a subprocess of the main scanner)
- IPC: stdin/stdout, length-prefixed JSON, 4-byte LE length header
- `secret` field in IPC payload treated as sensitive: `O_CLOEXEC` on all inherited FDs,
  verifier calls `prctl(PR_SET_DUMPABLE, 0)` (Linux) or `ptrace(PT_DENY_ATTACH, 0, 0, 0)` (macOS)
- `VerifiedStatus::Error` must use `VerifyErrorKind` enum, never raw HTTP error strings
  (raw HTTP errors can contain the secret being verified)
- `--verify` is always opt-in with an explicit network warning
- Verifier is a separate opt-in crate (`sanitai-verifier`), not bundled with the main binary

---

## Cross-Cutting Concerns

### Security invariants (enforced across ALL phases)
1. `matched_raw` is wrapped in `secrecy::Secret<String>` — `Debug` and `Display` output `[REDACTED]`
2. `matched_raw` is only accessed (via `.expose_secret()`) in `sanitai-core` and `sanitai-store`
3. `secret_hash()` lives in `sanitai-store` only — not a public method on `Finding`
4. All buffers holding decoded/reassembled secrets use `ZeroizeOnDrop` or are zeroed on scope exit
5. No `unwrap()` in production paths (enforced by `#![deny(clippy::unwrap_used)]`)
6. CI security lint (`tools/security-lint/check_no_log_secrets.sh`) fails build if any `tracing`
   macro receives `matched_raw` or `expose_secret` as a field

### `DetectorScratch` cleanup (pre-Phase-2 tech debt)
`DetectorScratch` in `chunk.rs:64-77` has `decode_buf: Vec<u8>` and `decode_bytes_used: usize`
that are never used by `TransformDetector` (which maintains its own `CascadeCtx`). Before Phase 2
adds `KeywordFilter` to the hot path:
- Move `decoded_total` and `seen: HashSet<u64>` out of `CascadeCtx` into `DetectorScratch`
- Call `scratch.reset_for_chunk()` in `TransformDetector::scan` before the cascade
- This consolidates decode budget tracking into one place and eliminates dead fields

### Observability (address before Phase 5 ships)
There is currently no feedback loop to know which rules fire in the wild. Before Phase 5 ships,
add opt-in anonymized telemetry (off by default, explicit `--telemetry` flag or config key):
- Counts per `detector_id` (not content): `{ detector_id, context_class, was_dismissed: bool }`
- User can mark findings as false positives in TUI → feeds corpus improvement loop
- Without this, Phase 5 corpus goes stale the moment v1 ships

### Dependency additions
```toml
# Cargo.toml (workspace)
aho-corasick = "1"
hmac = "0.12"
sha2 = "0.10"
# serde_sarif or hand-roll SARIF 2.1.0 structs in sanitai-cli
# secrecy already present at Cargo.toml:31
# percent-encoding already present
# dirs-next already present
```

### Rule provenance requirement
Every rule added in Phase 1a/1b must include a source comment:
```rust
// source: gitleaks/rules/discord.toml @ abc1234
// or
// source: original
```
This matters for (a) correctness (gitleaks patterns are battle-tested), and (b) license hygiene
(gitleaks is MIT-licensed — attribution is required).

---

## QA Strategy Summary

| Layer | Tool | Gate |
|---|---|---|
| Unit | `cargo test` | All public fns, per-module |
| Integration | `cargo test --test '*'` with fixture files | End-to-end scan → finding sets |
| Regression corpus | `tools/differential` | precision ≥ 0.98, recall ≥ 0.95 |
| Context eval | `tools/context-eval` | precision ≥ 0.90, recall ≥ 0.85 on RealPaste |
| Benchmark | `cargo bench` (criterion) | KeywordFilter + full scan throughput |
| Fuzz | `cargo fuzz` targets | Parsers, transform cascade, SARIF serializer |
| Security lint | `tools/security-lint/check_no_log_secrets.sh` | Zero tracing leaks |

**Fuzz targets (Phase 2+):**
- `fuzz_chatgpt_parser`: random JSON input → no panic
- `fuzz_cursor_parser`: random SQLite bytes → no panic
- `fuzz_transform_cascade`: random bytes → no panic, budget always respected
- `fuzz_keyword_filter`: random haystack → bitmask always within [0, rule_count)
- `fuzz_sarif_serializer`: random Finding → valid SARIF output

---

## Open Questions — Resolved

| # | Question | Decision |
|---|---|---|
| 1 | Rule count ceiling: u128 vs `[u64;N]` | `[u64; 4]` (256 rules) from day one |
| 2 | Context classifier LLM tier | No LLM in v1. Better heuristics/data first. |
| 3 | `--verify` opt-in vs opt-out | Opt-in, explicit network warning. Phase 6 deferred entirely. |
| 4 | Parser auto-discovery | `sanitai discover` subcommand, never auto-scan silently |
| 5 | Phase ordering enforcement | Feature flags (`--experimental-rules`), not compile-time guards |
| 6 | SARIF schema version | 2.1.0 |
