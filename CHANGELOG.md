# Changelog

> **Note:** Versions 0.3.26 – 0.3.55 were released as git tags without changelog entries. Changelog resumes at 0.3.56 below.

## 0.3.63

### Changed (BREAKING)
- `sym-daemon` now uses `cliHostMode: true` (renamed from `relayMode`). Daemon no longer stores forwarded CMBs — eliminates ~5x duplication on multi-agent hosts.
- `sym recall` is now federated: scans `~/.sym/nodes/*/meshmem/` directly, deduped by CMB key, sorted by recency. Works without the daemon. New `--node <name>` flag scopes the scan.
- Requires `@sym-bot/core@^0.3.30`.

## 0.3.61

### Fixed
- **High-quality CMBs were silently buried**, never promoted to the Review Board, because of two compounding bugs:
  1. `lib/llm-reason.js` appended a hardcoded "Return a JSON object with 7 CAT7 fields" suffix to every prompt, **with no mention of `_meta`**. This overrode any `_meta.founderAction` instructions the agent's role definition (SKILL.md) tried to convey, so the model emitted just the 7 fields and the founderAction signal was lost. Suffix now requests the optional `_meta` tag explicitly: `_meta:{founderAction, urgency, reason}` and instructs the model to set it per role rules.
  2. `lib/mesh-agent.js` `detectFounderAction` (the fallback when `_meta` is missing) only scanned `intent + issue` and only matched a hedge-paraphrase vocabulary list (`prioritize`, `monitor`, `competitive`, etc.). Disciplined extraction prompts produce CMBs with concrete verbs like `fetch`, `flag`, `draft`, `endorser`, `arxiv`, `cite`, `respond`, `submit` — none of which were in the list, so high-quality CMBs failed to promote. Now scans `intent + issue + commitment + mood.text` (wider field surface) and the keyword list is expanded with concrete-action verbs, research vocabulary, and stakes-signalling affect words.

Verified: a real research-win arxiv CMB ("Fetch full PDF today. Check author list for endorser candidates...") now correctly promotes via the keyword fallback path. Going forward, disciplined agents using the `_meta` schema in their prompt suffix will set founderAction explicitly and bypass the keyword fallback entirely.

## 0.3.59

### Fixed
- **Windows terminal popups in CLI provider** (`lib/llm-cli.js`) — `claude` resolved to a `.cmd` shim that opened visible cmd.exe windows on every spawn. Now uses `platform.resolveClaudeCLI()` to get the node binary + `cli.js` path directly, plus `windowsHide: true` on the spawn options.
- **Per-agent env vars not loaded at module-load time** (`lib/mesh-agent.js`) — agents read `SYM_RESEARCH_PROVIDER`, `SYM_COO_MODEL`, etc. at top-of-file constants before the `MeshAgent` constructor runs. Added a top-level `loadRelayEnv()` IIFE that loads `~/.sym/relay.env` when `mesh-agent.js` is first required, so per-agent env overrides resolve correctly.

## 0.3.58

### Added
- **Claude Code CLI provider** (`provider: 'cli'`). Spawns `claude -p --output-format json` as a subprocess instead of hitting an HTTP API. Gives every agent the full Claude Code tool surface — Read, Write, Bash, Grep, WebFetch, Skill, etc. — and auto-loads `CLAUDE.md` / `.claude/settings.json` / project skills from the agent's working directory. Uses local Claude Code auth (no API key needed). Per-call options: `model` (opus/sonnet/haiku alias or full id), `addDirs`, `allowedTools`, `permissionMode` (default `bypassPermissions`), `maxBudget` (passed as `--max-budget-usd`), `timeoutMs`. Selectable via `provider: 'cli'` per call or `SYM_LLM_PROVIDER=cli` globally. See `lib/llm-cli.js`.
- This is the path for the existing `addDirs` parameter that HTTP providers were silently ignoring — agents that already passed `addDirs: [...]` get directory access for free as soon as they switch provider.

### Changed
- `lib/llm-reason.js` `getProviderConfig` and `invoke` updated to dispatch `cli` / `anthropic` / `openai`. CLI provider skips the API-key check (uses local Claude Code auth) and skips `withRetry` (subprocess errors aren't typically transient).

## 0.3.57

### Changed
- **`MemoryStore._cmbKey` now delegates to `@sym-bot/core` `cmbKey()`** instead of re-implementing the SHA256-truncate logic. Eliminates duplicated CMB key code that had drifted multiple times. Single source of truth lives in `sym-core/lib/cmb-encoder.js`. The raw-content fallback path remains a direct SHA256 (distinct input space, cannot collide with the field-keyed path).
- **`@sym-bot/core` dependency bumped** to `^0.3.29` to pick up the new `cmbKey` export and the FNV-1a context encoder fix. The encoder fix restores cross-SDK n-gram embedding parity with `sym-core-swift` for the first time — see `@sym-bot/core` 0.3.29 changelog for the wire-impact details.

## 0.3.56

### Changed
- **CMB content key algorithm: MD5 → SHA256 (truncated to 32 hex chars).** `MemoryStore._cmbKey()` now uses `crypto.createHash('sha256').digest('hex').slice(0, 32)` for both the field-text and raw-content code paths. This duplicated CMB-key logic (separate from `@sym-bot/core` `cmb-encoder.js`) is now back in sync. Wire-breaking with respect to dedup against pre-0.3.56 stored CMBs. Coordinated with `@sym-bot/core` 0.3.28 and `sym-core-swift` 0.3.6.
- **`@sym-bot/core` dependency bumped** to `^0.3.28`.

### Fixed
- Removed accidental self-dependency `@sym-bot/sym: ^0.3.43` from `package.json` `dependencies`. The package now declares only its real runtime deps (`@sym-bot/core`, `bonjour-service`, `ws`).

## 0.3.25

### Changed
- **sym-core 0.2.0** — semantic encoder for SVAF evaluation. Paraphrase similarity: 0.31 (n-gram) → 0.69 (semantic). Per-field evaluation quality bounded by encoder quality, not model capacity.

## 0.3.24

### Added
- **Catchup via mesh broadcast.** Daemon broadcasts `"catchup"` message to all peers. `MeshAgent` listens for it and triggers immediate domain poll. Replaces the old hosted-agent-only catchup path.

## 0.3.23

### Added
- **Handshake: `version` and `extensions` fields** per MMP v0.2.1 Section 5.2. Handshake now sends `version: "0.2.1"` and `extensions: []`.
- **Error frame support** per MMP v0.2.1 Section 7.2. `sendError(peerId, code, message, detail)` sends protocol-level error frames. Codes 1xxx close connection; 2xxx informational.

### Parity
- 100% feature parity with sym-swift (Swift SDK). Both SDKs implement all 10 frame types, handshake with version/extensions/e2ePublicKey, error frames, multi-transport per peer, SVAF per-field evaluation, MD5 content-addressable CMB keys, lineage, remix guard, and metrics.

## 0.3.22

### Changed
- **MeshAgent: every agent is a standalone peer node** (MMP v0.2.1). Removed hosted/daemon mode. Every `MeshAgent` creates its own `SymNode` with own identity, transport, coupling engine, and memory store. Coupling is per-node — agents that share another node's identity cannot have independent SVAF weights.
- **`sym recall --json`** — new flag returns full entry objects (source, peerId, CMB fields, lineage) as JSON. Enables sym.day to get real source data from daemon memory.

### Tests
- 119 tests (was 100). MeshAgent test updated for standalone-only constructor.

## 0.3.21

### Added
- **MeshAgent** — protocol-level agent lifecycle class. Agents provide `fetchDomain()`, `reason()`, `remix()`. Protocol handles event-driven remix, `canRemix()` gate, fingerprint dedup, lineage, silence. No LLM code in SDK.
- **`sym metrics`** — new CLI command exposing protocol-level metrics (CMBs, peers, LLM cost, uptime)
- **`--json` flag** for `sym status`, `sym peers`, `sym metrics` — structured output for programmatic consumers

### Fixed
- **Remix guard**: `remember()` with parents now resets `hasNewDomainData`. Previously a remix counted as new domain data, allowing infinite remix chains from a single observation.
- **Startup race**: relay disconnect handlers directly deleted peers, bypassing multi-transport failover (Section 4.6/5.5). Now only closes the relay transport — Bonjour survives.
- **Undefined variables** in `_handleRelayPeerLeft` (`peers`, `peer`) — leftover from refactoring.

### Changed
- IPC socket moved from `/tmp/sym.sock` to `~/.sym/daemon.sock` per spec Section 4.5. `SYM_SOCKET` env var still overrides.

### Tests
- 100 tests (was 83). Added: remix guard reset, MeshAgent validation, CLI --json, socket path.
