# Changelog

> **Note:** Versions 0.3.26 – 0.3.55 were released as git tags without changelog entries. Changelog resumes at 0.3.56 below.

## 0.5.1

### Fixed

- **Mac↔Windows peer connections over LAN.** `BonjourDiscovery` now
  publishes an explicit `host` field with a normalized mDNS-valid hostname
  (`.local` suffix). On Windows, `os.hostname()` returns a bare NetBIOS
  name (e.g. `xmesh-hp`) with no domain suffix; `bonjour-service`
  previously advertised that verbatim as the SRV target. macOS
  mDNSResponder only resolves the `.local.` TLD, so the Mac could
  discover the Windows peer via mDNS browse but failed to open an
  outbound TCP connection — hostname resolution returned `No Such
  Record`. CMBs sent to Windows peers never arrived; no replies ever
  came back. (Same class of bug as the 0.3.72 cross-platform resolve
  fix; regression path was the `host` field being unset.)

  Fix is two-part:
  1. `config.loadOrCreateIdentity()` normalizes `identity.hostname` via
     the new `normalizeMdnsHostname()` helper — bare names get `.local`
     appended, FQDNs and already-`.local` names pass through. Existing
     identities with bare hostnames are auto-migrated on next load.
  2. `BonjourDiscovery._startBonjourFallback()` passes the normalized
     `identity.hostname` as the `host` field to `bonjour.publish()` so
     the SRV target matches.

  Affects all peers; Windows nodes must upgrade (their advertisement
  was broken). Mac nodes benefit from the explicit `host:` field for
  determinism even though `os.hostname()` happens to produce
  `.local`-suffixed output on macOS.

## 0.5.0

### Added

- **`node.buildStartupPrimer({ maxCount, maxAgeMs })`** — reconstitute an
  agent's remix memory as a human-readable primer, suitable for injection
  into the LLM context at session start. Operationalises MMP §4.2 O2
  (rejoin-without-replay). A fresh agent session wakes with its prior
  cognitive state already loaded — zero first-turn `sym_recall` overhead.
  Returns `{ text, count, dropped, totalInStore }`. Defaults:
  `maxCount=20`, `maxAgeMs=86_400_000` (24h). Recency window applied
  first, then count cap. Empty store yields an empty primer.

  Intended use — call as the final step of plugin initialisation:

  ```js
  const node = new SymNode({ name, ... });
  await node.start();
  // ... transport, tool surface, subscriptions ...
  const primer = node.buildStartupPrimer();
  mcpServer.instructions += '\n\n' + primer.text;
  ```

  Inherits to every plugin that depends on `@sym-bot/sym`. Consumers:
  `@sym-bot/mesh-channel` v0.3.0, `@sym-bot/melotune-plugin` v0.1.7.

## 0.3.82

### Fixed

- **Remix CMB key self-reference on first-observation (MMP §14).**
  Pairs with the `@sym-bot/core` 0.3.36 fix. When neural SVAF admits
  an incoming CMB, `_processNeuralSVAF` now mints a fresh remix key
  via `remixKey(fusedFields, incomingKey, this._node.name)` and
  overwrites both `fusedEntry.cmb.key` and `fusedEntry.key` before
  remix-store. Previously the receiver preserved the sender's CMB
  key on the stored remix, producing `lineage.parents=[remix.key]` —
  a self-edge that broke DAG traversal. Fix guarantees remix key ≠
  parent key by construction while keeping idempotent dedup for
  retries from the same sender to the same receiver. The heuristic
  SVAF path is fixed in `@sym-bot/core` 0.3.36.

### Changed

- **`@sym-bot/core` dep bumped to `^0.3.36`** for `remixKey` +
  heuristic-SVAF fix.

## 0.3.81

### Added

- **MMP §5.8 mesh group membership.** `SymNode` accepts `opts.group`
  (default `"default"`) and `opts.discoveryServiceType` (default
  `"_sym._tcp"`); both are propagated into `BonjourDiscovery` for
  LAN-layer isolation. The handshake frame version is bumped `0.2.2` →
  `0.2.3` and carries the optional `group` field per §5.2. Matches the
  `sym-swift` `SymNode(discoveryServiceType:)` parameter so Node and
  Swift implementations align.
- **MMP §4.4.4 targeted CMB send.** `SymNode.remember(fields, opts)`
  now accepts `opts.to` (full peerId). When set, the CMB frame is
  emitted only to that connected peer; when omitted, behaviour is
  unchanged (broadcast to all peers). The local store write runs in
  both cases — lineage and §14.7 remix-guard invariants are enforced
  identically.
- **`peers()` exposes `peerId`** (full nodeId) alongside the truncated
  `id` display form, so external callers can resolve a peer by name to
  a full peerId without reaching into internal `_peers` state.
- `tests/remember-targeted.test.js` covering broadcast regression,
  targeted send to connected peer, targeted send to disconnected peer,
  and `peers().peerId` exposure.

## 0.3.80

### Added

- **`frame-handler.js` moved from `@sym-bot/core`.**  FrameHandler is
  protocol plumbing — frame routing, store writes, event emission — and
  belongs in the protocol/node package. Imports now resolve to the local
  copy; `@sym-bot/core` retains a backward-compat re-export.
- **Echo loop prevention (MMP Section 14).** `_handleMemoryShare()` now
  checks whether incoming CMB lineage parents exist as local keys in the
  memory store. If so, the CMB is a derivative of our own broadcast and
  is silently dropped — preventing ping-pong between same-app peers.
- **`MemoryStore.hasLocalKey(key)`** — returns true if a CMB key exists
  in local (non-peer) entries. Used by the echo loop guard.

### Changed

- Bump `@sym-bot/core` dependency to `^0.3.35`.

## 0.3.78

### Changed

- Bump `@sym-bot/core` to 0.3.33. Migrates `@xenova/transformers` →
  `@huggingface/transformers@^4.0.1`. Eliminates deprecated
  `prebuild-install` and the EBUSY DLL lock on Windows.

## 0.3.77

### Fixed

- **Clear socket timeout after TCP connect.** `_connectToPeer` set a
  10-second `socket.setTimeout` as a connect timeout but never cleared
  it after success. The timeout kept firing on the CONNECTED socket,
  killing any LAN connection idle for >10 seconds. Connections now
  stay open indefinitely after establishment.

## 0.3.76

### Fixed

- **Fresh mDNS re-browse on reconnect timer.** The 15s reconnect timer
  now restarts the bonjour-service browser (fresh mDNS query) instead
  of retrying stale cached addresses/ports.
- **On-demand reconnect on send failure.** `node.send()` triggers an
  immediate `discovery.reconnect()` when delivery returns 0 peers,
  instead of waiting for the next 15s timer tick.

## 0.3.75

### Added

- **LAN reconnect timer.** Discovered peers are cached. Every 15 seconds,
  `peer-found` is re-emitted for cached peers not currently connected.
  Handles TCP drops without requiring a process restart.

## 0.3.74

### Fixed

- **Removed leader-election gate from bonjour discovery.** Both sides
  now emit `peer-found` and attempt to connect. The old gate (only
  the lower nodeId initiates) was fragile: stale bonjour cache on the
  initiator side → no connection, because the other side was gated.

## 0.3.73

### Fixed

- **Prefer IPv4 in bonjour-service discovery.** `service.addresses`
  from bonjour-service can include IPv6 link-local (`fe80::...`) which
  requires a scope ID for TCP. Now picks the first IPv4 address.

## 0.3.72

### Fixed

- **Cross-platform LAN discovery: use `bonjour-service` instead of
  native `dns-sd` binary.** The macOS `dns-sd -L` resolve step uses
  unicast DNS-SD queries that fail to resolve services advertised by
  Windows' Bonjour implementation. Browse (multicast) works, but
  resolve (unicast) returns empty — so Mac discovers Windows peers
  but can't get their port, and the TCP connection never happens.
  The `bonjour-service` npm package uses multicast for both browse
  AND resolve, which works cross-platform. Verified Mac↔Windows on
  the same wifi (2026-04-09). The `dns-sd` binary code path remains
  in `lib/discovery.js` as dead code for reference but is no longer
  called.

## 0.3.71

### Fixed

- **`windowsHide: true` added to all 10 child_process spawn sites** so
  Windows agents (especially the four Centro pm2 agents) no longer
  flood the desktop with cmd.exe popup windows on every git query,
  python resolution, port lookup, etc. Sites: 7 in `lib/platform.js`
  (`resolvePython` × 2, `resolveClaudeCLI`, `findProcessByPort` × 2,
  `findProcessByName` × 2, `safeExec` defaults) and 3 in
  `lib/discovery.js` (`dns-sd -R` register, `dns-sd -B` browse,
  `dns-sd -L` resolve). `lib/llm-cli.js` already had it. No-op on
  macOS/Linux. Catalogued by claude-code-win during the 2026-04-09
  cross-machine round-trip session.

## 0.3.70

### Fixed

- **Identity lockfile prevents two SymNode processes from claiming the
  same nodeId on the same host.** `~/.sym/nodes/<name>/lock.pid` is
  acquired in the constructor and released in `stop()`. Cross-process
  duplicates throw `EIDENTITYLOCK`; same-PID re-acquisition (tests,
  hot-reload) is allowed; stale locks (dead PID) are reclaimed
  automatically. Catches the `sym-daemon` + MCP server collision that
  silently broke real-time push on Windows. See `cliHostMode-vs-MCP`
  bug from 2026-04-09 round-trip test.
- **`node.send()` now returns the actual delivered count.** Previously
  returned undefined; sym-mesh-channel had to read `peers().length`
  separately, which could disagree with reality (peers in `_peers`
  with broken transports). `_broadcastToPeers()` now wraps each
  `transport.send()` in try/catch and counts successes. Backwards
  compatible — existing callers ignoring the return value continue
  to work.

### Migration

`SymNode` now acquires a lockfile on construction. Hosts MUST wire
`SIGTERM`/`SIGINT` to call `node.stop()` so the lockfile is cleaned
up — otherwise stale locks accumulate (they're auto-reclaimed on
next startup, but cleaner shutdown is better). sym-mesh-channel
v0.1.3+ already does this.

If two of your processes legitimately need different identities,
set `SYM_NODE_NAME` to distinct values per process. If they're
fighting for the same identity by mistake (e.g. inherited shell
env), the lockfile error message will tell you which PID holds the
existing claim.

## 0.3.69

### Fixed

- Excluded `*.bak`, `*.swp`, `.DS_Store` from published tarball via
  `.npmignore`. 0.3.68 accidentally shipped local backup files. Same
  code as 0.3.68; deprecate 0.3.68.

## 0.3.68

### Fixed

- `RelayConnection` no longer silently reconnects on close code 4004
  ("Replaced by new connection"). Logs FATAL, sets a hard-stop flag,
  fires the new `identity-collision` event, and exits the close
  handler. Breaks the duplicate-identity ping-pong loop. See `d6a17f6`.

### Added

- `identity-collision` event on `SymNode` — `{ nodeId, name, code }`.
  Optional listener; default behavior is loud-log + stop reconnecting.
  Hosts wanting hard-exit semantics should listen and call
  `process.exit()` themselves.

### Why

Two processes holding the same nodeId would enter a 1s ping-pong loop
on the relay, flooding peer-left/peer-joined events. MMP principle:
identity is bound to a keypair, so two simultaneous holders is an
error condition — refuse loudly instead of silently retrying.

## 0.3.67

### Added

- **`sym observe --standalone`** — daemon-less one-shot CMB emission.
  Spins up a fresh `SymNode` inside the CLI process, reads relay
  credentials from `~/.sym/relay.env`, emits one CMB, and disconnects.
  Works even when `sym-daemon` is not running — the daemon becomes an
  optimisation, not a requirement. Auto-enabled as a graceful fallback
  whenever the daemon is down, so existing `sym observe` commands no
  longer fail with "sym-daemon is not running."
- **`sym observe --name <id>`** — set the mesh identity for
  standalone-mode emissions. Defaults to `sym-cli`. Identity is stable
  across invocations via the cached `SymIdentity` keypair in
  `~/.sym/nodes/<name>/`, so repeated calls with the same name resolve
  to the same `nodeId`. Claude Code users should pass
  `--name claude-code-mac` (or `claude-code-win` / `claude-code-linux`)
  so their CMBs are attributable on the mesh grid.
- **`sym observe --parents <key1,key2>`** — comma-separated parent CMB
  keys for remix lineage. Using this flag implies `--standalone` (the
  daemon IPC `remember` handler does not accept lineage parents). Makes
  it trivial to emit resolution CMBs that close upstream tickets on the
  Review Board via the SVAF lineage graph.

### Why

Before this release, `sym observe` required `sym-daemon` to be running
— any user who had stopped the daemon (or never started it) hit a hard
failure. This was the main friction for Claude Code sessions that want
to participate in the mesh as real peers without running a persistent
background daemon. The daemon-less path makes the entire mesh emission
surface usable out of the box after `npm install -g @sym-bot/sym`.

### Migration

No breaking changes. Existing `sym observe '<json>'` calls continue
to work unchanged when the daemon is running (same IPC fast path).
When the daemon is down, the CLI now falls back to standalone mode
instead of failing.

## 0.3.66

### Changed (MMP v0.2.2 spec conformance)

- **`state-sync` frame is now deprecated.** CfC hidden states never cross
  the wire under SVAF (Xu, 2026, *Symbolic-Vector Attention Fusion for
  Collective Intelligence*, [arXiv:2604.03955](https://arxiv.org/abs/2604.03955),
  §3.4). Cognitive coupling propagates as **CMBs** at SVAF Layer 4 only;
  the per-agent CfC at Layer 6 stays private to each agent.
- `_reencodeAndBroadcast()` updates the local CfC only; no `state-sync`
  broadcast.
- `updateContext(text)` updates the local CfC only; no `state-sync`
  broadcast.
- The per-handshake `state-sync` send is removed. Handshake exchanges
  identity, version, and lifecycle role only; cognitive bootstrap
  happens via the anchor CMB exchange that follows.
- Coordinated with `@sym-bot/core` 0.3.32, which silently drops inbound
  `state-sync` frames at the frame-handler with a deprecation log.
- The wire format is preserved (the `state-sync` frame type is still
  parseable for backward compatibility with v0.2.0 / v0.2.1 peers); only
  the *send* paths are removed.

### Migration

If you previously listened for `coupling-decision` events driven by
state-sync, switch to events emitted by the CMB pipeline
(`memoryReceived`, `cmbAccepted`) and read `(valence, arousal)` from
`cmb.fields.mood`. The mood field is delivered across domain boundaries
even when SVAF rejects the rest of the CMB (MMP §9.3 protocol guarantee R5).

## 0.3.65

### Fixed
- `sym-daemon` default node name is now platform-scoped (`sym-daemon-mac` / `sym-daemon-win` / `sym-daemon-linux`) instead of the hardcoded `sym-daemon-win`. The hardcoded fallback caused Mac daemons to identify as `sym-daemon-win`, leading to identity collisions and stale `~/.sym/nodes/` directories on cross-platform development machines.

## 0.3.64

### Fixed
- Bumped `@sym-bot/core` to `^0.3.31` to restore `cmb-accepted` event emission in `cliHostMode`. Without this bump, `bin/sym-daemon.js`'s `cmb-accepted` listener never fires under `cliHostMode`, silently disabling `sym sub` IPC subscribers and the daemon→hosted-agent fanout path.

## 0.3.63

### Changed (BREAKING)
- `sym-daemon` now uses `cliHostMode: true` (renamed from `relayMode`). Daemon no longer stores forwarded CMBs — eliminates ~5x duplication on multi-agent hosts.
- `sym recall` is now federated: scans `~/.sym/nodes/*/meshmem/` directly, deduped by CMB key, sorted by recency. Works without the daemon. New `--node <name>` flag scopes the scan.
- Requires `@sym-bot/core@^0.3.31` (originally shipped against 0.3.30; 0.3.30 had a regression — see sym-core CHANGELOG).

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
