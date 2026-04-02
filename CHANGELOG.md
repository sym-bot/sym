# Changelog

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
