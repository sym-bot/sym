# Changelog

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
