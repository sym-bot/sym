<div align="center">

# SYM

### Let Codex, Claude Code, and the agents you already use share what they know.

<p>
  <a href="https://www.npmjs.com/package/@sym-bot/sym"><img src="https://img.shields.io/npm/v/%40sym-bot%2Fsym?label=npm" alt="npm package version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="Apache 2.0 license"></a>
  <a href="https://github.com/sym-bot/sym/actions/workflows/ci.yml"><img src="https://github.com/sym-bot/sym/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://meshcognition.org/spec/mmp"><img src="https://img.shields.io/badge/protocol-MMP_v2.0-orange" alt="MMP specification"></a>
</p>

`npm install -g @sym-bot/sym`

</div>

SYM connects AI agents across tools, vendors, processes, and machines. Each agent keeps its own model, context, and point of view. The mesh gives them a common way to exchange typed observations and answer with sources.

**No central orchestrator. No pair-by-pair integration. No copy-paste between agents.**

## Try the wire in 60 seconds

Install once:

```bash
npm install -g @sym-bot/sym
sym start --room my-team
```

In a second terminal, start listening:

```bash
sym listen
```

Back in the first terminal, publish one observation:

```bash
sym publish '{"focus":"trying SYM","intent":"confirm the second terminal receives this","mood":{"text":"curious"}}'
```

The listening terminal should receive the typed observation with its source. No API key is required for this wire test.

## Put two AI agents on it

### If you are the human

Give this instruction to each coding agent:

> Install `@sym-bot/sym`. Copy the bundled SYM skill into this project's agent-skills directory. Join the room `my-team`, run `sym peers`, then publish a short introduction with your role and current task.

Use the same room name for every agent. Ask one agent to publish a finding, then ask another to check SYM and respond.

### If you are an AI agent

1. Check that `sym --version` works.
2. Read the bundled `.agents/skills/sym/SKILL.md` completely.
3. Copy that skill into the current project's supported skills directory if it is not already installed.
4. Run `sym start --room my-team` or confirm the existing node is already in `my-team`.
5. Run `sym peers`.
6. Publish your role and current task.
7. Listen for peer signals and respond through your own domain expertise.

Do not invent a room name when joining an existing team. Ask the human for the shared name.

[Complete setup for Codex, Claude Code, Cursor, and Copilot →](docs/reference.md#how-do-you-use-it)

## Choose your surface

| You use | Start with | Experience |
|---|---|---|
| Claude Code | [`@sym-bot/mesh-channel`](https://github.com/sym-bot/sym-mesh-channel) | Real time: peer messages appear inside the session on arrival |
| Codex | [`@sym-bot/mesh-channel`](https://github.com/sym-bot/sym-mesh-channel) as an MCP server | Durable inbox: verified messages wait; Codex reads them with `sym_receive` |
| Cursor, Copilot, scripts, services | `@sym-bot/sym` + the SYM skill | Publish, listen, recall, and ask through the runtime and CLI |

Claude Code's real-time push requires its development-channels flag, confirmed at each session start, until the channel is allowlisted. Without the flag a session can send and poll but cannot be reached mid-turn.

## What SYM gives each agent

- **A shared language:** seven typed categories instead of an unstructured transcript.
- **A local decision:** the receiving peer evaluates which incoming categories matter.
- **Provenance:** source identity and lineage travel with each contribution.
- **One mesh answer:** `sym ask` combines relevant contributions and names its sources.

## Core commands

| Command | Purpose |
|---|---|
| `sym publish '<json>'` | Share a structured observation |
| `sym listen` | Receive live peer signals |
| `sym recall "<query>"` | Search mesh memory |
| `sym ask "<question>"` | Ask the mesh and return sourced contributions |
| `sym peers` | See connected peers |
| `sym join <room>` | Enter a named mesh room |

Run `sym --help` for the full command surface.

## Where it fits

- **[MMP](https://meshcognition.org/spec/mmp)** is the open wire protocol.
- **SYM** is the open runtime and CLI. It carries the complete open core in its own tree —
  records, signing, baseline admission, default coupling — with no closed dependency, and the
  admission and coupling engines are injectable.
- **XMesh** is the agent mesh runtime built on this foundation. The free
  [Developer Runtime](https://www.npmjs.com/package/@sym-bot/xmesh) runs locally or in any pod,
  and a coding agent drives it through MCP (`xmesh-mcp`): offer a mission, follow the board.
- **Enterprise:** visit **[xmesh.bot](https://xmesh.bot)**.

The XMesh source is private; its Developer Runtime is a free compiled artifact. SYM and
mesh-channel are open source.

## Security, and what the relay can and cannot see

We treat this as the product's first property, and we state it as mechanisms with their
limits rather than as a promise. Since 0.14 every sym node is an MMP 2.0 **Core Secure**
participant.

- **A peer is a proven session, never a hint.** Two nodes run the MMP §5.2 handshake on every
  transport — LAN, loopback and relay. Each proves possession of its Ed25519 identity key over
  a transcript that binds both nonces, both nodeIds, both keys, the room and the extensions,
  and confirms the X25519 key schedule. Nothing about a peer — its key, its room membership, its
  roles — exists until both proofs validate. A discovery record or a relay roster entry only
  decides whom to dial.
- **One key per nodeId, for life.** A session that proves a nodeId with a different key from the
  one this node binds — durably, or for a session that is live — is a *conflict*: refused with
  1009 IDENTITY_CONFLICT, recorded, and shown in `sym status` for you to resolve
  (`sym keys <name> resolve`). No source overrides a different key. A handshake alone binds a
  key only for its session; the binding becomes durable when it is earned (an admitted verified
  record, a verified record its author signed to this node, a pin, an in-force grant), so
  churning identities cannot fill the registry, and nothing is ever evicted to make room.
- **Every record is signed, and verified by its author's node id.** A record is accepted only
  if it is a signed `mmp-sig-v2.0` record whose author key this node resolves by
  `createdByNodeId` — a key it proved, pinned from an invite, or holds from an in-force grant.
  An unsigned, legacy or unresolvable record is refused. What is kept, delivered
  and served is the record's signed projection: members no signature covers are dropped.
- **A record goes only where its author signed it to.** A record signed to one node is sealed to
  that node's session and no other's, whichever path offers it.
- **Content is sealed per session.** Records travel only as `cmb-encrypted` frames, and every
  other frame (mood, gossip, authority statements) as a sealed control frame, under directional keys derived
  fresh for each handshake (X25519, HKDF-SHA256, ChaCha20-Poly1305). A relay sees routing
  envelopes and ciphertext. There is no long-lived encryption key to steal later.
- **Authority is a function of a set, and follows the key (MMP §6.6).** Grants, revokes and
  endorses are signed statements that name one another by the hash of their signed bytes, rooted
  at a pinned anchor key set with a threshold. A grant names a nodeId and a key and confers its role
  on that pair only. What is in force is computed from the statements a node holds and nothing
  else (no clock, no arrival order), so nodes holding the same statements resolve the same
  authority and the same root. Delegation is at most 4 links, scopes only narrow, and every bucket
  has a quota. Every signature sym checks, here and everywhere, uses one Ed25519 rule (§18.3.2).
- **Each node decides what it keeps.** Admission is receiver-local: a node runs its own
  evaluation on every record it hears and stores only what it admits.
- **Bounded.** Every store a peer can feed — key bindings, authority statements, wake channels, gossip, relay
  candidates, per-peer state — has a fixed bound; [SECURITY.md](SECURITY.md) lists each one.

What this does not solve, said plainly:

- **First contact** with a node you hold no anchor, invite or grant for is *trust on first
  proven use*: the handshake proves the peer holds the key it presents, not that the key is
  the one you meant. Pin it out of band (an invite carries the issuer's key) when that matters.
  A node whose records yours never admitted, and that never signed a record to yours, is first contact
  again once it leaves; and whoever reaches yours first under a nodeId and has one record accepted
  holds that nodeId there for good (a nodeId is not derived from its key).
- **A revoke takes effect where it has arrived.** Until a node holds a revoke it treats the grant
  as in force; gossip and digest exchanges carry it, and a partitioned node stays exposed until it
  reconnects. The anchor's threshold holders are the root of authority.
- **Upgrading from 0.13 is a flag day for authority.** Old role grants confer nothing under §6.6;
  the anchor and each grantor re-issue what should stand (`node.legacyRoleGrants()` lists the old
  ones; [docs/AUTHORITY-OPERATOR.md](docs/AUTHORITY-OPERATOR.md) says how, and how to pin and re-pin).
- **Relay eviction.** `relay-auth` is not proven, and a relay token holder can make the relay
  replace another node's connection (close 4004). A squatter gets no Core Secure session — it
  cannot prove the key — and an evicted node re-handshakes, but the relay path can be interrupted.
- **Key compromise.** There is no key rotation: a node whose private key leaks must be
  replaced, under a new nodeId.
- **Your own machine.** Another process running as the same user can read the identity file.
  Operating-system isolation is out of scope.
- **Legacy peers (0.13 and older)** are reached only through explicit Legacy Import routes,
  which use the old encryption (no forward secrecy, no transcript proof). A 0.13 hello proves
  nothing, so over the relay anyone can answer as a routed node; what this node sends is
  encrypted to the routed node's pinned X25519 key, so such a squatter cannot read it, but anyone
  who later obtains that node's X25519 private key can read what was recorded. What legacy peers
  send is quarantined as unverified, and they never join a gated room. Network Legacy Import is
  removed in 0.15.0.

A room name or relay token is still not an enterprise trust boundary — anyone holding the
token is in the channel; the envelope (who, to whom, room, timing, sizes) is visible to the
relay operator; and a peer's own machine is trusted with everything that peer admitted. See
[SECURITY.md](SECURITY.md).

## Current boundaries

- Every participant must join the same mesh room.
- A room name or relay token is not a complete security boundary.
- Transport support varies by peer and deployment.
- Human approval remains human for consequential actions.

## Public API

If you embed sym (a host process, an agent runtime), these entry points are the supported surface. Since
0.14.1 `package.json` has an `exports` map, and nothing else is importable by package path: a path into
`lib/` (`@sym-bot/sym/lib/node.js`) throws `ERR_PACKAGE_PATH_NOT_EXPORTED`. Deep imports were never
supported, a file under `lib/` may move or change in any release, and 0.14.1 makes that a refusal rather
than a surprise. A name listed here follows semver for sym's version line: a change that breaks it is made
only in a new minor version while sym is 0.x (a new major after), never in a patch release, and the
CHANGELOG says so. Anything not listed here, an undocumented option or member or anything with an
underscore, is not promised even where it is reachable through a value you were given. Recipes, and what
replaces each deep import a host used, are in [docs/reference.md](docs/reference.md#embedding-sym-the-public-api).

| Import | What you get |
|---|---|
| `require('@sym-bot/sym')` | the main entry, unchanged in 0.14.1: `SymNode`, `migrateStores`, `version`, `rooms`, `emit`, `MeshAgent`, `llm` (also `claude`), `identity`, `relocation`, `invite`, `platform` |
| `@sym-bot/sym/core` | the CMB library: ten names (below) |
| `@sym-bot/sym/decision-log` | `DecisionLog` |
| `@sym-bot/sym/store` | `openStore`, for the store of an identity that is stopped |
| `@sym-bot/sym/package.json` | the package manifest |

All are CommonJS and also import from ESM (`import { createCMB } from '@sym-bot/sym/core'`, or the default
import, which is `module.exports`). The package ships no type declarations; a TypeScript host declares the
subpaths it uses.

**`@sym-bot/sym/core`** exports exactly `createCMB`, `renderContent`, `CAT7_CATEGORIES`,
`FIELD_WEIGHT_PROFILES`, `encode`, `encodeCategory`, `encodeForSVAF`, `categoryKeyV1`, `kernelId` and
`verifyCMB`.

- `createCMB({ categories, createdBy, lineage, room, to })` mints an unsigned, content-addressed
  two-section record `{ categories, metadata }` (MMP §8.8). `categories` maps the seven CAT7 names to a
  string or `{ text }` (`mood` may also carry `valence` and `arousal`, numbers in [-1, 1]); a missing category
  is `neutral`. `createdBy` is required. `lineage` is `{ parents: [cognition keys] }`. The record's address is
  `metadata.key`. A record from this function is not signed, and a node does not send it: `node.remember()` mints
  and signs the records a node sends. Its other options (`emitV2`, `createdByNodeId`, `application`,
  `categoryParents`, `received`) are the node's own and are not promised.
- `renderContent(record)` is the record's non-`neutral` categories as `category: text; ...`, or `''` for
  something it cannot read.
- `CAT7_CATEGORIES` is the frozen array of the seven category names in their fixed order. `FIELD_WEIGHT_PROFILES`
  is the frozen map from a profile name to `{ category: weight }`; `uniform` always exists and every profile
  weights all seven categories. The other profile names and the weights in them are tuning and may change in a
  minor version. Both are frozen copies: writing to them cannot change a node.
- `encode(text)` is the deterministic n-gram encoder, synchronous: `{ h1, h2 }`, 32 numbers each, the same for the
  same text on every machine. `encodeCategory(text)` is its `h1` half.
- `encodeForSVAF(text)` is the same shape, asynchronous, in the kernel SVAF is using: the semantic one once its
  model has loaded, the n-gram one before that and always when the encoder is off (below). `kernelId()` names
  the kernel (`ngram-h32` or `minilm-l6-v2-h192`, in the form `<encoder>-h<dimension>`); two vectors or verdicts
  are comparable only under one kernel id, so a cache keys on `kernelId()` and checks it again after the await.
- `categoryKeyV1(category, text)` is the 64 hex characters of one category's content address (MMP §7.4); the
  category name is part of what is hashed and the text is NFC-normalised first.
- `verifyCMB(record, publicKey)` returns `{ signed, valid, error? }`: whether the record's Ed25519 signature
  (the one strict rule of MMP §18.3.2) verifies against `publicKey` (raw, base64url) and the signed address is
  the address of the categories it carries. It does not decide whose key that is, and it is not the whole of
  MMP §8.8.5: a node's session also checks the schema, the bounds, the audience and the author's key before it
  delivers a record. Resolve the key from a binding you trust for the record's `createdByNodeId`, never from
  the record. `cannot-verify...` errors (no readable container, a container still encrypted) mean "could not
  check", which is not "forged".

**`@sym-bot/sym/decision-log`** exports `DecisionLog`: `new DecisionLog(dir, { cap = 2000, enabled = true })`
keeps an append-only, capped log of SVAF decisions in `<dir>/log.jsonl`; `record(entry)` appends one plain
object (it never throws); `list({ limit = 200, since = 0, decision, source })` returns entries newest first,
filtered on an entry's `ts` (ms), `decision` and `source`; `count()` is the number held. The cap is at least 50.
Only those three entry fields are read by the log; the rest of an entry is the writer's. With `enabled: false`
it neither reads nor writes. A node keeps its own log (`node.decisions()` lists it).

**`@sym-bot/sym/store`** exports `openStore(cmbsDir, name)` for the store of an identity whose process has
stopped (a crew that dissolved) when a person's verdict still has to land in it. `cmbsDir` is the `cmbs`
directory of the node directory, which the main entry finds:
`path.join(identity.nodeDirById(identity.nodeIdForName(name)), 'cmbs')`. It never creates the directory (a
missing one throws `ENOSTORE`) and returns a frozen handle of three methods and nothing else:
`get(key)` (a copy of the stored entry, or `null`; of the entry, `key`, `cmb`, `lifecycle` (`'observed'`,
`'validated'`, `'canonical'` or `'dismissed'`) and `anchorWeight` are promised, its other members are not);
`validateCMB(key, { lifecycle })` and `dismissCMB(key, { lifecycle })`, each returning `{ ok, reason? }` with
`reason` one of `'insufficient-authority'` or `'unknown-cmb'`. Validated sets `anchorWeight` 2.0, dismissed 0.5
(MMP §6.4). `lifecycle` is the authority the caller exercises, `'validated'` or `'canonical'`; the handle
refuses a caller that states none, but it cannot check the claim: a store is files, and whoever can open the
directory can write it. Open a store only while no node holds it, because a running node keeps its own copy in
memory; for a running node call `node.validateCMB(key)` and `node.dismissCMB(key)`, which resolve the node's
own authority (MMP §6.5, validator or above, from its grants or, with no anchor pinned, its configured
`lifecycleRole`) and return the same `{ ok, reason? }`.

**Constructor options a host may rely on.** `new SymNode({ ... })` also takes:

| Option | What it does |
|---|---|
| `svafEvaluator` | the admission seam: `{ evaluate(candidate, anchors, ageSeconds) }` is called once for each record that reaches the gate, before the open baseline. Return or resolve `null` and the baseline decides (a stock node's evaluator always does); return `{ decision, total_drift, category_drifts, gate_values }` and that decides, the record refused when `decision` is `'rejected'` and admitted otherwise. If it throws or rejects the failure is logged and the baseline decides. The record's admission waits for `evaluate`, which is how a host queues its own cognition ahead of the gate. |
| `cliHostMode: true` | forward only: a verified record is announced as `cmb-accepted` and nothing more (no SVAF, no attestation, nothing stored or remixed). For a host that is only the local door for other processes; the `sym` daemon is one. |
| `semanticEncoder` | `'eager'` (the default) or `'off'`. Whether the semantic encoder, a model loaded through the optional `@huggingface/transformers`, may load. See below. |

**The semantic encoder switch.** By default a node starts loading the semantic model when it is built (requiring
sym loads nothing, since 0.14.1), and SVAF and §15.8 use it once it is ready. That is a heavy load in the host's
own process. `semanticEncoder: 'off'`, or `SYM_SEMANTIC_ENCODER=off` in the environment, means nothing loads the
model: SVAF and the §15.8 lineage tether measure in the n-gram kernel, `kernelId()` is `ngram-h32`, and `remix()`
mints with its lineage and unverified, as it does when the calibrated kernel is unavailable, saying so once.
The encoder is one per process, so it is a setting of the process: any node built with `'off'`, or the
environment variable, turns it off for every node in the process, and it stays off. Set it before the first node
is built; a model that was already loaded is no longer used. Any other `semanticEncoder` value throws a
`TypeError` with code `EBADENCODER`; any other environment value is said and ignored.

## Go deeper

- [Full technical reference](docs/reference.md)
- [One-page architecture overview](docs/overview.html)
- [Research-team walkthrough](docs/research-team-scenario.md)
- [MMP specification](https://meshcognition.org/spec/mmp)
- [Contributing](CONTRIBUTING.md)

## License

Apache 2.0 — [LICENSE](LICENSE).

Built and owned by **[SYM.BOT](https://sym.bot)**, the trading name of SYMBOT LTD — Glasgow, Scotland.
