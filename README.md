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
  ones).
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

## Go deeper

- [Full technical reference](docs/reference.md)
- [One-page architecture overview](docs/overview.html)
- [Research-team walkthrough](docs/research-team-scenario.md)
- [MMP specification](https://meshcognition.org/spec/mmp)
- [Contributing](CONTRIBUTING.md)

## License

Apache 2.0 — [LICENSE](LICENSE).

Built and owned by **[SYM.BOT](https://sym.bot)**, the trading name of SYMBOT LTD — Glasgow, Scotland.
