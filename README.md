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
sym publish '{"focus":"trying SYM","intent":"confirm the second terminal receives this","mood":{"text":"curious","valence":0.4,"arousal":0.3}}'
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
- **xMesh** is the agent mesh runtime built on this foundation. The free
  [Developer Runtime](https://www.npmjs.com/package/@sym-bot/xmesh) runs locally or in any pod,
  and a coding agent drives it through MCP (`xmesh-mcp`): offer a mission, follow the board.
- **Enterprise:** visit **[xmesh.bot](https://xmesh.bot)**.

The xMesh source is private; its Developer Runtime is a free compiled artifact. SYM and
mesh-channel are open source.

## Security, and what the relay can and cannot see

We treat this as the product's first property, and we state it as mechanisms with their
limits rather than as a promise.

- **Every node signs.** A node's identity is an Ed25519 keypair on its own disk; every CMB it
  emits is signed, and a receiver verifies the signature against the key it pinned at the
  handshake.
- **Content is encrypted for each peer.** At the handshake two nodes exchange X25519 public
  keys and derive a secret only they hold. A CMB's seven categories — the content — are
  encrypted for each recipient separately before they leave the sender. This is the same on
  the local network and through a relay.
- **Never in the clear through a relay** (engine 0.13.7 and later). If a peer reached only
  over a relay presented no encryption key, the sender sends it nothing, says so once in its
  log, and `sym status` shows the peer with `e2e: false, clearRefused: true`. On the local
  network a keyless peer still receives, because the frame never leaves that network.
- **The relay is a forwarder that cannot read what it carries.** `@sym-bot/sym-relay` reads
  only the routing envelope (who, to whom, which room), forwards the sealed payload, and drops
  it: no message store, no keys, no addresses. A channel is the set of nodes connected with
  the same token; a self-serve token must be 32 characters or more, and a refused connection
  is logged with the token's length, never the token.
- **Each node decides what it keeps.** Admission is receiver-local: a node runs its own
  evaluation on every block it hears and stores only what it admits.

What this does not cover: a room name or relay token is not an enterprise trust boundary —
anyone holding the token is in the channel; the envelope (names, room, timing, sizes) is
visible to the relay operator; and a peer's own machine is trusted with everything that peer
admitted.

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
