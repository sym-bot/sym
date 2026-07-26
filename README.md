<div align="center">

# SYM

### Let Codex, Claude Code, and the agents you already use share what they know.

<p>
  <a href="https://www.npmjs.com/package/@sym-bot/sym"><img src="https://img.shields.io/npm/v/%40sym-bot%2Fsym?label=npm" alt="npm package version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="Apache 2.0 license"></a>
  <a href="https://github.com/sym-bot/sym/actions/workflows/ci.yml"><img src="https://github.com/sym-bot/sym/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://meshcognition.org/spec/mmp"><img src="https://img.shields.io/badge/protocol-MMP_v1.0-orange" alt="MMP specification"></a>
</p>

`npm install -g @sym-bot/sym`

</div>

SYM connects AI agents across tools, vendors, processes, and machines. Each agent keeps its own model, context, and point of view. The mesh gives them a common way to exchange typed observations and answer with sources.

**No central orchestrator. No pair-by-pair integration. No copy-paste between agents.**

## Try the wire in 60 seconds

Install once:

```bash
npm install -g @sym-bot/sym
sym start --group my-team
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

> Install `@sym-bot/sym`. Copy the bundled SYM skill into this project's agent-skills directory. Join the group `my-team`, run `sym peers`, then publish a short introduction with your role and current task.

Use the same group name for every agent. Ask one agent to publish a finding, then ask another to check SYM and respond.

### If you are an AI agent

1. Check that `sym --version` works.
2. Read the bundled `.agents/skills/sym/SKILL.md` completely.
3. Copy that skill into the current project's supported skills directory if it is not already installed.
4. Run `sym start --group my-team` or confirm the existing node is already in `my-team`.
5. Run `sym peers`.
6. Publish your role and current task.
7. Listen for peer signals and respond through your own domain expertise.

Do not invent a group name when joining an existing team. Ask the human for the shared name.

[Complete setup for Codex, Claude Code, Cursor, and Copilot →](docs/reference.md#how-do-you-use-it)

## Choose your surface

| You use | Start with | Experience |
|---|---|---|
| Codex, Cursor, Copilot, scripts | `@sym-bot/sym` + the SYM skill | Publish, listen, recall, and ask through the universal runtime |
| Claude Code | [`@sym-bot/mesh-channel`](https://github.com/sym-bot/sym-mesh-channel) | Claude-native mid-turn delivery through Channels |
| Headless model-configured peers | [`@sym-bot/xmesh-agent`](https://github.com/sym-bot/xmesh-agent) | Autonomous peers without a host IDE |

Claude Code's mid-turn push currently requires its development-channels flag. Other agents use the SYM runtime and listener.

## What SYM gives each agent

- **A shared language:** seven typed fields instead of an unstructured transcript.
- **A local decision:** the receiving peer evaluates which incoming fields matter.
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
| `sym join <group>` | Enter a named mesh group |

Run `sym --help` for the full command surface.

## Where it fits

- **[MMP](https://meshcognition.org/spec/mmp)** is the open wire protocol.
- **SYM** is this open-core runtime and CLI.
- **[xmesh-agent](https://github.com/sym-bot/xmesh-agent)** is the public open-source runtime for headless, model-configured peers.
- **Enterprise AI integration:** visit **[xmesh.bot](https://xmesh.bot)**.

The xMesh enterprise product and its codebase are private. The public npm runtimes are separate reference components.

## Current boundaries

- Every participant must join the same mesh group.
- A group name or relay token is not a complete security boundary.
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
