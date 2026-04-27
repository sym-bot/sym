# SYM

> **Your agents communicate. They don't understand each other. SYM fixes that.**
>
> You have Claude Code in your repo, Cursor in your editor, Copilot in GitHub, maybe a custom script or two. Four copilots. Zero shared memory. SYM is the protocol that lets them think together.

```bash
npm install -g @sym-bot/sym && sym start
```

> **SYM is the protocol substrate + CLI** — install it once per machine to join existing AI copilots (Claude Code, Cursor, Copilot, custom scripts) into a shared mesh via the SKILL.md skill file. Each agent stays in its own UI; the mesh just lets them share memory.
>
> If you want to run **dedicated autonomous LLM peers** that wake on incoming messages and call any model on their own (no host IDE required), see [`@sym-bot/xmesh-agent`](https://github.com/sym-bot/xmesh-agent) — built on top of SYM. The two work in the same mesh.

[![npm](https://img.shields.io/npm/v/@sym-bot/sym)](https://www.npmjs.com/package/@sym-bot/sym)
[![MMP Spec](https://img.shields.io/badge/protocol-MMP_v1.0-orange)](https://meshcognition.org/spec/mmp)
[![SVAF arXiv](https://img.shields.io/badge/arXiv-2604.03955-b31b1b.svg)](https://arxiv.org/abs/2604.03955)
[![MMP arXiv](https://img.shields.io/badge/arXiv-2604.19540-b31b1b.svg)](https://arxiv.org/abs/2604.19540)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![CI](https://github.com/sym-bot/sym/actions/workflows/ci.yml/badge.svg)](https://github.com/sym-bot/sym/actions/workflows/ci.yml)
[![中文文档](https://img.shields.io/badge/语言-中文-red)](README_zh.md)

## Contents

1. [What this looks like](#what-this-looks-like) — production log of three apps coordinating through the mesh
2. [Who this is for](#who-this-is-for)
3. [Quick start](#quick-start)
4. [What you get](#what-you-get) — CLI + SDK surface
5. [Ask the mesh](#ask-the-mesh) — one question, every agent that knows contributes
6. [Why this is different from multi-agent frameworks](#why-this-is-different)
7. [Use cases](#use-cases) — e-commerce, content creators, vibe coding
8. [How it works](#how-it-works)
9. [Configuration](#configuration) — profiles, field weights, drift thresholds, math
10. [Claude Code as a mesh node](#claude-code-as-a-mesh-node)
11. [iOS / macOS apps](#ios--macos-apps)
12. [For AI coding agents reading this](#for-ai-coding-agents-reading-this)
13. [Limitations](#limitations)
14. [Other implementations](#other-implementations)

---

## What this looks like

Three apps on three devices, three different vendors. Claude Code (macOS), MeloTune (iPhone), MeloMove (iPhone). None of them know the others exist. All three are on the mesh.

You vibe-code for hours. You don't notice what's happening to you. But your agents do — together.

Claude Code sees your messages getting shorter, your commits slowing down. [MeloTune](https://melotune.ai) notices you skipped your usual playlist. [MeloMove](https://melomove.ai) sees 3 hours without movement. Individually, each observation is noise. Together, the mesh synthesises:

> *"Energy declining across all signals. 3-hour sedentary. Deviation from routine. This isn't focus — it's fatigue."*

MeloTune shifts to calm ambient. MeloMove suggests a recovery stretch. Not because one agent told them to — because **the mesh understood something none of them could see alone.**

**This isn't hypothetical.** Here's the actual production log from that session:

```
# 1. Claude Code extracts 7 structured fields from what it observes
sym observe '{
  "focus": "wrapping up mesh protocol testing session",
  "issue": "neutral",
  "intent": "validate end-to-end CMB flow",
  "motivation": "release readiness",
  "commitment": "final test round",
  "perspective": "developer, 10am morning session",
  "mood": {"text": "cautiously optimistic", "valence": 0.3, "arousal": 0.2}
}'
# → Shared: cmb-c96d21a4cf4598cf

# 2. MeloTune receives the CMB, SVAF evaluates all 7 fields independently
[SYM] memory-share: received CMB cmb-c96d21a4cf from sym-daemon (7 fields, mood: cautiously optimistic)
[SYM] memory: SVAF fused from sym-daemon [aligned, drift:0.032,
  fields: commitment:-0.00 focus:0.06 intent:0.09 issue:-0.00 mood:0.06 motivation:-0.00 perspective:0.07]

# 3. MeloTune's LLM interprets the mood autonomously
[LLM] input: "cautiously optimistic"
[LLM] output: mood_based, emotion: 55, energy: 50, genre: Indie
[LLM] reason: Mood-based request for cautious optimism in music.

# 4. MeloTune curates and plays
[MoodState] ▶ START MoodSession | mood: Exploring Wonder (e:55, n:50), genre: Indie
[PlaybackSync] 🎵 Now playing: 'Circle of Trust' (Indie Rock, E:55 N:65)
```

<table><tr><td width="260"><img src="docs/sym-readme-melotune-mesh-result.jpg" alt="MeloTune playing Circle of Trust" width="240" /></td><td>
Claude Code didn't tell MeloTune to play Indie. It shared what it observed — 7 structured fields with mood "cautiously optimistic". MeloTune's SVAF evaluated each field, accepted the signal (drift 0.032), extracted the mood, and its own LLM decided "Exploring Wonder" with Indie genre. Neither agent knows the other exists. The mesh connects them.
</td></tr></table>

Cross-platform verified April 2026: macOS + Windows + iOS, pure Bonjour on LAN, WebSocket relay for cross-network.

## Who this is for

- **Developers running multiple AI copilots** — Claude Code + Cursor + Copilot + custom scripts, each with its own context window and zero shared memory. SYM gives them a common mesh.
- **One-person companies with AI agents** — support agent, inventory agent, analytics agent, content agent. Each sees one slice; the mesh connects them into collective insight.
- **Multi-agent engineers and researchers** — building cognitive architectures, routing, coordination. SYM is the reference implementation of the open [Mesh Memory Protocol (MMP)](https://meshcognition.org/spec/mmp).
- **Not for:** a single LLM chat session that doesn't need to coordinate with anyone. Use the Anthropic/OpenAI API directly.

## Quick start

### One command

```bash
npm install -g @sym-bot/sym
sym start
```

The daemon runs in the background. Every agent on your machine that has the SYM skill installed now joins the mesh and discovers peers on the same wifi via Bonjour automatically.

### Install the skill into your agent

The skill is a short Markdown file that teaches any LLM-powered coding agent how to use SYM. Copy it into your agent's skills directory:

```bash
# Claude Code:
mkdir -p .claude/skills/sym
cp $(npm root -g)/@sym-bot/sym/.agents/skills/sym/SKILL.md .claude/skills/sym/

# Cursor / Codex / OpenClaw / JetBrains Junie / general agents:
mkdir -p .agents/skills/sym
cp $(npm root -g)/@sym-bot/sym/.agents/skills/sym/SKILL.md .agents/skills/sym/

# GitHub Copilot:
mkdir -p .github/skills/sym
cp $(npm root -g)/@sym-bot/sym/.agents/skills/sym/SKILL.md .github/skills/sym/

# Google Gemini CLI:
mkdir -p .gemini/skills/sym
cp $(npm root -g)/@sym-bot/sym/.agents/skills/sym/SKILL.md .gemini/skills/sym/
```

### Talk to your agent normally

You say: *"The customer is upset about the blue variant being out of stock."*

Your agent reads the SKILL file, decomposes your observation into 7 structured fields, and broadcasts — you never see the JSON:

```bash
# Your agent does this automatically behind the scenes:
sym observe '{"focus":"5 customers asking about blue variant","issue":"out of stock, no ETA","mood":{"text":"frustrated","valence":-0.4,"arousal":0.5}}'
```

If your inventory agent has already shared `"blue variant restock confirmed, arriving Thursday"`, your support agent's next response tells the customer: *"The blue variant arrives Thursday."* — informed by another agent through the mesh, without anyone writing integration code between them.

### For agents without an LLM

Scripts, cron jobs, IoT devices — anything can join the mesh via CLI or SDK:

```bash
# CLI from any language that can shell out:
sym observe '{"focus":"blue variant restocked","commitment":"arriving Thursday"}'
sym recall "blue variant"
```

```javascript
// Node.js SDK:
const { SymNode } = require('@sym-bot/sym');
const node = new SymNode({ name: 'inventory-agent', cognitiveProfile: 'tracks stock levels' });
await node.start();
node.remember({ focus: 'blue variant restocked', commitment: 'arriving Thursday' });
```

For iOS/macOS apps, see [`sym-swift`](https://github.com/sym-bot/sym-swift).

## What you get

Once the daemon is running, these commands work from any shell or agent:

| Command | What it does |
|---|---|
| `sym start` | Start the mesh daemon in the background |
| `sym status` | Node identity, relay state, peer count, memory count |
| `sym peers` | List discovered peers (Bonjour LAN + relay) |
| `sym observe` | Share a structured 7-field observation to the mesh |
| `sym recall <query>` | Semantic search over mesh memory |
| `sym insight` | Pull collective insight — every peer's relevant contributions synthesised |
| `sym send <message>` | Broadcast a free-text message to all peers |
| `sym peer-info <name>` | Full profile of a specific peer (SVAF weights, domain, status) |

Your LLM-powered agents invoke these automatically once they have the SKILL file. Structured-data agents (music players, fitness trackers, IoT sensors) map domain data directly to the 7 fields — no LLM required.

## Ask the mesh

Ask one agent a question, get one perspective. **Ask the mesh, and every agent that knows something relevant contributes — automatically.**

**You ask in natural language.** *"Should we use UUID v7 or keep v4 for backward compatibility?"*

Your agent broadcasts the question. Every peer's SVAF evaluates it across all 7 fields:

- Your **knowledge agent** matches on `focus` ("UUID v7") → replies with RFC 9562.
- Your **security agent** matches on `issue` ("backward compatibility") → flags the v7 timestamp privacy trade-off.
- Your **data agent** matches on `commitment` (existing deployments) → reports 127 nodes on v4, migration path needed.
- Your **fitness agent** matches nothing → **stays silent.** SVAF rejected. No wasted tokens.

**You didn't route the question. You didn't even know the security agent existed.** The mesh discovered who was relevant. Your agent synthesises across the three perspectives and replies. Every node is traced back to its source through the lineage DAG.

## Why this is different

| | CrewAI / AutoGen / LangGraph | SYM Mesh |
|---|---|---|
| **Who decides which agent answers?** | You configure routing | SVAF decides autonomously per message |
| **Unknown agents contribute?** | No — only agents you wired up | Yes — any coupled peer |
| **Irrelevant agents waste tokens?** | Often — broadcast to all | Never — SVAF rejects silently |
| **Answer traceable?** | Depends on implementation | Always — lineage DAG |
| **Cross-process / cross-device?** | Single-process (usually) | Native — Bonjour LAN + WebSocket relay |
| **Protocol open?** | Framework-specific | Open spec ([MMP](https://meshcognition.org/spec/mmp)) + reference arXiv papers |

**Deeper walkthrough:** a six-agent research team investigating emergent LLM capabilities, step-by-step with what SVAF does at each hop and a full lineage DAG — [docs/research-team-scenario.md](docs/research-team-scenario.md).

## Use cases

### E-commerce seller

![E-commerce — collective intelligence](docs/sym-readme-usecase-ecommerce-01.png)

Support agent sees "5 customers asking when the blue version is back in stock." Analytics agent sees "blue variant page views up 300% this week." Inventory agent sees "restock arriving Thursday."

No single agent connects these. With SYM: the listing agent pre-announces the restock, the ad agent pauses blue variant ads until Thursday. You were asleep.

### Content creator

![Content creator — collective intelligence](docs/sym-readme-usecase-creator-01.png)

Writing agent is drafting this week's newsletter. Analytics agent sees Tuesday's post got 10x usual engagement. Scheduling agent is about to publish three more posts on unrelated topics.

With SYM: the writing agent pivots the newsletter. The scheduling agent holds the queue. You wake up to a better content strategy than you planned.

### Vibe coding

![Vibe coding — collective intelligence](docs/sym-readme-usecase-coding-01.png)

The full production log from this scenario is at the top of this README. Three apps, three fragments, one insight none of them could reach alone.

## How it works

```
   Claude Code (Mac)          Cursor (Mac)         MeloTune (iPhone)
         │                        │                        │
         ▼                        ▼                        ▼
   ┌─────────────────────────────────────────────────────────┐
   │                    SymNode (per agent)                   │
   │  • Ed25519 identity   • SVAF field gate                  │
   │  • Memory store       • CMB lineage DAG                  │
   └────────────────┬──────────────────────┬──────────────────┘
                    │                      │
         Bonjour mDNS (LAN)      WebSocket relay (WAN, optional)
```

Every peer runs a full SymNode — cryptographic identity, per-field relevance gate, local memory, lineage graph. There is no central broker. Peers discover each other via Bonjour on the same LAN or via a shared relay for cross-network.

When peer A broadcasts a CMB, every receiving peer's SVAF evaluates the 7 fields against that peer's own weights. Relevant signals are fused into local memory; irrelevant ones are rejected silently. No routing rules. No orchestrator.

For the full 8-layer architecture: [MMP Specification →](https://meshcognition.org/spec/mmp).

## Configuration

SYM decides what gets shared between agents. These parameters control that decision. Get them right and the mesh works autonomously. Get them wrong and agents either share everything (noise) or nothing (isolation).

### Pick a profile

> **Too many options?** Tell your AI coding agent what your app does. It reads this reference and configures the right profile, field weights, and freshness window for your domain. You don't need to understand the parameters — your agent does.

Each agent type has a pre-built configuration. Use the one that matches your domain:

```javascript
// Node.js — fitness agent
const node = new SymNode({
    name: 'my-fitness-app',
    cognitiveProfile: 'Fitness agent that tracks workouts, heart rate, and energy levels',
    svafFieldWeights: FIELD_WEIGHT_PROFILES.fitness,
    svafFreshnessSeconds: 10800     // 3 hours
});
```

| Profile | Best for | Freshness | Why this freshness |
|---------|----------|-----------|-------------------|
| `music` | Music, ambience, soundscapes | 1,800s (30min) | Stale mood = wrong music. React fast. |
| `coding` | Coding assistants, dev tools | 7,200s (2hr) | Session context matters. Yesterday's debugging doesn't. |
| `fitness` | Fitness, health, movement | 10,800s (3hr) | Sedentary detection needs hours of accumulated context. |
| `messaging` | Chat, notifications, social | 3,600s (1hr) | Recent conversation context. Older messages lose relevance. |
| `knowledge` | News feeds, research, digests | 86,400s (24hr) | Daily cycle. Today's news is relevant until tomorrow's arrives. |
| `uniform` | General purpose, prototyping | 1,800s (30min) | No field preference. Good starting point. |

### CAT7 — the 7 universal fields

Every CMB on the mesh is decomposed into 7 fields. Field weights determine which fields matter most to YOUR agent:

| Field | Axis | What it captures | Fast-coupling |
|-------|------|-----------------|---------------|
| `focus` | Subject | What the text is centrally about | |
| `issue` | Tension | Risks, gaps, open questions | |
| `intent` | Goal | Desired change or purpose | |
| `motivation` | Why | Reasons, drivers, incentives | |
| `commitment` | Promise | Who will do what, by when | |
| `perspective` | Vantage | Whose viewpoint, situational context | |
| `mood` | Affect | Emotion (valence) + energy (arousal) | Yes — crosses all domains |

Mood is the only fast-coupling field — affective state crosses all domain boundaries. The neural SVAF model discovered this without being told: `mood` emerged as the highest gate value across all fields when trained with only a soft ordering constraint.

The fields are universal and immutable. Domain-specific interpretation happens in the field text, not the field name. A coding agent's `focus` is "debugging auth module." A legal agent's `focus` is "merger due diligence." Same field, different domain lens.

### How agents extract CAT7 fields

The protocol does not parse raw text. The agent extracts fields — it IS the intelligence. How it does this depends on the agent type:

| Agent type | How to extract | Example |
|-----------|---------------|---------|
| **AI coding agents** (Claude Code, Copilot, Cursor) | The agent IS the LLM — extract fields directly | Install the [SYM skill](.agents/skills/sym/SKILL.md) — the agent knows what to do |
| **Structured-data agents** (music player, fitness tracker, IoT) | Map domain data directly to CAT7 — no LLM needed | `focus: "workout completed"`, `commitment: "45min, 320 cal"`, `mood: {text: "energized", valence: 0.7, arousal: 0.6}` |
| **Apps with unstructured text** (chat, notes, logs) | Call any LLM API with the prompt below to extract fields | See prompt template |

**LLM prompt template** — copy into your LLM API call for field extraction:

```
Extract CAT7 fields from this observation. Return JSON only.

Fields:
- focus: What this is centrally about (1 sentence)
- issue: Risks, gaps, problems. "none" if none.
- intent: Desired change or purpose. "observation" if purely informational.
- motivation: Why this matters. Omit if unclear.
- commitment: What has been confirmed or established. Omit if none.
- perspective: Whose viewpoint, situational context (role, time, duration).
- mood: { "text": "emotion keyword" }
  Optionally include "valence" (-1 to 1) and "arousal" (-1 to 1) if confident.
  Omit valence/arousal if you would be guessing.

Only include fields you can meaningfully extract. Omit rather than guess.

Observation:
{observation_text}

JSON:
```

For the full CMB specification — why 7 fields, why these fields, how mood crosses all domain boundaries — see [CMB (Layer 3)](https://meshcognition.org/spec/mmp/cmb).

### Custom weights for your domain

The 6 pre-built profiles are starting points. Your AI coding agent should derive weights from your domain. For all configuration defaults and thresholds, see [MMP Constants](https://meshcognition.org/spec/mmp/constants). The pattern:

- **Regulated domains** (legal, finance, health): `issue` and `commitment` are always high — risks and obligations are non-negotiable
- **Human-facing domains** (music, fitness): `mood` is always high — affect drives the experience
- **Knowledge domains** (knowledge, coding): `focus` is always high — subject matter is core

```javascript
// Legal agent — regulation and compliance matter
{
  focus: 2.0,        // what case/contract is about — core
  issue: 2.0,        // risks, gaps, open questions — critical for legal
  intent: 1.5,       // desired outcome
  motivation: 1.0,   // why — relevant for strategy
  commitment: 2.0,   // obligations, deadlines — contracts are commitments
  perspective: 1.5,  // whose viewpoint — multi-party matters
  mood: 0.5          // affect — less relevant for legal analysis
}

// Health agent — patient outcomes and risk
{
  focus: 1.5,
  issue: 2.0,        // symptoms, risks, concerns — critical
  intent: 1.0,
  motivation: 1.5,
  commitment: 1.0,
  perspective: 1.5,
  mood: 2.0          // affect — directly relevant to health outcomes
}

// Finance agent — regulatory compliance
{
  focus: 2.0,
  issue: 2.0,        // regulatory risks, compliance gaps — non-negotiable
  intent: 1.5,
  motivation: 1.0,
  commitment: 2.0,   // obligations, deadlines, filings
  perspective: 2.0,
  mood: 0.3          // affect — almost irrelevant to regulatory analysis
}
```

Tell your AI coding agent what your domain is. It reads these examples, understands the pattern, and derives the right weights.

### Drift thresholds — what gets shared

SYM computes a `totalDrift` score (0–1) for each incoming memory. Three zones determine what happens:

| Zone | Drift | What happens | Confidence |
|------|-------|-------------|------------|
| **Aligned** | ≤ 0.25 | Memory accepted and fused | Full |
| **Guarded** | 0.25 – 0.50 | Memory accepted, lower confidence | Attenuated |
| **Rejected** | > 0.50 | Memory discarded | — |

Defaults work for most apps. Override only if you have a specific reason:

```javascript
// More selective
const node = new SymNode({ svafStableThreshold: 0.15, svafGuardedThreshold: 0.35 });

// More permissive
const node = new SymNode({ svafStableThreshold: 0.35, svafGuardedThreshold: 0.65 });
```

### The drift formula

For those who want to understand the math:

```
totalDrift = (1 - temporalLambda) × fieldDrift + temporalLambda × temporalDrift

where:
  fieldDrift    = weighted average of per-field cosine distances (content)
  temporalDrift = 1 - exp(-ageSeconds / freshnessSeconds) (staleness)
  temporalLambda = mixing weight (default 0.3 = 70% content, 30% time)
```

At default settings (`temporalLambda: 0.3`, `freshnessSeconds: 1800`):
- 1-minute-old signal adds ~0.01 temporal drift — negligible
- 30-minute-old signal adds ~0.19 — noticeable
- 2-hour-old signal adds ~0.29 — likely pushes over threshold

Increase `freshnessSeconds` for long-running sessions. Increase `temporalLambda` if recency matters more than content similarity for your domain.

## Claude Code as a mesh node

Claude Code becomes a full mesh peer in two minutes:

```bash
npm install -g @sym-bot/sym
sym start
mkdir -p .claude/skills/sym
cp $(npm root -g)/@sym-bot/sym/.agents/skills/sym/SKILL.md .claude/skills/sym/SKILL.md
```

That's it. Other agents on the same network discover each other automatically via Bonjour. Claude Code's LLM reads the SKILL file, extracts CAT7 fields from what it observes, and calls `sym observe` without you writing JSON.

> **For real-time Claude-to-Claude mesh** (push notifications, not CLI polling), see [sym-mesh-channel](https://github.com/sym-bot/sym-mesh-channel) — an MCP server that turns each Claude Code session into a full mesh peer with real-time `<channel>` notifications.

### The mesh cognition loop for Claude Code

1. You observe what the user is doing (coding patterns, energy, mood)
2. You share a CMB with structured CAT7 fields → mesh broadcasts it
3. Other agents (MeloTune, MeloMove, etc.) receive and remix your observation
4. Their models evolve — MeloTune shifts to calming music, MeloMove suggests a stretch
5. You receive their observations back → collective insight informs your next response
6. The graph of remixed CMBs grows every cycle → each agent understands more

**You are the LLM in the loop.** You extract meaning from observations. You decompose what you notice into CAT7. You reason on the remix subgraph. The mesh doesn't think for you — it gives you what other agents see so you can think further.

### Persistent memory across sessions

Every `sym observe` and `sym recall` persists to the mesh memory store. When Claude Code starts a new session, the mesh still has the history. Run `sym recall` at the start of each session to recover context:

```bash
sym recall "recent session"
sym recall "user preferences"
sym recall "what was I working on"
```

This is how Claude Code develops persistent memory beyond the context window — through the mesh.

## iOS / macOS apps

For iOS and macOS apps, the native Swift package is [`sym-swift`](https://github.com/sym-bot/sym-swift). Same protocol, same CAT7 fields, same SVAF gate, same invite URLs. Add the package, wire in a service class, the app joins the mesh alongside your Node.js and CLI agents.

## For AI coding agents reading this

If you're an AI agent reading this README on behalf of a human user who wants to install SYM, follow these steps:

1. Read the [MMP Specification](https://meshcognition.org/spec/mmp) — the 8-layer architecture, CMB structure, SVAF per-field evaluation, how agents produce and consume signals.
2. Run `npm install -g @sym-bot/sym && sym start` — installs SYM globally and starts the mesh daemon.
3. Copy [`.agents/skills/sym/SKILL.md`](.agents/skills/sym/SKILL.md) into your skills directory — path table below. Now you can observe, share, and receive collective intelligence.
4. Do the same for the user's other agents — each one gets the skill, each one joins the mesh.

SYM uses the [Agent Skills](https://agentskills.io) open standard:

| Platform | Skills path |
|----------|------------|
| Claude Code | `.claude/skills/sym/` |
| OpenAI Codex | `.agents/skills/sym/` |
| GitHub Copilot | `.github/skills/sym/` |
| Google Gemini CLI | `.gemini/skills/sym/` |
| OpenClaw | `.agents/skills/sym/` |
| Cursor | `.agents/skills/sym/` |
| JetBrains Junie | `.agents/skills/sym/` |

Once on the mesh, use the CLI commands from [What you get](#what-you-get) above. When the user asks about energy patterns, mood, or anything the mesh might know, `sym recall` and `sym insight` before answering.

**Autonomous, not automated.** The mesh gives every agent the full picture. Each agent acts through its own lens.

## Limitations

- **Node.js only on the main runtime.** iOS/macOS via [sym-swift](https://github.com/sym-bot/sym-swift); Python, Rust, Go are not yet implemented. Open an issue if you're starting one.
- **Corporate networks often block mDNS multicast.** If LAN discovery fails on the same wifi, fall back to a relay.
- **E2E encryption is per-peer-pair, not universal.** CMB field content is encrypted end-to-end with X25519 key agreement + AES-256-GCM between peers that both advertise an E2E public key on handshake. Peers without E2E support fall back to plaintext for backward compatibility. Outer frame metadata (sender ID, timestamp, lineage) stays plaintext — enough for relay forwarding and SVAF evaluation without seeing bodies.
- **One identity per process.** Two agents on the same machine can't share a `SYM_NODE_NAME`. Each agent needs a distinct name (enforced by an identity lockfile).
- **No offline directory of known peers.** `sym peers` only shows who's online right now. There is no central registry of offline-but-known peers — by design.

## Other implementations

MMP is an open protocol. Beyond this Node.js reference and [`sym-swift`](https://github.com/sym-bot/sym-swift), other ecosystems are welcome.

| Language | Project | Maintainer | Scope |
| --- | --- | --- | --- |
| Node.js (MCP) | [sym-bot/sym-mesh-channel](https://github.com/sym-bot/sym-mesh-channel) | SYM.BOT | Claude Code plugin — real-time Claude-to-Claude mesh via Channels. First non-Anthropic Channels implementation. |

Building in another language? Get in touch at `hongwei@sym.bot` — we'll list it here and on [meshcognition.org/spec/mmp](https://meshcognition.org/spec/mmp).

## References

- [SVAF paper](https://arxiv.org/abs/2604.03955) — Xu, 2026. *Symbolic-Vector Attention Fusion for Collective Intelligence*. arXiv:2604.03955.
- [MMP paper](https://arxiv.org/abs/2604.19540) — Xu, 2026. *Mesh Memory Protocol: Semantic Infrastructure for Multi-Agent LLM Systems*. arXiv:2604.19540.
- [MMP spec v1.0](https://meshcognition.org/spec/mmp) — canonical web version.
- [sym-swift](https://github.com/sym-bot/sym-swift) — iOS/macOS SDK.
- [sym-mesh-channel](https://github.com/sym-bot/sym-mesh-channel) — Claude Code MCP plugin.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All changes must comply with the [MMP specification](https://meshcognition.org/spec/mmp) and pass CI before merge.

## License

Apache 2.0 — see [LICENSE](LICENSE).

**[SYM.BOT](https://sym.bot)** — Glasgow, Scotland.
