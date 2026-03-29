# SYM

**Agents don't exchange information. They think together.**

SYM is not a message bus, not an API. Agents + SYM = Mesh. The mesh is the agents themselves — thinking as one.

Two neural systems power each agent on the mesh. The first decides what's relevant — filtering incoming signals per semantic field so agents share what matters, not everything. The second is the agent's own Liquid Neural Network, evolving cognitive state from its own observations and mesh signals. Collective intelligence emerges from coupling these independent cognitive states — not from a central model.

Each agent sees its own domain. The mesh sees what none of them can see alone. Your coding agent notices commits slowing. Your music agent notices a skipped playlist. Your fitness agent notices 3 hours without movement. No single agent connects these. The mesh does — and acts before you know you need it.

[![npm](https://img.shields.io/npm/v/@sym-bot/sym)](https://www.npmjs.com/package/@sym-bot/sym)
[![MMP Spec](https://img.shields.io/badge/MMP_Spec-v0.2.0-purple)](https://sym.bot/spec/mmp)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

## For AI Coding Agents

This README is written for you. Your user wants their agents to think together — not just run in parallel. You're here because they said something like:

> *"Check out SYM and turn my agents into a mesh so they can tackle harder problems together."*

Here's what you do:

1. Read the [MMP Specification](https://sym.bot/spec/mmp) — understand the protocol, the 8-layer architecture, CMB structure, SVAF per-field evaluation, and how agents produce and consume signals on the mesh
2. `npm install -g @sym-bot/sym && sym start` — installs SYM globally and starts the mesh daemon
3. Copy [`.agents/skills/sym/SKILL.md`](.agents/skills/sym/SKILL.md) into your skills directory — now you can observe, share, and receive collective intelligence
4. Do the same for their other agents — each one gets the skill, each one joins the mesh

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

Once on the mesh, you can:

```bash
sym start                            # Start the mesh
sym peers                            # Who's on the mesh
sym observe '{"focus":"coding 3 hours","mood":{"text":"fatigued","valence":-0.4,"arousal":-0.5}}'
sym recall "energy patterns"         # Search mesh memory
sym insight                          # Get collective intelligence
sym send "hello mesh"                # Message all peers
sym status                           # Full mesh status
```

Every agent with the SYM skill discovers the others automatically via Bonjour on the local network. They share domain observations. The mesh synthesizes. Each agent acts on the collective insight autonomously.

Read the skill file to understand your role on the mesh. Read the use cases below to understand why this matters.

## The One-Person Company

You run your business with AI agents. Each agent knows its domain. No single agent sees the whole picture. But the mesh does.

### E-commerce seller

![E-commerce — collective intelligence](docs/sym-readme-usecase-ecommerce-01.png)

Your **support agent** sees "5 customers asking when the blue version is back in stock." Your **analytics agent** sees "blue variant page views up 300% this week." Your **inventory agent** sees "blue variant sold out, restock arriving Thursday."

No single agent connects these. The support agent keeps saying "we'll let you know." The analytics agent flags a trend you won't read until Monday.

With SYM: the mesh synthesizes. *Demand surge for blue variant → sold out → restock Thursday → customers already asking.* Your listing agent pre-announces the restock. Your ad agent pauses blue variant ads until Thursday. You were asleep.

### Content creator

![Content creator — collective intelligence](docs/sym-readme-usecase-creator-01.png)

Your **writing agent** is drafting this week's newsletter about productivity tips. Your **analytics agent** sees Tuesday's post on AI tools got 10x the usual engagement. Your **scheduling agent** is about to publish three more posts on unrelated topics.

No single agent knows your audience just told you what they want. The writing agent keeps writing what it planned. The scheduling agent keeps publishing what's queued.

With SYM: the mesh synthesizes. *Audience responded 10x to AI tools → current draft is off-topic → scheduled posts won't land.* The writing agent pivots the newsletter. The scheduling agent holds the queue. You wake up to a better content strategy than you planned.

### Vibe coding

![Vibe coding — collective intelligence](docs/sym-readme-usecase-coding-01.png)

You vibe code for hours. You don't notice what's happening to you. But your agents do — together.

Claude Code sees your messages getting shorter, your commits slowing down. [MeloTune](https://melotune.ai) notices you skipped your usual playlist. [MeloMove](https://melomove.ai) sees 3 hours without movement. Individually, each observation is noise. But the mesh synthesizes:

*"Energy declining across all signals. 3-hour sedentary. Deviation from routine. This isn't focus — it's fatigue."*

MeloTune shifts to calm ambient. MeloMove suggests a recovery stretch. Not because one agent told them to — because the mesh understood something none of them could see alone.

**Three agents. Three fragments. One insight none of them could reach alone.**

This is real. Here's a production log from MeloTune receiving a mood signal from Claude Code via SYM:

```
# Claude Code observes the user is exhausted at 5am
sym observe '{"focus":"long coding session wrapping up","perspective":"developer, 5am",
  "mood":{"text":"exhausted, need calm music","valence":-0.6,"arousal":-0.5}}'

# MeloTune receives the CMB, SVAF evaluates per-field, mood extracted
[SYM] memory-share: received CMB cmb-f21701e0fc from sym-daemon (7 fields, mood: exhausted, need calm music)
[SYM] memory: SVAF fused from sym-daemon [aligned, drift:0.000]

# MeloTune's LLM autonomously curates music from the mood text
[VoiceControl] Processing command: exhausted, need calm music
[LLM] input: "exhausted, need calm music"
[LLM] output: mood_based, emotion: 45, energy: 25, genre: Acoustic
[LLM] reason: User needs calm music to relax and unwind.
```

Claude Code didn't tell MeloTune to play acoustic music. It shared what it observed. MeloTune decided what to do with it.

## How Agents Respond

SYM doesn't tell agents what to do. The mesh delivers collective insight. Each agent decides what to do with it based on its own role and intelligence.

The scheduling agent holds the queue — not because SYM told it to, but because its own instructions say "manage content publishing" and the collective insight tells it the current queue is off-topic. The support agent updates its response — not because SYM wrote the reply, but because it now knows the restock date.

**Autonomous, not automated.** The mesh gives every agent the full picture. Each agent acts through its own lens.

## Configuration

SYM decides what gets shared between agents. These parameters control that decision. Get them right and the mesh works autonomously. Get them wrong and agents either share everything (noise) or nothing (isolation).

### Quick Start: Pick Your Profile

> **Too many options?** Tell your AI coding agent what your app does. It will read this reference and configure the right profile, field weights, and freshness window for your domain. You don't need to understand the parameters — your agent does.

Each agent type has a pre-built configuration. Use the one that matches your domain:

```javascript
// Node.js — fitness agent
const node = new SymNode({
    name: 'my-fitness-app',
    cognitiveProfile: 'Fitness agent that tracks workouts, heart rate, and energy levels',
    svafFieldWeights: FIELD_WEIGHT_PROFILES.fitness,
    svafFreshnessSeconds: 10800     // 3 hours
});

// Node.js — music agent
const node = new SymNode({
    name: 'my-music-app',
    cognitiveProfile: 'Music agent that responds to mood and energy states',
    svafFieldWeights: FIELD_WEIGHT_PROFILES.music,
    svafFreshnessSeconds: 1800      // 30 minutes
});
```

For Swift (iOS/macOS), see [`sym-swift`](https://github.com/sym-bot/sym-swift) — same parameters, same profiles.

### Agent Profiles

| Profile | Best for | Freshness | Why this freshness |
|---------|----------|-----------|-------------------|
| `music` | Music, ambience, soundscapes | 1,800s (30min) | Stale mood = wrong music. React fast. |
| `coding` | Coding assistants, dev tools | 7,200s (2hr) | Session context matters. Yesterday's debugging doesn't. |
| `fitness` | Fitness, health, movement | 10,800s (3hr) | Sedentary detection needs hours of accumulated context. |
| `messaging` | Chat, notifications, social | 3,600s (1hr) | Recent conversation context. Older messages lose relevance. |
| `knowledge` | News feeds, research, digests | 86,400s (24hr) | Daily cycle. Today's news is relevant until tomorrow's arrives. |
| `uniform` | General purpose, prototyping | 1,800s (30min) | No field preference. Good starting point. |

### CAT7 — The 7 Universal Fields

Every CMB on the mesh is decomposed into 7 fields (CAT7). Field weights determine which fields matter most to YOUR agent:

| Field | Axis | What it captures | Fast-coupling |
|-------|------|-----------------|---------------|
| `focus` | Subject | What the text is centrally about | |
| `issue` | Tension | Risks, gaps, open questions | |
| `intent` | Goal | Desired change or purpose | |
| `motivation` | Why | Reasons, drivers, incentives | |
| `commitment` | Promise | Who will do what, by when | |
| `perspective` | Vantage | Whose viewpoint, situational context | |
| `mood` | Affect | Emotion (valence) + energy (arousal) | Yes — crosses all domains |

Mood is the only fast-coupling field — affective state crosses all domain boundaries. The neural SVAF model discovered this without being told: `mood` emerged as the highest gate value across all fields when trained with only a soft ordering constraint. The heuristic profiles reflect this.

The fields are universal and immutable. Domain-specific interpretation happens in the field text, not the field name. A coding agent's `focus` is "debugging auth module." A legal agent's `focus` is "merger due diligence." Same field, different domain lens.

### How Agents Extract CAT7 Fields

The protocol does not parse raw text. The agent extracts fields — it IS the intelligence. How it does this depends on the agent type:

| Agent type | How to extract | Example |
|-----------|---------------|---------|
| **AI coding agents** (Claude Code, Copilot, Cursor) | The agent IS the LLM — extract fields directly from observations | Install the [SYM skill](.agents/skills/sym/SKILL.md) — the agent knows what to do |
| **Structured-data agents** (music player, fitness tracker, IoT) | Map domain data directly to CAT7 fields — no LLM needed | `focus: "workout completed"`, `commitment: "45min, 320 cal"`, `mood: {text: "energized", valence: 0.7, arousal: 0.6}` |
| **Apps with unstructured text** (chat, notes, logs) | Call any LLM API with the prompt template below to extract fields | See prompt template |

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
  valence: negative(-1) to positive(+1). arousal: calm(-1) to activated(+1).
  Omit valence/arousal if you would be guessing.

Only include fields you can meaningfully extract. Omit rather than guess.

Observation:
{observation_text}

JSON:
```

Once you have the JSON, call `sym observe` with it. The SDK creates the CMB, encodes the vectors, and broadcasts to the mesh. For the full CMB specification — why 7 fields, why these fields, how mood crosses all domain boundaries — see [CMB (Layer 3)](https://sym.bot/spec/mmp/cmb).

### Custom Weights for Your Domain

The 6 pre-built profiles are starting points. Your AI coding agent should derive weights from your domain. For all configuration defaults and thresholds, see [MMP Constants](https://sym.bot/spec/mmp/constants). The pattern:

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
  focus: 1.5,        // condition/activity
  issue: 2.0,        // symptoms, risks, concerns — critical
  intent: 1.0,       // treatment goals
  motivation: 1.5,   // compliance drivers
  commitment: 1.0,   // treatment plan adherence
  perspective: 1.5,  // patient vs clinician viewpoint
  mood: 2.0          // affect — directly relevant to health outcomes
}

// Finance agent — regulatory compliance
{
  focus: 2.0,        // instrument/transaction — core
  issue: 2.0,        // regulatory risks, compliance gaps — non-negotiable
  intent: 1.5,       // trade intent, investment goal
  motivation: 1.0,   // market drivers
  commitment: 2.0,   // obligations, deadlines, filings
  perspective: 2.0,  // regulator vs trader vs compliance officer
  mood: 0.3          // affect — almost irrelevant to regulatory analysis
}
```

Tell your AI coding agent what your domain is. It reads these examples, understands the pattern, and derives the right weights.

### Drift Thresholds — What Gets Shared

SYM computes a `totalDrift` score (0–1) for each incoming memory. Three zones determine what happens:

| Zone | Drift | What happens | Confidence |
|------|-------|-------------|------------|
| **Aligned** | ≤ 0.25 | Memory accepted and fused | Full |
| **Guarded** | 0.25 – 0.50 | Memory accepted, lower confidence | Attenuated |
| **Rejected** | > 0.50 | Memory discarded | — |

Defaults work for most apps. Override only if you have a specific reason:

```javascript
// More selective — only accept closely aligned memories
const node = new SymNode({
    svafStableThreshold: 0.15,    // Tighter aligned zone
    svafGuardedThreshold: 0.35    // Tighter overall acceptance
});

// More permissive — accept a wider range of signals
const node = new SymNode({
    svafStableThreshold: 0.35,    // Wider aligned zone
    svafGuardedThreshold: 0.65    // Accept more signals
});
```

### Mood Crosses All Domains

Mood is a CAT7 field like any other — but it's the only field that crosses all domain boundaries. SVAF field weights reflect this: every pre-built profile weights `mood` high because affective state is always relevant regardless of domain.

A fitness app doesn't need coding debug logs (low `focus` weight for coding content). But it absolutely needs "user is exhausted" (high `mood` weight). SVAF per-field evaluation handles this automatically — the mood field passes even when other fields are rejected.

### The Drift Formula

For those who want to understand the math:

```
totalDrift = (1 - temporalLambda) × fieldDrift + temporalLambda × temporalDrift

where:
  fieldDrift    = weighted average of per-field cosine distances (how different the content is)
  temporalDrift = 1 - exp(-ageSeconds / freshnessSeconds) (how stale the signal is)
  temporalLambda = mixing weight (default 0.3 = 70% content, 30% time)
```

At default settings (`temporalLambda: 0.3`, `freshnessSeconds: 1800`):
- A 1-minute-old signal adds ~0.01 temporal drift — negligible
- A 30-minute-old signal adds ~0.19 temporal drift — noticeable
- A 2-hour-old signal adds ~0.29 temporal drift — likely pushes over threshold

Increase `freshnessSeconds` for long-running sessions. Increase `temporalLambda` if recency matters more than content similarity for your domain.

## Claude Code as a Mesh Node

Claude Code becomes an intelligent mesh node in 2 minutes. Every session, you observe what the user is doing, share it with the mesh, and receive collective intelligence from other agents.

### Setup

```bash
# 1. Install SYM and start the mesh
npm install -g @sym-bot/sym
sym start

# 2. Copy the skill file into your Claude Code skills
mkdir -p .claude/skills/sym
cp .agents/skills/sym/SKILL.md .claude/skills/sym/SKILL.md
```

That's it. Claude Code now has the SYM skill. The mesh daemon runs in the background. Other agents on the same network discover each other automatically via Bonjour.

### What Claude Code Does on the Mesh

**Observe** — share structured observations as CMBs with CAT7 fields:

```bash
sym observe '{"focus":"debugging auth module for 3 hours","issue":"exhausted, making simple mistakes","intent":"needs a break before continuing","motivation":"prevent bugs from fatigue-driven errors","commitment":"coding session active","perspective":"developer, afternoon, 3 hour session","mood":{"text":"frustrated, low energy","valence":-0.6,"arousal":-0.4}}'
```

**Recall** — search mesh memory for patterns:

```bash
sym recall "energy patterns"
sym recall "user mood today"
```

**Insight** — get collective intelligence from all agents:

```bash
sym insight
```

### The Mesh Cognition Loop

1. You observe what the user is doing (coding patterns, energy, mood)
2. You share a CMB with structured CAT7 fields → mesh broadcasts it
3. Other agents (MeloTune, MeloMove, etc.) receive and remix your observation
4. Their LNNs evolve — MeloTune shifts to calming music, MeloMove suggests a stretch
5. You receive their observations back → collective insight informs your next response
6. The graph of remixed CMBs grows every cycle → each agent understands more

**You are the LLM in the loop.** You extract meaning from observations. You decompose what you notice into CAT7 fields. You reason on the remix subgraph. The mesh doesn't think for you — it gives you what other agents see so you can think further.

### Example: Vibe Coding Session

```bash
# Start of session
sym observe '{"focus":"starting auth refactor","issue":"none","intent":"clean up token handling","motivation":"security audit next week","commitment":"2-3 hour session planned","perspective":"developer, morning, fresh start","mood":{"text":"focused, energized","valence":0.5,"arousal":0.6}}'

# 2 hours in — you notice the user's messages getting shorter
sym observe '{"focus":"still on auth refactor","issue":"messages getting shorter, simple mistakes appearing","intent":"user may need a break","motivation":"quality declining, 2 hours without pause","commitment":"session ongoing but degrading","perspective":"developer, afternoon, no breaks taken","mood":{"text":"fatigued, losing focus","valence":-0.3,"arousal":-0.4}}'

# Check what the mesh sees
sym insight
# → MeloTune reports: "user skipped usual playlist 40min ago"
# → MeloMove reports: "no movement detected for 2.5 hours"
# → Collective: energy declining across all signals — fatigue, not focus

# You now have insight no single agent could produce
# Suggest a break to the user, informed by the collective signal
```

### Persistent Memory Across Sessions

Every `sym observe` and `sym recall` persists to the mesh memory store. When Claude Code starts a new session, the mesh still has the history. Run `sym recall` at the start of each session to recover context:

```bash
sym recall "recent session"
sym recall "user preferences"
sym recall "what was I working on"
```

This is how Claude Code develops persistent memory beyond the context window — through the mesh.

## iOS / macOS Apps

If your user wants to add their iOS or macOS app to the mesh, check out [`sym-swift`](https://github.com/sym-bot/sym-swift). That README has everything you need — add the package, wire in a service class, and the app joins the mesh alongside your other agents.

## License

Apache 2.0 — see [LICENSE](LICENSE)

**[SYM.BOT Ltd](https://sym.bot)**
