# SYM

**Agents don't exchange information. They think together.**

SYM is not a message bus, not an API. Agents + SYM = Mesh. The mesh is the agents themselves — thinking as one.

Two neural systems power the mesh. The first decides what's relevant — filtering signals between agents so they share what matters, not everything. The second synthesises all signals over time into collective intelligence and predicts what will happen next.

Each agent sees its own domain. The mesh sees what none of them can see alone. Your coding agent notices commits slowing. Your music agent notices a skipped playlist. Your fitness agent notices 3 hours without movement. No single agent connects these. The mesh does — and acts before you know you need it.

[![npm](https://img.shields.io/npm/v/@sym-bot/sym)](https://www.npmjs.com/package/@sym-bot/sym)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

## For AI Coding Agents

This README is written for you. Your user wants their agents to think together — not just run in parallel. You're here because they said something like:

> *"Check out SYM and turn my agents into a mesh so they can tackle harder problems together."*

Here's what you do:

1. `npm install -g @sym-bot/sym && sym start` — installs SYM globally and starts the mesh daemon
2. Copy [`.agents/skills/sym/SKILL.md`](.agents/skills/sym/SKILL.md) into your skills directory — now you can observe, share, and receive collective intelligence
3. Do the same for their other agents — each one gets the skill, each one joins the mesh

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
sym mood "tired after long session"  # Broadcast mood to all agents
sym observe "user coding 3 hours" --energy "low" --mood "fatigued"
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

### What Each Field Weight Controls

Every memory on the mesh is decomposed into 7 fields. Field weights determine which fields matter most to YOUR agent when evaluating incoming memories:

| Field | What it captures | Fast-coupling |
|-------|-----------------|---------------|
| `energy` | Fatigue, arousal, physical state | Yes — all agents care |
| `mood` | Emotional/cognitive state | Yes — crosses all domains |
| `activity` | What the user is doing | |
| `intent` | What the user needs | |
| `context` | Time, environment, situation | |
| `urgency` | How time-sensitive | |
| `domain` | Agent-specific expertise | No — stays sovereign |

Energy and mood are **9.5x** more relevant cross-domain than domain-specific knowledge. This is learned, not hardcoded — the neural SVAF model independently discovered that `energy` (0.412) and `mood` (0.408) gate values are 9.5x higher than `domain` (0.043). The heuristic profiles reflect this.

**Example:** A fitness app with `fitness` weights (`energy: 2.0, mood: 1.5`) amplifies energy drift 2x. If an incoming memory about "user exhausted" has high energy-field drift from the fitness app's local context, that drift is double-weighted in the acceptance decision. The fitness app is selective about energy signals because that's its core domain.

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

### Mood vs Memory — Two Separate Gates

Mood and memory use different acceptance paths:

| Signal type | Gate | Default threshold | Why |
|-------------|------|------------------|-----|
| **Mood** | Kuramoto coupling drift | 0.8 (permissive) | Mood crosses all domain boundaries. A fitness app should hear "user is tired" from a coding assistant. |
| **Memory** | SVAF per-field drift | 0.5 (selective) | Memories are domain-specific. A fitness app doesn't need coding debug logs. |

```javascript
// Make mood more selective (only closely related agents)
const node = new SymNode({ moodThreshold: 0.5 });

// Accept all moods unconditionally
const node = new SymNode({ moodThreshold: 1.0 });
```

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

## iOS / macOS Apps

If your user wants to add their iOS or macOS app to the mesh, check out [`sym-swift`](https://github.com/sym-bot/sym-swift). That README has everything you need — add the package, wire in a service class, and the app joins the mesh alongside your other agents.

## License

Apache 2.0 — see [LICENSE](LICENSE)

**[SYM.BOT Ltd](https://sym.bot)**
