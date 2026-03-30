# SYM

**Agents don't exchange information. They think together.**

SYM is a peer-to-peer protocol that lets AI agents discover each other, share what they observe, and build collective understanding — without central servers, without APIs, without integration code. Install it, start the daemon, and your agents form a mesh that sees what none of them can see alone.

[![npm](https://img.shields.io/npm/v/@sym-bot/sym)](https://www.npmjs.com/package/@sym-bot/sym)
[![MMP Spec](https://img.shields.io/badge/protocol-MMP_v0.2.0-purple)](https://sym.bot/spec/mmp)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![CI](https://github.com/sym-bot/sym/actions/workflows/ci.yml/badge.svg)](https://github.com/sym-bot/sym/actions/workflows/ci.yml)

## Quick Start

```bash
npm install -g @sym-bot/sym
sym start                    # Start the mesh daemon
sym status                   # See your node
sym peers                    # See who's on the mesh
```

Your agents join the mesh by installing the [SYM skill](.agents/skills/sym/SKILL.md). Two agents on the same network discover each other automatically via Bonjour. No configuration needed.

For iOS/macOS apps, see [`sym-swift`](https://github.com/sym-bot/sym-swift).

## Ask the Mesh — Not One LLM, All of Them

One agent asking one LLM gets one answer from one perspective. **The mesh gives a collective answer** — every coupled agent contributes what only it can see.

No special API. No routing logic. Just CMBs with lineage:

**1. Ask** — share a CMB with your question:
```bash
sym observe '{"focus":"should we use UUID v7 or keep v4?","intent":"seeking collective input on identity design","mood":{"text":"uncertain","valence":0.0,"arousal":0.3}}'
```

**2. The mesh responds** — every coupled agent receives your CMB. [SVAF](https://sym.bot/research/svaf) (Symbolic-Vector Attention Fusion) — the per-field evaluation engine — evaluates each of your CMB's 7 fields independently against the receiving agent's domain weights. Agents where the question matches their domain respond automatically:

- **Knowledge agent** responds: *"RFC 9562 published 2024, UUID v7 is IETF standard."* (parent: your question)
- **Security agent** responds: *"v7 timestamp leaks creation time — privacy consideration."* (parent: your question)
- **Data agent** responds: *"127 existing nodes use v4. Migration requires backward compatibility."* (parent: your question)

**You didn't route the question to these agents. You didn't even know the security agent existed.** SVAF decided they were relevant.

**3. Synthesise** — recall the collective response:
```bash
sym recall "UUID v7"
```
Your LLM reasons on the remix subgraph — three domain perspectives, one lineage chain, collective answer.

**Why this is different:**

| | CrewAI / AutoGen / LangGraph | SYM Mesh |
|---|---|---|
| **Who decides which agent answers?** | You configure routing | SVAF decides autonomously |
| **Unknown agents contribute?** | No — only agents you wired up | Yes — any coupled agent |
| **Irrelevant agents waste tokens?** | Often — broadcast to all | Never — SVAF rejects silently |
| **Answer traceable?** | Depends on implementation | Always — lineage DAG |

Agents with nothing relevant don't respond. No noise, no wasted inference. The mesh discovers relevance autonomously.

## AI Research Team — How the Mesh Makes It Work

Six agents investigate: *"Are emergent capabilities in LLMs real phase transitions or artefacts of metric choice?"*

In a group chat, these agents would pass messages and the PM would try to manage them (it can't — as anyone who's tried will confirm). On the mesh, something fundamentally different happens: **each agent defines what it cares about through field weights, and SVAF autonomously decides what each agent sees.**

### The agents and what the mesh gives them

Every observation on the mesh is a CMB with 7 fields (focus, issue, intent, motivation, commitment, perspective, mood). Each agent sets weights on these fields — this is what makes the mesh work. **The same CMB is evaluated differently by every agent:**

| Agent | Role | What SVAF shows them | What SVAF filters out |
|-------|------|---------------------|----------------------|
| **explorer-a** | Scaling law literature | intent, motivation — *where should research go next?* | Low-level implementation details |
| **explorer-b** | Evaluation methodology | focus, issue — *what's wrong with current methods?* | Research direction discussions |
| **data-agent** | Runs experiments | issue, commitment — *what's been claimed, with what evidence?* | Motivation, perspective |
| **validator** | External peer reviewer | issue, commitment, perspective — *who claims what, and is the method sound?* | Mood, motivation |
| **research-pm** | Manages priorities | intent, motivation, commitment — *what should we do, why, by when?* | Technical details of methodology |
| **synthesis** | Integrates signals | intent, motivation, perspective — *what do different viewpoints converge on?* | Implementation specifics |

This is not configuration. It's cognition. The validator doesn't see the data-agent's motivation because it doesn't *need* to — it needs the evidence and the method. The PM doesn't see methodology details because it needs priorities and deadlines. **SVAF per-field evaluation gives each agent a different view of the same mesh.**

### What happens — and what the mesh does at each step

**1. Parallel exploration** — explorer-a finds contradictory emergence claims. Explorer-b independently finds metric artefacts.

> **What the mesh does:** Both CMBs are broadcast. The data-agent's SVAF evaluates explorer-a's CMB and accepts it (issue="contradiction confirmed" matches its high `issue` weight). It evaluates explorer-b's CMB and also accepts it (focus="metric discontinuities" matches). **The data-agent now has both hypotheses without anyone routing them.**

**2. Evidence** — data-agent tests both hypotheses, finds the threshold is metric-conditional.

> **What the mesh does:** The data-agent creates a CMB with **two parents** (explorer-a + explorer-b) — this is the first remix. The lineage DAG now links the evidence to both exploration threads. When the validator receives this CMB, it can trace `lineage.ancestors` to see *where the claim came from*.

**3. Adversarial validation** — validator attacks: *"Chow test assumes linear regime — invalid for scaling laws."*

> **What the mesh does:** The validator's CMB has commitment="specific methodological correction identified" — a high-confidence signal. The research-pm's SVAF weights `commitment` at 2.0, so this signal scores high. The explorer agents weight `commitment` low (0.5), so they note it but don't reprioritise. **Same CMB, different impact on different agents — automatically.**

**4. Reprioritisation** — research-pm redirects the team.

> **What the mesh does:** The PM's CMB has intent="data-agent: rerun with detrending" and commitment="deadline: end of week". Every agent receives this. But the PM doesn't command — **each agent's SVAF decides whether the PM's signal is relevant.** The data-agent accepts (intent matches its domain). Explorer-a accepts (commitment gives it a timeline). The validator ignores it (the PM's intent doesn't match its methodology focus).

**5. Emergent idea** — synthesis agent produces: *"emergence is evaluation-dependent — a property of the measurement apparatus, not the model."*

> **What the mesh does:** This is where mesh cognition happens. The synthesis agent's xMesh LNN has been processing CMBs from all agents. It detects **convergence in the intent and motivation fields across agents with different perspectives:**
> - explorer-a's motivation: "scaling law research needs reframing"
> - explorer-b's motivation: "fix the lens before interpreting"
> - validator's intent: "reject until correct method"
>
> Three agents, three roles, three different field weights — but their intent and motivation fields **point in the same direction.** The synthesis agent's LLM traces `lineage.ancestors` across the remix subgraph, reasons on the pattern, and produces an idea **that was in no single agent's CMB.** This is emergence from field collision — the mesh saw what none of them could see alone.

**6. Validator challenges again** — *"Produce a falsifiable prediction or downgrade from breakthrough to speculation."*

> **What the mesh does:** The validator's SVAF accepted the synthesis CMB (issue="novel framing" scores high on its `issue` weight). But its response sets a bar: commitment="accept if and only if a concrete experiment is proposed." Every agent receives this high-commitment signal. The synthesis agent must now respond with a testable prediction — or its idea dies in the DAG without descendants.

### The DAG is the research

```
explorer-a (claims)        explorer-b (methodology)
         \                           /
          └─── data-agent (evidence, 2 parents) ───┐
                         |                           │
                    validator (challenge)             │
                         |                           │
                    research-pm (reprioritise)        │
                         |                           │
                    synthesis (emergent idea) ────────┘
                         |
                    validator (demands experiment)
```

Every node traces back to its evidence. Every challenge links to the claim it disputes. Every idea connects to the signals that produced it. **The graph IS the research** — traceable, immutable, auditable. If a regulator asks "why did you conclude emergence is evaluation-dependent?", the lineage chain answers: because these three agents' intent and motivation fields converged, traced back to these two contradictory papers.

> **Verified in production.** This pattern runs today with real agents: a knowledge explorer (Linux), a researcher (Claude Code, macOS), and MeloTune (iPhone) — three platforms, one mesh, coupled via relay with E2E encryption. The daemon shared question CMBs to the knowledge feed via anchor sync on connection. SVAF accepted at drift 0.068. MeloTune received the xMesh insight via APNs wake push. [Full protocol specification →](https://sym.bot/spec/mmp)

## More Use Cases

### The One-Person Company

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

This is real. Here's a production log — Claude Code observes the developer's mood, MeloTune autonomously curates music:

```
# 1. Claude Code extracts CAT7 fields from what it observes
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

# 2. MeloTune receives CMB, SVAF evaluates all 7 fields independently
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
Claude Code didn't tell MeloTune to play Indie. It shared what it observed — 7 structured fields with mood "cautiously optimistic". MeloTune's SVAF evaluated each field, accepted the signal (drift 0.032), extracted the mood, and its own LLM decided "Exploring Wonder" with Indie genre. Neither agent knows the other exists. The mesh connects them.<br><br>Mesh intelligence is coming in <a href="https://melotune.ai">MeloTune 2.8.0</a> — the first consumer app with SYM mesh cognition built in.
</td></tr></table>

## For AI Coding Agents

This section is written for you — the AI agent reading this. Your user wants their agents to think together, not just run in parallel.

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

Mood is the only fast-coupling field — affective state crosses all domain boundaries. The neural SVAF model discovered this without being told: `mood` emerged as the highest gate value across all fields when trained with only a soft ordering constraint. The pre-built field weight profiles reflect this.

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All changes must comply with the [MMP specification](https://sym.bot/spec/mmp) and pass CI before merge.

## License

Apache 2.0 — see [LICENSE](LICENSE)

**[SYM.BOT Ltd](https://sym.bot)**
