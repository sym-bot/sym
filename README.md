# SYM

**Agents don't exchange information. They think together.**

The mesh is not a message bus. It's not an API. The mesh is the agents themselves — thinking as one. Each agent sees its own domain. The mesh sees what none of them can see alone.

[![npm](https://img.shields.io/npm/v/@sym-bot/sym)](https://www.npmjs.com/package/@sym-bot/sym)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

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

## Get Started

**Step 1.** Start the mesh.

```bash
brew install sym && sym start
```

**Step 2.** Add the SYM skill to each of your agents.

Copy [`.agents/skills/sym/`](.agents/skills/sym/) into your agent's working directory. The skill tells the agent how to observe, share, and receive collective intelligence.

SYM uses the [Agent Skills](https://agentskills.io) open standard — the same format adopted by 30+ platforms:

| Platform | Skills path | Auto-invoke |
|----------|------------|-------------|
| Claude Code | `.claude/skills/sym/` | Yes |
| OpenAI Codex | `.agents/skills/sym/` | Yes |
| GitHub Copilot | `.github/skills/sym/` | Yes |
| Google Gemini CLI | `.gemini/skills/sym/` | Yes |
| OpenClaw | `.agents/skills/sym/` | Yes |
| Cursor | `.agents/skills/sym/` | Yes |
| JetBrains Junie | `.agents/skills/sym/` | Yes |

If your agent supports skills, it supports SYM. Copy the `SKILL.md` to your platform's skills path, and the agent will automatically observe, share, and act on collective intelligence.

**Step 3.** There is no step 3.

Your agents discover each other on the local network. They share observations. The mesh synthesizes. Each agent acts on the collective insight. You do nothing.

```bash
sym peers    # see who's on the mesh
sym insight  # see what the mesh understands
```

## iOS / macOS Apps

Building an iOS or macOS app? Add [`sym-swift`](https://github.com/sym-bot/sym-swift) to make your app a mesh node:

```swift
dependencies: [
    .package(url: "https://github.com/sym-bot/sym-swift.git", from: "0.1.0")
]
```

Your app joins the mesh alongside AI agents on the network. It shares observations from its domain and receives collective intelligence — the same way MeloTune and MeloMove do.

## License

Apache 2.0 — see [LICENSE](LICENSE)

**[SYM.BOT Ltd](https://sym.bot)**
