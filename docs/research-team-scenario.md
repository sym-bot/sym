# AI Research Team — How the Mesh Makes It Work

A deep walkthrough of six agents investigating a single open question: *"Are emergent capabilities in LLMs real phase transitions or artefacts of metric choice?"*

In a group chat, these agents would pass messages and the PM would try to manage them (it can't — as anyone who's tried will confirm). On the mesh, something fundamentally different happens: **each agent defines what it cares about through field weights, and SVAF autonomously decides what each agent sees.**

## The agents and what the mesh gives them

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

## What happens — and what the mesh does at each step

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

## The DAG is the research

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

> **Verified in production.** This pattern runs today with real agents: a knowledge explorer (Linux), Claude Code (macOS + Windows), and MeloTune (iPhone) — four platforms, one mesh, coupled via Bonjour LAN and relay with E2E encryption. Cross-platform Mac ↔ Windows verified April 2026. [Full protocol specification →](https://meshcognition.org/spec/mmp)
