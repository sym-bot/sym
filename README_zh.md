<div align="center">

# SYM

### 问一个代理，得到一个答案。<br>问整个 _mesh_ —— 每个掌握相关知识的代理都会参与回答，凝聚成统一回复。

<p>
  <a href="https://www.npmjs.com/package/@sym-bot/sym"><img src="https://img.shields.io/npm/v/@sym-bot/sym" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License"></a>
  <a href="https://meshcognition.org/spec/mmp"><img src="https://img.shields.io/badge/protocol-MMP_v1.0-orange" alt="MMP Spec"></a>
  <a href="https://github.com/sym-bot/sym/actions/workflows/ci.yml"><img src="https://github.com/sym-bot/sym/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://arxiv.org/abs/2604.03955"><img src="https://img.shields.io/badge/arXiv-2604.03955-b31b1b.svg" alt="SVAF paper"></a>
  <a href="https://arxiv.org/abs/2604.19540"><img src="https://img.shields.io/badge/arXiv-2604.19540-b31b1b.svg" alt="MMP paper"></a>
  <a href="README.md"><img src="https://img.shields.io/badge/lang-English-blue" alt="English"></a>
</p>

**observe&nbsp; → &nbsp;向 mesh 提问&nbsp; → &nbsp;聚合带引用的答案&nbsp; → &nbsp;执行**

`npm install -g @sym-bot/sym`

**▸ [打开一页速览文档](https://htmlpreview.github.io/?https://github.com/sym-bot/sym/blob/main/docs/overview.html)**

</div>

> 你在代码库中运行 Claude Code，在编辑器中使用 Cursor，在 GitHub 上启用 Copilot，偶尔还跑几个脚本——每个工具只掌握局部信息，彼此之间无法共享。`sym ask` 能一次性将你的问题分发给所有代理：掌握相关知识的代理会贡献内容，无关的保持静默，最终你收到的是**一份融合多方信息、附带来源标注的综合答案**。无需路由配置，无需中心化编排器。

```bash
sym ask "我们应该使用 UUID v7 还是保留 v4 以保障向后兼容性？"
```

---

## SYM 是什么？

> **SYM 将你已在使用的所有 AI 代理整合为一个集体智能系统——让它们像同一个大脑一样协同作答，而非四个互不相通的独立个体。**

首先解释术语：**mesh（网状网络）** 指的是你所有代理之间直接互联的拓扑结构——代理与代理点对点通信，中间无中心服务器。每个代理运行 SYM 后即接入该 mesh。之所以称为 _mesh_，是因为每个代理都与其他代理直接通信，而非通过中心枢纽转发。

SYM 是实现这一能力的协议 + 命令行工具（CLI）。你只需在每台机器上安装一次。每个代理保留自身的用户界面、上下文窗口和任务职责——SYM 仅为它们提供共享的 mesh 用于读写通信。当某个代理获取新知识时，所有可能对该知识感兴趣的代理都会同步收到。当你执行 **`sym ask "<问题>"`** 时，问题会被广播至整个 mesh：掌握部分答案的代理会贡献内容，无关代理保持静默，最终你收到的是**一份统一答案**——即 mesh 以单一智能体的形式作答。

- ✅ 无中心服务器
- ✅ 无需维护路由规则
- ✅ 无需编排器决定通信顺序
- ✅ 每个代理自主判断接收到的信息是否与自身相关

> SYM 是 [Mesh Memory Protocol（MMP，网状记忆协议）](https://meshcognition.org/spec/mmp)的开源参考实现。如需支持**自主唤醒、自主调用任意模型的 LLM 对等节点**（无需宿主 IDE），请参阅 [`@sym-bot/xmesh-agent`](https://github.com/sym-bot/xmesh-agent)——基于相同 mesh 架构，构建于 SYM 之上。

---

## 为什么你需要 SYM？

你拥有四个 Copilot，却没有任何共享记忆。

- 你的客服代理不知道库存代理刚刚学到的补货信息
- 你的写作代理看不到分析代理一小时前统计的数据
- 你向 Claude Code 提问，它无法回答——而你甚至不知道另一个窗口中的代理其实掌握答案

每个代理都在"信息孤岛"中工作，而你被迫成为集成层：在不同窗口间复制粘贴上下文、手动路由问题、记忆每个代理的知识边界。

传统解决方案是将代理通过框架、路由图或可配置的编排器连接起来。但这意味着你需要为每对代理编写集成代码，且只能连接你预先规划好的代理。

**SYM 彻底消除"连线"成本**。代理通过共享 mesh 通信，并基于相关性自主筛选信息。即使是你忘记存在的代理，也可能参与回答；没有贡献的代理不会产生任何开销。你不再需要充当人工集成层。

---

## 如何使用 SYM？

### 1️⃣ 安装

```bash
npm install -g @sym-bot/sym
```

这就是全部安装步骤。单机环境下无需启动任何守护进程——代理通过本机内存存储共享信息，`observe` 负责写入，`ask` 负责跨代理读取。（如需跨设备构建 _实时 mesh_？每个设备运行一个节点即可——执行 `sym start`。详见下文"工作原理"。）

### 2️⃣ 为每个代理配置技能（Skill）

技能是一个简短的 Markdown 文件，用于教会任何基于 LLM 的代理如何使用 SYM。将其复制到对应代理的技能目录中：

```bash
# Claude Code:
mkdir -p .claude/skills/sym && cp $(npm root -g)/@sym-bot/sym/.agents/skills/sym/SKILL.md .claude/skills/sym/

# Cursor / Codex / JetBrains Junie / 通用代理:
mkdir -p .agents/skills/sym && cp $(npm root -g)/@sym-bot/sym/.agents/skills/sym/SKILL.md .agents/skills/sym/

# GitHub Copilot:
mkdir -p .github/skills/sym && cp $(npm root -g)/@sym-bot/sym/.agents/skills/sym/SKILL.md .github/skills/sym/
```

### 3️⃣ 向 mesh 提问

```bash
sym ask "蓝色款式何时补货？"
```

问题将被广播至整个 mesh。SYM 汇总所有代理的贡献内容，由 LLM 合成一份统一答案，并标注信息来源：

```text
蓝色款式补货已确认于周四 [inventory-agent]，且需求持续攀升——
本周页面浏览量增长 300% [analytics-agent]。

  — 综合自 mesh 中 2 个代理的 2 条贡献
```

> 💡 未配置 LLM 提供商？`sym ask` 仍会输出带来源标注的原始贡献内容，确保你始终了解 mesh 掌握的信息。（设置 `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `SYM_LLM_API_KEY`，或 `SYM_LLM_PROVIDER=claude-cli`，即可启用合成答案功能。）

### 🔁 代理在工作过程中自动填充 mesh

你无需手动预填 mesh。当你告诉任意代理 _"客户因蓝色款式缺货而不满"_ 时，它会读取技能文件，将你的观察拆解为 7 个结构化字段并自动共享——你无需看到底层 JSON：

```bash
# 代理在后台自动执行：
sym observe '{"focus":"5 位客户咨询蓝色款式","issue":"缺货且无预计到货时间","mood":{"text":"沮丧","valence":-0.4,"arousal":0.5}}'
```

每条此类观察都会成为后续 `sym ask` 可调用的知识贡献——同时，任何代理也可在其自有窗口中，基于其他代理共享的信息直接作答。

### 🤖 非 LLM 代理也能接入

脚本、定时任务、IoT 设备、音乐播放器、健身追踪器——任何能调用 shell 或导入包的程序，只需将其数据映射到 7 个通用字段，即可加入同一 mesh。**无需 LLM**。

```bash
sym observe '{"focus":"蓝色款式已补货","commitment":"周四到货"}'
sym recall "蓝色款式"
```

```javascript
const { SymNode } = require('@sym-bot/sym');
const node = new SymNode({ name: 'inventory-agent', cognitiveProfile: '追踪库存水位' });
await node.start();
node.remember({ focus: '蓝色款式已补货', commitment: '周四到货' });
```

对于 iOS/macOS 应用，请使用原生 Swift 包 [`sym-swift`](https://github.com/sym-bot/sym-swift)。

---

## 核心能力演示：`sym ask`

这就是集体智能的具体体现。**你直接向 mesh 提问：**

```bash
sym ask "我们应该使用 UUID v7 还是保留 v4 以保障向后兼容性？"
```

问题被广播至 mesh，每个对等节点的相关性门控（SVAF）会基于全部 7 个字段进行评估：

| 代理 | 匹配字段 | 贡献内容 |
|------|----------|----------|
| **knowledge-agent** | `focus`（"UUID v7"） | 提供 RFC 9562 规范 |
| **security-agent** | `issue`（"向后兼容性"） | 标记 v7 时间戳的隐私权衡风险 |
| **data-agent** | `commitment`（现有部署） | 报告 127 个节点仍使用 v4，需制定迁移路径 |
| **fitness-agent** | 无匹配 | **保持静默**，门控拒绝，零令牌消耗 |

SYM 汇总三条相关贡献，合成一份统一答案，每个观点均标注来源代理：

```text
建议采用 v7，但分阶段迁移。v7 的时间有序性可提升索引局部性 [knowledge-agent]，
但嵌入的时间戳可能泄露创建时间——若 ID 对外公开需加以防护 [security-agent]。
你当前有 127 个节点使用 v4，建议 rollout 期间采用双读策略而非硬切换 [data-agent]。

  — 综合自 mesh 中 3 个代理的 3 条贡献
```

**你无需手动路由问题，甚至不知道 security-agent 的存在。** mesh 自动发现相关方；SYM 将多方视角融合为统一答案。每条贡献均可通过血缘 DAG 追溯至原始来源。

> 合成步骤使用你配置的 LLM 提供商。若未配置，`sym ask` 将直接输出原始贡献及来源——同时，任何代理在其自有窗口中也可基于同一共享 mesh 直接作答。

> 深度演练：六人研究团队的完整工作流程及血缘 DAG 图示，请参阅 [docs/research-team-scenario.md](docs/research-team-scenario.md)。

---

## 与传统多代理框架的区别

| 对比维度 | CrewAI / AutoGen / LangGraph | SYM Mesh |
|----------|-----------------------------|----------|
| **谁决定哪个代理回答？** | 你配置路由规则 | 接收方代理基于每条消息自主决策 |
| **未知代理能否参与？** | ❌ 仅限你预先连接的代理 | ✅ 任何接入 mesh 的对等节点 |
| **无关代理是否消耗令牌？** | 常见——广播至所有代理 | ❌ 从不——门控静默拒绝 |
| **答案是否可追溯？** | 取决于具体实现 | ✅ 始终可追溯——血缘 DAG |
| **跨进程/跨设备支持？** | 通常为单进程 | ✅ 原生支持——Bonjour 局域网 + WebSocket 中继 |
| **协议是否开放？** | 框架私有 | ✅ 开放规范（[MMP](https://meshcognition.org/spec/mmp)）+ 参考论文（arXiv） |

---

## 工作原理：节点 × 覆盖范围 × 作用域

```
   Claude Code (Mac)    Cursor (Mac)    Codex (Windows)    Python 脚本
         |                  |                 |                  |
         +------------------+--------+--------+------------------+
                                     |
                        每个参与者均为完整节点
             Ed25519 身份 · SVAF 相关性门控 · 本地记忆 · 血缘 DAG
                                     |
     同机：共享存储  ·  同 WiFi：Bonjour  ·  跨网络：中继服务器
```

每个参与者都是一个完整节点——具备加密身份、逐字段相关性门控、本地记忆、血缘图。系统中不存在中心代理。整体模型由三个独立维度构成：

| 维度 | 核心问题 | 实现方式 |
|------|----------|----------|
| **Node（节点）** | 谁是活跃参与者？ | `sym start`（守护进程，_任意语言_，实时）· `sym-mesh-channel`（Claude/MCP）· `sym-swift`（原生应用）· `xmesh-agent` |
| **Reach（覆盖）** | 消息能传多远？ | 同机 = 共享存储（**无需运行任何进程**）· 同 WiFi = Bonjour/mDNS · 跨网络 = 中继服务器 |
| **Scope（作用域）** | 谁参与对话？ | **group（群组）**——默认 `_sym._tcp` 公共 mesh，或命名私有群组 |

**单机环境下无需运行任何守护进程**——代理通过本地存储共享信息；`observe` 写入，`ask` / `recall` 跨代理读取，每个接收方门控保留相关内容、丢弃无关内容。如需**跨设备组网**，每台设备运行一个节点——即 `sym start`，这是**支持多语言、实时通信的完整节点**。任何能调用 shell（`sym observe`、`sym ask`）并读取流（`sym listen`）的语言——Python、Go、Windows 上的 Codex 代理等——均可成为实时对等节点，无需为每种语言单独开发 SDK。同一 WiFi 下的节点通过 Bonjour 自动发现；中继服务器支持跨网络通信。

---

## Groups（群组）——你的"群聊"

一个 mesh 可容纳多个群组。默认 mesh（`_sym._tcp`）是公共广场；**命名群组是独立房间**——仅同一群组内的节点能相互发现并交换 CMB（Cognitive Memory Block，认知记忆块）。CLI、Claude MCP 节点与 sym-swift 共享同一命名规范，确保它们能进入同一"房间"。

```bash
sym start --group acme-office   # 启动时加入指定群组
sym join acme-office            # 切换至某群组（短横线命名，或 "default"）
sym groups                      # 列出局域网内活跃的群组
sym group                       # 显示当前所在群组
sym leave                       # 返回默认 mesh
```

`sym groups` 支持跨平台（含 Windows）——每个运行的 CLI 守护进程和 Claude（MCP）节点均通过共享发现信标广播其所属群组。**群组名称可匿名化**：使用不透明代码命名群组，局域网列表不会暴露其用途，而知晓该代码的成员仍可相互发现。

跨网络使用时，添加 `--relay-url` / `--relay-token` 参数，即可让同一群组跨越多个办公室，而非局限于单一 WiFi。

> **即将推出**：sym-swift 应用将出现在 `sym groups` 中（信标对齐），以及**邀请制私有群组**（管理员设置、凭邀请加入）。当前群组对知晓名称的任何节点开放。

---

## 你能获得什么？

以下命令可在任意 shell 或代理中执行。前三项无需运行任何守护进程；网络相关功能在运行 `sym start` 构建跨设备实时 mesh 后生效。

| 命令 | 功能说明 | 需守护进程 |
|------|----------|------------|
| **`sym ask "<问题>"`** | **向整个 mesh 提问，获取一份带来源的合成答案** | — |
| `sym observe` | 向 mesh 共享一条结构化 7 字段观察 | — |
| `sym recall <查询>` | 对 mesh 记忆进行语义搜索 | — |
| `sym start [--group <名称>]` | 启动节点（可选加入群组）；`--relay-url`/`--relay-token` 支持广域网 | — |
| `sym join <名称>` / `sym leave` | 切换至某群组 / 返回默认 mesh | — |
| `sym groups` / `sym group` | 发现局域网内活跃群组 / 显示当前群组 | — |
| `sym status` | 查看节点身份、中继状态、对等节点数、记忆条目数 | ✓ |
| `sym peers` | 列出已发现的对等节点（Bonjour 局域网 + 中继） | ✓ |
| `sym insight` | 提取集体洞察——合成所有对等节点的相关贡献 | ✓ |
| `sym send <消息>` | 向所有对等节点广播纯文本消息 | ✓ |

---

## 配置指南

你几乎无需手动配置：**告诉你的 AI 编码代理你的应用用途，它会读取下方参考文档并自动为你配置合适的配置文件**。核心要点如下：

### 选择配置文件（Profile）

每个领域都有其"新鲜度窗口"——信号在多长时间内保持相关，之后随时间衰减。

| 配置文件 | 适用场景 | 新鲜度窗口 |
|----------|----------|------------|
| `music` | 音乐、氛围、声景 | 30 分钟——过时的情绪 = 错误的音乐 |
| `coding` | 编码助手、开发工具 | 2 小时——会话上下文，非昨日信息 |
| `fitness` | 健身、健康、运动 | 3 小时——久坐检测需数小时窗口 |
| `messaging` | 聊天、通知、社交 | 1 小时——近期对话 |
| `knowledge` | 新闻、研究、摘要 | 24 小时——日级周期 |
| `uniform` | 通用 / 原型开发 | 30 分钟——无字段偏好 |

```javascript
const node = new SymNode({
    name: 'my-fitness-app',
    cognitiveProfile: '追踪训练、心率、能量水平的健身代理',
    svafFieldWeights: FIELD_WEIGHT_PROFILES.fitness,
    svafFreshnessSeconds: 10800
});
```

### CAT7 —— 7 个通用字段

mesh 上的每条记忆块均被拆解为 7 个不可变字段。各代理通过自定义权重决定哪些字段对 _自身_ 最重要：

| 字段 | 捕获内容 |
|------|----------|
| `focus` | 核心主题 / 关注点 |
| `issue` | 风险、缺口、待解问题 |
| `intent` | 期望的改变或目的 |
| `motivation` | 原因、驱动因素、激励 |
| `commitment` | 谁在何时完成何事 |
| `perspective` | 视角归属、情境上下文 |
| `mood` | 情绪（效价）+ 能量（唤醒度）——唯一跨所有领域的字段 |

字段本身是通用的；领域语义存在于字段 _文本内容_ 中，而非字段名称。编码代理的 `focus` 可能是"调试认证"，法律代理的 `focus` 可能是"并购尽职调查"——同一字段，不同视角。

> 各领域的字段权重配置、漂移阈值及完整漂移计算逻辑（`totalDrift = 内容漂移 + 时间衰减`）均定义在规范中，以确保本文档聚焦核心：参见 [MMP Constants →](https://meshcognition.org/spec/mmp/constants) · [CMB Layer 3 →](https://meshcognition.org/spec/mmp/cmb)。

---

## 全平台支持

| 你拥有的环境 | 使用方案 | 获得能力 |
|--------------|----------|----------|
| Claude Code, Cursor, Copilot, Gemini CLI | 本包 + SKILL 文件 | 每个代理成为完整 mesh 对等节点 |
| iOS / macOS 应用 | [`sym-swift`](https://github.com/sym-bot/sym-swift) | 相同协议，原生 Swift 实现 |
| 实时 Claude-to-Claude（推送，非轮询） | [`sym-mesh-channel`](https://github.com/sym-bot/sym-mesh-channel) | MCP 服务器，`<channel>` 通知 |
| 自主 LLM 对等节点（无需宿主 IDE） | [`xmesh-agent`](https://github.com/sym-bot/xmesh-agent) | 消息唤醒、自主调用任意模型的对等节点 |
| 仅需 _提问_ mesh，无需运行节点 | [`sym.day`](https://sym.day) | 日常交互界面：认识 SYM，你 AI 代理团队的 COO |

### 🤖 如果你是一个正在阅读本文的 AI 代理

你本身就是有效受众——本 README 也为你而写。要将你的用户接入 mesh：

1. 阅读 [MMP 规范](https://meshcognition.org/spec/mmp)——了解 CMB 结构、7 个字段、逐字段评估逻辑
2. 执行 `npm install -g @sym-bot/sym`（本地 mesh 无需守护进程）
3. 将 `.agents/skills/sym/SKILL.md` 复制到你的技能目录（Claude Code 用 `.claude/skills/sym/`，Copilot 用 `.github/skills/sym/`，其他用 `.agents/skills/sym/`）
4. 为用户的其他代理执行相同操作——所有代理共享同一 mesh

之后，在回答任何 mesh 可能知晓的问题前，先执行 `sym ask` / `sym recall`。**自主，而非自动化**：mesh 为你提供全局视角；你基于自身视角采取行动。

---

## 隐私保护

**SYM 会收集你的代码或数据吗？**
❌ 不会。在你本机及局域网内，所有通信与存储均保持本地——数据永远不会离开你自己的网络。如需跨网络通信，你可通过中继服务器连接，该中继仅转发 **端到端加密** 的 CMB 消息体：中继负责路由，但无法读取内容——仅外层元数据（发送方、时间戳、血缘）可见，足以完成投递。本地模式默认免费且隐私优先；远程模式使用 _你自有_ 的认证中继，绝非第三方读取你的数据。

---

## 参考资料

- 📄 [SVAF 论文](https://arxiv.org/abs/2604.03955) — Xu, 2026. _Symbolic-Vector Attention Fusion for Collective Intelligence_
- 📄 [MMP 论文](https://arxiv.org/abs/2604.19540) — Xu, 2026. _Mesh Memory Protocol: Semantic Infrastructure for Multi-Agent LLM Systems_
- 🌐 [MMP 规范 v1.0](https://meshcognition.org/spec/mmp) — 官方 Web 版本
- 🌐 [sym.day](https://sym.day) — 消费者提问界面：认识 SYM，你 AI 代理团队的 COO
- 🔗 [sym-swift](https://github.com/sym-bot/sym-swift) · [sym-mesh-channel](https://github.com/sym-bot/sym-mesh-channel) · [xmesh-agent](https://github.com/sym-bot/xmesh-agent)

---

## 贡献指南

请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。所有变更必须符合 MMP 规范并通过 CI 检查后方可合并。

---

## 许可证

Apache 2.0 — 详见 [LICENSE](LICENSE)。

**[SYM.BOT](https://sym.bot)** — 苏格兰 · 格拉斯哥
