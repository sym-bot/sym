# SYM

> **问一个代理，得到一个答案。问整个 _mesh_（网状网络）—— 每个掌握相关知识的代理都会参与回答，最终呈现为统一回复。**

```bash
sym ask "我们应该使用 UUID v7 还是保留 v4 以保障向后兼容性？"
```

> 你在代码库中运行 Claude Code，在编辑器中使用 Cursor，在 GitHub 上启用 Copilot，偶尔还跑几个脚本——每个工具只掌握局部信息，彼此之间无法共享。`sym ask` 能一次性将你的问题分发给所有代理：掌握相关知识的代理会贡献内容，无关的保持静默，最终你收到的是**一份融合多方信息、附带来源标注的综合答案**。无需路由配置，无需中心化编排器。

只需在每台机器上安装一次——无需服务器，无需常驻后台进程：

```bash
npm install -g @sym-bot/sym
```

[![npm](https://img.shields.io/npm/v/@sym-bot/sym)](https://www.npmjs.com/package/@sym-bot/sym)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![MMP Spec](https://img.shields.io/badge/protocol-MMP_v1.0-orange)](https://meshcognition.org/spec/mmp)
[![English](https://img.shields.io/badge/语言-English-red)](README.md)

---

## SYM 是什么？

**SYM 将你已在使用的所有 AI 代理整合为一个集体智能系统——让它们像同一个大脑一样协同作答，而非四个互不相通的独立个体。**

首先解释术语：**mesh（网状网络）** 指的是你所有代理之间直接互联的拓扑结构——代理与代理点对点通信，中间无中心服务器。每个代理运行 SYM 后即接入该 mesh。之所以称为 _mesh_，是因为每个代理都与其他代理直接通信，而非通过中心枢纽转发。

SYM 是实现这一能力的协议 + 命令行工具（CLI）。你只需在每台机器上安装一次。每个代理保留自身的用户界面、上下文窗口和任务职责——SYM 仅为它们提供共享的 mesh 用于读写通信。当某个代理获取新知识时，所有可能对该知识感兴趣的代理都会同步收到。当你执行 **`sym ask "<问题>"`** 时，问题会被广播至整个 mesh：掌握部分答案的代理会贡献内容，无关代理保持静默，最终你收到的是**一份统一答案**——即 mesh 以单一智能体的形式作答。

- ✅ 无中心服务器  
- ✅ 无需维护路由规则  
- ✅ 无需编排器决定通信顺序  
- ✅ 每个代理自主判断接收到的信息是否与自身相关  

> SYM 是 Mesh Memory Protocol（MMP，网状记忆协议）的开源参考实现。如需支持**自主唤醒、自主调用任意模型的 LLM 对等节点**（无需宿主 IDE），请参阅 `@sym-bot/xmesh-agent`——基于相同 mesh 架构，构建于 SYM 之上。

---

## 为什么你需要 SYM？

你拥有四个 Copilot，却没有任何共享记忆。

- 你的客服代理不知道库存代理刚刚学到的补货信息  
- 你的写作代理看不到分析代理一小时前统计的数据  
- 你向 Claude Code 提问，它无法回答——而你甚至不知道另一个窗口中的代理其实掌握答案  

每个代理都在「信息孤岛」中工作，而你被迫成为集成层：在不同窗口间复制粘贴上下文、手动路由问题、记忆每个代理的知识边界。

传统解决方案是将代理通过框架、路由图或可配置的编排器连接起来。但这意味着你需要为每对代理编写集成代码，且只能连接你预先规划好的代理。

**SYM 彻底消除「连线」成本**。代理通过共享 mesh 通信，并基于相关性自主筛选信息。即使是你忘记存在的代理，也可能参与回答；没有贡献的代理不会产生任何开销。你不再需要充当人工集成层。

---

## 如何使用 SYM？

### 1️⃣ 安装

```bash
npm install -g @sym-bot/sym
```

这就是全部安装步骤。无需启动服务器，无需维护常驻进程——代理通过本机内存存储共享信息，`observe` 负责写入，`ask` 负责跨代理读取。（如需在局域网内多台设备间构建 _实时 mesh_？只需一条可选命令——详见下文。）

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

### 你的代理在工作中自动填充 mesh

你无需手动录入 mesh。当你对任意代理说「客户对蓝色款式缺货感到不满」时，它会读取技能文件，将你的观察分解为 7 个结构化字段并共享出去——你不会看到任何 JSON：

```bash
# 代理在后台自动完成：
sym observe '{"focus":"5 位顾客询问蓝色款式","issue":"缺货且无补货时间","mood":{"text":"不满","valence":-0.4,"arousal":0.5}}'
```

每一条这样的观察，都是下一次 `sym ask` 可以调用的贡献。

---

## 核心特性速览

| 特性 | 说明 |
|------|------|
| 🔗 去中心化 mesh 架构 | 代理点对点直连，无单点故障，无中心服务器依赖 |
| 🎯 相关性自主筛选 | 每个代理基于自身上下文判断是否响应，零配置路由 |
| 🧠 答案自动合成 | 支持 LLM 融合多方信息，输出带来源标注的统一回复 |
| ⚡ 零运维负担 | 单机开箱即用，无中心服务器；跨机器只需各跑一个节点 |
| 🔌 广泛兼容 | 支持 Claude Code、Cursor、Copilot 等主流 AI 代理 |
| 📦 技能即插即用 | 通过标准化 SKILL.md 文件快速赋能任意 LLM 代理 |

---

## 高级用法（可选）

### 🌐 跨机器互通：节点 × 范围 × 群组

单机上无需运行任何后台进程——以上功能开箱即用。要让 mesh **跨机器**互通，每台机器各运行一个节点，即 `sym start`——**这是与语言无关的实时节点**：任何能调用子进程（`sym observe` / `sym ask`）并读取流（`sym listen`）的语言都是完整的实时对等节点（Python、Go、Windows 上的 Codex……），无需各语言 SDK。同一局域网内的节点通过 Bonjour 互相发现，跨网络则经由中继（relay）。

整个模型由三个独立选择构成：

| 维度 | 问题 | 方式 |
|------|------|------|
| **节点 Node** | 谁是实时参与者 | `sym start`（守护进程，任意语言，实时）· `sym-mesh-channel`（Claude/MCP）· `sym-swift`（App）· `xmesh-agent` |
| **范围 Reach** | 传播多远 | 同机 = 本地存储（**无需运行**）· 同局域网 = Bonjour · 跨网络 = 中继 |
| **群组 Scope** | 谁在对话中 | **group**——默认 `_sym._tcp` 公共 mesh，或具名私有群组 |

### 💬 群组：你的「群聊」

mesh 可容纳多个群组。默认 mesh（`_sym._tcp`）是公共广场，**具名群组则是私密房间**——只有同一群组内的节点才会互相发现并交换 CMB。CLI、Claude MCP 节点与 sym-swift 共用同一命名约定，因此都能聚到同一房间。

```bash
sym start --group acme-office   # 启动时加入群组
sym join acme-office            # 切换群组（kebab-case，或 "default"）
sym groups                      # 发现局域网内在线的群组
sym group                       # 显示当前群组
sym leave                       # 回到默认 mesh
```

跨网络时加 `--relay-url` / `--relay-token`，群组即可跨越多个办公室，而不止一个局域网。

### 🗃️ 结构化记忆：CAT7 字段

mesh 上的每条记忆块（CMB）都被分解为 7 个通用字段（CAT7：6 个语义字段 + 1 个情绪字段）。字段权重决定哪些字段对**你的**代理最重要：

| 字段 | 含义 |
|------|------|
| `focus`（焦点） | 这条信息的核心主题 |
| `issue`（问题） | 风险、缺口、未决问题 |
| `intent`（意图） | 期望的改变或目的 |
| `motivation`（动机） | 原因、驱动力、动机 |
| `commitment`（承诺） | 谁将做什么、何时完成 |
| `perspective`（视角） | 谁的视角、情境上下文 |
| `mood`（情绪） | 情感效价（valence）+ 唤醒度（arousal）；唯一跨越所有领域的字段 |

字段是通用且不可变的——领域含义体现在字段的**文本内容**中，而非字段名称。编码代理的 `focus` 是「调试鉴权模块」，法律代理的 `focus` 是「并购尽职调查」：同一字段，不同领域视角。

---

## 常见问题

**Q：SYM 会收集我的代码或数据吗？**  
A：不会。在你的机器与局域网内，一切都留在本地——通信与存储不会离开你自己的网络。要跨网络互通时，你会经由一个中继（relay）连接：它转发的 CMB 内容在你的对等节点之间**端到端加密**——中继只负责转发，无法读取；仅外层帧的元数据（发送方、时间戳、血缘）可见，足以完成投递。本地默认免费且私密；远程则是**你自己的**已认证中继，绝非第三方读取你的数据。

**Q：如何卸载？**  
```bash
npm uninstall -g @sym-bot/sym
# 可选：清理本地技能配置
rm -rf .agents/skills/sym .claude/skills/sym .github/skills/sym
```

**Q：支持哪些 LLM 提供商？**  
A：目前支持 Anthropic（Claude）、OpenAI 及任意兼容 OpenAI 接口的服务（如 Ollama、vLLM），以及通过 `SYM_LLM_PROVIDER=claude-cli` 调用本地 Claude CLI。

---

> 📄 许可证：Apache 2.0  
> 🔗 项目主页：[https://github.com/sym-bot/sym](https://github.com/sym-bot/sym)  
> 📚 协议规范：[Mesh Memory Protocol (MMP)](https://meshcognition.org/spec/mmp) · [SVAF 论文](https://arxiv.org/abs/2604.03955) · [MMP 论文](https://arxiv.org/abs/2604.19540)  
> 💬 问题反馈：欢迎提交 Issue 或参与讨论  

*让每个代理发挥所长，让答案自然汇聚——这就是 SYM。* 🤝✨
