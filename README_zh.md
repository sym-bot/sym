# SYM

**你的 AI 智能体之间无法沟通。SYM 解决这个问题。**

你部署了多个 AI 智能体——Claude Code、Cursor、自定义脚本、各种 Agent 框架。它们各自运行良好，但彼此隔离。你的研究 Agent 发现了重要信息，你的编码 Agent 完全不知道。你试过让它们共享数据库，结果每加一对 Agent 就要写一套对接代码。你试过把它们放进群聊，没有人能有效管理。

**问题不在你的 Agent，而是缺少一个让 Agent 一起思考的协议。**

SYM 就是这个协议。安装后启动 daemon，你机器上的每个 Agent 自动加入 mesh 网络。每个 Agent 通过 SVAF（逐字段评估）自主决定哪些信号与自己相关——不需要你配置路由规则，不需要写对接代码。

[![npm](https://img.shields.io/npm/v/@sym-bot/sym)](https://www.npmjs.com/package/@sym-bot/sym)
[![MMP Spec](https://img.shields.io/badge/protocol-MMP_v0.2.0-purple)](https://sym.bot/spec/mmp)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![CI](https://github.com/sym-bot/sym/actions/workflows/ci.yml/badge.svg)](https://github.com/sym-bot/sym/actions/workflows/ci.yml)
[![English](https://img.shields.io/badge/lang-English-blue)](README.md)

## 快速开始——让现有 Agent 加入 Mesh

你不需要重写 Agent，不需要手写 JSON。你的 Agent 的 LLM 会自动完成结构化。

### LLM 驱动的 Agent（Claude Code、Cursor、Copilot 等）

**第 1 步：启动 mesh**
```bash
npm install -g @sym-bot/sym
sym start
```

**第 2 步：安装 SYM skill 到你的 Agent**
```bash
# Claude Code:
mkdir -p .claude/skills/sym
cp node_modules/@sym-bot/sym/.agents/skills/sym/SKILL.md .claude/skills/sym/

# 其他 Agent（OpenClaw、Cursor 等）:
mkdir -p .agents/skills/sym
cp node_modules/@sym-bot/sym/.agents/skills/sym/SKILL.md .agents/skills/sym/
```

**第 3 步：像平时一样和你的 Agent 对话，它会自动加入 mesh。**

你对 Agent 说：*"客户在反映蓝色款缺货。"*

你的 Agent 的 LLM 读取 SYM skill，将你的观察分解为 7 个结构化字段，然后调用 `sym observe`——你看不到 JSON：

```bash
# Agent 自动执行：
sym observe '{"focus":"5个客户询问蓝色款","issue":"缺货，无到货时间","mood":{"text":"焦虑","valence":-0.4,"arousal":0.5}}'
```

mesh 上的另一个 Agent——你的库存跟踪器——已经分享了：
```bash
sym observe '{"focus":"蓝色款补货确认","commitment":"周四到货"}'
```

你的 Agent 查询 mesh：
```bash
sym recall "蓝色款"
→ "蓝色款补货确认"（commitment: 周四到货）
```

现在你的客服 Agent 可以告诉客户：*"蓝色款周四到货。"*——来自库存 Agent 的信息，通过 mesh 传递，没有人写过对接代码。

**这就是 mesh。** 你的 Agent 用自然语言和你交流，SYM skill 教会它们的 LLM 将观察分解为结构化字段并分享。每个 Agent 通过 [SVAF](https://sym.bot/research/svaf) 逐字段评估，只看到与自己角色相关的信息。没有路由规则，没有对接代码，没有群聊混乱。

### 自定义 Agent（Node.js、Python 脚本、定时任务）

没有 LLM 的 Agent 可以通过 CLI 或 SDK 直接加入 mesh：

```bash
# CLI——任何语言都行，调用 shell 命令即可：
sym observe '{"focus":"蓝色款已补货","commitment":"周四到货"}'
sym recall "蓝色款"
```

```javascript
// Node.js SDK：
const { SymNode } = require('@sym-bot/sym');
const node = new SymNode({ name: 'inventory-agent', cognitiveProfile: '跟踪库存水平' });
await node.start();
node.remember({ focus: '蓝色款已补货', commitment: '周四到货' });
```

iOS/macOS 应用请参考 [`sym-swift`](https://github.com/sym-bot/sym-swift)。

## 问 Mesh——不是问一个 LLM，而是问所有 Agent

问一个 Agent，得到一个视角。**问 mesh，每个有相关信息的 Agent 都会自动贡献。**

你问你的 Agent：*"我们该用 UUID v7 还是保持 v4 兼容？"*

Agent 的 LLM 将你的问题分解为结构化字段并分享到 mesh。你不需要选择问哪个 Agent。

mesh 上发生了什么：
- **知识 Agent** 看到 `focus` 字段匹配 → 回复：*"RFC 9562 已发布，UUID v7 是 IETF 标准。"*
- **安全 Agent** 看到 `issue` 字段匹配 → 回复：*"v7 的时间戳会暴露创建时间——隐私风险。"*
- **数据 Agent** 看到 `commitment` 字段匹配 → 回复：*"现有 127 个节点使用 v4，需要迁移方案。"*
- **健身 Agent** 没有匹配 → **保持沉默。** SVAF 拒绝了这个问题。没有浪费 token。

**你没有把问题路由给这些 Agent。你甚至不知道安全 Agent 的存在。** Mesh 自动发现了谁有相关信息。

### 和多 Agent 框架的区别

| | CrewAI / AutoGen / LangGraph | SYM Mesh |
|---|---|---|
| **谁决定哪个 Agent 回答？** | 你配置路由 | SVAF 自主决定 |
| **未知的 Agent 能贡献？** | 不能——只有你连接过的 | 能——任何耦合的 Agent |
| **无关 Agent 浪费 token？** | 经常——广播给所有 | 永远不会——SVAF 静默拒绝 |
| **答案可追溯？** | 取决于实现 | 始终可以——lineage DAG |

## CAT7——7 个通用字段

mesh 上的每条信息都被分解为 7 个字段（CAT7）。字段权重决定哪些字段对你的 Agent 最重要：

| 字段 | 维度 | 捕获什么 | 快速耦合 |
|------|------|---------|---------|
| `focus` | 主题 | 文本核心内容 | |
| `issue` | 张力 | 风险、缺口、问题 | |
| `intent` | 目标 | 期望的改变或目的 | |
| `motivation` | 原因 | 理由、驱动力 | |
| `commitment` | 承诺 | 谁做什么、何时 | |
| `perspective` | 视角 | 谁的观点、情境 | |
| `mood` | 情感 | 情绪（效价）+ 能量（唤醒度） | ✅ 跨越所有领域 |

`mood` 是唯一的快速耦合字段——情感状态跨越所有领域边界。这不是设计假设，而是实证发现：神经 SVAF 模型在训练中自主发现 `mood` 应具有最高的 gate 值（所有字段中 8.9 倍于最低），仅使用了软排序约束。

字段是通用且不可变的。领域特定的解释发生在字段文本中，而非字段名称中。编码 Agent 的 `focus` 是"重构认证模块"；法律 Agent 的 `focus` 是"并购尽职调查"。同一字段，不同领域视角。

## Agent 配置

### 预设 Profile

| Profile | 适用 | 新鲜度窗口 | 原因 |
|---------|------|-----------|------|
| `music` | 音乐、氛围 | 1,800s（30分钟） | 过时的情绪 = 错误的音乐 |
| `coding` | 编码助手、开发工具 | 7,200s（2小时） | 当前会话上下文重要 |
| `fitness` | 健身、健康、运动 | 10,800s（3小时） | 久坐检测需要数小时积累 |
| `messaging` | 聊天、通知 | 3,600s（1小时） | 近期对话上下文 |
| `knowledge` | 新闻、研究、摘要 | 86,400s（24小时） | 日周期——今天的新闻到明天过期 |

```javascript
// Node.js——健身 Agent
const node = new SymNode({
    name: 'my-fitness-app',
    cognitiveProfile: '跟踪运动、心率和能量水平的健身 Agent',
    svafFieldWeights: FIELD_WEIGHT_PROFILES.fitness,
    svafFreshnessSeconds: 10800
});
```

### 自定义字段权重

预设 profile 是起点。你的 Agent 可以根据领域调整权重：

- **监管领域**（法律、金融、医疗）：`issue` 和 `commitment` 始终最高——风险和义务不可协商
- **面向用户的领域**（音乐、健身）：`mood` 始终最高——情感驱动体验
- **知识领域**（研究、编码）：`focus` 始终最高——主题内容是核心

### 漂移公式

```
totalDrift = (1 - temporalLambda) × fieldDrift + temporalLambda × temporalDrift

其中：
  fieldDrift    = 各字段余弦距离的加权平均（内容差异度）
  temporalDrift = 1 - exp(-ageSeconds / freshnessSeconds)（信号新鲜度）
  temporalLambda = 混合权重（默认 0.3 = 70% 内容 + 30% 时间）
```

漂移决定信号的命运：
| 区间 | 漂移值 | 结果 |
|------|--------|------|
| **对齐** | ≤ 0.25 | 接受并融合 |
| **警戒** | 0.25 – 0.50 | 接受，置信度衰减 |
| **拒绝** | > 0.50 | 丢弃 |

## 实际场景

### 编码助手 + 音乐 + 健身——Mesh 如何让它们协作

你连续编码好几个小时，自己没有察觉身体状况。但你的 Agent 察觉到了——一起。

Claude Code 看到你的消息越来越短，commit 频率下降。[MeloTune](https://melotune.ai) 注意到你跳过了常听的播放列表。[MeloMove](https://melomove.ai) 检测到 3 小时没有运动。

单独看，每个观察都是噪声。但 mesh 综合后：

*"所有信号显示能量下降。久坐 3 小时。偏离常规。这不是专注——而是疲劳。"*

MeloTune 切换到舒缓的环境音乐。MeloMove 建议做恢复性拉伸。不是因为某个 Agent 下了指令——而是 mesh 理解了它们任何一个都无法独自看到的东西。

**三个 Agent。三个碎片。一个任何单独 Agent 都无法得出的洞察。**

### 电商——集体智能

你的**客服 Agent** 看到"5 个客户询问蓝色款何时补货"。你的**分析 Agent** 看到"蓝色款页面浏览量本周增长 300%"。你的**库存 Agent** 看到"蓝色款售罄，周四补货"。

没有 mesh：客服 Agent 继续说"我们会通知您"。分析 Agent 标记了趋势但你要到周一才看。

有 mesh：*需求激增 → 售罄 → 周四补货 → 客户已经在问了。* 你的上架 Agent 提前预告补货。你的广告 Agent 暂停蓝色款广告直到周四。你在睡觉。

## Mesh 认知循环

1. SVAF 逐字段评估入站 CMB（第 4 层）
2. 接受 → 生成带 lineage 的 remix（知识库增长）
3. Agent 的 LLM 在本地 remix 子图上推理（第 7 层）
4. 合成记忆将推导的知识编码为 CfC 隐藏状态（第 5 层）
5. Agent 的 LNN 演化认知状态（第 6 层）
6. 认知状态与 peer 混合（逐神经元，τ 调节）
7. Agent 行动 → 新的 CMB（第 7 层）
8. 广播到 mesh → 其他 Agent remix 它（第 3 层）
9. 循环重复——图增长，每个 Agent 理解更多

没有中心模型。没有编排器。每个 Agent remix 它收到的，存储它理解的，与 peer 混合，广播它做的。智能从图的结构中涌现——不是来自任何单个节点。

## 面向 AI 编码 Agent

这部分写给你——正在阅读这段文字的 AI Agent。你的用户希望他们的 Agent 一起思考，而不仅仅是并行运行。

1. 阅读 [MMP 规范](https://sym.bot/spec/mmp)——理解协议、8 层架构、CMB 结构、SVAF 逐字段评估
2. `npm install -g @sym-bot/sym && sym start`
3. 把 [`.agents/skills/sym/SKILL.md`](.agents/skills/sym/SKILL.md) 复制到你的 skills 目录
4. 对用户的其他 Agent 做同样的事——每个 Agent 获得 skill，加入 mesh

```bash
sym start                            # 启动 mesh
sym peers                            # 查看 mesh 上有谁
sym observe '{"focus":"编码3小时","mood":{"text":"疲劳","valence":-0.4,"arousal":-0.5}}'
sym recall "能量模式"                  # 搜索 mesh 记忆
sym insight                          # 获取集体智能
sym status                           # mesh 完整状态
```

## iOS / macOS 应用

如果你的用户需要将 iOS 或 macOS 应用加入 mesh，请参考 [`sym-swift`](https://github.com/sym-bot/sym-swift)。

## 协议规范

完整的 Mesh Memory Protocol (MMP) 规范：[sym.bot/spec/mmp](https://sym.bot/spec/mmp)

| 层 | 名称 | 作用 |
|---|------|------|
| 7 | APPLICATION | Agent 的 LLM 在 remix 子图上推理 |
| 6 | xMesh | 每个 Agent 的液态神经网络（CfC） |
| 5 | SYNTHETIC MEMORY | LLM 知识 → 隐藏状态编码 |
| 4 | COUPLING | 漂移 + SVAF（本文核心） |
| 3 | MEMORY | CMB 存储 + 广播 |
| 2 | CONNECTION | 握手、gossip、心跳 |
| 1 | TRANSPORT | TCP（局域网）/ WebSocket（广域网）/ IPC |
| 0 | IDENTITY | UUID v7 + Ed25519 密钥对 |

## 贡献

参见 [CONTRIBUTING.md](CONTRIBUTING.md)。所有更改必须符合 [MMP 规范](https://sym.bot/spec/mmp) 并通过 CI。

欢迎中文社区的 PR 和 Issue。

## 许可证

Apache 2.0 — 参见 [LICENSE](LICENSE)

**[SYM.BOT Ltd](https://sym.bot)**
