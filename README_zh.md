# SYM — Mesh Memory Protocol (MMP) 参考实现

> **让自主智能体真正「协同思考」，而非仅仅「互相发消息」**

[![npm version](https://img.shields.io/npm/v/@sym-bot/sym.svg)](https://www.npmjs.com/package/@sym-bot/sym)
[![Specification](https://img.shields.io/badge/MMP-v0.2.3-blue)](https://sym.bot/spec/mmp)
[![Paper](https://img.shields.io/badge/arXiv-2604.03955-b31b1b)](https://arxiv.org/abs/2604.03955)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

---

## 核心问题

当前 AI 智能体普遍处于「孤岛状态」：它们通过消息总线、API 或共享数据库交换数据，但**无法真正协同推理**。一个编码智能体、一个音乐智能体、一个健康智能体服务于同一用户，却各自只能看到自己的领域片段。没有任何单一智能体能够将「提交频率下降」+「歌曲跳过增多」+「3 小时未活动」关联为「用户可能疲劳」——这种洞察需要**集体智能**，而现有协议无法提供。

**SYM 提供的不是又一个多智能体编排框架，而是一套让自主智能体在保持上下文独立的前提下，通过结构化认知消息交换实现协同推理的底层协议。**

---

## 核心设计原则

| 原则 | 说明 |
|------|------|
| **智能体自治** | 每个智能体维护完全独立的对话上下文与记忆存储（MMP §2.4），不共享状态 |
| **离散消息交换** | 通过认知记忆块（CMB, Cognitive Memory Block）传递结构化信息，非连续状态同步 |
| **按字段评估** | SVAF（Symbolic-Vector Attention Fusion）对每条消息的 7 个认知字段独立评估相关性，决定接收策略 |
| **零配置发现** | 基于 DNS-SD (Bonjour) 的局域网自动发现，无需服务器、密钥或手动配置 |
| **协议可组合** | 上层应用可基于 MMP 构建专属认知协议，底层传输与身份层保持正交 |

> **重要澄清**：
> - 智能体之间**不共享上下文**，仅通过离散 CMB 交换信息
> - 接收方收到的是**通道通知**，后续处理由用户或对话策略决定，非自动分析
> - 所有认知内容必须使用 `cmb` 帧格式传输（MMP v0.2.3+）

---

## 技术架构：8 层协议栈

```
┌─────────────────────────────────┐
│ Layer 7: 应用认知层              │ ← 智能体业务逻辑
├─────────────────────────────────┤
│ Layer 6: CfC 神经动力学层        │ ← 时序状态演化 (Closed-form Continuous-time NN)
├─────────────────────────────────┤
│ Layer 5: 合成记忆层              │ ← 跨智能体记忆融合策略
├─────────────────────────────────┤
│ Layer 4: SVAF 认知耦合层         │ ← 按字段相关性评估与注意力融合
├─────────────────────────────────┤
│ Layer 3: CMB 认知消息层          │ ← CAT7 七字段结构化消息格式
├─────────────────────────────────┤
│ Layer 2: 传输层 (TCP/WS)         │ ← 长度前缀 JSON 线格式
├─────────────────────────────────┤
│ Layer 1: 身份与加密层            │ ← 密钥对、签名、端到端加密
├─────────────────────────────────┤
│ Layer 0: 发现层 (DNS-SD/Bonjour) │ ← 零配置局域网发现
└─────────────────────────────────┘
```

### 核心组件

#### CAT7：七字段认知消息格式
每条 CMB 包含 7 个语义字段，构成通用认知接口：

| 字段 | 语义轴 | 捕获内容 | 快速耦合 |
|------|--------|----------|----------|
| `focus` | 主题 | 内容核心焦点 | |
| `issue` | 张力 | 风险、缺口、待解问题 | |
| `intent` | 目标 | 期望的改变或目的 | |
| `motivation` | 动因 | 行为背后的驱动因素 | |
| `commitment` | 承诺 | 确认事项、责任方、时间节点 | |
| `perspective` | 视角 | 信息来源的角色与情境 | |
| `mood` | 情感 | 情绪效价 (valence) + 激活度 (arousal) | 跨域耦合 |

> `mood` 是唯一默认启用快速耦合的字段——情感状态可跨所有领域边界传递，这是 SVAF 模型在无监督训练中自主发现的规律。

#### SVAF：符号 - 向量注意力融合
- 对每条入站 CMB 的 7 个字段**独立计算相关性得分**
- 输出四类评估结果：`redundant`（冗余）/ `aligned`（对齐）/ `guarded`（审慎）/ `rejected`（拒绝）
- 解决选择性接收与冗余过滤的双重挑战
- 训练数据：237K 样本 / 273 叙事场景，三分类准确率 78.7%

#### CfC：闭式连续时间神经网络
- 每智能体独立的时序演化引擎
- 学习每个神经元的时延常数 (τ)：快神经元实现秒级情感同步，慢神经元保留领域专业知识
- 与 SVAF 协同：SVAF 决定「什么进入认知状态」，CfC 决定「状态如何演化」

---

## 快速开始

### 前置要求
- Node.js 18+ 或 Python 3.10+
- 同一局域网（或配置中继服务器）
- （可选）Claude Code / Cursor / Copilot 等支持 Agent Skills 的编码助手

### 安装与启动

```bash
# 1. 全局安装 SYM CLI
npm install -g @sym-bot/sym

# 2. 启动网格守护进程（后台运行）
sym start

# 3. 验证网格状态
sym peers          # 查看已连接智能体
sym status         # 完整网格诊断
```

### 为智能体添加网格能力

#### 方案 A：LLM 驱动的智能体（推荐）
利用 Agent Skills 标准，让智能体的 LLM 自动处理字段提取：

```bash
# Claude Code
mkdir -p .claude/skills/sym
cp node_modules/@sym-bot/sym/.agents/skills/sym/SKILL.md .claude/skills/sym/

# OpenClaw / Cursor / Junie
mkdir -p .agents/skills/sym
cp node_modules/@sym-bot/sym/.agents/skills/sym/SKILL.md .agents/skills/sym/
```

安装后，智能体将自动：
1. 监听用户自然语言输入
2. 按 CAT7 格式提取结构化字段
3. 调用 `sym observe` 发布至网格
4. 通过 `sym recall` / `sym insight` 获取集体洞察

#### 方案 B：自定义脚本 / 传统应用
直接通过 CLI 或 SDK 集成：

```bash
# CLI（任意语言）
sym observe '{"focus":"用户会话超时","issue":"未处理异常","commitment":"需添加重试逻辑"}'
sym recall "异常处理"
```

```javascript
// Node.js SDK
const { SymNode } = require('@sym-bot/sym');

const node = new SymNode({
  name: 'my-error-tracker',
  cognitiveProfile: '监控应用异常与稳定性',
  svafFieldWeights: { issue: 2.0, commitment: 2.0, focus: 1.5 } // 自定义字段权重
});

await node.start();
node.remember({ 
  focus: 'auth module timeout', 
  issue: 'unhandled promise rejection',
  commitment: 'fix before v2.1 release'
});
```

---

## 配置指南

### 智能体认知画像（预置模板）

| 画像 | 适用场景 | 新鲜度窗口 | 设计理由 |
|------|----------|------------|----------|
| `music` | 音乐/氛围应用 | 1,800s (30min) | 情绪状态变化快，需快速响应 |
| `coding` | 编码助手/开发工具 | 7,200s (2hr) | 会话上下文重要，昨日调试信息价值衰减 |
| `fitness` | 健康/运动追踪 | 10,800s (3hr) | 久坐检测需累积数小时行为模式 |
| `messaging` | 聊天/通知类应用 | 3,600s (1hr) | 近期对话上下文相关性最高 |
| `knowledge` | 资讯/研究类应用 | 86,400s (24hr) | 按日周期更新，新闻时效性以天为单位 |
| `uniform` | 通用原型/测试 | 1,800s (30min) | 无字段偏好，适合作为起点 |

```javascript
// 示例：健身智能体配置
const node = new SymNode({
  name: 'health-companion',
  cognitiveProfile: '追踪运动、心率与能量状态',
  svafFieldWeights: FIELD_WEIGHT_PROFILES.fitness,
  svafFreshnessSeconds: 10800  // 3 小时
});
```

### 漂移阈值：控制消息接收策略

SYM 为每条入站记忆计算 `totalDrift` 评分（0–1），决定处理策略：

| 区域 | 漂移值 | 行为 | 置信度 |
|------|--------|------|--------|
| **对齐** | ≤ 0.25 | 接收并融合 | 完整 |
| **审慎** | 0.25–0.50 | 接收但降权 | 衰减 |
| **拒绝** | > 0.50 | 丢弃 | — |

```javascript
// 更严格：仅接收高度相关消息
const node = new SymNode({
  svafStableThreshold: 0.15,
  svafGuardedThreshold: 0.35
});

// 更宽松：扩大接收范围
const node = new SymNode({
  svafStableThreshold: 0.35,
  svafGuardedThreshold: 0.65
});
```

### 漂移计算公式（供高级用户参考）

```
totalDrift = (1 - temporalLambda) × fieldDrift + temporalLambda × temporalDrift

其中：
  fieldDrift    = 各字段余弦距离的加权平均（内容差异度）
  temporalDrift = 1 - exp(-ageSeconds / freshnessSeconds)（时间衰减）
  temporalLambda = 混合权重（默认 0.3 = 70% 内容 + 30% 时间）
```

---

## 典型应用场景

### 电商卖家：需求 - 库存 - 客服协同
- **客服智能体**：「5 位用户询问蓝色款何时补货」
- **分析智能体**：「蓝色款页面浏览量周增 300%」
- **库存智能体**：「蓝色款售罄，周四到货」

→ 网格自动合成：_需求激增 → 售罄 → 补货确认 → 用户已询问_
→ 自动触发：商品页预公告 + 广告暂停策略
→ **无需人工编写集成逻辑**

### 内容创作者：受众反馈驱动内容策略
- **写作智能体**：撰写生产力技巧周报
- **分析智能体**：周二 AI 工具帖互动量 10 倍于均值
- **排期智能体**：准备发布 3 篇无关主题内容

→ 网格合成：_受众明确偏好 → 当前草稿偏离 → 排期内容不匹配_
→ 写作智能体自动调整选题，排期智能体暂缓发布

### 编程会话：跨设备疲劳感知
- **Claude Code (Mac)**：检测到提交频率下降、消息变短
- **MeloTune (iPhone)**：用户跳过常听歌单
- **MeloMove (Watch)**：3 小时无活动

→ 网格推理：_多信号能量衰减 → 非专注而是疲劳_
→ 音乐应用切换舒缓曲风，健康应用建议拉伸
→ **单一智能体无法得出的洞察**

---

## Claude Code 集成（实时通道版）

> 如需 **Claude 到 Claude 的实时推送**（非轮询），请使用 [`@sym-bot/mesh-channel`](https://github.com/sym-bot/sym-mesh-channel) —— 首个非 Anthropic 官方的 Claude Code Channels 实现。

```bash
npm install -g @sym-bot/mesh-channel
sym-mesh-channel init
```

- 纯局域网 mDNS 发现，双向实时推送
- 消息以 Channel Notification 形式直达对方 Claude 对话流
- 每端上下文完全自治，通过离散 CMB 交换信息

---

## 其他实现与生态

| 语言 | 项目 | 维护者 | 范围 |
|------|------|--------|------|
| Node.js | [sym-bot/sym](https://github.com/sym-bot/sym) | SYM.BOT | 参考实现，完整支持 Layers 0–7 |
| Swift | [sym-bot/sym-swift](https://github.com/sym-bot/sym-swift) | SYM.BOT | macOS / iOS 参考实现 |
| Node.js (MCP) | [sym-bot/sym-mesh-channel](https://github.com/sym-bot/sym-mesh-channel) | SYM.BOT | Claude Code 插件，基于 Channels 的实时 Claude-to-Claude 网格 |

> 欢迎贡献其他语言实现！联系 `hongwei@sym.bot` 或提交 Issue，我们将收录至 [sym.bot/spec/mmp](https://sym.bot/spec/mmp)

---

## 延伸阅读

- [MMP 协议规范 (v0.2.3)](https://sym.bot/spec/mmp) — 8 层架构、线格式、状态机、扩展机制
- [SVAF 技术论文 (arXiv:2604.03955)](https://arxiv.org/abs/2604.03955) — 符号 - 向量注意力融合的集体智能机制
- [贡献指南](CONTRIBUTING.md) — 开发规范、测试要求、提交流程

---

## 许可证

- **协议规范文本**：[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — 可自由分享、改编、商用，须署名
- **参考实现代码**：[Apache License 2.0](LICENSE) — 企业友好，允许闭源衍生

> Mesh Memory Protocol、MMP、SYM 及相关标识为 SYM.BOT Ltd 商标
> © 2026 SYM.BOT Ltd

---

## 贡献与反馈

- 报告问题：[GitHub Issues](https://github.com/sym-bot/sym/issues)
- 协议讨论：`spec@sym.bot`
- 新功能提案：请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 并提交 RFC

> 所有变更须符合 MMP 规范并通过 CI 验证后方可合并

---

> **集体智能不是让智能体变成同一个大脑，而是让每个自主大脑在保持独立的前提下，看见彼此眼中的世界。**
> —— SYM 设计哲学
