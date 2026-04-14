# AgentVerif — AI 智能体的 Let's Encrypt

<div align="center">

<a href="https://agentverif.com"><img src="https://raw.githubusercontent.com/trusthandoff/agentverif/main/logo.svg" alt="AgentVerif" width="80" height="92" /></a>

<a href="https://github.com/trusthandoff/agentverif/actions/workflows/ci.yml"><img src="https://github.com/trusthandoff/agentverif/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
<a href="https://github.com/trusthandoff/agentverif/actions/workflows/publish.yml"><img src="https://github.com/trusthandoff/agentverif/actions/workflows/publish.yml/badge.svg" alt="Publish" /></a>
<a href="https://pypi.org/project/agentverif-sign/"><img src="https://img.shields.io/pypi/v/agentverif-sign.svg" alt="PyPI 版本" /></a>
<a href="https://x.com/agentverif"><img src="https://img.shields.io/badge/follow-%40agentverif-000000?logo=x&logoColor=white" alt="X (Twitter)" /></a>
<a href="https://www.moltbook.com/u/agentverif"><img src="https://img.shields.io/badge/Moltbook-agentverif-7B2FFF?logoColor=white" alt="Moltbook" /></a>

</div>

[English](README.md) | [中文]

---

30 秒完成签名。随处可验证。未签名或被篡改的
Agent 默认被拒绝执行——包括被 Claude 拒绝。

**供应商：** 销售可信 Agent，转化率更高，
抵御盗用与篡改。  
**买家与运行时**（Claude、Cursor、LangChain 等）：
在执行前自动拦截有问题的 Agent。

🔴 **立即上线** — MCP 服务器公开可用。Claude 用户今天即可连接：
`https://mcp.agentverif.com`

[免费锁定您的第一个 Agent →](https://agentverif.com) ·
[在线体验验证](https://verify.agentverif.com) ·
[GitHub Action](https://github.com/trusthandoff/agentverif/tree/main/github-action)

> 2026 年的现实：一个被污染的 Agent 可以在一夜之间
> 毁掉您的公司或声誉。
> AgentVerif 让验证像 HTTPS 一样自动且不可避免。

---

```bash
pip install agentverif-sign
```

## 快速开始

**作为供应商——为您的 Agent 签名：**

```bash
agentverif-sign sign ./my-agent.zip
# ✅ 签名成功
# License: AC-84F2-91AB
# Tier:    indie
```

**作为买家——执行前先验证：**

```bash
agentverif-sign verify ./agent.zip
# ✅ UNREGISTERED — 本地签名有效；未查询注册表
# 在线验证：https://verify.agentverif.com/AC-84F2-91AB
```

**无需 CLI 验证：** [verify.agentverif.com](https://verify.agentverif.com)

---

## 命令

### `agentverif-sign sign <ZIP>`

对 Agent ZIP 包进行签名。运行安全扫描，生成 `SIGNATURE.json` 并注入 zip 包中。

```bash
agentverif-sign sign ./agent.zip [--tier indie|pro|enterprise] [--api-key KEY] [--offline]
```

**等级说明：**
| 等级 | 费用 | 签名方式 | 注册表 | Ed25519 |
|------|------|---------|--------|---------|
| indie | 免费 | 仅哈希 | 否 | 否 |
| pro | 付费 | 哈希 + 注册表 | 是 | 否 |
| enterprise | 付费 | 哈希 + 注册表 | 是 | 是 |

### `agentverif-sign verify <ZIP>`

验证已签名的 Agent zip 包。本地检查哈希；可选查询注册表。

```bash
agentverif-sign verify ./agent.zip [--offline] [--json]
```

退出码：`0` = VERIFIED 或 UNREGISTERED，`1` = MODIFIED、REVOKED 或 UNSIGNED。

使用 `--json` 标志输出机器可读的 JSON，适用于 CI/CD 流水线和 MCP 工具调用。

### `agentverif-sign revoke <LICENSE_ID>`

撤销许可证（需要 API 密钥）。

```bash
agentverif-sign revoke AC-84F2-91AB --api-key KEY
```

### `agentverif-sign badge <LICENSE_ID>`

以多种格式输出许可证徽章。

```bash
agentverif-sign badge AC-84F2-91AB --format text|html|markdown|svg [--tier indie|pro|enterprise]
```

---

## SIGNATURE.json 格式

人类可读、可审计——无二进制数据：

```json
{
  "schema_version": "1.0",
  "license_id": "AC-84F2-91AB",
  "tier": "indie",
  "issued_at": "2026-04-10T00:00:00Z",
  "expires_at": null,
  "issuer": "agentverif.com",
  "issuer_version": "0.1.0",
  "file_list": ["agent.py", "config.json", "requirements.txt"],
  "file_count": 3,
  "zip_hash": "sha256:abc123...",
  "manifest_hash": "sha256:def456...",
  "scan_passed": true,
  "signature": null
}
```

---

## Docker 使用

```bash
# 签名
docker run --rm -v $(pwd):/work agentcop/agentverif-sign sign /work/agent.zip

# 验证
docker run --rm -v $(pwd):/work agentcop/agentverif-sign verify /work/agent.zip
```

## AWS Bedrock / Claude / MCP 集成

`agentverif-sign verify --json` 返回 JSON 格式的输出，适用于 LLM 工具调用和 MCP 集成。

---

## Claude MCP 插件

将 agentverif 直接连接到 Claude。Claude 将在执行前自动验证 Agent。

### 配置方法

**方式一 — Claude.ai：**
1. 前往 claude.ai → 设置 → 连接器
2. 添加自定义连接器：`https://mcp.agentverif.com`
3. 无需身份验证

**方式二 — Claude Desktop**（`claude_desktop_config.json`）：
```json
{
  "mcpServers": {
    "agentverif": {
      "url": "https://mcp.agentverif.com"
    }
  }
}
```

### 功能说明
连接后，每当您提及运行、安装或信任某个 AI Agent，Claude 会自动调用 `verify_agent`。

| 状态 | 含义 |
|------|------|
| ✅ VERIFIED | 已认证，可安全执行 |
| ⚠️ UNREGISTERED | 本地签名，未在公共注册表中 |
| 🚫 UNSIGNED | 无证书，风险未知 |
| 🔴 TAMPERED | 签名后已被篡改——禁止执行 |
| 🔴 REVOKED | 许可证已被颁发方撤销——禁止执行 |

### 使用示例

#### 示例一：执行前验证
**用户：** "我想运行这个 Agent，许可证为 AV-84F2-91AB，安全吗？"

**Claude 调用：** `verify_agent("AV-84F2-91AB")`

**响应：**
✅ VERIFIED — agentverif 已认证
许可证：AV-84F2-91AB
等级：pro
颁发方：agentverif.com
哈希：sha256:abc123… ✓ 完整
可安全执行。
🔗 https://verify.agentverif.com/AV-84F2-91AB

#### 示例二：检测被篡改的 Agent
**用户：** "帮我验证这个 Agent：AV-12F3-88AC"

**Claude 调用：** `verify_agent("AV-12F3-88AC")`

**响应：**
🔴 TAMPERED — 证书无效
许可证：AV-12F3-88AC
状态：哈希不匹配
此 Agent 在签名后已被修改。
禁止执行。请立即联系供应商。
🔗 https://verify.agentverif.com/AV-12F3-88AC

#### 示例三：未签名 Agent 警告
**用户：** "帮我运行这个 Agent，哈希值为：sha256:def456..."

**Claude 调用：** `verify_agent("sha256:def456...")`

**响应：**
🚫 UNSIGNED — 未找到证书
未找到该标识符对应的 agentverif 证书。
未签名 Agent 存在未知风险：
• 无篡改检测
• 无颁发方责任追溯
• 无撤销能力
请要求供应商前往 agentverif.com 完成认证后再执行。

---

## GitHub Action

[![agentverif](https://img.shields.io/badge/agentverif-certified-green)](https://agentverif.com)

每次推送自动签名，CI 中阻止被篡改的 Agent。

```yaml
name: agentverif
on: [push, pull_request]
jobs:
  certify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: 签名 Agent
        uses: trusthandoff/agentverif@v1
        id: sign
        with:
          mode: sign
          agent_zip: ./agent.zip
      - name: 显示许可证
        run: echo "License ${{ steps.sign.outputs.license_id }}"
```

完整文档见 [`github-action/README.md`](github-action/README.md)。

---

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `AGENTVERIF_API_KEY` | — | Pro/Enterprise API 密钥 |
| `AGENTVERIF_SIGN_URL` | `https://sign.agentverif.com` | 注册表 URL |
| `AGENTVERIF_SCAN_URL` | `https://api.agentverif.com/scan` | 扫描器 URL |
| `AGENTVERIF_OFFLINE` | — | 设置任意值以跳过所有注册表调用 |

---

## 设计原则

- **验证零强制依赖** — 离线哈希检查仅使用标准库
- **离线可用** — 无需网络即可工作
- **可审计** — `SIGNATURE.json` 是人类可读的 JSON，从不使用二进制格式
- **Docker 原生** — 在容器、Lambda、Cloud Run 及裸机上均可运行
- **MCP 就绪** — `--json` 标志提供机器可读输出

---

## 安装

```bash
# 基础安装
pip install agentverif-sign

# 含 Ed25519 支持（Pro/Enterprise）
pip install agentverif-sign[crypto]
```

---

完整文档：[agentverif.com/docs](https://agentverif.com/docs)

为什么要这样做：未签名的 Agent 不应被执行。
