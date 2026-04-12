<div align="center">

<a href="https://agentverif.com"><img src="https://agentverif.com/logo.png" alt="AgentVerif" width="200" /></a>

<h1>AgentVerif</h1>

<p>✅ Sell verified agents. Buyers trust verified packages. Unsigned agents get ignored. Add verification in seconds. <a href="https://agentverif.com">agentverif.com</a></p>

<a href="https://github.com/trusthandoff/agentverif/actions/workflows/publish.yml"><img src="https://github.com/trusthandoff/agentverif/actions/workflows/publish.yml/badge.svg" alt="CI" /></a>
<a href="https://pypi.org/project/agentverif-sign/"><img src="https://img.shields.io/pypi/v/agentverif-sign.svg" alt="PyPI 版本" /></a>
<a href="https://x.com/agentverif"><img src="https://img.shields.io/badge/follow-%40agentverif-000000?logo=x&logoColor=white" alt="X (Twitter)" /></a>
<a href="https://www.moltbook.com/u/agentverif"><img src="https://img.shields.io/badge/Moltbook-agentverif-7B2FFF?logoColor=white" alt="Moltbook" /></a>

</div>

[English](README.md) | [中文]

---

**agentverif-sign** 是 AI Agent 分发的 SSL 证书。供应商签名，买家验证，注册表是唯一可信来源。

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
