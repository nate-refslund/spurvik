# Spurvik — EU AI Act Runtime Guardrails (`@spurvik/sdk` · MCP · Claude Code Plugin)

Runtime controls for AI builders and engineering teams that support **EU AI Act Art. 50** AI transparency notices (applies **2 August 2026**) and, for high-risk AI systems, **Art. 12** pseudonymised HMAC-SHA256 event logging (`0B` raw prompt text persisted, supporting **GDPR Art. 5(1)(c)** data minimisation) and **Art. 14** deterministic `ask_human` oversight gates.

- **Website**: [https://spurvik.com](https://spurvik.com)
- **Interactive Sandbox & Cockpit**: [https://console.spurvik.com/sandbox](https://console.spurvik.com/sandbox)
- **Remote MCP Endpoint (Replit / Lovable / Cursor)**: `https://console.spurvik.com/api/mcp`
- **v0 / shadcn Registry Starter**: `https://spurvik.com/r/eu-ai-act.json`

---

## Included in This Repository

| Path | Description |
| :--- | :--- |
| [`plugins/spurvik`](./plugins/spurvik) | Official Claude Code & Antigravity Plugin (`/spurvik:check`, `/spurvik:wrap`, `/spurvik:dpo-pack`, `eu-ai-act-guardrails` skill) |
| [`packages/spurvik-sdk`](./packages/spurvik-sdk) | TypeScript Runtime SDK (`withSpurvik`, `wrapOpenAIDecision`, `wrapHermesOrOpenClawAgent`, System-One `Jev` Router, Ed25519 + HMAC-SHA256 receipts) |
| [`packages/spurvik-mcp-server`](./packages/spurvik-mcp-server) | Local & stdio MCP Server for Claude Code, Cursor, and Windsurf |
| [`.claude-plugin/marketplace.json`](./.claude-plugin/marketplace.json) | Claude Code Plugin Marketplace manifest |

---

## Quick Start

### 1. Claude Code Plugin
```bash
/plugin marketplace add spurvik/spurvik
/plugin install spurvik@spurvik-marketplace
```

### 2. Remote MCP (Lovable / Replit / Cursor)
Add the zero-auth Streamable HTTP MCP server:
```text
https://console.spurvik.com/api/mcp
```

### 3. v0 by Vercel / shadcn Registry
```bash
npx shadcn@latest add https://spurvik.com/r/eu-ai-act.json
```

---

## Scope & Legal Notice
Operated in Denmark by **EyeTea Solutions ApS** (CVR 37093378 · `hello@spurvik.com`). Spurvik provides software runtime controls and technical evidence summaries that support obligations under Regulation (EU) 2024/1689 (EU AI Act) and Regulation (EU) 2016/679 (GDPR). It is not legal advice and does not constitute a notified-body conformity certification.
