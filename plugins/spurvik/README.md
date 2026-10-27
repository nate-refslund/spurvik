# Spurvik Plugin for Claude Code & Antigravity (`spurvik`)

Runtime controls for AI engineers and builders that support **EU AI Act Art. 50** AI transparency notices (applies 2 August 2026) and, for high-risk AI systems, **Art. 12** pseudonymised HMAC-SHA256 event logging (no raw prompt text persisted, supporting **GDPR Art. 5(1)(c)** data minimisation) and **Art. 14** deterministic System-One `ask_human` gates.

Built in Denmark by **EyeTea Solutions ApS** (CVR 37093378 · [https://spurvik.com](https://spurvik.com)).

---

## Install in Claude Code (2 Commands)

1. Register the Spurvik Plugin Marketplace inside Claude Code:
   ```bash
   /plugin marketplace add https://spurvik.com/.claude-plugin/marketplace.json
   ```
   *(Or via GitHub: `/plugin marketplace add spurvik/spurvik`)*

2. Install the `spurvik` plugin:
   ```bash
   /plugin install spurvik@spurvik-marketplace
   ```

---

## Included Slash Commands, Skills, MCP Server & Hooks

| Component | Name | What It Does |
| :--- | :--- | :--- |
| **Command** | `/spurvik:check` | Scans your repository for unwrapped OpenAI / Anthropic / Vercel AI calls, plaintext prompt logs (`console.log(prompt)`), missing Art. 50 notices, and unguarded agent tools. |
| **Command** | `/spurvik:wrap` | Wraps your LLM client in 2 lines with `@spurvik/sdk` or injects the 1-line `<script src="https://spurvik.com/badge.js" defer></script>` for no-code/static HTML sites. |
| **Command** | `/spurvik:dpo-pack` | Generates `SPURVIK-EVIDENCE.md` — a structured technical readiness brief for your DPO, legal counsel, or enterprise customer security review. |
| **Skill** | `eu-ai-act-guardrails` | Contextually loaded whenever Claude Code writes or edits LLM/agent code so Art. 50, Art. 12 (HMAC-SHA256 digests), and Art. 14 (`ask_human` gate) patterns are written by default. |
| **MCP Server** | `spurvik-mcp` | Connects `@spurvik/mcp-server` automatically while the plugin is enabled. |
| **Hook** | `PostToolUse` | Non-blocking hint whenever a file is edited with an unwrapped `new OpenAI` / `new Anthropic` call. |

---

## Scope & Legal Notice

Spurvik provides software runtime controls and engineering evidence summaries that support your obligations under Regulation (EU) 2024/1689 (EU AI Act) and Regulation (EU) 2016/679 (GDPR). It is not legal advice and does not constitute a notified-body conformity certification.
