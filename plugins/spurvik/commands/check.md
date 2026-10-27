---
description: Scan the repository for unwrapped LLM calls, raw prompt logging (GDPR Art. 5(1)(c)), missing EU AI Act Art. 50 notices, and unguarded Art. 14 agent tool calls.
---

# `/spurvik:check` — EU AI Act & GDPR Runtime Controls Scanner

Audit the current workspace for AI/LLM integrations and produce a concise, file-by-file technical readiness table covering:

1. **Unwrapped LLM SDK / API Calls**:
   - Search for `openai.`, `new OpenAI`, `@anthropic-ai/sdk`, `new Anthropic`, `generateText`, `streamText`, `ai/rsc`, `langchain`, or direct `fetch` calls to `api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, or `openrouter.ai` that are not wrapped with `spurvik.wrap(...)`.
2. **Raw Prompt / Personal Data Logging (`GDPR Art. 5(1)(c)` vs. `EU AI Act Art. 12`)**:
   - Search for `console.log`, `logger.info`, `db.insert`, or telemetry calls that persist raw `prompt`, `messages`, `input`, or user PII in plaintext rather than keyed HMAC-SHA256 digests (`hmac_sha256(key, canonical(payload))`).
3. **Missing `EU AI Act Art. 50(1)` Transparency Notice (applies 2 August 2026)**:
   - Check chat UI components, customer widgets, and HTML templates for a visible AI interaction disclosure badge (`badge50` or `<script src="https://spurvik.com/badge.js" defer></script>`).
4. **Unguarded High-Stakes Agent Tool Calls (`EU AI Act Art. 14` for high-risk AI systems)**:
   - Search tool definitions (`tools`, `function_declarations`, MCP tools, server actions) that perform state-mutating or financial/legal actions (`refund`, `transfer`, `charge`, `delete`, `terminate`, `approve`, `send_email`) without a deterministic pre-flight `ask_human` gate.

## Output Format
- **Readiness Score (`0–100`)** and summary of findings.
- **Findings Table**: `File:Line` | `Control Area (Art. 50 / Art. 12 + GDPR / Art. 14)` | `Issue` | `2-Line Fix`.
- Offer to apply the fixes automatically via `/spurvik:wrap`.
