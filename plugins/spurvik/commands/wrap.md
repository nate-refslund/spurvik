---
description: Wrap LLM SDK calls with Spurvik's 2-line runtime controls (Art. 50 notice, Art. 12 HMAC-SHA256 digest logging without raw prompt text, and Art. 14 System-One human gate) or inject the 1-line no-code HTML script.
---

# `/spurvik:wrap` — Apply 2-Line Spurvik EU AI Act Runtime Controls

Inspect the current project (or the file specified in `$ARGUMENTS`) and apply the minimal, non-breaking Spurvik runtime controls:

## Option A: TypeScript / JavaScript / Next.js / Node / Bun Projects
Wrap existing OpenAI, Anthropic, or Vercel AI SDK clients in 2 lines using `@spurvik/sdk`:

```ts
import { spurvik } from "@spurvik/sdk";

const ai = spurvik.wrap(openai, {
  systemId: process.env.SPURVIK_SYSTEM_ID ?? "prod-assistant",
  art50Notice: true, // Emits Art. 50(1) AI disclosure metadata / badge hook
  art12HmacLog: {
    persistRawPrompts: false, // Never persists raw prompt text (GDPR Art. 5(1)(c))
    region: "eu-central-1"
  },
  art14HumanGate: {
    mode: "active", // Deterministic System-One pre-flight gate -> proceed | ask_human
    requireApprovalAboveEur: 200,
    highStakesTools: ["issue_refund", "wire_transfer", "delete_account", "send_contract"]
  }
});
```

## Option B: No-Code / Static HTML / Webflow / WordPress / Shopify / Lovable Export
Add the 1-line cookie-free Art. 50 AI Transparency Badge before `</body>`:

```html
<script src="https://spurvik.com/badge.js" data-position="bottom-right" data-lang="auto" defer></script>
```

After applying the changes, show a clean diff and run the project's typecheck or linter to verify zero regressions.
