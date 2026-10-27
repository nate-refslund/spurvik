# `@spurvik/mcp-server` — Official Spurvik MCP Server

Operated by **EyeTea Solutions ApS** (CVR: 37093378, Denmark) · [https://spurvik.com](https://spurvik.com)

Model Context Protocol (MCP) server exposing EU AI Act Art. 50 Transparency, Art. 12 Keyed-HMAC-SHA256 + Ed25519 Signed Audit Receipts, Art. 14 System-One (`Jev`) Pre-Flight Human Oversight Routing, and Annex IV / CEN-CENELEC prEN 18286 QMS conformity checks directly inside Claude Code, Cursor, Windsurf, and MCP-compatible agent runtimes.

## Tools Included

1. **`spurvik_scan_repo`** — Scans a repository directory for unwrapped LLM calls and scores EU AI Act readiness (0–100).
2. **`spurvik_system_one_route`** — Deterministic pre-flight router (`proceed`, `reuse_cache`, `stop_retry`, `research_capped`, `ask_human`).
3. **`spurvik_sign_ed25519_receipt`** — Generates a dual Keyed-HMAC-SHA256 + Ed25519 detached signature receipt (`did:key`).
4. **`spurvik_verify_ed25519_receipt`** — Independently verifies any Spurvik Ed25519 compliance receipt.
5. **`spurvik_fria_annex_iv_check`** — Evaluates an AI system against Annex III, Annex IV, Art. 27 FRIA, and prEN 18286 QMS obligations.
