---
description: Generate a DPO & Conformity Assessment Technical Evidence Summary (SPURVIK-EVIDENCE.md) mapping the repository's AI controls to EU AI Act Art. 50, Art. 12, Art. 14, and GDPR Art. 5(1)(c).
---

# `/spurvik:dpo-pack` — Generate DPO & Conformity Technical Evidence Summary

Scan the repository and generate `SPURVIK-EVIDENCE.md` (or update it if it exists) so engineering can hand a clear, verifiable technical brief to the Data Protection Officer (DPO), Legal Counsel, or Enterprise Procurement team.

Include:
1. **AI System Inventory**: Every LLM provider, model, and user-facing surface detected in the repository.
2. **Art. 50(1) Transparency Controls (applies 2 August 2026)**: How and where users are informed they are interacting with an AI system (plus opt-in C2PA content credentials if synthetic media is generated).
3. **Art. 12 Record-Keeping & GDPR Art. 5(1)(c) Data Minimisation (for high-risk AI systems, 2 August 2026 / 2 August 2027)**: How event logs are recorded as chained HMAC-SHA256 digests (`prev_hash || event_digest`) in `eu-central-1` (Frankfurt) with **no raw prompt text persisted**.
4. **Art. 14 Human Oversight Controls (for high-risk AI systems)**: Which agent tools or thresholds trigger the deterministic System-One pre-flight `ask_human` gate before execution.
5. **Scope & Legal Note**: State clearly that Spurvik provides technical runtime controls and engineering evidence summaries that support the deployer/provider's obligations under Regulation (EU) 2024/1689 and GDPR, and is not legal advice or a notified-body certification.
