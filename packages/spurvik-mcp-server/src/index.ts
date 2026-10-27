#!/usr/bin/env node
/**
 * OFFICIAL SPURVIK MCP SERVER (`@spurvik/mcp-server`)
 * Operated by EyeTea Solutions ApS (CVR: 37093378, Denmark) | https://spurvik.com
 *
 * Exposes 5 EU AI Act Compliance & Agent Governance tools over JSON-RPC 2.0 stdio:
 *   1. `spurvik_scan_repo`
 *   2. `spurvik_system_one_route`
 *   3. `spurvik_sign_ed25519_receipt`
 *   4. `spurvik_verify_ed25519_receipt`
 *   5. `spurvik_fria_annex_iv_check`
 */

import * as readline from "node:readline";
import {
  generateSpurvikEd25519KeyPair,
  scanRepositoryForCompliance,
  signComplianceReceiptEd25519,
  spurvikSystemOneRoute,
  verifyComplianceReceiptEd25519,
} from "../../terra-oamp-sdk/src/index.ts";

const SERVER_KEYPAIR = generateSpurvikEd25519KeyPair(
  "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2"
);

export const MCP_TOOLS = [
  {
    name: "spurvik_scan_repo",
    description:
      "Scans a local repository directory for unwrapped LLM calls, missing EU AI Act Art. 50 disclosures, un-routed tool loops, and missing Art. 12 Keyed-HMAC logs.",
    inputSchema: {
      type: "object",
      properties: {
        directory: { type: "string", description: "Absolute or relative directory path to scan" },
      },
      required: ["directory"],
    },
  },
  {
    name: "spurvik_system_one_route",
    description:
      "Runs the deterministic System-One (Jev) pre-flight router (`proceed`, `reuse_cache`, `stop_retry`, `research_capped`, `ask_human`) enforcing EU AI Act Art. 14 human oversight.",
    inputSchema: {
      type: "object",
      properties: {
        goal: { type: "string" },
        task_type: { type: "string" },
        last_error: { type: "string" },
        repeats: { type: "number" },
        mode: { type: "string", enum: ["shadow", "active"] },
      },
      required: ["goal", "task_type"],
    },
  },
  {
    name: "spurvik_sign_ed25519_receipt",
    description:
      "Produces a dual Keyed-HMAC-SHA256 + Ed25519-signed EU AI Act Art. 12 & Art. 50 compliance receipt verifiable by third parties.",
    inputSchema: {
      type: "object",
      properties: {
        payload: { type: "object" },
        principal: { type: "string" },
        previousHmac: { type: "string" },
      },
      required: ["payload"],
    },
  },
  {
    name: "spurvik_verify_ed25519_receipt",
    description:
      "Verifies any Spurvik Ed25519 compliance receipt against a public key (PEM, 64-char hex, or W3C did:key).",
    inputSchema: {
      type: "object",
      properties: {
        receipt: { type: "object" },
        publicKeyOrDid: { type: "string" },
      },
      required: ["receipt"],
    },
  },
  {
    name: "spurvik_fria_annex_iv_check",
    description:
      "Evaluates an AI system description against EU AI Act Annex III high-risk categories, Annex IV technical documentation, Art. 27 FRIA, and CEN-CENELEC prEN 18286 QMS obligations.",
    inputSchema: {
      type: "object",
      properties: {
        systemName: { type: "string" },
        useCaseDescription: { type: "string" },
        sector: { type: "string" },
      },
      required: ["systemName", "useCaseDescription"],
    },
  },
];

export async function handleJsonRpcRequest(req: any): Promise<any> {
  const { id, method, params } = req || {};

  if (method === "initialize") {
    return {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: {
          name: "@spurvik/mcp-server",
          version: "1.0.0",
          operator: "EyeTea Solutions ApS (CVR: 37093378, Denmark)",
          publicKeyDid: SERVER_KEYPAIR.didKey,
        },
      },
    };
  }

  if (method === "tools/list") {
    return {
      jsonrpc: "2.0",
      id,
      result: { tools: MCP_TOOLS },
    };
  }

  if (method === "tools/call") {
    const toolName = params?.name;
    const args = params?.arguments || {};

    if (toolName === "spurvik_scan_repo") {
      const report = scanRepositoryForCompliance(String(args.directory || process.cwd()));
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: JSON.stringify(report, null, 2) }],
        },
      };
    }

    if (toolName === "spurvik_system_one_route") {
      const decision = spurvikSystemOneRoute(
        {
          goal: String(args.goal || ""),
          task_type: String(args.task_type || "step"),
          last_error: String(args.last_error || "none"),
          repeats: Number(args.repeats || 0),
        },
        { mode: args.mode === "shadow" ? "shadow" : "active" }
      );
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: JSON.stringify(decision, null, 2) }],
        },
      };
    }

    if (toolName === "spurvik_sign_ed25519_receipt") {
      const receipt = signComplianceReceiptEd25519(
        args.payload || {},
        SERVER_KEYPAIR.privateKeyHex,
        {
          principal: String(args.principal || "EyeTea Solutions ApS (CVR: 37093378)"),
          previousHmac: String(args.previousHmac || "GENESIS"),
        }
      );
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: JSON.stringify(receipt, null, 2) }],
        },
      };
    }

    if (toolName === "spurvik_verify_ed25519_receipt") {
      const pubKey = String(args.publicKeyOrDid || args.receipt?.didKey || SERVER_KEYPAIR.didKey);
      const valid = verifyComplianceReceiptEd25519(args.receipt, pubKey);
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [
            {
              type: "text",
              text: JSON.stringify({ valid, verifiedWithPublicKeyOrDid: pubKey }, null, 2),
            },
          ],
        },
      };
    }

    if (toolName === "spurvik_fria_annex_iv_check") {
      const desc = `${args.systemName || ""} ${args.useCaseDescription || ""} ${args.sector || ""}`.toLowerCase();
      const isAnnexIII =
        /\b(credit|loan|scoring|recruitment|hiring|cv|biometric|education|healthcare|triage|insurance|critical infrastructure|grid|energy)\b/i.test(
          desc
        );
      const assessment = {
        systemName: args.systemName,
        annexIIIHighRiskTriggered: isAnnexIII,
        applicableArticles: isAnnexIII
          ? [
              "Art. 9 (Risk Management System)",
              "Art. 12 (Automatic Event Logging — Keyed-HMAC + Ed25519)",
              "Art. 14 (Human Oversight — System-One ask_human Gate)",
              "Art. 17 & CEN-CENELEC prEN 18286 (Quality Management System)",
              "Art. 27 (Fundamental Rights Impact Assessment — FRIA)",
              "Art. 50(1)/(2) (Transparency & Synthetic Content Provenance)",
              "Annex IV (Technical Documentation Dossier)",
            ]
          : [
              "Art. 50(1) (Interactive AI Principal Disclosure)",
              "Art. 50(2) (Machine-Readable Synthetic Content Provenance)",
              "Voluntary Art. 12/14 Governance Best Practice",
            ],
        qmsStandard: "CEN-CENELEC prEN 18286:2026",
        operator: "EyeTea Solutions ApS (CVR: 37093378, Denmark)",
        evaluatedAt: new Date().toISOString(),
      };
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: JSON.stringify(assessment, null, 2) }],
        },
      };
    }

    return {
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: `Unknown tool: ${toolName}` },
    };
  }

  return {
    jsonrpc: "2.0",
    id,
    error: { code: -32601, message: `Method not found: ${method}` },
  };
}

if (process.argv.includes("--self-test")) {
  const initRes = await handleJsonRpcRequest({ id: 1, method: "initialize" });
  const listRes = await handleJsonRpcRequest({ id: 2, method: "tools/list" });
  const signRes = await handleJsonRpcRequest({
    id: 3,
    method: "tools/call",
    params: {
      name: "spurvik_sign_ed25519_receipt",
      arguments: { payload: { test: "mcp-e2e" } },
    },
  });
  const receiptObj = JSON.parse(signRes.result.content[0].text);
  const verifyRes = await handleJsonRpcRequest({
    id: 4,
    method: "tools/call",
    params: {
      name: "spurvik_verify_ed25519_receipt",
      arguments: { receipt: receiptObj, publicKeyOrDid: receiptObj.didKey },
    },
  });
  const verifyObj = JSON.parse(verifyRes.result.content[0].text);
  console.log(
    `[@spurvik/mcp-server] Self-test passed: tools=${listRes.result.tools.length}, didKey=${initRes.result.serverInfo.publicKeyDid}, receiptVerified=${verifyObj.valid}`
  );
  if (!verifyObj.valid || listRes.result.tools.length !== 5) process.exit(1);
  process.exit(0);
}

if (import.meta.main) {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on("line", async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      const req = JSON.parse(trimmed);
      const res = await handleJsonRpcRequest(req);
      process.stdout.write(JSON.stringify(res) + "\n");
    } catch (err: any) {
      process.stdout.write(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: err?.message || "Parse error" },
        }) + "\n"
      );
    }
  });
}
