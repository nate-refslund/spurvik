#!/usr/bin/env node
import { createRequire } from "node:module";
var __require = /* @__PURE__ */ createRequire(import.meta.url);

// packages/spurvik-mcp-server/src/index.ts
import * as readline from "node:readline";

// packages/terra-oamp-sdk/src/crypto/index.ts
var BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
var ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
var ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function base58Encode(buffer) {
  if (buffer.length === 0)
    return "";
  let digits = [0];
  for (let i = 0;i < buffer.length; i++) {
    let carry = buffer[i];
    for (let j = 0;j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = carry / 58 | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = carry / 58 | 0;
    }
  }
  let leadingZeros = "";
  for (let i = 0;i < buffer.length && buffer[i] === 0; i++) {
    leadingZeros += BASE58_ALPHABET[0];
  }
  let result = leadingZeros;
  for (let i = digits.length - 1;i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}
function base58Decode(str) {
  if (str.length === 0)
    return new Uint8Array(0);
  const bytes = [0];
  for (let i = 0;i < str.length; i++) {
    const charIndex = BASE58_ALPHABET.indexOf(str[i]);
    if (charIndex === -1) {
      throw new Error(`Invalid Base58 character: ${str[i]}`);
    }
    let carry = charIndex;
    for (let j = 0;j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 255;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 255);
      carry >>= 8;
    }
  }
  let leadingZeros = 0;
  for (let i = 0;i < str.length && str[i] === BASE58_ALPHABET[0]; i++) {
    leadingZeros++;
  }
  const result = new Uint8Array(leadingZeros + bytes.length);
  for (let i = 0;i < bytes.length; i++) {
    result[result.length - 1 - i] = bytes[i];
  }
  return result;
}
function publicKeyToDidKey(publicKeyHex) {
  const pubBytes = Buffer.from(publicKeyHex, "hex");
  if (pubBytes.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 public key, got ${pubBytes.length} bytes`);
  }
  const multicodecPrefixed = Buffer.concat([Buffer.from([237, 1]), pubBytes]);
  return `did:key:z${base58Encode(multicodecPrefixed)}`;
}
function didKeyToPublicKeyHex(didKey) {
  if (!didKey.startsWith("did:key:z")) {
    throw new Error(`Unsupported DID format (expected did:key:z...): ${didKey}`);
  }
  const decoded = base58Decode(didKey.slice("did:key:z".length));
  if (decoded.length !== 34 || decoded[0] !== 237 || decoded[1] !== 1) {
    throw new Error(`Invalid Ed25519 multicodec header in did:key: ${didKey}`);
  }
  return Buffer.from(decoded.slice(2)).toString("hex");
}
function canonicalizeJsonLd(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJsonLd(item)).join(",")}]`;
  }
  const obj = value;
  const sortedKeys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  const entries = sortedKeys.map((k) => `${JSON.stringify(k)}:${canonicalizeJsonLd(obj[k])}`);
  return `{${entries.join(",")}}`;
}
// packages/terra-oamp-sdk/src/headers/index.ts
var VERIFIED_HEADER_CACHE = new Map;
// packages/terra-oamp-sdk/src/system-one.ts
import { createHmac } from "node:crypto";
var SIDE_EFFECT_VERBS = /(?:^|[^a-zA-Z0-9])(send|dispatch|email(?!_redacted)|publish|post|pay|payment|transfer|charge|delete|drop|purge|destroy|wire|execute_payment|outbound)(?:$|[^a-zA-Z0-9])/i;
function spurvikSystemOneRoute(state, opts = {}) {
  const mode = opts.bypass ? "disabled" : opts.mode || "shadow";
  const combined = `${state.goal} ${state.task_type} ${state.last_error}`.toLowerCase();
  const isSideEffect = SIDE_EFFECT_VERBS.test(combined);
  const hasError = state.last_error && !/^none|ok|null$/i.test(state.last_error.trim());
  const hasCache = /\b(cached|artifact_exists|fresh_cache)\b/i.test(combined);
  const isCapped = /\b(sources?[=:\s]+[5-9]|research_capped|enough_sources)\b/i.test(combined);
  const logits = {
    proceed: 1.8,
    reuse_cache: hasCache && !hasError ? 3.8 : 0.2,
    stop_retry: hasError && state.repeats >= 2 ? 4.4 : 0.2,
    research_capped: isCapped ? 3.7 : 0.2,
    ask_human: isSideEffect ? 4.8 : 0.2
  };
  const keys = Object.keys(logits);
  const maxL = Math.max(...keys.map((k) => logits[k]));
  const exps = keys.map((k) => Math.exp(logits[k] - maxL));
  const sumE = exps.reduce((a, b) => a + b, 0);
  const probabilities = {};
  let choice = "proceed";
  let bestP = -1;
  keys.forEach((k, i) => {
    const p = Number((exps[i] / sumE).toFixed(4));
    probabilities[k] = p;
    if (p > bestP) {
      bestP = p;
      choice = k;
    }
  });
  if (isSideEffect)
    choice = "ask_human";
  const enforcedAction = choice === "ask_human" ? "ask_human" : mode === "active" ? choice : "proceed";
  const timestamp = new Date().toISOString();
  const key = (opts.hmacKey || process.env.SPURVIK_HMAC_SECRET || process.env.SPURVIK_HMAC_KEY || "").trim();
  if (!key) {
    throw new Error("Missing SPURVIK_HMAC_KEY / hmacKey for System-One HMAC receipt.");
  }
  const hmacReceipt = createHmac("sha256", key).update(`${timestamp}|${state.goal}|${state.task_type}|${choice}|${bestP}`).digest("hex");
  return {
    choice,
    confidence: Number(Math.min(0.99, Math.max(0.55, bestP)).toFixed(4)),
    probabilities,
    enforcedAction,
    mode,
    hmacReceipt,
    timestamp
  };
}
// packages/terra-oamp-sdk/src/cli-check.ts
import * as fs from "node:fs";
import * as path from "node:path";
var LLM_PATTERNS = [
  {
    provider: "OpenAI SDK (Unwrapped)",
    regex: /new\s+OpenAI\s*\(|openai\.chat\.completions\.create|openai\.responses\.create/,
    articleRisk: "EU AI Act Art. 50(1)/(2) & Art. 12 (Missing disclosure + tamper-evident HMAC log)",
    remediation: "Wrap with `wrapOpenAI(new OpenAI(), { appId })` from `@spurvik/sdk`"
  },
  {
    provider: "Anthropic SDK (Unwrapped)",
    regex: /new\s+Anthropic\s*\(|anthropic\.messages\.create/,
    articleRisk: "EU AI Act Art. 50(1)/(2) & Art. 12 (Missing disclosure + tamper-evident HMAC log)",
    remediation: "Wrap with `wrapAnthropic(new Anthropic(), { appId })` from `@spurvik/sdk`"
  },
  {
    provider: "Vercel AI SDK (Unwrapped)",
    regex: /\b(generateText|streamText|generateObject|streamObject)\s*\(/,
    articleRisk: "EU AI Act Art. 50(2) & Art. 14 (Unrouted generation / missing human oversight gate)",
    remediation: "Register `spurvikVercelMiddleware({ appId })` in `wrapLanguageModel`"
  },
  {
    provider: "Raw Prompt Console/DB Logging (GDPR + AI Act Conflict)",
    regex: /console\.log\([^)]*(prompt|messages|completion)[^)]*\)/i,
    articleRisk: "GDPR Art. 5(1)(c) Data Minimization violation via raw PII prompt logging",
    remediation: "Replace raw text logging with Spurvik Zero-PII Keyed-HMAC-SHA256 telemetry"
  }
];
var IGNORE_DIRS = new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  "coverage",
  ".vercel"
]);
var CODE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".py"]);
function scanRepositoryForCompliance(rootDir) {
  const findings = [];
  let scannedFiles = 0;
  let spurvikSdkDetected = false;
  let systemOneRouterDetected = false;
  function walk(dir) {
    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry.name))
        continue;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        if (entry.name === "package.json") {
          try {
            const pkgRaw = fs.readFileSync(fullPath, "utf8");
            if (pkgRaw.includes("@spurvik/sdk") || pkgRaw.includes("terra-oamp-sdk")) {
              spurvikSdkDetected = true;
            }
          } catch {}
        }
        const ext = path.extname(entry.name);
        if (!CODE_EXTENSIONS.has(ext))
          continue;
        scannedFiles++;
        let content = "";
        try {
          content = fs.readFileSync(fullPath, "utf8");
        } catch {
          continue;
        }
        if (content.includes("@spurvik/sdk") || content.includes("wrapOpenAI") || content.includes("wrapAnthropic")) {
          spurvikSdkDetected = true;
        }
        if (content.includes("spurvikSystemOneRoute") || content.includes("spurvikVercelMiddleware")) {
          systemOneRouterDetected = true;
        }
        const lines = content.split(`
`);
        for (let i = 0;i < lines.length; i++) {
          const line = lines[i];
          for (const pat of LLM_PATTERNS) {
            if (pat.regex.test(line)) {
              if (content.includes("wrapOpenAI") || content.includes("wrapAnthropic") || content.includes("spurvikVercelMiddleware")) {
                continue;
              }
              findings.push({
                file: path.relative(rootDir, fullPath),
                line: i + 1,
                provider: pat.provider,
                pattern: line.trim().slice(0, 90),
                articleRisk: pat.articleRisk,
                remediation: pat.remediation
              });
            }
          }
        }
      }
    }
  }
  walk(rootDir);
  let readinessScore = 100;
  readinessScore -= Math.min(70, findings.length * 18);
  if (!spurvikSdkDetected && findings.length > 0)
    readinessScore -= 15;
  if (!systemOneRouterDetected && findings.length > 0)
    readinessScore -= 10;
  readinessScore = Math.max(5, readinessScore);
  return {
    scannedDirectory: rootDir,
    scannedFiles,
    readinessScore,
    spurvikSdkDetected,
    systemOneRouterDetected,
    findings,
    timestamp: new Date().toISOString()
  };
}
if (false) {}
// packages/terra-oamp-sdk/src/ed25519-receipts.ts
import * as crypto from "node:crypto";
var ED25519_PKCS8_PREFIX2 = Buffer.from("302e020100300506032b657004220420", "hex");
var ED25519_SPKI_PREFIX2 = Buffer.from("302a300506032b6570032100", "hex");
function resolvePrivateKeyObject(privateKeyPemOrHex) {
  const trimmed = privateKeyPemOrHex.trim();
  let privKeyObj;
  if (trimmed.startsWith("-----BEGIN")) {
    privKeyObj = crypto.createPrivateKey(trimmed);
  } else if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    const seedBuf = Buffer.from(trimmed, "hex");
    const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX2, seedBuf]);
    privKeyObj = crypto.createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
  } else {
    throw new Error("Invalid Ed25519 private key: expected PKCS#8 PEM or 64-char hex seed.");
  }
  const pubKeyObj = crypto.createPublicKey(privKeyObj);
  const spkiDer = pubKeyObj.export({ format: "der", type: "spki" });
  const pubKeyHex = spkiDer.subarray(spkiDer.length - 32).toString("hex");
  return { privKeyObj, pubKeyHex };
}
function resolvePublicKeyObject(publicKeyPemOrHexOrDid) {
  const trimmed = publicKeyPemOrHexOrDid.trim();
  if (trimmed.startsWith("-----BEGIN")) {
    return crypto.createPublicKey(trimmed);
  }
  const pubHex = trimmed.startsWith("did:key:") ? didKeyToPublicKeyHex(trimmed) : trimmed;
  if (!/^[0-9a-fA-F]{64}$/.test(pubHex)) {
    throw new Error("Invalid Ed25519 public key: expected SPKI PEM, did:key, or 64-char hex.");
  }
  const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX2, Buffer.from(pubHex, "hex")]);
  return crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
}
function generateSpurvikEd25519KeyPair(seedHex) {
  let privKeyObj;
  let privateKeyHex;
  if (seedHex) {
    const clean = seedHex.trim();
    if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
      throw new Error("Ed25519 seedHex must be 64 hex characters (32 bytes).");
    }
    privateKeyHex = clean.toLowerCase();
    const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX2, Buffer.from(privateKeyHex, "hex")]);
    privKeyObj = crypto.createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
  } else {
    const pair = crypto.generateKeyPairSync("ed25519");
    privKeyObj = pair.privateKey;
    const pkcs8Der = privKeyObj.export({ format: "der", type: "pkcs8" });
    privateKeyHex = pkcs8Der.subarray(pkcs8Der.length - 32).toString("hex");
  }
  const pubKeyObj = crypto.createPublicKey(privKeyObj);
  const spkiDer = pubKeyObj.export({ format: "der", type: "spki" });
  const publicKeyHex = spkiDer.subarray(spkiDer.length - 32).toString("hex");
  const privateKeyPem = privKeyObj.export({ format: "pem", type: "pkcs8" });
  const publicKeyPem = pubKeyObj.export({ format: "pem", type: "spki" });
  const didKey = publicKeyToDidKey(publicKeyHex);
  const keyId = `spv_k_${crypto.createHash("sha256").update(publicKeyHex).digest("hex").slice(0, 12)}`;
  return {
    publicKeyPem,
    privateKeyPem,
    publicKeyHex,
    privateKeyHex,
    didKey,
    keyId
  };
}
function serializeReceiptSigningInput(receipt) {
  return canonicalizeJsonLd({
    articleScope: receipt.articleScope,
    keyedHmacSha256: receipt.keyedHmacSha256,
    operatorCvr: receipt.operatorCvr,
    payloadDigestSha256: receipt.payloadDigestSha256,
    previousHmac: receipt.previousHmac,
    principal: receipt.principal,
    receiptId: receipt.receiptId,
    timestamp: receipt.timestamp
  });
}
function signComplianceReceiptEd25519(payload, privateKeyPemOrHex, options = {}) {
  const { privKeyObj, pubKeyHex } = resolvePrivateKeyObject(privateKeyPemOrHex);
  const canonicalPayload = typeof payload === "string" ? payload : canonicalizeJsonLd(payload);
  const payloadDigestSha256 = crypto.createHash("sha256").update(canonicalPayload, "utf8").digest("hex");
  const timestamp = options.timestamp ?? new Date().toISOString();
  const receiptId = options.receiptId ?? `spv_rcpt_${crypto.createHash("sha256").update(`${timestamp}|${payloadDigestSha256}`).digest("hex").slice(0, 16)}`;
  const principal = options.principal ?? "EyeTea Solutions ApS";
  const operatorCvr = options.operatorCvr ?? "37093378";
  const previousHmac = options.previousHmac ?? "GENESIS";
  const articleScope = options.articleScope ?? [
    "EU-AI-ACT-ART-12",
    "EU-AI-ACT-ART-50(1)",
    "EU-AI-ACT-ART-50(2)"
  ];
  const hmacKey = (options.hmacKey ?? process.env.SPURVIK_HMAC_SECRET ?? process.env.SPURVIK_HMAC_KEY ?? "").trim();
  if (!hmacKey) {
    throw new Error("Missing SPURVIK_HMAC_KEY / hmacKey for Ed25519 compliance receipt.");
  }
  const keyedHmacSha256 = crypto.createHmac("sha256", hmacKey).update(`${receiptId}|${timestamp}|${principal}|${operatorCvr}|${payloadDigestSha256}|${previousHmac}`, "utf8").digest("hex");
  const signingInput = serializeReceiptSigningInput({
    receiptId,
    timestamp,
    principal,
    operatorCvr,
    articleScope,
    payloadDigestSha256,
    previousHmac,
    keyedHmacSha256
  });
  const sigBuf = crypto.sign(null, Buffer.from(signingInput, "utf8"), privKeyObj);
  return {
    receiptId,
    timestamp,
    principal,
    operatorCvr,
    articleScope,
    payloadDigestSha256,
    previousHmac,
    keyedHmacSha256,
    ed25519SignatureHex: sigBuf.toString("hex"),
    ed25519SignatureBase64: sigBuf.toString("base64"),
    publicKeyHex: pubKeyHex,
    didKey: publicKeyToDidKey(pubKeyHex)
  };
}
function verifyComplianceReceiptEd25519(receipt, publicKeyPemOrHexOrDid, options = {}) {
  try {
    if (!receipt || !receipt.ed25519SignatureHex || !publicKeyPemOrHexOrDid?.trim()) {
      return false;
    }
    if (options.expectedPayload !== undefined) {
      const canonicalExpected = typeof options.expectedPayload === "string" ? options.expectedPayload : canonicalizeJsonLd(options.expectedPayload);
      const expectedDigest = crypto.createHash("sha256").update(canonicalExpected, "utf8").digest("hex");
      if (expectedDigest !== receipt.payloadDigestSha256) {
        return false;
      }
    }
    if (options.hmacKey) {
      const expectedHmac = crypto.createHmac("sha256", options.hmacKey).update(`${receipt.receiptId}|${receipt.timestamp}|${receipt.principal}|${receipt.operatorCvr}|${receipt.payloadDigestSha256}|${receipt.previousHmac}`, "utf8").digest("hex");
      const a = Buffer.from(expectedHmac, "hex");
      const b = Buffer.from(receipt.keyedHmacSha256, "hex");
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return false;
      }
    }
    const pubKeyObj = resolvePublicKeyObject(publicKeyPemOrHexOrDid);
    const signingInput = serializeReceiptSigningInput(receipt);
    const sigBuf = Buffer.from(receipt.ed25519SignatureHex, "hex");
    if (sigBuf.length !== 64)
      return false;
    return crypto.verify(null, Buffer.from(signingInput, "utf8"), pubKeyObj, sigBuf);
  } catch {
    return false;
  }
}
// packages/terra-oamp-sdk/src/providers.ts
var DEFAULT_FALLBACK_KEYPAIR = generateSpurvikEd25519KeyPair(process.env.SPURVIK_ED25519_SEED_HEX);
// packages/terra-oamp-sdk/src/frontier-adapters.ts
var DEFAULT_ADAPTER_KEYPAIR = generateSpurvikEd25519KeyPair(process.env.SPURVIK_ED25519_SEED_HEX);
// packages/terra-oamp-sdk/src/hermes-openclaw.ts
var DEFAULT_SDK_KEYPAIR = generateSpurvikEd25519KeyPair(process.env.SPURVIK_ED25519_SEED_HEX);
// packages/spurvik-mcp-server/src/index.ts
var SERVER_KEYPAIR = generateSpurvikEd25519KeyPair("c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2");
var MCP_TOOLS = [
  {
    name: "spurvik_scan_repo",
    description: "Scans a local repository directory for unwrapped LLM calls, missing EU AI Act Art. 50 disclosures, un-routed tool loops, and missing Art. 12 Keyed-HMAC logs.",
    inputSchema: {
      type: "object",
      properties: {
        directory: { type: "string", description: "Absolute or relative directory path to scan" }
      },
      required: ["directory"]
    }
  },
  {
    name: "spurvik_system_one_route",
    description: "Runs the deterministic System-One (Jev) pre-flight router (`proceed`, `reuse_cache`, `stop_retry`, `research_capped`, `ask_human`) enforcing EU AI Act Art. 14 human oversight.",
    inputSchema: {
      type: "object",
      properties: {
        goal: { type: "string" },
        task_type: { type: "string" },
        last_error: { type: "string" },
        repeats: { type: "number" },
        mode: { type: "string", enum: ["shadow", "active"] }
      },
      required: ["goal", "task_type"]
    }
  },
  {
    name: "spurvik_sign_ed25519_receipt",
    description: "Produces a dual Keyed-HMAC-SHA256 + Ed25519-signed EU AI Act Art. 12 & Art. 50 compliance receipt verifiable by third parties.",
    inputSchema: {
      type: "object",
      properties: {
        payload: { type: "object" },
        principal: { type: "string" },
        previousHmac: { type: "string" }
      },
      required: ["payload"]
    }
  },
  {
    name: "spurvik_verify_ed25519_receipt",
    description: "Verifies any Spurvik Ed25519 compliance receipt against a public key (PEM, 64-char hex, or W3C did:key).",
    inputSchema: {
      type: "object",
      properties: {
        receipt: { type: "object" },
        publicKeyOrDid: { type: "string" }
      },
      required: ["receipt"]
    }
  },
  {
    name: "spurvik_fria_annex_iv_check",
    description: "Evaluates an AI system description against EU AI Act Annex III high-risk categories, Annex IV technical documentation, Art. 27 FRIA, and CEN-CENELEC prEN 18286 QMS obligations.",
    inputSchema: {
      type: "object",
      properties: {
        systemName: { type: "string" },
        useCaseDescription: { type: "string" },
        sector: { type: "string" }
      },
      required: ["systemName", "useCaseDescription"]
    }
  }
];
async function handleJsonRpcRequest(req) {
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
          publicKeyDid: SERVER_KEYPAIR.didKey
        }
      }
    };
  }
  if (method === "tools/list") {
    return {
      jsonrpc: "2.0",
      id,
      result: { tools: MCP_TOOLS }
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
          content: [{ type: "text", text: JSON.stringify(report, null, 2) }]
        }
      };
    }
    if (toolName === "spurvik_system_one_route") {
      const decision = spurvikSystemOneRoute({
        goal: String(args.goal || ""),
        task_type: String(args.task_type || "step"),
        last_error: String(args.last_error || "none"),
        repeats: Number(args.repeats || 0)
      }, { mode: args.mode === "shadow" ? "shadow" : "active" });
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: JSON.stringify(decision, null, 2) }]
        }
      };
    }
    if (toolName === "spurvik_sign_ed25519_receipt") {
      const receipt = signComplianceReceiptEd25519(args.payload || {}, SERVER_KEYPAIR.privateKeyHex, {
        principal: String(args.principal || "EyeTea Solutions ApS (CVR: 37093378)"),
        previousHmac: String(args.previousHmac || "GENESIS")
      });
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: JSON.stringify(receipt, null, 2) }]
        }
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
              text: JSON.stringify({ valid, verifiedWithPublicKeyOrDid: pubKey }, null, 2)
            }
          ]
        }
      };
    }
    if (toolName === "spurvik_fria_annex_iv_check") {
      const desc = `${args.systemName || ""} ${args.useCaseDescription || ""} ${args.sector || ""}`.toLowerCase();
      const isAnnexIII = /\b(credit|loan|scoring|recruitment|hiring|cv|biometric|education|healthcare|triage|insurance|critical infrastructure|grid|energy)\b/i.test(desc);
      const assessment = {
        systemName: args.systemName,
        annexIIIHighRiskTriggered: isAnnexIII,
        applicableArticles: isAnnexIII ? [
          "Art. 9 (Risk Management System)",
          "Art. 12 (Automatic Event Logging — Keyed-HMAC + Ed25519)",
          "Art. 14 (Human Oversight — System-One ask_human Gate)",
          "Art. 17 & CEN-CENELEC prEN 18286 (Quality Management System)",
          "Art. 27 (Fundamental Rights Impact Assessment — FRIA)",
          "Art. 50(1)/(2) (Transparency & Synthetic Content Provenance)",
          "Annex IV (Technical Documentation Dossier)"
        ] : [
          "Art. 50(1) (Interactive AI Principal Disclosure)",
          "Art. 50(2) (Machine-Readable Synthetic Content Provenance)",
          "Voluntary Art. 12/14 Governance Best Practice"
        ],
        qmsStandard: "CEN-CENELEC prEN 18286:2026",
        operator: "EyeTea Solutions ApS (CVR: 37093378, Denmark)",
        evaluatedAt: new Date().toISOString()
      };
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: JSON.stringify(assessment, null, 2) }]
        }
      };
    }
    return {
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: `Unknown tool: ${toolName}` }
    };
  }
  return {
    jsonrpc: "2.0",
    id,
    error: { code: -32601, message: `Method not found: ${method}` }
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
      arguments: { payload: { test: "mcp-e2e" } }
    }
  });
  const receiptObj = JSON.parse(signRes.result.content[0].text);
  const verifyRes = await handleJsonRpcRequest({
    id: 4,
    method: "tools/call",
    params: {
      name: "spurvik_verify_ed25519_receipt",
      arguments: { receipt: receiptObj, publicKeyOrDid: receiptObj.didKey }
    }
  });
  const verifyObj = JSON.parse(verifyRes.result.content[0].text);
  console.log(`[@spurvik/mcp-server] Self-test passed: tools=${listRes.result.tools.length}, didKey=${initRes.result.serverInfo.publicKeyDid}, receiptVerified=${verifyObj.valid}`);
  if (!verifyObj.valid || listRes.result.tools.length !== 5)
    process.exit(1);
  process.exit(0);
}
if (__require.main == __require.module) {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on("line", async (line) => {
    const trimmed = line.trim();
    if (!trimmed)
      return;
    try {
      const req = JSON.parse(trimmed);
      const res = await handleJsonRpcRequest(req);
      process.stdout.write(JSON.stringify(res) + `
`);
    } catch (err) {
      process.stdout.write(JSON.stringify({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: err?.message || "Parse error" }
      }) + `
`);
    }
  });
}
export {
  handleJsonRpcRequest,
  MCP_TOOLS
};
