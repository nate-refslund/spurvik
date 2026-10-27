// packages/terra-oamp-sdk/src/crypto/index.ts
import * as crypto from "node:crypto";
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
function publicKeyToDidIon(publicKeyHex) {
  const pubBytes = Buffer.from(publicKeyHex, "hex");
  const jwkCanonical = JSON.stringify({
    crv: "Ed25519",
    kty: "OKP",
    x: pubBytes.toString("base64url")
  });
  const suffixHash = crypto.createHash("sha256").update(jwkCanonical).digest("base64url");
  return `did:ion:Ei${suffixHash.slice(0, 42)}`;
}
function generateEd25519KeyPair(seedHex) {
  let privKeyObj;
  let rawPrivHex;
  if (seedHex) {
    const seedBuf = Buffer.from(seedHex, "hex");
    if (seedBuf.length !== 32) {
      throw new Error("Ed25519 seed must be exactly 32 bytes (64 hex chars)");
    }
    rawPrivHex = seedBuf.toString("hex");
    const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX, seedBuf]);
    privKeyObj = crypto.createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
  } else {
    const { privateKey } = crypto.generateKeyPairSync("ed25519");
    privKeyObj = privateKey;
    const pkcs8Der = privateKey.export({ format: "der", type: "pkcs8" });
    rawPrivHex = pkcs8Der.subarray(pkcs8Der.length - 32).toString("hex");
  }
  const pubKeyObj = crypto.createPublicKey(privKeyObj);
  const spkiDer = pubKeyObj.export({ format: "der", type: "spki" });
  const publicKeyHex = spkiDer.subarray(spkiDer.length - 32).toString("hex");
  return {
    publicKeyHex,
    privateKeyHex: rawPrivHex,
    didKey: publicKeyToDidKey(publicKeyHex),
    didIon: publicKeyToDidIon(publicKeyHex)
  };
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
function signEd25519Detached(payload, privateKeyHex) {
  const seedBuf = Buffer.from(privateKeyHex, "hex");
  if (seedBuf.length !== 32) {
    throw new Error(`Invalid Ed25519 private key length: ${seedBuf.length}`);
  }
  const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX, seedBuf]);
  const privKeyObj = crypto.createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
  const dataBuf = typeof payload === "string" ? Buffer.from(payload, "utf8") : Buffer.from(payload);
  const sig = crypto.sign(null, dataBuf, privKeyObj);
  return sig.toString("hex");
}
function verifyEd25519Detached(payload, signatureHex, publicKeyOrDid) {
  try {
    const pubKeyHex = publicKeyOrDid.startsWith("did:key:") ? didKeyToPublicKeyHex(publicKeyOrDid) : publicKeyOrDid;
    const pubBuf = Buffer.from(pubKeyHex, "hex");
    const sigBuf = Buffer.from(signatureHex, "hex");
    if (pubBuf.length !== 32 || sigBuf.length !== 64) {
      return false;
    }
    const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, pubBuf]);
    const pubKeyObj = crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
    const dataBuf = typeof payload === "string" ? Buffer.from(payload, "utf8") : Buffer.from(payload);
    return crypto.verify(null, dataBuf, pubKeyObj, sigBuf);
  } catch {
    return false;
  }
}
var SECP256K1_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
var SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
var SECP256K1_GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
var SECP256K1_GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
function mod(a, m = SECP256K1_P) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}
function modInv(a, m = SECP256K1_P) {
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, m);
}
function jacDouble(p) {
  if (p.y === 0n || p.z === 0n)
    return { x: 0n, y: 1n, z: 0n };
  const y2 = mod(p.y * p.y);
  const s = mod(4n * p.x * y2);
  const x2 = mod(p.x * p.x);
  const m = mod(3n * x2);
  const nx = mod(m * m - 2n * s);
  const ny = mod(m * (s - nx) - 8n * mod(y2 * y2));
  const nz = mod(2n * p.y * p.z);
  return { x: nx, y: ny, z: nz };
}
function jacAdd(p1, p2) {
  if (p1.z === 0n)
    return p2;
  if (p2.z === 0n)
    return p1;
  const z1z1 = mod(p1.z * p1.z);
  const z2z2 = mod(p2.z * p2.z);
  const u1 = mod(p1.x * z2z2);
  const u2 = mod(p2.x * z1z1);
  const s1 = mod(p1.y * mod(p2.z * z2z2));
  const s2 = mod(p2.y * mod(p1.z * z1z1));
  if (u1 === u2) {
    return s1 === s2 ? jacDouble(p1) : { x: 0n, y: 1n, z: 0n };
  }
  const h = mod(u2 - u1);
  const i = mod(4n * h * h);
  const j = mod(h * i);
  const r = mod(2n * (s2 - s1));
  const v = mod(u1 * i);
  const nx = mod(r * r - j - 2n * v);
  const ny = mod(r * (v - nx) - 2n * s1 * j);
  const nz = mod(mod((p1.z + p2.z) * (p1.z + p2.z) - z1z1 - z2z2) * h);
  return { x: nx, y: ny, z: nz };
}
function jacToAffine(p) {
  if (p.z === 0n)
    return null;
  const iz = modInv(p.z);
  const iz2 = mod(iz * iz);
  const iz3 = mod(iz2 * iz);
  return { x: mod(p.x * iz2), y: mod(p.y * iz3) };
}
function pointAdd(p1, p2) {
  if (!p1)
    return p2;
  if (!p2)
    return p1;
  return jacToAffine(jacAdd({ x: p1.x, y: p1.y, z: 1n }, { x: p2.x, y: p2.y, z: 1n }));
}
function pointMul(k, p = { x: SECP256K1_GX, y: SECP256K1_GY }) {
  if (!p)
    return null;
  let result = { x: 0n, y: 1n, z: 0n };
  let addend = { x: p.x, y: p.y, z: 1n };
  let scalar = mod(k, SECP256K1_N);
  while (scalar > 0n) {
    if (scalar & 1n)
      result = jacAdd(result, addend);
    addend = jacDouble(addend);
    scalar >>= 1n;
  }
  return jacToAffine(result);
}
function generateSecp256k1KeyPair(privHex) {
  const rawPrivHex = privHex ?? crypto.randomBytes(32).toString("hex");
  const d = mod(BigInt(`0x${rawPrivHex}`), SECP256K1_N - 1n) + 1n;
  const privScalarHex = d.toString(16).padStart(64, "0");
  const pubPoint = pointMul(d);
  const pubHex = `04${pubPoint.x.toString(16).padStart(64, "0")}${pubPoint.y.toString(16).padStart(64, "0")}`;
  return {
    publicKeyPem: pubHex,
    privateKeyPem: privScalarHex,
    publicKeyHex: pubHex
  };
}
function signSecp256k1Escrow(payload, privateKeyHexOrPem) {
  const d = BigInt(`0x${privateKeyHexOrPem.trim()}`);
  const zHex = crypto.createHash("sha256").update(payload, "utf8").digest("hex");
  const z = BigInt(`0x${zHex}`);
  const kHex = crypto.createHmac("sha256", Buffer.from(privateKeyHexOrPem.trim(), "hex")).update(payload, "utf8").digest("hex");
  const k = BigInt(`0x${kHex}`) % (SECP256K1_N - 1n) + 1n;
  const R = pointMul(k);
  const r = mod(R.x, SECP256K1_N);
  const s = mod(modInv(k, SECP256K1_N) * (z + r * d), SECP256K1_N);
  return `${r.toString(16).padStart(64, "0")}${s.toString(16).padStart(64, "0")}`;
}
function verifySecp256k1Escrow(payload, signatureHex, publicKeyHexOrPem) {
  try {
    const pubClean = publicKeyHexOrPem.trim();
    if (signatureHex.length !== 128 || !pubClean.startsWith("04") || pubClean.length !== 130) {
      return false;
    }
    const r = BigInt(`0x${signatureHex.slice(0, 64)}`);
    const s = BigInt(`0x${signatureHex.slice(64, 128)}`);
    if (r <= 0n || r >= SECP256K1_N || s <= 0n || s >= SECP256K1_N)
      return false;
    const qx = BigInt(`0x${pubClean.slice(2, 66)}`);
    const qy = BigInt(`0x${pubClean.slice(66, 130)}`);
    const Q = { x: qx, y: qy };
    const zHex = crypto.createHash("sha256").update(payload, "utf8").digest("hex");
    const z = BigInt(`0x${zHex}`);
    const w = modInv(s, SECP256K1_N);
    const u1 = mod(z * w, SECP256K1_N);
    const u2 = mod(r * w, SECP256K1_N);
    const P = pointAdd(pointMul(u1), pointMul(u2, Q));
    if (!P)
      return false;
    return mod(P.x, SECP256K1_N) === r;
  } catch {
    return false;
  }
}
function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}
// packages/terra-oamp-sdk/src/headers/index.ts
import * as crypto2 from "node:crypto";
function createMandate(opts) {
  const now = opts.issuedAt ?? Math.floor(Date.now() / 1000);
  const mandateId = opts.mandateId ?? crypto2.randomUUID();
  const signerDid = opts.signerDid ?? opts.principalDid;
  const decayFactor = opts.authorityDecayFactor ?? 0.8;
  const hop0Payload = canonicalizeJsonLd({
    hop: 0,
    mandateId,
    issuerDid: opts.principalDid,
    delegateDid: opts.agentDid,
    maxPerCallUsd: opts.maxPerCallUsd,
    allowedTools: [...opts.allowedTools].sort()
  });
  const hop0Sig = signEd25519Detached(hop0Payload, opts.signerPrivateKeyHex);
  const payload = {
    "@context": "https://schema.terra-protocol.org/oamp/v1",
    mandateId,
    version: "1.0.0",
    principalDid: opts.principalDid,
    agentDid: opts.agentDid,
    jurisdiction: opts.jurisdiction ?? "EU-DK",
    allowedTools: [...opts.allowedTools],
    spendCap: {
      currency: opts.currency ?? "USD",
      maxPerCallUsd: opts.maxPerCallUsd,
      dailyCapUsd: opts.dailyCapUsd,
      cumulativeSpentUsd: 0
    },
    velocityLimit: {
      maxCallsPerMinute: opts.maxCallsPerMinute ?? 120,
      maxConcurrentEscrows: opts.maxConcurrentEscrows ?? 16
    },
    delegation: {
      depth: 0,
      maxDepth: opts.maxDelegationDepth ?? 3,
      parentMandateId: null,
      authorityDecayFactor: decayFactor,
      chain: [
        {
          hop: 0,
          mandateId,
          issuerDid: opts.principalDid,
          delegateDid: opts.agentDid,
          maxPerCallUsd: opts.maxPerCallUsd,
          allowedTools: [...opts.allowedTools].sort(),
          signature: hop0Sig
        }
      ]
    },
    issuedAt: now,
    expiresAt: now + (opts.ttlSeconds ?? 3600)
  };
  const canonicalPayload = canonicalizeJsonLd(payload);
  const signatureValue = signEd25519Detached(canonicalPayload, opts.signerPrivateKeyHex);
  return {
    ...payload,
    proof: {
      type: "Ed25519Signature2020",
      verificationMethod: `${signerDid}#keys-1`,
      created: now,
      signatureValue
    }
  };
}
function delegateMandate(opts) {
  const { parentMandate } = opts;
  const nextDepth = parentMandate.delegation.depth + 1;
  if (nextDepth > parentMandate.delegation.maxDepth) {
    throw new Error(`OAMP Rule B Violation: Delegation depth ${nextDepth} exceeds maxDepth ${parentMandate.delegation.maxDepth}`);
  }
  const maxDecayedSpend = Number((parentMandate.spendCap.maxPerCallUsd * parentMandate.delegation.authorityDecayFactor).toFixed(4));
  const newMaxPerCall = opts.requestedMaxPerCallUsd !== undefined ? Math.min(opts.requestedMaxPerCallUsd, maxDecayedSpend) : maxDecayedSpend;
  if (opts.requestedMaxPerCallUsd !== undefined && opts.requestedMaxPerCallUsd > maxDecayedSpend) {
    throw new Error(`OAMP Authority Decay Violation: Requested spend ${opts.requestedMaxPerCallUsd} exceeds decayed cap ${maxDecayedSpend}`);
  }
  const requestedTools = opts.requestedAllowedTools ?? parentMandate.allowedTools;
  for (const tool of requestedTools) {
    if (!parentMandate.allowedTools.includes(tool) && !parentMandate.allowedTools.includes("*")) {
      throw new Error(`OAMP Scope Escalation Violation: Sub-agent requested unpermitted tool '${tool}'`);
    }
  }
  const now = Math.floor(Date.now() / 1000);
  const childMandateId = crypto2.randomUUID();
  const expiresAt = opts.ttlSeconds ? Math.min(parentMandate.expiresAt, now + opts.ttlSeconds) : parentMandate.expiresAt;
  const hopPayload = canonicalizeJsonLd({
    hop: nextDepth,
    mandateId: childMandateId,
    issuerDid: parentMandate.agentDid,
    delegateDid: opts.subAgentDid,
    maxPerCallUsd: newMaxPerCall,
    allowedTools: [...requestedTools].sort()
  });
  const hopSignature = signEd25519Detached(hopPayload, opts.delegatingAgentPrivateKeyHex);
  const payload = {
    "@context": "https://schema.terra-protocol.org/oamp/v1",
    mandateId: childMandateId,
    version: "1.0.0",
    principalDid: parentMandate.principalDid,
    agentDid: opts.subAgentDid,
    jurisdiction: parentMandate.jurisdiction,
    allowedTools: [...requestedTools],
    spendCap: {
      currency: parentMandate.spendCap.currency,
      maxPerCallUsd: newMaxPerCall,
      dailyCapUsd: Number((parentMandate.spendCap.dailyCapUsd * parentMandate.delegation.authorityDecayFactor).toFixed(4)),
      cumulativeSpentUsd: parentMandate.spendCap.cumulativeSpentUsd
    },
    velocityLimit: {
      maxCallsPerMinute: Math.max(1, Math.floor(parentMandate.velocityLimit.maxCallsPerMinute * parentMandate.delegation.authorityDecayFactor)),
      maxConcurrentEscrows: parentMandate.velocityLimit.maxConcurrentEscrows
    },
    delegation: {
      depth: nextDepth,
      maxDepth: parentMandate.delegation.maxDepth,
      parentMandateId: parentMandate.mandateId,
      authorityDecayFactor: parentMandate.delegation.authorityDecayFactor,
      chain: [
        ...parentMandate.delegation.chain,
        {
          hop: nextDepth,
          mandateId: childMandateId,
          issuerDid: parentMandate.agentDid,
          delegateDid: opts.subAgentDid,
          maxPerCallUsd: newMaxPerCall,
          allowedTools: [...requestedTools].sort(),
          signature: hopSignature
        }
      ]
    },
    issuedAt: now,
    expiresAt
  };
  const canonicalPayload = canonicalizeJsonLd(payload);
  const signatureValue = signEd25519Detached(canonicalPayload, opts.delegatingAgentPrivateKeyHex);
  return {
    ...payload,
    proof: {
      type: "Ed25519Signature2020",
      verificationMethod: `${parentMandate.agentDid}#keys-1`,
      created: now,
      signatureValue
    }
  };
}
function computePromptHash(ctx) {
  const canonicalInput = canonicalizeJsonLd({
    baseModelId: ctx.baseModelId,
    systemPrompt: ctx.systemPrompt,
    activeTools: ctx.activeTools,
    triggeringContext: ctx.triggeringContext
  });
  return sha256Hex(canonicalInput);
}
function encodeMandateHeader(mandate) {
  return Buffer.from(JSON.stringify(mandate), "utf8").toString("base64url");
}
function decodeMandateHeader(headerValue) {
  const trimmed = headerValue.trim();
  const jsonStr = trimmed.startsWith("{") ? trimmed : Buffer.from(trimmed, "base64url").toString("utf8");
  return JSON.parse(jsonStr);
}
function buildTerraHeaders(opts) {
  const promptHash = computePromptHash(opts.promptContext);
  const mandateId = opts.mandate.mandateId;
  const escrowReservationId = opts.escrowReservationId ?? `escrow_${crypto2.randomUUID()}`;
  const stateBindingPayload = `${mandateId}:${promptHash}`;
  const proofHashSig = signEd25519Detached(stateBindingPayload, opts.agentPrivateKeyHex);
  const escrowBindingPayload = `${mandateId}:${escrowReservationId}:${opts.mandate.spendCap.maxPerCallUsd}`;
  const escrowSig = signSecp256k1Escrow(escrowBindingPayload, opts.escrowPrivateKeyPem);
  const liabilityProof = {
    policyId: opts.policyId ?? "TERRA-MGA-LLOYDS-2026-001",
    underwriterSyndicate: opts.underwriterSyndicate ?? "Lloyd's Syndicate 2026 / Munich Re AI Pool",
    escrowReservationId,
    coverageCapUsd: opts.coverageCapUsd ?? 1e6,
    premiumBps: opts.premiumBps ?? 15,
    mandateId,
    runtimePromptHash: promptHash,
    proofHashSig,
    escrowSig,
    escrowPublicKeyPem: opts.escrowPublicKeyPem,
    issuedAt: Math.floor(Date.now() / 1000)
  };
  return {
    "X-Terra-Mandate": encodeMandateHeader(opts.mandate),
    "X-Terra-Principal": opts.mandate.principalDid,
    "X-Terra-Prompt-Hash": promptHash,
    "X-Terra-Liability-Proof": Buffer.from(JSON.stringify(liabilityProof), "utf8").toString("base64"),
    "X-TERRA-OAMP-MANDATE-ID": mandateId,
    "X-TERRA-OAMP-PROOF-HASH": proofHashSig,
    "X-TERRA-OAMP-ESCROW-SIG": escrowSig
  };
}
var VERIFIED_HEADER_CACHE = new Map;
function verifyTerraHeaders(headers, context = {}) {
  const normalized = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v !== undefined) {
      normalized[k.toLowerCase()] = v;
    }
  }
  const rawMandate = normalized["x-terra-mandate"];
  const rawPrincipal = normalized["x-terra-principal"];
  const rawPromptHash = normalized["x-terra-prompt-hash"];
  const rawLiabilityProof = normalized["x-terra-liability-proof"];
  const rawOampMandateId = normalized["x-terra-oamp-mandate-id"];
  const rawOampProofHash = normalized["x-terra-oamp-proof-hash"];
  const rawOampEscrowSig = normalized["x-terra-oamp-escrow-sig"];
  if (!rawMandate || !rawPrincipal || !rawPromptHash || !rawLiabilityProof || !rawOampMandateId || !rawOampProofHash || !rawOampEscrowSig) {
    return {
      valid: false,
      contagionClauseViolation: true,
      ruleTriggered: "SECTION_8_14_CONTAGION",
      reason: "Section 8.14 Contagion Clause Violation: Missing required TERRA OAMP Mandate or Escrow headers"
    };
  }
  const cacheKey = `${rawOampMandateId}:${rawPromptHash}:${rawOampProofHash}:${rawOampEscrowSig}:${rawPrincipal}:${rawMandate.length}`;
  const cached = VERIFIED_HEADER_CACHE.get(cacheKey);
  if (cached) {
    const { mandate: mandate2, liabilityProof: liabilityProof2 } = cached;
    const now2 = context.nowTimestampSec ?? Math.floor(Date.now() / 1000);
    if (now2 > mandate2.expiresAt) {
      return {
        valid: false,
        contagionClauseViolation: true,
        ruleTriggered: "SECTION_8_14_CONTAGION",
        reason: `OAMP Mandate expired at ${mandate2.expiresAt} (current: ${now2})`
      };
    }
    if (context.expectedPromptHash && context.expectedPromptHash !== rawPromptHash) {
      return {
        valid: false,
        ruleTriggered: "RULE_A_HASH_DRIFT",
        reason: `Rule A Hash Drift: Runtime prompt hash ${rawPromptHash} diverged from registered hash ${context.expectedPromptHash}`
      };
    }
    if (context.requestedTool) {
      const allowed = mandate2.allowedTools.includes("*") || mandate2.allowedTools.includes(context.requestedTool);
      if (!allowed) {
        return {
          valid: false,
          ruleTriggered: "SPEND_OR_SCOPE_BREACH",
          reason: `Tool '${context.requestedTool}' is outside OAMP Mandate allowedTools [${mandate2.allowedTools.join(", ")}]`
        };
      }
    }
    if (context.requestedSpendUsd !== undefined) {
      if (context.requestedSpendUsd > mandate2.spendCap.maxPerCallUsd) {
        return {
          valid: false,
          ruleTriggered: "SPEND_OR_SCOPE_BREACH",
          reason: `Requested spend $${context.requestedSpendUsd} exceeds per-call cap $${mandate2.spendCap.maxPerCallUsd}`
        };
      }
      if (mandate2.spendCap.cumulativeSpentUsd + context.requestedSpendUsd > mandate2.spendCap.dailyCapUsd) {
        return {
          valid: false,
          ruleTriggered: "SPEND_OR_SCOPE_BREACH",
          reason: `Cumulative spend $${mandate2.spendCap.cumulativeSpentUsd + context.requestedSpendUsd} exceeds daily cap $${mandate2.spendCap.dailyCapUsd}`
        };
      }
    }
    return { valid: true, mandate: mandate2, liabilityProof: liabilityProof2 };
  }
  let mandate;
  let liabilityProof;
  try {
    mandate = decodeMandateHeader(rawMandate);
    liabilityProof = JSON.parse(Buffer.from(rawLiabilityProof, "base64").toString("utf8"));
  } catch {
    return {
      valid: false,
      contagionClauseViolation: true,
      ruleTriggered: "SECTION_8_14_CONTAGION",
      reason: "Malformed X-Terra-Mandate or X-Terra-Liability-Proof encoding"
    };
  }
  if (mandate.mandateId !== rawOampMandateId || liabilityProof.mandateId !== mandate.mandateId) {
    return {
      valid: false,
      contagionClauseViolation: true,
      ruleTriggered: "SECTION_8_14_CONTAGION",
      reason: "Mandate ID mismatch between X-Terra-Mandate, X-TERRA-OAMP-MANDATE-ID, and Liability Proof"
    };
  }
  if (mandate.principalDid !== rawPrincipal) {
    return {
      valid: false,
      reason: "X-Terra-Principal does not match Mandate principalDid"
    };
  }
  const now = context.nowTimestampSec ?? Math.floor(Date.now() / 1000);
  if (now > mandate.expiresAt) {
    return {
      valid: false,
      contagionClauseViolation: true,
      ruleTriggered: "SECTION_8_14_CONTAGION",
      reason: `OAMP Mandate expired at ${mandate.expiresAt} (current: ${now})`
    };
  }
  if (mandate.delegation.depth > mandate.delegation.maxDepth) {
    return {
      valid: false,
      ruleTriggered: "RULE_B_CASCADE_DEPTH",
      reason: `Rule B Violation: Delegation depth ${mandate.delegation.depth} exceeds maxDepth ${mandate.delegation.maxDepth}`
    };
  }
  if (mandate.delegation.chain.length !== mandate.delegation.depth + 1) {
    return {
      valid: false,
      ruleTriggered: "RULE_B_CASCADE_DEPTH",
      reason: "Invalid delegation chain length"
    };
  }
  for (let i = 0;i < mandate.delegation.chain.length; i++) {
    const hop = mandate.delegation.chain[i];
    if (i === 0 && hop.issuerDid !== mandate.principalDid) {
      return { valid: false, reason: "Root delegation hop must be signed by principalDid" };
    }
    if (i > 0) {
      const prevHop = mandate.delegation.chain[i - 1];
      if (hop.issuerDid !== prevHop.delegateDid) {
        return { valid: false, reason: `Broken delegation chain at hop ${i}` };
      }
      if (hop.maxPerCallUsd > prevHop.maxPerCallUsd) {
        return { valid: false, reason: `Authority escalation detected at hop ${i}` };
      }
    }
    const hopCanonical = canonicalizeJsonLd({
      hop: hop.hop,
      mandateId: hop.mandateId,
      issuerDid: hop.issuerDid,
      delegateDid: hop.delegateDid,
      maxPerCallUsd: hop.maxPerCallUsd,
      allowedTools: [...hop.allowedTools].sort()
    });
    if (!verifyEd25519Detached(hopCanonical, hop.signature, hop.issuerDid)) {
      return {
        valid: false,
        reason: `Invalid Ed25519 signature at delegation hop ${i} (issuer: ${hop.issuerDid})`
      };
    }
  }
  const { proof, ...unsignedMandate } = mandate;
  const signerDid = proof.verificationMethod.split("#")[0];
  const expectedSignerDid = mandate.delegation.depth === 0 ? mandate.principalDid : mandate.delegation.chain[mandate.delegation.depth].issuerDid;
  if (signerDid !== expectedSignerDid) {
    return {
      valid: false,
      reason: `Mandate proof signer ${signerDid} does not match expected issuer ${expectedSignerDid}`
    };
  }
  const canonicalMandate = canonicalizeJsonLd(unsignedMandate);
  if (!verifyEd25519Detached(canonicalMandate, proof.signatureValue, signerDid)) {
    return {
      valid: false,
      reason: "Invalid Ed25519 signature on X-Terra-Mandate"
    };
  }
  if (!/^[a-f0-9]{64}$/i.test(rawPromptHash)) {
    return { valid: false, reason: "Invalid SHA-256 hex format in X-Terra-Prompt-Hash" };
  }
  if (context.expectedPromptHash && context.expectedPromptHash !== rawPromptHash) {
    return {
      valid: false,
      ruleTriggered: "RULE_A_HASH_DRIFT",
      reason: `Rule A Hash Drift: Runtime prompt hash ${rawPromptHash} diverged from registered hash ${context.expectedPromptHash}`
    };
  }
  const stateBindingPayload = `${mandate.mandateId}:${rawPromptHash}`;
  if (!verifyEd25519Detached(stateBindingPayload, rawOampProofHash, mandate.agentDid)) {
    return {
      valid: false,
      contagionClauseViolation: true,
      ruleTriggered: "SECTION_8_14_CONTAGION",
      reason: "Invalid Ed25519 signature on X-TERRA-OAMP-PROOF-HASH"
    };
  }
  const escrowBindingPayload = `${mandate.mandateId}:${liabilityProof.escrowReservationId}:${mandate.spendCap.maxPerCallUsd}`;
  if (rawOampEscrowSig !== liabilityProof.escrowSig || !verifySecp256k1Escrow(escrowBindingPayload, rawOampEscrowSig, liabilityProof.escrowPublicKeyPem)) {
    return {
      valid: false,
      contagionClauseViolation: true,
      ruleTriggered: "SECTION_8_14_CONTAGION",
      reason: "Invalid ECDSA secp256k1 signature on X-TERRA-OAMP-ESCROW-SIG"
    };
  }
  if (VERIFIED_HEADER_CACHE.size < 1e4) {
    VERIFIED_HEADER_CACHE.set(cacheKey, { mandate, liabilityProof });
  }
  if (context.requestedTool) {
    const allowed = mandate.allowedTools.includes("*") || mandate.allowedTools.includes(context.requestedTool);
    if (!allowed) {
      return {
        valid: false,
        ruleTriggered: "SPEND_OR_SCOPE_BREACH",
        reason: `Tool '${context.requestedTool}' is outside OAMP Mandate allowedTools [${mandate.allowedTools.join(", ")}]`
      };
    }
  }
  if (context.requestedSpendUsd !== undefined) {
    if (context.requestedSpendUsd > mandate.spendCap.maxPerCallUsd) {
      return {
        valid: false,
        ruleTriggered: "SPEND_OR_SCOPE_BREACH",
        reason: `Requested spend $${context.requestedSpendUsd} exceeds per-call cap $${mandate.spendCap.maxPerCallUsd}`
      };
    }
    if (mandate.spendCap.cumulativeSpentUsd + context.requestedSpendUsd > mandate.spendCap.dailyCapUsd) {
      return {
        valid: false,
        ruleTriggered: "SPEND_OR_SCOPE_BREACH",
        reason: `Cumulative spend $${mandate.spendCap.cumulativeSpentUsd + context.requestedSpendUsd} exceeds daily cap $${mandate.spendCap.dailyCapUsd}`
      };
    }
  }
  return {
    valid: true,
    mandate,
    liabilityProof
  };
}
// packages/terra-oamp-sdk/src/middleware/index.ts
function wrapMcpToolCall(request, headerOpts, estimatedSpendUsd = 0) {
  const terraHeaders = buildTerraHeaders(headerOpts);
  return {
    ...request,
    params: {
      ...request.params,
      _meta: {
        ...request.params._meta,
        terraHeaders,
        estimatedSpendUsd
      }
    }
  };
}
function verifyMcpToolCall(request, expectedPromptHash) {
  const terraHeaders = request.params._meta?.terraHeaders;
  if (!terraHeaders) {
    return {
      valid: false,
      contagionClauseViolation: true,
      ruleTriggered: "SECTION_8_14_CONTAGION",
      reason: "MCP tool call missing _meta.terraHeaders (Section 8.14 Contagion Clause)"
    };
  }
  return verifyTerraHeaders(terraHeaders, {
    requestedTool: request.params.name,
    requestedSpendUsd: request.params._meta?.estimatedSpendUsd,
    expectedPromptHash
  });
}
function createX402PaymentHeaders(intent, headerOpts) {
  const terraHeaders = buildTerraHeaders(headerOpts);
  const premiumUsd = Number((intent.amountUsd * 15 / 1e4).toFixed(6));
  const totalLockUsd = Number((intent.amountUsd + premiumUsd).toFixed(6));
  return {
    ...terraHeaders,
    "X-Payment-Protocol": "x402-terra-v1",
    "X-402-Amount-USD": intent.amountUsd.toFixed(6),
    "X-402-Terra-Premium-Bps": "15",
    "X-402-Terra-Premium-USD": premiumUsd.toFixed(6),
    "X-402-Total-Escrow-Lock-USD": totalLockUsd.toFixed(6),
    "X-402-Recipient-DID": intent.recipientDid,
    "X-402-Escrow-URI": intent.escrowAccountUri
  };
}
function verifyX402PaymentHeaders(headers, requestedTool) {
  const amountStr = headers["X-402-Amount-USD"] ?? headers["x-402-amount-usd"];
  const totalLockStr = headers["X-402-Total-Escrow-Lock-USD"] ?? headers["x-402-total-escrow-lock-usd"];
  const premiumStr = headers["X-402-Terra-Premium-USD"] ?? headers["x-402-terra-premium-usd"];
  const amountUsd = amountStr ? Number(amountStr) : undefined;
  const premiumUsd = premiumStr ? Number(premiumStr) : undefined;
  const totalLockUsd = totalLockStr ? Number(totalLockStr) : undefined;
  const verification = verifyTerraHeaders(headers, {
    requestedTool,
    requestedSpendUsd: totalLockUsd ?? amountUsd
  });
  return {
    ...verification,
    amountUsd,
    premiumUsd,
    totalLockUsd
  };
}
function withTerraLcelRunnable(toolName, runnableFn, headerOpts, estimatedSpendUsd = 0) {
  return {
    invoke: async (input) => {
      const terraHeaders = buildTerraHeaders(headerOpts);
      const check = verifyTerraHeaders(terraHeaders, {
        requestedTool: toolName,
        requestedSpendUsd: estimatedSpendUsd
      });
      if (!check.valid) {
        throw new Error(`TERRA LCEL Guard Blocked Execution: ${check.reason}`);
      }
      const output = await runnableFn(input, terraHeaders);
      return {
        input,
        output,
        terraHeaders,
        verifiedMandateId: check.mandate.mandateId
      };
    }
  };
}
async function executeCrewAiGuardedTask(task, headerOpts) {
  const headers = buildTerraHeaders(headerOpts);
  const check = verifyTerraHeaders(headers, {
    requestedTool: task.toolName,
    requestedSpendUsd: task.estimatedCostUsd
  });
  if (!check.valid) {
    throw new Error(`TERRA CrewAI Task Guard [${task.agentRole}]: ${check.reason}`);
  }
  const result = await task.execute(headers);
  return { result, headers };
}
// packages/terra-oamp-sdk/src/system-one.ts
import { createHmac as createHmac2 } from "node:crypto";
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
  const hmacReceipt = createHmac2("sha256", key).update(`${timestamp}|${state.goal}|${state.task_type}|${choice}|${bestP}`).digest("hex");
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
function spurvikVercelMiddleware(config) {
  return {
    wrapGenerate: async ({ doGenerate }) => {
      const result = await doGenerate();
      const ts = new Date().toISOString();
      const receipt = createHmac2("sha256", config.hmacKey).update(`${ts}|${config.principal}|${result?.text?.length ?? 0}`).digest("hex");
      return {
        ...result,
        spurvikCompliance: {
          principal: config.principal,
          art50Disclosure: config.art50Notice || `AI assistant acting on behalf of ${config.principal} (EU AI Act Art. 50(1)).`,
          hmacReceipt: receipt,
          timestamp: ts
        }
      };
    }
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
// packages/terra-oamp-sdk/src/machine-courtroom.ts
import { createHmac as createHmac3, timingSafeEqual } from "node:crypto";
function isEd25519SeedHex(key) {
  return /^[0-9a-fA-F]{64}$/.test(key.trim());
}
function canonicalizeAgentMandate(mandate) {
  return canonicalizeJsonLd({
    agentId: mandate.agentId,
    allowedCounterpartyDomains: [...mandate.allowedCounterpartyDomains].map((d) => d.toLowerCase().trim()),
    euAiActArt14HumanGateThresholdEur: mandate.euAiActArt14HumanGateThresholdEur,
    expiresAt: mandate.expiresAt,
    issuedAt: mandate.issuedAt,
    issuerCompanyCvrOrVat: mandate.issuerCompanyCvrOrVat,
    issuerPublicKeyOrDid: mandate.issuerPublicKeyOrDid,
    mandateId: mandate.mandateId,
    maxTransactionEur: mandate.maxTransactionEur,
    signingScheme: mandate.signingScheme,
    systemOneRouterMode: mandate.systemOneRouterMode
  });
}
function issueAgentMandate(input, optionsOrKey) {
  const opts = typeof optionsOrKey === "string" ? { signingKey: optionsOrKey } : optionsOrKey;
  const now = new Date;
  const issuedAt = input.issuedAt ?? now.toISOString();
  const expiresAt = input.expiresAt ?? new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000).toISOString();
  const scheme = opts.scheme ?? (isEd25519SeedHex(opts.signingKey) ? "Ed25519" : "HMAC-SHA256");
  const unsignedMandate = {
    mandateId: input.mandateId,
    issuerCompanyCvrOrVat: input.issuerCompanyCvrOrVat,
    agentId: input.agentId,
    maxTransactionEur: input.maxTransactionEur,
    allowedCounterpartyDomains: input.allowedCounterpartyDomains,
    euAiActArt14HumanGateThresholdEur: input.euAiActArt14HumanGateThresholdEur,
    systemOneRouterMode: input.systemOneRouterMode,
    issuedAt,
    expiresAt,
    signingScheme: scheme,
    ...opts.issuerPublicKeyOrDid || input.issuerPublicKeyOrDid ? { issuerPublicKeyOrDid: opts.issuerPublicKeyOrDid ?? input.issuerPublicKeyOrDid } : {}
  };
  const payload = canonicalizeAgentMandate(unsignedMandate);
  const signature = scheme === "Ed25519" ? signEd25519Detached(payload, opts.signingKey.trim()) : createHmac3("sha256", opts.signingKey).update(payload, "utf8").digest("hex");
  return {
    ...unsignedMandate,
    signature
  };
}
function verifyAgentMandate(mandate, verificationKeyOrDid, referenceTimeOrOptions, expectedSchemeArg) {
  try {
    if (!mandate || !mandate.signature)
      return false;
    if (typeof verificationKeyOrDid !== "string" || verificationKeyOrDid.trim().length === 0) {
      return false;
    }
    const opts = typeof referenceTimeOrOptions === "string" ? { referenceTimeIso: referenceTimeOrOptions, expectedScheme: expectedSchemeArg } : { ...referenceTimeOrOptions, expectedScheme: referenceTimeOrOptions?.expectedScheme ?? expectedSchemeArg };
    const refTime = opts.referenceTimeIso ? Date.parse(opts.referenceTimeIso) : Date.now();
    const expTime = Date.parse(mandate.expiresAt);
    if (!Number.isNaN(expTime) && refTime > expTime) {
      return false;
    }
    const key = verificationKeyOrDid.trim();
    const scheme = mandate.signingScheme ?? (key.startsWith("did:key:") || isEd25519SeedHex(key) && mandate.signature.length === 128 ? "Ed25519" : "HMAC-SHA256");
    if (opts.expectedScheme && scheme !== opts.expectedScheme) {
      return false;
    }
    const payload = canonicalizeAgentMandate(mandate);
    if (scheme === "Ed25519") {
      return verifyEd25519Detached(payload, mandate.signature, key);
    }
    const expectedHmac = createHmac3("sha256", key).update(payload, "utf8").digest("hex");
    const sigBuf = Buffer.from(mandate.signature, "hex");
    const expBuf = Buffer.from(expectedHmac, "hex");
    if (sigBuf.length !== expBuf.length || sigBuf.length === 0)
      return false;
    return timingSafeEqual(sigBuf, expBuf);
  } catch {
    return false;
  }
}
function verifyArt12HmacChain(chain, hmacKey) {
  let prev = "GENESIS";
  for (const entry of chain) {
    if (entry.previousHmac !== prev)
      return false;
    const expected = createHmac3("sha256", hmacKey).update(`${entry.eventId}|${entry.timestamp}|${entry.payloadHash}|${entry.previousHmac}`).digest("hex");
    if (expected !== entry.entryHmac)
      return false;
    prev = entry.entryHmac;
  }
  return true;
}
function adjudicateAgentDispute(claim) {
  const evaluatedAt = new Date().toISOString();
  const courtKey = (claim.courtSigningKey ?? claim.courtroomSigningKey ?? process.env.SPURVIK_COURT_SIGNING_KEY ?? "").trim();
  if (!courtKey) {
    throw new Error("MachineCourtroom Error: Missing courtSigningKey (provide claim.courtSigningKey or set SPURVIK_COURT_SIGNING_KEY).");
  }
  const buildVerdict = (status, reasoning) => {
    const base = {
      claimId: claim.claimId,
      mandateId: claim.mandate.mandateId,
      agentId: claim.mandate.agentId,
      issuerCompanyCvrOrVat: claim.mandate.issuerCompanyCvrOrVat,
      status,
      liableEntityCvrOrVat: claim.mandate.issuerCompanyCvrOrVat,
      reasoning,
      evaluatedAt
    };
    const verdictSignature = createHmac3("sha256", courtKey).update(canonicalizeJsonLd(base), "utf8").digest("hex");
    return {
      ...base,
      verdictSignature
    };
  };
  const mandateValid = verifyAgentMandate(claim.mandate, claim.mandateVerificationKey, undefined, claim.expectedMandateScheme);
  const hasValidChainInputs = Array.isArray(claim.art12HmacChain) && claim.art12HmacChain.length > 0 && typeof claim.art12HmacKey === "string" && claim.art12HmacKey.trim().length > 0;
  const chainValid = !claim.hmacChainTampered && Boolean(claim.systemOneDecision?.hmacReceipt) && hasValidChainInputs && verifyArt12HmacChain(claim.art12HmacChain, claim.art12HmacKey);
  if (!mandateValid || !chainValid) {
    return buildVerdict("REJECTED_TAMPERED_HMAC_CHAIN", "Mandate cryptographic signature or Spurvik Art. 12 Keyed-HMAC telemetry chain failed verification.");
  }
  const normalizedDomain = claim.counterpartyDomain.toLowerCase().trim();
  const allowedDomains = claim.mandate.allowedCounterpartyDomains.map((d) => d.toLowerCase().trim());
  const domainAllowed = allowedDomains.includes("*") || allowedDomains.includes(normalizedDomain);
  if (claim.transactionAmountEur > claim.mandate.maxTransactionEur || !domainAllowed) {
    return buildVerdict("REJECTED_EXCEEDED_MANDATE", `Transaction (${claim.transactionAmountEur} EUR with '${normalizedDomain}') exceeds bounded mandate envelope (max ${claim.mandate.maxTransactionEur} EUR, allowed: [${allowedDomains.join(", ")}]).`);
  }
  const requiresHumanGate = claim.transactionAmountEur > claim.mandate.euAiActArt14HumanGateThresholdEur || claim.systemOneDecision.choice === "ask_human" || claim.systemOneDecision.enforcedAction === "ask_human";
  if (requiresHumanGate && !claim.systemOneDecision.humanApproved) {
    return buildVerdict("REJECTED_MISSING_ART14_HUMAN_APPROVAL", `Transaction requires EU AI Act Art. 14 human oversight approval (threshold ${claim.mandate.euAiActArt14HumanGateThresholdEur} EUR / System-One decision '${claim.systemOneDecision.enforcedAction}'), but no human sign-off was recorded.`);
  }
  return buildVerdict("AUTHORIZED_WITHIN_MANDATE", `Transaction (${claim.transactionAmountEur} EUR with '${normalizedDomain}') verified within OAMP mandate '${claim.mandate.mandateId}', Art. 12 HMAC chain intact, and Art. 14 / System-One governance satisfied.`);
}
// packages/terra-oamp-sdk/src/openai-decisions.ts
import { createHash as createHash2, createHmac as createHmac4 } from "node:crypto";
function redactPiiForZeroPiiTransport(input) {
  return String(input || "").replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "[EMAIL_REDACTED]").replace(/\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, "[IBAN_REDACTED]").replace(/\b\d{6}-\d{4}\b/g, "[DK_CPR_REDACTED]").replace(/(sk-[a-zA-Z0-9_-]{12,}|whsec_[a-zA-Z0-9_-]+)/g, "[SECRET_REDACTED]");
}
async function wrapOpenAIDecision(input, config) {
  if (!config?.hmacKey || config.hmacKey.trim().length === 0) {
    throw new Error("Spurvik OpenAIDecision Error: non-empty hmacKey is required for Art. 12 evidence signing.");
  }
  const timestamp = new Date().toISOString();
  const eventId = `spv_oai_dec_${createHash2("sha256").update(`${config.appId}|${input.goal}|${input.taskType}|${timestamp}`).digest("hex").slice(0, 16)}`;
  const rawPrompt = input.promptOrInput ?? input.goal;
  const shouldRedact = config.redactPiiBeforeTransport !== false;
  const sanitizedPrompt = shouldRedact ? redactPiiForZeroPiiTransport(rawPrompt) : rawPrompt;
  const systemOneRouting = spurvikSystemOneRoute({
    goal: sanitizedPrompt,
    task_type: input.taskType,
    last_error: input.lastError || "none",
    repeats: input.repeats ?? 0
  }, {
    mode: config.mode || "active",
    hmacKey: config.hmacKey
  });
  const blockedByArt14 = (systemOneRouting.choice === "ask_human" || systemOneRouting.enforcedAction === "ask_human") && !config.humanApproved;
  const haltedByRouter = !blockedByArt14 && systemOneRouting.mode === "active" && (systemOneRouting.enforcedAction === "stop_retry" || systemOneRouting.enforcedAction === "reuse_cache" || systemOneRouting.enforcedAction === "research_capped");
  let output = null;
  let status = "EXECUTED";
  if (blockedByArt14) {
    status = "HELD_FOR_ART14_HUMAN_OVERSIGHT";
  } else if (haltedByRouter) {
    status = "HALTED_BY_SYSTEM_ONE";
  } else {
    output = await input.executeDecision(sanitizedPrompt);
  }
  const serializedOutput = output !== null && output !== undefined ? JSON.stringify(output) : "";
  const zeroPiiInputHmac = createHmac4("sha256", config.hmacKey).update(sanitizedPrompt, "utf8").digest("hex");
  const zeroPiiOutputHmac = createHmac4("sha256", config.hmacKey).update(serializedOutput, "utf8").digest("hex");
  const keyedHmacSha256Receipt = createHmac4("sha256", config.hmacKey).update(`${eventId}|${timestamp}|${config.appId}|${systemOneRouting.enforcedAction}|${zeroPiiInputHmac}|${zeroPiiOutputHmac}`).digest("hex");
  const c2paDigest = createHash2("sha256").update(`c2pa:spurvik:v1|${config.principal}|${timestamp}|${serializedOutput}`, "utf8").digest("hex");
  const sovereignProofHmac = createHmac4("sha256", config.hmacKey).update(`fra1|EyeTea-37093378|${eventId}|${keyedHmacSha256Receipt}|${c2paDigest}|${Boolean(config.humanApproved)}`).digest("hex");
  return {
    status,
    output,
    systemOneRouting,
    art12EvidenceEnvelope: {
      eventId,
      appId: config.appId,
      schemaName: input.schemaName || "openai.structured_decision.v1",
      zeroPiiInputHmac,
      zeroPiiOutputHmac,
      piiRedactedBeforeTransport: shouldRedact,
      keyedHmacSha256Receipt,
      timestamp
    },
    art50Provenance: {
      principal: config.principal,
      art50_1_InteractiveDisclosure: config.art50Notice || `Automated AI decision system operated on behalf of ${config.principal} (EU AI Act Art. 50(1)).`,
      art50_2_C2paContentDigestSha256: c2paDigest,
      syntheticOutputMarked: true
    },
    euSovereignAuditProof: {
      vaultRegion: "aws-eu-central-1 (Frankfurt, fra1)",
      operator: "EyeTea Solutions ApS (CVR: 37093378)",
      vendorNeutralVerifier: true,
      sovereignProofHmac
    }
  };
}
// packages/terra-oamp-sdk/src/ed25519-receipts.ts
import * as crypto3 from "node:crypto";
var ED25519_PKCS8_PREFIX2 = Buffer.from("302e020100300506032b657004220420", "hex");
var ED25519_SPKI_PREFIX2 = Buffer.from("302a300506032b6570032100", "hex");
function resolvePrivateKeyObject(privateKeyPemOrHex) {
  const trimmed = privateKeyPemOrHex.trim();
  let privKeyObj;
  if (trimmed.startsWith("-----BEGIN")) {
    privKeyObj = crypto3.createPrivateKey(trimmed);
  } else if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    const seedBuf = Buffer.from(trimmed, "hex");
    const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX2, seedBuf]);
    privKeyObj = crypto3.createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
  } else {
    throw new Error("Invalid Ed25519 private key: expected PKCS#8 PEM or 64-char hex seed.");
  }
  const pubKeyObj = crypto3.createPublicKey(privKeyObj);
  const spkiDer = pubKeyObj.export({ format: "der", type: "spki" });
  const pubKeyHex = spkiDer.subarray(spkiDer.length - 32).toString("hex");
  return { privKeyObj, pubKeyHex };
}
function resolvePublicKeyObject(publicKeyPemOrHexOrDid) {
  const trimmed = publicKeyPemOrHexOrDid.trim();
  if (trimmed.startsWith("-----BEGIN")) {
    return crypto3.createPublicKey(trimmed);
  }
  const pubHex = trimmed.startsWith("did:key:") ? didKeyToPublicKeyHex(trimmed) : trimmed;
  if (!/^[0-9a-fA-F]{64}$/.test(pubHex)) {
    throw new Error("Invalid Ed25519 public key: expected SPKI PEM, did:key, or 64-char hex.");
  }
  const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX2, Buffer.from(pubHex, "hex")]);
  return crypto3.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
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
    privKeyObj = crypto3.createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
  } else {
    const pair = crypto3.generateKeyPairSync("ed25519");
    privKeyObj = pair.privateKey;
    const pkcs8Der = privKeyObj.export({ format: "der", type: "pkcs8" });
    privateKeyHex = pkcs8Der.subarray(pkcs8Der.length - 32).toString("hex");
  }
  const pubKeyObj = crypto3.createPublicKey(privKeyObj);
  const spkiDer = pubKeyObj.export({ format: "der", type: "spki" });
  const publicKeyHex = spkiDer.subarray(spkiDer.length - 32).toString("hex");
  const privateKeyPem = privKeyObj.export({ format: "pem", type: "pkcs8" });
  const publicKeyPem = pubKeyObj.export({ format: "pem", type: "spki" });
  const didKey = publicKeyToDidKey(publicKeyHex);
  const keyId = `spv_k_${crypto3.createHash("sha256").update(publicKeyHex).digest("hex").slice(0, 12)}`;
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
  const payloadDigestSha256 = crypto3.createHash("sha256").update(canonicalPayload, "utf8").digest("hex");
  const timestamp = options.timestamp ?? new Date().toISOString();
  const receiptId = options.receiptId ?? `spv_rcpt_${crypto3.createHash("sha256").update(`${timestamp}|${payloadDigestSha256}`).digest("hex").slice(0, 16)}`;
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
  const keyedHmacSha256 = crypto3.createHmac("sha256", hmacKey).update(`${receiptId}|${timestamp}|${principal}|${operatorCvr}|${payloadDigestSha256}|${previousHmac}`, "utf8").digest("hex");
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
  const sigBuf = crypto3.sign(null, Buffer.from(signingInput, "utf8"), privKeyObj);
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
      const expectedDigest = crypto3.createHash("sha256").update(canonicalExpected, "utf8").digest("hex");
      if (expectedDigest !== receipt.payloadDigestSha256) {
        return false;
      }
    }
    if (options.hmacKey) {
      const expectedHmac = crypto3.createHmac("sha256", options.hmacKey).update(`${receipt.receiptId}|${receipt.timestamp}|${receipt.principal}|${receipt.operatorCvr}|${receipt.payloadDigestSha256}|${receipt.previousHmac}`, "utf8").digest("hex");
      const a = Buffer.from(expectedHmac, "hex");
      const b = Buffer.from(receipt.keyedHmacSha256, "hex");
      if (a.length !== b.length || !crypto3.timingSafeEqual(a, b)) {
        return false;
      }
    }
    const pubKeyObj = resolvePublicKeyObject(publicKeyPemOrHexOrDid);
    const signingInput = serializeReceiptSigningInput(receipt);
    const sigBuf = Buffer.from(receipt.ed25519SignatureHex, "hex");
    if (sigBuf.length !== 64)
      return false;
    return crypto3.verify(null, Buffer.from(signingInput, "utf8"), pubKeyObj, sigBuf);
  } catch {
    return false;
  }
}
// packages/terra-oamp-sdk/src/providers.ts
import * as crypto4 from "node:crypto";
var DEFAULT_FALLBACK_KEYPAIR = generateSpurvikEd25519KeyPair(process.env.SPURVIK_ED25519_SEED_HEX);
function isAsyncIterable(val) {
  return val != null && typeof val[Symbol.asyncIterator] === "function";
}
function extractChunkText(chunk) {
  if (!chunk)
    return "";
  if (typeof chunk === "string")
    return chunk;
  if (chunk.choices?.[0]?.delta?.content)
    return String(chunk.choices[0].delta.content);
  if (chunk.data?.choices?.[0]?.delta?.content)
    return String(chunk.data.choices[0].delta.content);
  if (chunk.delta?.text)
    return String(chunk.delta.text);
  if (typeof chunk.text === "function") {
    try {
      return String(chunk.text());
    } catch {
      return "";
    }
  }
  if (typeof chunk.text === "string")
    return chunk.text;
  if (chunk.candidates?.[0]?.content?.parts?.[0]?.text) {
    return String(chunk.candidates[0].content.parts[0].text);
  }
  return JSON.stringify(chunk);
}
function buildProviderReceipt(provider, model, contentDigestSha256, chunkCount, config) {
  const privKey = config.ed25519PrivateKeyPemOrHex || DEFAULT_FALLBACK_KEYPAIR.privateKeyHex;
  const receipt = signComplianceReceiptEd25519({
    appId: config.appId,
    chunkCount,
    contentDigestSha256,
    model,
    provider
  }, privKey, {
    hmacKey: (config.hmacKey || process.env.SPURVIK_HMAC_SECRET || process.env.SPURVIK_HMAC_KEY || "").trim(),
    principal: config.principal || "EyeTea Solutions ApS",
    previousHmac: config.previousHmac || "GENESIS",
    articleScope: ["EU-AI-ACT-ART-12", "EU-AI-ACT-ART-50(1)", "EU-AI-ACT-ART-50(2)"]
  });
  if (config.onReceipt) {
    config.onReceipt(receipt);
  }
  return receipt;
}
function wrapAsyncIterableStream(stream, provider, model, config) {
  const incrementalHash = crypto4.createHash("sha256");
  let chunkCount = 0;
  const disclosure = `AI output generated via ${provider} (${model}) on behalf of ${config.principal || "EyeTea Solutions ApS"} [EU AI Act Art. 50(1)/(2)].`;
  const origIterator = stream[Symbol.asyncIterator].bind(stream);
  const wrapped = Object.create(stream);
  wrapped.spurvikDisclosure = disclosure;
  wrapped[Symbol.asyncIterator] = async function* () {
    try {
      for await (const chunk of { [Symbol.asyncIterator]: origIterator }) {
        chunkCount++;
        incrementalHash.update(extractChunkText(chunk), "utf8");
        yield chunk;
      }
    } finally {
      const digest = incrementalHash.digest("hex");
      wrapped.spurvikReceipt = buildProviderReceipt(provider, model, digest, chunkCount, config);
    }
  };
  return wrapped;
}
function attachNonStreamReceipt(result, provider, model, config) {
  const serialized = JSON.stringify(result ?? {});
  const digest = crypto4.createHash("sha256").update(serialized, "utf8").digest("hex");
  const receipt = buildProviderReceipt(provider, model, digest, 1, config);
  const disclosure = `AI output generated via ${provider} (${model}) on behalf of ${config.principal || "EyeTea Solutions ApS"} [EU AI Act Art. 50(1)/(2)].`;
  if (result && typeof result === "object") {
    result.spurvikReceipt = receipt;
    result.spurvikDisclosure = disclosure;
  }
  return result;
}
function wrapOpenAI(client, config) {
  if (client?.chat?.completions?.create) {
    const origCreate = client.chat.completions.create.bind(client.chat.completions);
    client.chat.completions.create = async (...args) => {
      const params = args[0] || {};
      const model = String(params.model || "gpt-4o");
      const res = await origCreate(...args);
      if (params.stream || isAsyncIterable(res)) {
        return wrapAsyncIterableStream(res, "openai", model, config);
      }
      return attachNonStreamReceipt(res, "openai", model, config);
    };
  }
  if (client?.responses?.create) {
    const origResponses = client.responses.create.bind(client.responses);
    client.responses.create = async (...args) => {
      const params = args[0] || {};
      const model = String(params.model || "gpt-4o");
      const res = await origResponses(...args);
      if (params.stream || isAsyncIterable(res)) {
        return wrapAsyncIterableStream(res, "openai-responses", model, config);
      }
      return attachNonStreamReceipt(res, "openai-responses", model, config);
    };
  }
  return client;
}
function wrapAnthropic(client, config) {
  if (client?.messages?.create) {
    const origCreate = client.messages.create.bind(client.messages);
    client.messages.create = async (...args) => {
      const params = args[0] || {};
      const model = String(params.model || "claude-sonnet-4-6");
      const res = await origCreate(...args);
      if (params.stream || isAsyncIterable(res)) {
        return wrapAsyncIterableStream(res, "anthropic", model, config);
      }
      return attachNonStreamReceipt(res, "anthropic", model, config);
    };
  }
  return client;
}
function wrapGoogleGenAI(client, config) {
  if (client?.models?.generateContent) {
    const origGen = client.models.generateContent.bind(client.models);
    client.models.generateContent = async (...args) => {
      const params = args[0] || {};
      const model = String(params.model || "gemini-2.5-flash");
      const res = await origGen(...args);
      if (isAsyncIterable(res)) {
        return wrapAsyncIterableStream(res, "google-genai", model, config);
      }
      return attachNonStreamReceipt(res, "google-genai", model, config);
    };
  }
  if (client?.models?.generateContentStream) {
    const origStream = client.models.generateContentStream.bind(client.models);
    client.models.generateContentStream = async (...args) => {
      const params = args[0] || {};
      const model = String(params.model || "gemini-2.5-flash");
      const res = await origStream(...args);
      if (isAsyncIterable(res)) {
        return wrapAsyncIterableStream(res, "google-genai", model, config);
      }
      return attachNonStreamReceipt(res, "google-genai", model, config);
    };
  }
  return client;
}
function wrapMistral(client, config) {
  if (client?.chat?.complete) {
    const origComplete = client.chat.complete.bind(client.chat);
    client.chat.complete = async (...args) => {
      const params = args[0] || {};
      const model = String(params.model || "mistral-large-latest");
      const res = await origComplete(...args);
      return attachNonStreamReceipt(res, "mistral-ai", model, config);
    };
  }
  if (client?.chat?.stream) {
    const origStream = client.chat.stream.bind(client.chat);
    client.chat.stream = async (...args) => {
      const params = args[0] || {};
      const model = String(params.model || "mistral-large-latest");
      const res = await origStream(...args);
      if (isAsyncIterable(res)) {
        return wrapAsyncIterableStream(res, "mistral-ai", model, config);
      }
      return attachNonStreamReceipt(res, "mistral-ai", model, config);
    };
  }
  return client;
}
// packages/terra-oamp-sdk/src/frontier-adapters.ts
var DEFAULT_ADAPTER_KEYPAIR = generateSpurvikEd25519KeyPair(process.env.SPURVIK_ED25519_SEED_HEX);
function resolveAdapterHmacKey(hmacKey) {
  const key = (hmacKey || process.env.SPURVIK_HMAC_SECRET || process.env.SPURVIK_HMAC_KEY || "").trim();
  if (!key) {
    throw new Error("Missing SPURVIK_HMAC_KEY / hmacKey in Spurvik frontier adapter.");
  }
  return key;
}
function spurvikOpenAIAgentsProcessor(config) {
  const receipts = [];
  let prevHmac = "GENESIS";
  const emitReceipt = (eventPayload) => {
    const r = signComplianceReceiptEd25519({ appId: config.appId, framework: "openai-agents-sdk", ...eventPayload }, config.ed25519PrivateKeyPemOrHex || DEFAULT_ADAPTER_KEYPAIR.privateKeyHex, {
      hmacKey: resolveAdapterHmacKey(config.hmacKey),
      principal: config.principal || "EyeTea Solutions ApS",
      previousHmac: prevHmac,
      articleScope: ["EU-AI-ACT-ART-12", "EU-AI-ACT-ART-14", "EU-AI-ACT-ART-50(1)"]
    });
    prevHmac = r.keyedHmacSha256;
    receipts.push(r);
    if (config.onReceipt)
      config.onReceipt(r);
    return r;
  };
  return {
    name: "spurvik-openai-agents-processor",
    getReceipts: () => [...receipts],
    onTraceStart: (trace) => {
      return emitReceipt({
        event: "trace_start",
        traceId: trace.traceId || "trace_0",
        workflowName: trace.workflowName || "agent_workflow"
      });
    },
    onSpanEnd: (span) => {
      return emitReceipt({
        event: "span_end",
        spanId: span.spanId || "span_0",
        spanType: span.type || "tool",
        spanName: span.name || "agent_span"
      });
    },
    onTraceEnd: (trace) => {
      return emitReceipt({
        event: "trace_end",
        traceId: trace.traceId || "trace_0"
      });
    },
    requireHumanApproval: (toolName, toolArgsSummary = "") => {
      const sanitizedArgs = redactPiiForZeroPiiTransport(toolArgsSummary);
      const decision = spurvikSystemOneRoute({
        goal: `Execute tool ${toolName} ${sanitizedArgs}`,
        task_type: toolName,
        last_error: "none",
        repeats: 0
      }, { mode: config.mode || "active", hmacKey: config.hmacKey });
      const requiresApproval = decision.choice === "ask_human" || decision.enforcedAction === "ask_human";
      const receipt = emitReceipt({
        event: "tool_approval_check",
        toolName,
        requiresApproval,
        enforcedAction: decision.enforcedAction,
        confidence: decision.confidence
      });
      return { requiresApproval, decision, receipt };
    }
  };
}

class SpurvikOTelGenAIExporter {
  config;
  exportedReceipts = [];
  previousHmac = "GENESIS";
  constructor(config) {
    this.config = config;
  }
  export(spans, resultCallback) {
    const batchReceipts = [];
    for (const span of spans) {
      const attrs = span.attributes || {};
      const genAiSystem = String(attrs["gen_ai.system"] || "generic-llm");
      const genAiModel = String(attrs["gen_ai.request.model"] || attrs["gen_ai.response.model"] || "unknown-model");
      const genAiOperation = String(attrs["gen_ai.operation.name"] || span.name || "chat");
      const inputTokens = Number(attrs["gen_ai.usage.input_tokens"] || 0);
      const outputTokens = Number(attrs["gen_ai.usage.output_tokens"] || 0);
      const ctx = span.spanContext ? span.spanContext() : { traceId: "0", spanId: "0" };
      const receipt = signComplianceReceiptEd25519({
        appId: this.config.appId,
        framework: "opentelemetry-genai",
        genAiModel,
        genAiOperation,
        genAiSystem,
        inputTokens,
        outputTokens,
        spanId: ctx.spanId,
        traceId: ctx.traceId
      }, this.config.ed25519PrivateKeyPemOrHex || DEFAULT_ADAPTER_KEYPAIR.privateKeyHex, {
        hmacKey: resolveAdapterHmacKey(this.config.hmacKey),
        principal: this.config.principal || "EyeTea Solutions ApS",
        previousHmac: this.previousHmac,
        articleScope: ["EU-AI-ACT-ART-12", "EU-AI-ACT-ART-50(2)"]
      });
      this.previousHmac = receipt.keyedHmacSha256;
      this.exportedReceipts.push(receipt);
      batchReceipts.push(receipt);
      if (this.config.onReceipt)
        this.config.onReceipt(receipt);
    }
    if (resultCallback) {
      resultCallback({ code: 0 });
    }
    return batchReceipts;
  }
  getExportedReceipts() {
    return [...this.exportedReceipts];
  }
  async forceFlush() {}
  async shutdown() {}
}
function spurvikLangGraphInterrupt(config) {
  return {
    guardNode: (state, interruptFn) => {
      const sanitizedGoal = redactPiiForZeroPiiTransport(state.goal || "langgraph_node");
      const taskType = state.taskType || "node_step";
      const decision = spurvikSystemOneRoute({
        goal: sanitizedGoal,
        task_type: taskType,
        last_error: "none",
        repeats: 0
      }, { mode: config.mode || "active", hmacKey: config.hmacKey });
      const receipt = signComplianceReceiptEd25519({
        appId: config.appId,
        enforcedAction: decision.enforcedAction,
        framework: "langgraph",
        goal: sanitizedGoal,
        humanApproved: Boolean(state.humanApproved),
        taskType
      }, config.ed25519PrivateKeyPemOrHex || DEFAULT_ADAPTER_KEYPAIR.privateKeyHex, {
        hmacKey: resolveAdapterHmacKey(config.hmacKey),
        principal: config.principal || "EyeTea Solutions ApS",
        articleScope: ["EU-AI-ACT-ART-12", "EU-AI-ACT-ART-14"]
      });
      if (config.onReceipt)
        config.onReceipt(receipt);
      const needsInterrupt = (decision.choice === "ask_human" || decision.enforcedAction === "ask_human") && !state.humanApproved;
      let interruptValue = null;
      if (needsInterrupt) {
        interruptValue = interruptFn({
          reason: "EU_AI_ACT_ART_14_HUMAN_OVERSIGHT_REQUIRED",
          taskType,
          confidence: decision.confidence,
          receiptId: receipt.receiptId,
          ed25519SignatureHex: receipt.ed25519SignatureHex
        });
      }
      return {
        decision,
        receipt,
        interrupted: needsInterrupt,
        interruptValue
      };
    }
  };
}
function spurvikMastraProcessor(config) {
  let prevHmac = "GENESIS";
  return {
    id: "spurvik-mastra-eu-ai-act-processor",
    processInput: (input) => {
      const sanitizedText = redactPiiForZeroPiiTransport(input.text);
      const decision = spurvikSystemOneRoute({
        goal: sanitizedText,
        task_type: input.taskType || "mastra_agent_step",
        last_error: "none",
        repeats: 0
      }, { mode: config.mode || "active", hmacKey: config.hmacKey });
      const receipt = signComplianceReceiptEd25519({
        appId: config.appId,
        enforcedAction: decision.enforcedAction,
        framework: "mastra",
        phase: "input",
        sanitizedText
      }, config.ed25519PrivateKeyPemOrHex || DEFAULT_ADAPTER_KEYPAIR.privateKeyHex, {
        hmacKey: resolveAdapterHmacKey(config.hmacKey),
        principal: config.principal || "EyeTea Solutions ApS",
        previousHmac: prevHmac
      });
      prevHmac = receipt.keyedHmacSha256;
      if (config.onReceipt)
        config.onReceipt(receipt);
      return {
        sanitizedText,
        decision,
        receipt,
        blockedByArt14: decision.enforcedAction === "ask_human"
      };
    },
    processOutput: (output) => {
      const receipt = signComplianceReceiptEd25519({
        appId: config.appId,
        framework: "mastra",
        outputLength: output.text.length,
        phase: "output"
      }, config.ed25519PrivateKeyPemOrHex || DEFAULT_ADAPTER_KEYPAIR.privateKeyHex, {
        hmacKey: resolveAdapterHmacKey(config.hmacKey),
        principal: config.principal || "EyeTea Solutions ApS",
        previousHmac: prevHmac
      });
      prevHmac = receipt.keyedHmacSha256;
      if (config.onReceipt)
        config.onReceipt(receipt);
      return {
        ...output,
        art50Disclosure: `AI assistant operated on behalf of ${config.principal || "EyeTea Solutions ApS"} (EU AI Act Art. 50(1)).`,
        spurvikReceipt: receipt
      };
    }
  };
}
// packages/terra-oamp-sdk/src/hermes-openclaw.ts
import { createHmac as createHmac6 } from "node:crypto";
var DEFAULT_SDK_KEYPAIR = generateSpurvikEd25519KeyPair(process.env.SPURVIK_ED25519_SEED_HEX);
async function withSpurvik(callOrThunk, config) {
  const hmacKey = (config?.hmacKey || process.env.SPURVIK_HMAC_SECRET || process.env.SPURVIK_HMAC_KEY || "").trim();
  if (!hmacKey) {
    throw new Error("Missing SPURVIK_HMAC_KEY / hmacKey in withSpurvik.");
  }
  const principal = config?.principal || "EyeTea Solutions ApS";
  const sanitizedGoal = redactPiiForZeroPiiTransport(config?.goal || "llm_generation");
  const taskType = config?.taskType || "chat.completion";
  const decision = spurvikSystemOneRoute({
    goal: sanitizedGoal,
    task_type: taskType,
    last_error: config?.lastError || "none",
    repeats: config?.repeats ?? 0
  }, {
    mode: config?.mode || "active",
    hmacKey
  });
  if (decision.enforcedAction === "ask_human" && !config?.humanApproved) {
    const heldReceipt = signComplianceReceiptEd25519({
      appId: config?.appId || "spurvik-app",
      enforcedAction: "ask_human",
      rawPromptStored: false,
      status: "HELD_FOR_ART14_HUMAN_OVERSIGHT",
      taskType
    }, config?.ed25519PrivateKeyPemOrHex || DEFAULT_SDK_KEYPAIR.privateKeyHex, { hmacKey, principal });
    return {
      status: "HELD_FOR_ART14_HUMAN_OVERSIGHT",
      spurvikReceipt: heldReceipt,
      spurvikSystemOne: decision,
      spurvikArt50Notice: `AI system operated on behalf of ${principal} (EU AI Act Art. 50(1)).`
    };
  }
  const rawResult = typeof callOrThunk === "function" ? await callOrThunk() : await callOrThunk;
  const outputDigest = createHmac6("sha256", hmacKey).update(JSON.stringify(rawResult ?? {}), "utf8").digest("hex");
  const receipt = signComplianceReceiptEd25519({
    appId: config?.appId || "spurvik-app",
    enforcedAction: decision.enforcedAction,
    outputHmac: outputDigest,
    rawPromptStored: false,
    taskType
  }, config?.ed25519PrivateKeyPemOrHex || DEFAULT_SDK_KEYPAIR.privateKeyHex, { hmacKey, principal });
  const notice = `AI system operated on behalf of ${principal} (EU AI Act Art. 50(1)).`;
  if (rawResult && typeof rawResult === "object") {
    rawResult.spurvikReceipt = receipt;
    rawResult.spurvikSystemOne = decision;
    rawResult.spurvikArt50Notice = notice;
    return rawResult;
  }
  return {
    value: rawResult,
    spurvikReceipt: receipt,
    spurvikSystemOne: decision,
    spurvikArt50Notice: notice
  };
}
function wrapHermesOrOpenClawAgent(agentConfig, spurvikConfig) {
  const runtime = agentConfig.runtime || "hermes-agent";
  const version = agentConfig.version || "v2026.10.x";
  const hmacKey = (spurvikConfig.hmacKey || process.env.SPURVIK_HMAC_SECRET || process.env.SPURVIK_HMAC_KEY || "").trim();
  if (!hmacKey) {
    throw new Error("Missing SPURVIK_HMAC_KEY / hmacKey in wrapHermesOrOpenClawAgent.");
  }
  const principal = spurvikConfig.principal || "EyeTea Solutions ApS";
  let previousHmac = "GENESIS";
  async function executeToolCall(toolName, toolInput, executeFn, opts) {
    const serializedInput = typeof toolInput === "string" ? toolInput : JSON.stringify(toolInput ?? {});
    const sanitizedInput = redactPiiForZeroPiiTransport(serializedInput);
    const inputHmac = createHmac6("sha256", hmacKey).update(sanitizedInput, "utf8").digest("hex");
    const decision = spurvikSystemOneRoute({
      goal: `${runtime}:${toolName} ${sanitizedInput}`,
      task_type: toolName,
      last_error: opts?.lastError || spurvikConfig.lastError || "none",
      repeats: opts?.repeats ?? spurvikConfig.repeats ?? 0
    }, {
      mode: spurvikConfig.mode || "active",
      hmacKey
    });
    const humanApproved = opts?.humanApproved ?? spurvikConfig.humanApproved ?? false;
    const heldByArt14 = (decision.choice === "ask_human" || decision.enforcedAction === "ask_human") && !humanApproved;
    const haltedBySystemOne = !heldByArt14 && decision.mode === "active" && (decision.enforcedAction === "stop_retry" || decision.enforcedAction === "reuse_cache" || decision.enforcedAction === "research_capped");
    let output = null;
    let status = "EXECUTED";
    if (heldByArt14) {
      status = "HELD_FOR_ART14_HUMAN_OVERSIGHT";
    } else if (haltedBySystemOne) {
      status = "HALTED_BY_SYSTEM_ONE";
    } else {
      output = await executeFn();
    }
    const receipt = signComplianceReceiptEd25519({
      agentName: agentConfig.agentName || runtime,
      appId: spurvikConfig.appId,
      enforcedAction: decision.enforcedAction,
      inputHmac,
      rawPromptStored: false,
      runtime,
      status,
      toolName,
      version
    }, spurvikConfig.ed25519PrivateKeyPemOrHex || DEFAULT_SDK_KEYPAIR.privateKeyHex, {
      hmacKey,
      principal,
      previousHmac,
      articleScope: ["EU-AI-ACT-ART-12", "EU-AI-ACT-ART-14", "EU-AI-ACT-ART-50(1)"]
    });
    const currentPrev = previousHmac;
    previousHmac = receipt.keyedHmacSha256;
    return {
      status,
      decision,
      enforcedAction: decision.enforcedAction,
      output,
      receipt,
      art12HmacEnvelope: {
        runtime,
        version,
        toolName,
        inputHmac,
        previousHmac: currentPrev,
        rawPromptStored: false
      }
    };
  }
  return {
    runtime,
    version,
    executeToolCall
  };
}
export {
  wrapOpenAIDecision,
  wrapOpenAI,
  wrapMistral,
  wrapMcpToolCall,
  wrapHermesOrOpenClawAgent,
  wrapGoogleGenAI,
  wrapAnthropic,
  withTerraLcelRunnable,
  withSpurvik,
  verifyX402PaymentHeaders,
  verifyTerraHeaders,
  verifySecp256k1Escrow,
  verifyMcpToolCall,
  verifyEd25519Detached,
  verifyComplianceReceiptEd25519,
  verifyArt12HmacChain,
  verifyAgentMandate,
  spurvikVercelMiddleware,
  spurvikSystemOneRoute,
  spurvikOpenAIAgentsProcessor,
  spurvikMastraProcessor,
  spurvikLangGraphInterrupt,
  signSecp256k1Escrow,
  signEd25519Detached,
  signComplianceReceiptEd25519,
  sha256Hex,
  scanRepositoryForCompliance,
  redactPiiForZeroPiiTransport,
  publicKeyToDidKey,
  publicKeyToDidIon,
  issueAgentMandate,
  generateSpurvikEd25519KeyPair,
  generateSecp256k1KeyPair,
  generateEd25519KeyPair,
  executeCrewAiGuardedTask,
  encodeMandateHeader,
  didKeyToPublicKeyHex,
  delegateMandate,
  decodeMandateHeader,
  createX402PaymentHeaders,
  createMandate,
  computePromptHash,
  canonicalizeJsonLd,
  canonicalizeAgentMandate,
  buildTerraHeaders,
  base58Encode,
  base58Decode,
  adjudicateAgentDispute,
  SpurvikOTelGenAIExporter,
  SIDE_EFFECT_VERBS
};
