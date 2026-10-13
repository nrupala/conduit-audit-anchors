// Copyright (C) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0
//
// Standalone Conduit Router receipt verifier (spec Stage 4, D5).
//
// Verifies a Conduit receipt against PUBLIC artifacts only — the receipt
// itself, the published anchor list, and the published anchor public
// key. It never asks a Conduit server whether the receipt is valid: the
// math is the verdict. Zero dependencies; Node >= 18.
//
//   node scripts/verify-receipt.mjs <receipt.json>
//   node scripts/verify-receipt.mjs <receipt.json> \
//        --anchors https://raw.githubusercontent.com/nrupala/conduit-audit-anchors/main/anchors.jsonl \
//        --key     https://raw.githubusercontent.com/nrupala/conduit-audit-anchors/main/ANCHOR-KEY.json
//   cat receipt.json | node scripts/verify-receipt.mjs - --json
//
// Defaults fetch the public git mirror. --anchors/--key also accept local
// files and the gateway's own endpoints (GET /v1/audit/anchors and
// GET /.well-known/conduit/anchor-key.json on router.pipavia.com).
//
// Checks (all must pass for INDEPENDENT-VERIFIED, exit 0):
//   1. the receipt's hash recomputes from its own fields;
//   2. the receipt sits in a signed anchor's segment at its seq, and its
//      prev_hash links to the record (or anchor head) before it;
//   3. that anchor's head equals the last hash of its segment;
//   4. the anchor's Ed25519 signature verifies against the public key;
//   5. the anchor list chains: each anchor names the previous anchor's
//      hash, and anchor seqs strictly increase.
// Exit 1 = a check failed. Exit 2 = the covering anchor is not
// independently verifiable (e.g. HMAC-signed deployment).

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { readFile } from "node:fs/promises";

// --- canonical JSON: byte-identical to the gateway's canonical() -------
export function canonical(value) {
  return JSON.stringify(sortKeys(value));
}
function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v !== null && typeof v === "object") {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortKeys(v[k]);
    return out;
  }
  return v;
}
export function sha256Hex(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}
function without(obj, field) {
  const out = {};
  for (const k of Object.keys(obj)) if (k !== field) out[k] = obj[k];
  return out;
}
/** An anchor's own hash: sha256 of its canonical body (signature excluded). */
export function anchorHash(anchor) {
  return sha256Hex(canonical(without(anchor, "signature")));
}

// --- Ed25519 via node:crypto (JWK OKP) -----------------------------------
export function ed25519Verify(publicKeyRaw, signatureHex, canonicalBody) {
  const jwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: Buffer.from(publicKeyRaw).toString("base64url"),
  };
  const key = createPublicKey({ key: jwk, format: "jwk" });
  return cryptoVerify(
    null,
    Buffer.from(canonicalBody, "utf8"),
    key,
    Buffer.from(signatureHex, "hex")
  );
}

/** The pure verification core. `anchors`: array of anchor objects (any
 *  order). `publicKeyRaw`: Uint8Array of the raw Ed25519 public key, or
 *  null when the key document is unavailable. */
export function verifyReceiptIndependent(receipt, anchors, publicKeyRaw) {
  const checks = [];
  const push = (id, label, pass, note) =>
    checks.push({ id, label, pass: Boolean(pass), ...(note ? { note } : {}) });

  if (!receipt || typeof receipt !== "object" || typeof receipt.seq !== "number") {
    push("shape", "receipt is a record object with a numeric seq", false);
    return { verdict: "FAILED", checks };
  }
  const sorted = [...anchors].sort((a, b) => a.seq - b.seq);

  // 1. receipt self-integrity
  const recomputed = sha256Hex(canonical(without(receipt, "hash")));
  push(
    "receipt_hash",
    "receipt hash recomputes from its own fields",
    recomputed === receipt.hash
  );

  // 2 + 3. segment inclusion, prev linkage, anchor head
  const covering = sorted.find((a) => a.seq >= receipt.seq) ?? null;
  if (!covering) {
    push("covered", "receipt is covered by a published anchor", false);
  } else {
    const seg = Array.isArray(covering.segment) ? covering.segment : [];
    const idx = seg.findIndex((e) => e.seq === receipt.seq);
    const included = idx >= 0 && seg[idx].hash === receipt.hash;
    let linked = false;
    if (included) {
      if (receipt.seq === 0) linked = receipt.prev_hash === "GENESIS";
      else if (idx > 0) linked = receipt.prev_hash === seg[idx - 1].hash;
      else {
        const prevAnchor = sorted.find((a) => a.seq === receipt.seq - 1);
        linked = prevAnchor ? receipt.prev_hash === prevAnchor.head_hash : false;
      }
    }
    push(
      "segment_inclusion",
      "receipt sits in the covering anchor's segment, linked to its predecessor",
      included && linked
    );
    push(
      "anchor_head",
      "covering anchor's head equals its segment's last hash",
      covering.segment_complete !== false &&
        seg.length > 0 &&
        seg[seg.length - 1].hash === covering.head_hash
    );

    // 4. anchor signature
    if (covering.alg !== "Ed25519") {
      push(
        "anchor_signature",
        "anchor signature verifies against the published public key",
        false,
        `anchor alg is ${covering.alg ?? "unknown"} — holder-verifiable only, not independent`
      );
    } else if (!publicKeyRaw) {
      push(
        "anchor_signature",
        "anchor signature verifies against the published public key",
        false,
        "public key document unavailable"
      );
    } else {
      let ok = false;
      try {
        ok = ed25519Verify(
          publicKeyRaw,
          covering.signature,
          canonical(without(covering, "signature"))
        );
      } catch {
        ok = false;
      }
      push(
        "anchor_signature",
        "anchor signature verifies against the published public key",
        ok
      );
    }
  }

  // 5. anchor chain
  let chainOk = sorted.length > 0;
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i].seq <= sorted[i - 1].seq) chainOk = false;
    if (sorted[i].prev_anchor_hash !== anchorHash(sorted[i - 1])) chainOk = false;
  }
  if (sorted.length > 0 && sorted[0].prev_anchor_hash !== "GENESIS") chainOk = false;
  push("anchor_chain", "anchors chain together in order, none rewritten", chainOk);

  const sigCheck = checks.find((c) => c.id === "anchor_signature");
  const allPass = checks.every((c) => c.pass);
  const verdict = allPass
    ? "INDEPENDENT-VERIFIED"
    : sigCheck && sigCheck.note
      ? "NOT-INDEPENDENTLY-VERIFIABLE"
      : "FAILED";
  return { verdict, checks };
}

// --- IO shell --------------------------------------------------------------
const DEFAULT_ANCHORS_URL =
  "https://raw.githubusercontent.com/nrupala/conduit-audit-anchors/main/anchors.jsonl";
const DEFAULT_KEY_URL =
  "https://raw.githubusercontent.com/nrupala/conduit-audit-anchors/main/ANCHOR-KEY.json";

async function readSource(src) {
  if (/^https?:\/\//.test(src)) {
    const res = await fetch(src);
    if (!res.ok) throw new Error(`fetch ${src} → HTTP ${res.status}`);
    return res.text();
  }
  return readFile(src, "utf8");
}

export function parseAnchors(text) {
  const trimmed = text.trim();
  if (!trimmed) return [];
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) return parsed;
    if (parsed && Array.isArray(parsed.anchors)) return parsed.anchors;
    if (parsed && typeof parsed.seq === "number") return [parsed];
  } catch {
    /* fall through to JSONL */
  }
  return trimmed
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

export function parsePublicKey(text) {
  const doc = JSON.parse(text);
  const b64 = doc.public_key ?? doc.publicKey ?? null;
  if (b64) return new Uint8Array(Buffer.from(b64, "base64"));
  if (doc.x) return new Uint8Array(Buffer.from(doc.x, "base64url"));
  return null;
}

async function main(argv) {
  const args = [...argv];
  let receiptSrc = null;
  let anchorsSrc = DEFAULT_ANCHORS_URL;
  let keySrc = DEFAULT_KEY_URL;
  let jsonOut = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--anchors") anchorsSrc = args[++i];
    else if (a === "--key") keySrc = args[++i];
    else if (a === "--json") jsonOut = true;
    else if (!a.startsWith("--")) receiptSrc = a;
  }
  if (!receiptSrc) {
    console.error("usage: verify-receipt.mjs <receipt.json|-> [--anchors src] [--key src] [--json]");
    process.exit(64);
  }
  const receiptText =
    receiptSrc === "-"
      ? await new Promise((resolve, reject) => {
          let data = "";
          process.stdin.setEncoding("utf8");
          process.stdin.on("data", (c) => (data += c));
          process.stdin.on("end", () => resolve(data));
          process.stdin.on("error", reject);
        })
      : await readSource(receiptSrc);
  const receiptDoc = JSON.parse(receiptText);
  const receipt = receiptDoc.receipt ?? receiptDoc.record ?? receiptDoc;
  const anchors = parseAnchors(await readSource(anchorsSrc));
  let publicKeyRaw = null;
  try {
    publicKeyRaw = parsePublicKey(await readSource(keySrc));
  } catch {
    publicKeyRaw = null;
  }
  const result = verifyReceiptIndependent(receipt, anchors, publicKeyRaw);
  if (jsonOut) {
    console.log(JSON.stringify({ ...result, receipt_seq: receipt.seq }, null, 2));
  } else {
    console.log(`receipt rcpt_${receipt.seq} — ${result.verdict}`);
    for (const c of result.checks) {
      console.log(`  ${c.pass ? "✓" : "✗"} ${c.label}${c.note ? ` (${c.note})` : ""}`);
    }
  }
  process.exit(result.verdict === "INDEPENDENT-VERIFIED" ? 0 : result.verdict === "FAILED" ? 1 : 2);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).catch((e) => {
    console.error(`verifier error: ${e.message ?? e}`);
    process.exit(1);
  });
}
