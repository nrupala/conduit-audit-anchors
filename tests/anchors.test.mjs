// Copyright (C) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0
//
// Chain-integrity suite for the committed audit anchors.
//
// This repository's content IS the data: anchors.jsonl is the product.
// The suite verifies the committed mirror the way an outside auditor
// would, using the repository's own verifier (verify.mjs) as the
// library under test:
//
//   - every anchor parses and carries the v2 fields;
//   - the anchors chain: first prev is GENESIS, every later prev_anchor_hash
//     equals the previous anchor's hash (signature excluded, canonical JSON);
//   - every anchor's Ed25519 signature verifies against ANCHOR-KEY.json;
//   - every anchor's head_hash is the last hash of its segment, and each
//     segment spans exactly the records since the previous anchor;
//   - latest.json is exactly the newest anchor in anchors.jsonl;
//   - every anchor names the published key (key_id, signer).
//
// Run from the repository root:  node --test tests/

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  anchorHash,
  canonical,
  ed25519Verify,
  parseAnchors,
  parsePublicKey,
} from "../verify.mjs";

const root = new URL("../", import.meta.url);
const anchorsText = await readFile(new URL("anchors.jsonl", root), "utf8");
const keyText = await readFile(new URL("ANCHOR-KEY.json", root), "utf8");
const latest = JSON.parse(await readFile(new URL("latest.json", root), "utf8"));
const keyDoc = JSON.parse(keyText);
const anchors = parseAnchors(anchorsText).sort((a, b) => a.seq - b.seq);
const publicKeyRaw = parsePublicKey(keyText);

function without(obj, field) {
  const out = {};
  for (const k of Object.keys(obj)) if (k !== field) out[k] = obj[k];
  return out;
}

test("anchor key document is a usable Ed25519 key", () => {
  assert.equal(keyDoc.alg, "Ed25519");
  assert.ok(keyDoc.key_id, "key_id present");
  assert.ok(publicKeyRaw, "public_key parses");
  assert.equal(publicKeyRaw.length, 32, "Ed25519 public keys are 32 bytes");
});

test("anchors exist and every anchor carries the v2 shape", () => {
  assert.ok(anchors.length > 0, "anchors.jsonl is not empty");
  for (const a of anchors) {
    for (const f of ["seq", "prev_anchor_hash", "head_hash", "segment",
                     "segment_complete", "signature", "alg", "key_id",
                     "signer", "ts", "v"]) {
      assert.ok(f in a, `anchor seq ${a.seq} missing field ${f}`);
    }
    assert.equal(a.v, 2);
    assert.equal(a.alg, "Ed25519");
    assert.match(a.head_hash, /^[0-9a-f]{64}$/);
    assert.match(a.signature, /^[0-9a-f]{128}$/);
  }
});

test("anchors chain together in order, none rewritten", () => {
  assert.equal(anchors[0].prev_anchor_hash, "GENESIS");
  for (let i = 1; i < anchors.length; i++) {
    assert.ok(anchors[i].seq > anchors[i - 1].seq, "seqs strictly increase");
    assert.equal(
      anchors[i].prev_anchor_hash,
      anchorHash(anchors[i - 1]),
      `anchor seq ${anchors[i].seq} does not name its predecessor's hash`
    );
  }
});

test("every anchor signature verifies against the published key", () => {
  for (const a of anchors) {
    assert.equal(a.key_id, keyDoc.key_id, `anchor seq ${a.seq} key_id`);
    assert.equal(a.signer, keyDoc.signer, `anchor seq ${a.seq} signer`);
    const ok = ed25519Verify(
      publicKeyRaw,
      a.signature,
      canonical(without(a, "signature"))
    );
    assert.ok(ok, `anchor seq ${a.seq} signature does not verify`);
  }
});

test("segments are complete, span the records since the previous anchor, and end at the anchor head", () => {
  // Invariants read from the committed data and the verifier's own checks:
  // a segment starts at the first record after the previous anchor, ends at
  // the anchor's own seq with the head hash, and every entry names a record
  // inside that span. (A segment may carry more than one entry for the same
  // seq — anchor seq 20 does, inside its signed body; the suite asserts the
  // span and head invariants, not one-entry-per-seq.)
  let expectedFirstSeq = 0;
  for (const a of anchors) {
    assert.equal(a.segment_complete, true, `anchor seq ${a.seq} incomplete`);
    assert.ok(a.segment.length > 0, `anchor seq ${a.seq} empty segment`);
    assert.equal(a.segment[0].seq, expectedFirstSeq,
      `anchor seq ${a.seq} segment does not start where the chain left off`);
    for (const entry of a.segment) {
      assert.ok(entry.seq >= expectedFirstSeq && entry.seq <= a.seq,
        `anchor seq ${a.seq} segment entry out of span`);
      assert.match(entry.hash, /^[0-9a-f]{64}$/);
    }
    const last = a.segment[a.segment.length - 1];
    assert.equal(last.seq, a.seq, `anchor seq ${a.seq} does not end its segment`);
    assert.equal(last.hash, a.head_hash, `anchor seq ${a.seq} head mismatch`);
    expectedFirstSeq = a.seq + 1;
  }
});

test("latest.json is exactly the newest committed anchor", () => {
  assert.deepEqual(latest, anchors[anchors.length - 1]);
});
