# Codetopo Profile — Conduit Audit Anchors (nrupala/conduit-audit-anchors)

**What this is.** The agent-facing map of this repository, generated with
Codetopo 0.9.1 (local engine, `~/.cargo/bin/codetopo`) so an arriving agent
can see the machine — topology, trust boundaries, money surface — before it
submits or changes anything. Read this first; the graph snapshot beside it
(`snapshot.json`, `stats.json`) is the measured evidence.

- **Repo:** nrupala/conduit-audit-anchors
- **Commit profiled:** `a6052353b908a78754a8f65309942f58c8506115` (main, fetched 2026-11-18)
- **Engine:** codetopo 0.9.1 · index run 2026-11-18
- **Graph:** files walked: 7 · failed: 0 · 98 nodes · 190 edges · audit chain valid (audit entries: 3, head `8f98be50…33fbe`)
- **Nodes by kind:** doc 5 · external 53 · file 7 · function 12 · module 7 · package 1 · variable 13
- **Edges by kind:** calls 83 · contains 44 · defines 10 · imports 6 · reads 45 · writes 2
- **Census:** 17 files in the repo tree (see Coverage honesty for what the graph does and does not parse)

## Coverage honesty

Codetopo extracts Rust, TypeScript/JavaScript and Python, and indexes Markdown as Doc nodes. This repo's only code is JavaScript: `verify.mjs` and `tests/anchors.test.mjs` (2 `.mjs` files) are extracted at full symbol level (25 symbols). **Not covered:** `anchors.jsonl` and `latest.json` (the anchor data itself — append-only JSON, read directly), `ANCHOR-KEY.json` (the public verification key file), YAML workflows, and SVG/PNG assets. The 5 Markdown files are Doc nodes only. Symbol coverage of the code that exists is complete; the data files are the product, not code.

## Topology

A public, append-only verification mirror — deliberately tiny. There is no server, no build, and no runtime dependency in this repo.

- `verify.mjs` — the standalone verifier (276 lines). `canonical` / `sortKeys` produce the canonical receipt body; `sha256Hex` and `anchorHash` recompute the hash chain; `ed25519Verify` checks the anchor signature; `verifyReceiptIndependent(receipt, anchors, publicKeyRaw)` is the end-to-end check a third party runs; `parseAnchors` / `parsePublicKey` read the data files.
- `anchors.jsonl` — the hash-chained anchor records (one JSON object per line, append-only). `latest.json` points at the newest anchor.
- `ANCHOR-KEY.json` — the public Ed25519 verification key (public material by design; it verifies, it cannot sign).
- `tests/anchors.test.mjs` — the test suite for the verifier; `.github/workflows/` runs CI, the anchor publisher and CodeQL.

## Trust boundaries

- **Trust model is inverted by design:** the reader is expected to trust *nothing* from the operator's server. Verification needs only this repo's artifacts — the hash chain (`anchorHash` over the canonical body) plus the Ed25519 signature against the public key in `ANCHOR-KEY.json`.
- **No secrets exist in this repo.** There is no signing key, token, password or credential anywhere (grepped: no auth/secret/token handling code at all — 0 files). The signing key lives with the Conduit Router, never here.
- **Integrity boundary:** history is append-only. Rewriting or reordering `anchors.jsonl` breaks the chain and is detectable by `verify.mjs`; a change that rewrites published anchors is a defect, not an edit.
- **Blast radius:** `canonical` is the fragile point — any change to canonicalisation changes every hash and invalidates previously published anchors.

## Money surface

**No money surface found.** Grep over all code (`stripe|paddle|secret|token|api_key|auth|password|billing|checkout|webhook`) returns no payment, billing, checkout or credential handling — the only hits are documentation words. This repo moves no money, holds no keys that can spend, and exposes no paid API; its value is evidentiary (receipt verification for the Conduit Router).

## How an agent should approach

1. Read `README.md` and `TEST-PLAN.md`, then `verify.mjs` end to end — it is 276 lines and is the whole product surface.
2. Never rewrite `anchors.jsonl` history; append only, through the anchor workflow.
3. Run the test suite (`tests/anchors.test.mjs`) after any change to `verify.mjs`; a canonicalisation change must be treated as a breaking, chain-invalidating change.
4. Regenerate this profile (below) if the verifier or anchor format changes.

## Regeneration

`docs/codetopo-profile/refresh.sh` (in this pack) re-downloads the repo
at a named ref, re-runs the index, and rewrites `snapshot.json`,
`stats.json` and the header block inputs of this profile. Regenerate at
every release / material change.

**Release gate: NOT RUN — Guardian Mesh: NOT RUN** (profile publication is
documentation only; no gate verdict is claimed for this pack).
