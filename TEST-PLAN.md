# Test plan — conduit-audit-anchors

## Scope

This repository is a public, append-only mirror of Conduit Router audit
anchors plus the standalone verifier (`verify.mjs`, Node ≥ 18, zero
dependencies). Its content is data: testing therefore verifies the committed
data's integrity (the anchor chain and its signatures) and the verifier code
that reads it. The gateway that produces the anchors is proprietary and out
of scope; the mirror's scheduled workflow separately verifies chain
continuity before appending anything new.

## Suites

| Suite | Covers | Run it | Runs in CI |
|---|---|---|---|
| Anchor chain integrity (`tests/anchors.test.mjs`) | Key document shape (Ed25519, 32-byte key); every anchor's v2 fields; chain linkage (GENESIS start, each prev_anchor_hash = predecessor's hash); every anchor's Ed25519 signature against `ANCHOR-KEY.json`; segment completeness, span, and head agreement; `latest.json` identical to the newest anchor | `node --test "tests/*.test.mjs"` | Yes — CI workflow |
| Verifier syntax (lint) | `verify.mjs` parses under Node | `node --check verify.mjs` | Yes — CI workflow |

## CI gates

- Full chain-integrity suite + lint green on every push and pull request to `main`.
- CodeQL (JavaScript/TypeScript, buildless) on push/PR and weekly; findings are
  dispositioned on the house SLA (Critical 48 h · High 7 d · Medium 14 d).
- No merge with a red CI run (per CONTRIBUTING).

## Cadence

- Every pull request: the full suite + lint + CodeQL.
- Daily: the anchor-mirror workflow appends new anchors only after verifying
  chain continuity for every candidate (its own gate, separate from CI).
- Every release candidate: the release-readiness run (checker + evidence reads),
  per the house Release-Readiness Standard.

## Coverage bar

No numeric floor; changes to the verifier or the data format land with tests
per CONTRIBUTING. Every newly mirrored anchor is covered automatically — the
suite reads the whole committed chain.
