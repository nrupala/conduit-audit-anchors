<!-- Copyright (C) 2026 Nrupal Akolkar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Conduit Router — public audit anchors

This repository is the **public mirror of the Conduit Router audit
anchors**. It exists so that anyone can verify a Conduit Router receipt
**without trusting our server** — the artifacts here are all you need,
and this history is append-only.

Operated by Pipavia (2351485 ALBERTA INC.), Calgary, Canada.
Contact: info@pipavia.com

## What an anchor is

Every call routed by [Conduit Router](https://router.pipavia.com)
appends a hash-chained audit record and returns a receipt. On a daily
schedule, the gateway persists a signed **anchor**: a checkpoint naming

- every record since the previous anchor (their hashes, in order),
- the chain head,
- the previous anchor's hash (anchors form their own chain),

signed with **Ed25519**. If the record you hold is inside a signed
anchor in this repository, it existed, unchanged, in the chain at
anchor time — and nobody can quietly rewrite that history afterwards,
because this repository's history is public.

## Files

| file | what it is |
|---|---|
| `anchors.jsonl` | every anchor, one JSON object per line, append-only |
| `latest.json` | the newest anchor |
| `ANCHOR-KEY.json` | the Ed25519 public key anchors are signed with |
| `verify.mjs` | the standalone verifier (Apache-2.0, zero dependencies, Node ≥ 18) |

## Verify a receipt

Save your receipt record as `receipt.json` (from the gateway's
`GET /v1/receipts/{id}`, or the `_meta.receipt_id` of any routed call),
then:

```bash
node verify.mjs receipt.json
```

The verifier reads `anchors.jsonl` and `ANCHOR-KEY.json` **from this
repository** by default and runs five checks locally: the receipt's
hash recomputes; the receipt sits in a covering anchor's segment,
linked to its predecessor; the anchor's head matches its segment; the
Ed25519 signature verifies against `ANCHOR-KEY.json`; and the anchors
chain together in order.

Exit codes: `0` INDEPENDENT-VERIFIED · `1` FAILED ·
`2` NOT-INDEPENDENTLY-VERIFIABLE · `64` usage error.

## Threat model — what this does and does not prove

An anchor proves **inclusion and integrity**: a record existed in the
chain, unchanged, at anchor time. It does **not** prove that a call
which was never recorded happened or didn't — no inclusion proof can.
It also does not vouch for the content of a model's answer; it proves
the call's provenance (provider, model, tokens, cost, outcome) was
recorded and not altered.

Full detail: `docs/VERIFY.md` in the
[conduit-router repository](https://github.com/nrupala/conduit-router)
(the gateway itself is proprietary; this mirror and the verifier are
Apache-2.0).

## How this mirror stays current

A scheduled GitHub Action in this repository fetches the gateway's
latest anchor once a day and appends it if the chain has advanced. The
gateway holds no credential for this repository. If the gateway and
this mirror ever disagree, the disagreement is public evidence in
itself.

## License

Apache-2.0 — see the SPDX headers in each file. The verifier is meant
to be copied: take it, run it, keep it.
