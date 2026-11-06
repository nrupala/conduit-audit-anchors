# Changelog

All notable changes to the conduit-audit-anchors mirror and its verifier are recorded here, per release, in plain language
a user can act on — never a raw commit log. Entries are added with the change itself
(see CONTRIBUTING), and any security fix names the CVE or similar identifier where
one exists.

This project has not declared a version yet: the mirror's state is the anchor
chain itself (see *Mirror state* below), and the first version tag is a
maintainer decision. Until then, changes land under *Unreleased*.

## [Unreleased]

### Added

- Chain-integrity test suite (`tests/anchors.test.mjs`, Node's built-in test
  runner, zero dependencies): verifies every committed anchor's Ed25519
  signature against `ANCHOR-KEY.json`, the anchor chain linkage, segment
  spans, and that `latest.json` is the newest anchor. Runs in CI on push/PR.
- CodeQL static analysis (JavaScript, buildless) on push/PR and weekly.
- Project documentation set: CONTRIBUTING, SECURITY (private vulnerability
  reporting), TEST-PLAN, NOTICE.

## Mirror state

`anchors.jsonl` holds 13 anchors covering record seqs 0–68; the newest anchor
is seq 68, signed 2026-10-25. Anchors are appended only by the scheduled
anchor-mirror workflow after chain-continuity verification — never by hand.
