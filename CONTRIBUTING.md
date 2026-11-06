# Contributing

Thank you for considering a contribution. This project is maintained by AIMLDS
(2351485 ALBERTA INC.) and contributions are welcome under the project's licence.

One boundary first: `anchors.jsonl` and `latest.json` are append-only mirror
data, written only by the scheduled anchor-mirror workflow after it verifies
chain continuity. Contributions never edit, reorder, or remove committed
anchors — a change that rewrites anchor history defeats the purpose of this
repository. Contributions are welcome to the verifier (`verify.mjs`), the
documentation, and the tests.

## How to contribute

1. Open an issue first for anything beyond a trivial fix, so the change can be discussed.
2. Fork the repository and make your change on a branch.
3. Keep changes focused; unrelated refactors belong in their own pull request.
4. Add your change to the CHANGELOG's *Unreleased* section in the same pull request —
   a plain-language line a user would understand. If the change fixes a security issue,
   name the CVE or similar identifier where one exists.
5. Open a pull request describing what changed and why. A maintainer reviews every PR;
   expect a first response within two weeks.

## Tests are part of the change

- New functionality must come with tests, and bug fixes with a regression test where practical.
- The full test suite must pass before a PR is merged. Run it with: `node --test "tests/*.test.mjs"`
  (CI runs the same suite on every pull request).
- A test suite that CI does not run does not count: if you add a suite, wire it into CI
  in the same change.

## Conduct and licensing

Be civil and specific in issues and reviews. By contributing you agree your contribution
is provided under the project's licence.
