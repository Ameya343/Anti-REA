# Contributing to Anti-REA

Thanks for helping harden software against reverse engineering. A few conventions
keep the project honest and the CI green.

## Dev setup

```bash
pip install -e ".[dev]"
pytest          # run the full suite
flake8 antirea  # lint (config in setup.cfg)
```

## Lint on Python 3.12

CI lints and tests on **3.10, 3.11, and 3.12**. Python 3.12 tokenizes the
insides of f-strings (PEP 701), so `flake8` flags style issues *inside* f-string
expressions that older versions silently ignore. **Run `flake8` under 3.12
before pushing** — a comma without a trailing space inside an f-string passes on
3.11 and fails on 3.12. (This is a real bug we hit; see PR #1.)

## Guarantees we do not break

These are the invariants that make the tool trustworthy. A change that violates
one needs a very good reason and a test:

- **Hardening is non-destructive.** `harden` writes a new tree; it never edits
  the source in place, and the output directory must be outside the source.
- **Transforms are semantics-preserving.** The Python hardener must not change
  runtime behavior. The local renamer only touches provably-safe names and every
  hardened file is verified with `compile()`. Add a behavior-equivalence test
  for any new transform.
- **Secrets are never auto-rewritten.** We *report* hardcoded secrets and tell
  the user to move them server-side; we do not silently obfuscate them.
- **No false promises.** Docs and output must not claim an app becomes
  impossible to reverse. We raise cost; the decisive control is keeping trusted
  logic and secrets server-side. Keep that framing.

## Pull requests

- One focused change per PR. Branch names: `fix/…`, `feat/…`, `chore/…`, `docs/…`.
- Add or update tests; keep `flake8` and `pytest` green locally (on 3.12).
- The resistance gate (`antirea score --min-resistance 55` on the hardened
  sample) runs in CI — don't let a change regress the hardener below it.
- New signal detectors or hardeners should map to a concrete RE leverage point
  (see `THREAT_MODEL.md`) and say which one in the PR description.

## Scope

Anti-REA is strictly defensive: it hardens software you own or are authorized to
protect. Contributions that add offensive reverse-engineering capability, or that
help bypass protections on third-party software, are out of scope.
