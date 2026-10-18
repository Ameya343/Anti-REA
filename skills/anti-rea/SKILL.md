---
name: anti-rea
description: Harden the user's OWN application (including AI-generated apps and features) against reverse engineering and AI-assisted RE platforms such as REA. Use when asked to protect/obfuscate an app, make features hard to reverse, stop an AI from reconstructing features, reduce what ships to the client, or prepare generated code for release. Measures leaked signals, strips them non-destructively, and emits platform hardening configs. Not for analyzing or reversing someone else's software.
metadata:
  version: "0.1.0"
---

# Anti-REA

Anti-REA raises the cost of reverse engineering an application you own. It is
threat-informed: every control maps to a signal a reverse-engineering platform
(e.g. REA) harvests - source maps, string "feature trace seeds", readable
identifiers, comments, API/IPC surface, and native debug symbols.

## State the honest frame first

Before hardening, tell the user plainly: **nothing makes an app impossible to
reverse engineer.** Code that runs on a device the attacker controls can be
analyzed given enough effort. Anti-REA's job is defense-in-depth - raise cost,
time and skill required - and the single most effective control is
architectural: **keep genuinely sensitive logic and secrets on a server the
client cannot read.** Never promise "nobody can reverse this."

## Scope guardrail

Only use this skill to harden software the user owns or is authorized to protect.
It does not reverse engineer, deobfuscate, or bypass protections on third-party
software. Anti-REA never runs REA or any RE engine, and never auto-rewrites
secrets (that is a human decision - move them server-side and rotate).

## Workflow

Drive the bundled `antirea` CLI (pure Python stdlib; run `python -m antirea ...`
from the repo, or install it with `pip install -e .` for the `antirea` command).

1. **Detect + measure.** `python -m antirea detect <path>` identifies the
   platform(s) - web, Electron, Android, iOS, native, Python (often several at
   once). Then `python -m antirea scan <path>` gives the Reversibility Report;
   note the top contributors and the leaked-signal list. For just numbers:
   `python -m antirea score <path>`.

2. **Triage secrets and endpoints.** Any hardcoded secret in the report is a
   finding to fix at the source, not to obfuscate. Recommend moving it
   server-side and rotating anything already shipped. Treat exposed business
   logic (pricing, gating, licensing) the same way - if it must be trusted,
   it belongs on the server.

3. **Harden.** `python -m antirea harden <src> <dst>` writes a hardened COPY
   (the source is never modified; `<dst>` must be outside `<src>`). This:
   - encodes Python string/bytes literals and removes docstrings/comments,
   - with `--rename`, also mangles Python local variables that are provably safe
     (never parameters, closures, or reflective) - each file verified with
     `compile()` and reverted if it would break,
   - strips source-map references and drops `.map` sidecars,
   - strips JS/C comments (verified with `node --check` when Node is present;
     otherwise skipped unless `--force-comments`).
   It prints a manifest and a before/after resistance delta.

4. **Platform configs.** `python -m antirea gen-config <out_dir> --for <path>`
   auto-detects the stack and emits only the relevant configs (or force with
   `--platform android ios ...`): terser / javascript-obfuscator, Android
   R8/ProGuard, Electron fuses, TLS certificate pinning (Android NSC + OkHttp),
   Apple (iOS/macOS) strip + App Attest, native strip/obfuscation flags, and
   Python packaging guidance. Wire the ones matching the user's stack into their
   build, then read the matching `references/*.md` for runtime self-defense
   (anti-debug, integrity, anti-instrumentation).

5. **Prove it.** `python -m antirea test-rea <path>` runs a simulated REA pass
   before vs after and shows the reduction in recoverable signal. For
   independent validation, the report prints REA's own CLI command to run
   against the hardened copy - review before running; Anti-REA won't run it.

## For AI-generated apps and features

When you generate an app or feature the user will ship, harden it before
delivery: run `scan`, move any secrets/trusted logic server-side, apply
`harden`, and wire the relevant `gen-config` outputs into the build. Prefer
server-side enforcement for anything that must not be tampered with; client-side
hardening protects IP and raises cost, it does not establish trust.

## Read only the relevant guide

- JavaScript / TypeScript / Electron: `references/javascript.md`
- Android (APK/AAB): `references/android.md`
- Native binaries (C/C++/Rust/Go/Swift): `references/native.md`
- Runtime self-defense & network (anti-debug, integrity, cert pinning): `references/runtime.md`

## Finish

Report the before/after resistance score and grade, list which controls were
applied vs recommended-but-manual (e.g. ProGuard, cert pins), and restate the
top residual leaks - especially anything that still belongs server-side.
