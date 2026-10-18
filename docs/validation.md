# Validation: Anti-REA vs. the real REA tool

This is a real, side-by-side experiment: take one app, harden it with Anti-REA,
then point the actual REA reverse-engineering tool at both the original and the
hardened build and measure what REA can recover.

![Anti-REA vs REA — silent demo](validation-demo.gif)

*(Silent animated demo of the run. No audio.)*

## TL;DR

REA pulled the app's endpoints, IPC channel names, gating logic, and even source
comments out of the **original** build. Against the **Anti-REA-hardened** build,
REA recovered **none** of them, and its own count of unresolved ("unknown")
nodes rose **8×**. Hardening measurably blinded the real tool to the app's
features.

This is REA's **static** JavaScript pass. Hardening raises the cost of reverse
engineering; it does not make it impossible. See *Honest scope* below.

## Setup

| | |
|---|---|
| App | A small Electron main process with real "features": a license-validation endpoint, premium-feature IPC channels, and a telemetry endpoint. |
| Attacker | **REA** — `rea-agents` v6.5.0 (`github.com/morluto/rea`), run via `npx rea-agents@latest analyze-javascript-application <dir> --json`. |
| Defender | **Anti-REA** — this repo. Pipeline: `antirea harden` (strips source maps + comments) → `javascript-obfuscator` with the config from `antirea gen-config --platform electron` (RC4 string-array, control-flow flattening, hex identifiers). |
| Host | Windows, Node 26. REA's optional deobfuscator (Wakaru, Linux x64) was **not** available — see *Honest scope*. |

### Two builds

- `original/` — plain `app.js` (readable, with comments and a `//# sourceMappingURL`).
- `hardened/` — the same app after the full Anti-REA pipeline. Plaintext checks
  on the hardened `app.js`: `license:validate`, `features:unlock`,
  `acme.example.com`, `advanced_export`, `telemetry` → **0 occurrences each**;
  identifiers became hex (`a0_0x421f93`) behind an RC4 string-array decoder.

## Results — what REA recovered

Exact-string matches in REA's own evidence JSON:

| Signal (REA "feature trace seed") | `original` | `hardened` |
|---|---:|---:|
| IPC channel `license:validate` | 6 | **0** |
| IPC channel `features:unlock` | 6 | **0** |
| IPC channel `telemetry:event` | 9 | **0** |
| Endpoint `acme.example.com` | 7 | **0** |
| Route `v2/license/validate` | 2 | **0** |
| Gating identifier `allowed` | 7 | **0** |
| Source comment "premium gating actually happens" | recovered | **absent** |

### REA's own self-assessment

REA tags every fact with a confidence and emits `jsrg_unknown_…` placeholders for
nodes it cannot resolve. Both collapsed on the hardened build:

| REA metric | `original` | `hardened` |
|---|---:|---:|
| Unresolved `unknown` nodes | 86 | **700** |
| Facts at `exact` or `high` confidence | 37 | 14 |
| Facts at `unknown` confidence | 12 | **63** |

REA's stated limitation on the hardened run:

> "Static paths and relationships may remain unresolved when expressions are
> dynamic or obfuscated."

## Interpretation

The signals REA's documented methodology depends on — readable strings used as
feature trace seeds, descriptive identifiers, the API/IPC surface, and
source-map-recovered source — were present and plentiful in the original and
**eliminated** in the hardened build. REA did not fail to *run* on the hardened
app (it produced a larger evidence file); it failed to *understand* it, which is
exactly the goal: deny the semantic signal, not just add bytes.

## Honest scope (what this does and does not prove)

- This exercised REA's **static** JavaScript analysis. It does **not** prove the
  app is unreversible.
- The RC4 string-array key ships inside the bundle. A determined analyst with a
  deobfuscator (e.g. REA's Wakaru path, which was unavailable on this Windows
  host) or with **runtime** access could recover more.
- That is why Anti-REA is defense-in-depth, not one wall: it also generates an
  **Electron fuses** config (disables the `--inspect` inspector REA uses for
  runtime observation), **TLS certificate pinning** configs, and leads with the
  decisive control — **keep trusted logic and secrets server-side**, where the
  client cannot leak them regardless of how well it is obfuscated.

## Reproduce

```bash
# build the two versions
antirea harden ./app ./stage1
npx javascript-obfuscator ./stage1/app.js --output ./hardened/app.js \
    --config <(antirea gen-config ./cfg --platform electron && sed '/^\s*\/\//d' ./cfg/javascript-obfuscator.json)

# attack both with the real REA tool and compare
npx -y rea-agents@latest analyze-javascript-application ./app      --json > rea_original.json
npx -y rea-agents@latest analyze-javascript-application ./hardened --json > rea_hardened.json
```

The raw REA evidence files (243 KB / 2 MB) are not committed; the figures above
are taken directly from them.
