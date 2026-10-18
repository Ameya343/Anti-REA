# Threat model: REA → Anti-REA

This maps the capabilities of REA (an AI-assisted reverse-engineering platform)
to the defenses Anti-REA applies or recommends. It is derived from REA's own
documented methodology: an evidence-based pipeline that separates *observations*,
*inferences*, and *unknowns*, and reconstructs features from harvested signals.

## REA's capability surface (the attacker)

| REA capability | Mechanism | What the AI gets |
|---|---|---|
| JavaScript/Electron static analysis | `analyze_javascript_application`, `recover_javascript_sources` (Wakaru) | module graph, exports/imports, source ranges, **source-map-recovered original source** |
| Feature tracing | `trace_application_feature` | follows a seed (route, string, API, IPC channel, module) through the graph |
| Electron runtime | Inspector (if `EnableNodeCliInspectArguments` fuse on), fuse inspection | live state, bypasses static-only limits |
| Android | `inspect_android_package` (JADX) | class/method/field names, static references |
| Native | Ghidra/IDA/Kuna/Hopper via `open_binary`; Go/Rust metadata readers | pseudocode quality scales with **symbol/debug availability** |
| Network | `inspect_web_network_capture` (HAR/SAZ/mitmproxy), pcap tools | API behavior and payloads from captured traffic |
| Managed/other | PE/CLI, WASM, EVM, firmware, SQLite, packets, signals | broad artifact coverage |

**Key insight:** REA's AI layer is only as good as the *semantic signal* in the
artifact. Descriptive names, comments, plaintext strings, and especially source
maps are what let an LLM name and reconstruct "features." Deny those and you
degrade the AI's output specifically — not just a human's.

## Anti-REA's layered defense (the defender)

### Layer 0 — Architecture (the decisive one)
Keep trusted decisions and secrets on a server. The client cannot leak what it
does not contain. Everything below only raises cost; this changes what is
*possible* to recover. Anti-REA's scanner flags client-side secrets and the
API/IPC surface precisely to push you toward this layer.

### Layer 1 — Deny source recovery
- Strip `sourceMappingURL` references; never ship `.map` files (upload them
  privately to your error tracker instead).
- *Implemented:* `antirea harden` strips refs and drops map sidecars.

### Layer 2 — Degrade semantic signal (anti-AI-comprehension)
- Encode string literals (trace seeds); remove comments and docstrings; mangle
  identifiers.
- *Implemented:* Python literal encoding + docstring/comment removal via AST
  re-emit; JS comment stripping (node-verified). *Config-generated:* terser
  mangle, javascript-obfuscator string-array, R8/ProGuard renaming.

### Layer 3 — Raise disassembly/decompilation cost
- Strip native symbols/debug info; `-fvisibility=hidden`, `-trimpath`,
  `-ldflags "-s -w"`; optional compile-time obfuscation (control-flow
  flattening, bogus control flow).
- *Config-generated + documented:* `native-hardening.md`.

### Layer 4 — Deny runtime observation
- Electron: flip fuses off (no inspector), ASAR integrity, `OnlyLoadAppFromAsar`.
- Anti-debug / anti-instrumentation / integrity checks (RASP) to deter dynamic
  analysis of your own app.
- *Config-generated + documented:* `electron-fuses.js`, `references/runtime.md`.

### Layer 5 — Deny traffic interception
- TLS certificate/public-key pinning; ignore user-added CAs for pinned domains;
  app-layer encryption for the most sensitive payloads.
- *Config-generated:* `network_security_config.xml`, `okhttp-pinning.kt`.

## What each layer does and does not buy you

- Layers 1–2 defeat casual inspection, `grep`, naive bundlers, and — importantly
  — most **automated AI summarization**, because the easy semantic signal is gone.
- Layers 3–4 slow a skilled analyst with a disassembler/debugger; they do not
  stop one. Every check ships inside the artifact and can be patched out.
- Layer 5 stops passive proxy observation of a correctly pinned channel; it does
  not help if the endpoint itself returns the sensitive logic.
- Only Layer 0 removes capability rather than adding cost.

## Measuring it

`antirea scan`/`score` produce a **Reversibility Score (0–100)** weighted by how
much each signal actually helps a REA-style pass (source maps and secrets
dominate; names/comments/strings are strong AI aids; endpoints/IPC are seeds).
`antirea test-rea` runs a before/after simulated pass. For ground truth, run
REA's own CLI against the hardened copy and compare its recovered evidence — the
`test-rea` output prints the command.

> The simulated pass models REA's *static signal extraction*; it does not model a
> full dynamic/instrumented investigation. Use it to track signal reduction, not
> as proof of absolute safety — which, per Layer 0, does not exist client-side.
