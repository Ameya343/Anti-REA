# JavaScript / TypeScript / Electron hardening

REA route: `analyze_javascript_application`, `recover_javascript_sources`,
`trace_application_feature`, Electron fuse/inspector checks.

| REA leverage | What it recovers | Defense |
|---|---|---|
| Source maps (`.map`, `sourceMappingURL`, `sourcesContent`) | Full original source | **Never ship maps.** Anti-REA strips refs + drops `.map`. Set `sourceMap:false`/`devtool:false` in prod builds; upload maps privately to your error tracker only. |
| Readable module graph + identifiers | Feature reconstruction, export shapes | Minify + mangle (terser `mangle.toplevel`), bundle to few chunks. For high-value code add `javascript-obfuscator` (control-flow flattening, string array). |
| String literals as trace seeds (routes, IPC names, API paths, messages) | Seeds for `trace_application_feature` | `stringArray` + `splitStrings` in javascript-obfuscator; avoid descriptive literals for gated logic; keep route/permission checks server-side. |
| Electron `EnableNodeCliInspectArguments` fuse ON | Attach Inspector at runtime, read everything | Flip fuses OFF (see `electron-fuses.js` from `gen-config`): disable inspector args, `RunAsNode`, `NodeOptions`; enable `OnlyLoadAppFromAsar` + ASAR integrity. |
| contextBridge / preload / IPC channels (static) | Attack surface map | Minimize exposed `contextBridge` API; validate every IPC arg; don't expose privileged operations by channel name an attacker can call. |

## Order of operations (prod build)
1. Strip/withhold source maps.
2. `terser` (compress + mangle, drop console).
3. For sensitive bundles only, `javascript-obfuscator` on the terser output
   (measure startup cost; obfuscation is heavy).
4. Package Electron with hardened fuses + ASAR integrity.
5. `antirea scan` the final bundle to confirm residual signal.

## WASM / native addons
Compiling hot logic to WebAssembly or a native `.node` addon raises the bar vs
plain JS, but REA has `inspect_wasm_artifact` and native routes - treat WASM as
obfuscation, not a secret store. Secrets still go server-side.

## Honest limits
Minified/obfuscated JS is still JS; a determined analyst with runtime access
recovers behavior. The durable win is keeping trusted decisions (entitlements,
pricing, licensing) on the server and shipping only their results.
