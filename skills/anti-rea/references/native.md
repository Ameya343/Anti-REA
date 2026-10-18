# Native binaries (C / C++ / Rust / Go / Swift)

REA route: `open_binary` + Ghidra/IDA/Kuna/Hopper pseudocode, `inspect_go_binary`,
`inspect_rust_binary`, `inspect_binary_layout`, symbol/debug inspection.

| REA leverage | What it recovers | Defense |
|---|---|---|
| Symbol tables / debug info | Named functions -> readable pseudocode | **Strip.** `strip --strip-all`; ship stripped, keep an unstripped copy for your own crash symbolication. `cc -s -fvisibility=hidden`. |
| Go build/module metadata (`inspect_go_binary`) | Package paths, versions, build settings | `go build -ldflags "-s -w" -trimpath`. Metadata still partially recoverable - don't rely on its absence. |
| Rust `cargo-auditable` `.dep-v0`, `/rustc/<hash>/` paths | Dependency list, toolchain | Release profile: `strip=true`, `panic="abort"`, `lto=true`, `codegen-units=1`. `-trimpath`-style via `RUSTFLAGS=--remap-path-prefix`. |
| Straight-line, well-structured code | Easy decompilation | Compile-time obfuscation (obfuscator-llvm): control-flow flattening, bogus control flow, instruction substitution. Measure overhead. |
| Plaintext string literals | Endpoints, keys, feature markers | Build-time string literal encryption; decrypt at use. Keep real secrets server-side. |
| Low-entropy, unpacked image | Trivial static load | Optional packing/encryption of sections (adds anti-static cost; pair with anti-debug so dumping is harder). |

## Runtime self-defense (RASP)
- **Anti-debug:** Linux `ptrace(PTRACE_TRACEME)` self-attach / check `TracerPid`
  in `/proc/self/status`; Apple `PT_DENY_ATTACH` / `sysctl` P_TRACED check;
  Windows `IsDebuggerPresent`/`CheckRemoteDebuggerPresent`.
- **Integrity:** hash your own code sections / `__TEXT` at startup and refuse to
  run if modified; verify signatures of loaded modules.
- **Anti-instrumentation:** detect injected frameworks you didn't ship (scan
  loaded modules/maps). Treat as signal; still enforce trust server-side.

Apply these to protect your own binary. They are standard commercial RASP
measures; keep them proportionate and measure performance.

## Honest limits
Every anti-debug/integrity check ships inside the binary and can be patched out
by a determined analyst with a disassembler. These controls buy time and deter
casual and automated analysis; they are not a substitute for server-side trust.
