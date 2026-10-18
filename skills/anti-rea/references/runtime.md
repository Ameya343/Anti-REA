# Runtime self-defense & network hardening

REA route: `capture_browser_scenario`, Electron Inspector, process capture,
`inspect_web_network_capture` (HAR/SAZ/mitmproxy), packet/pcap tools.

## Network: deny traffic interception
REA (and analysts) learn features by watching API traffic through a proxy.

- **TLS certificate / public-key pinning.** Pin the leaf or intermediate SPKI.
  Android: `network_security_config.xml` + OkHttp `CertificatePinner` (see
  `gen-config`). Apple: `URLSession` delegate SPKI check or a pinning library.
  Keep a **backup pin** and rotate before expiry, or you brick the app.
- **Ignore user-added trust anchors** for pinned domains so a proxy root CA
  cannot MITM.
- **App-layer encryption** for the most sensitive payloads (e.g. an ephemeral
  key exchange) so that even a broken-pin capture yields little.
- Minimize what the client sees: the server returns decisions/results, not the
  rules behind them.

## Detect but don't rely on detection
These are speed bumps for protecting your own app; always enforce the real
decision server-side.

- **Debugger:** `TracerPid` (Linux), `PT_DENY_ATTACH`/P_TRACED (Apple),
  `IsDebuggerPresent` (Windows).
- **Emulator/VM:** build props, sensor absence, timing - heuristic only.
- **Instrumentation (Frida/Xposed/substrate):** unexpected loaded modules,
  suspicious ports, trampolines in your own functions.
- **Electron:** ship with `EnableNodeCliInspectArguments` fuse OFF so `--inspect`
  is ignored; enable ASAR integrity; `OnlyLoadAppFromAsar`.

## Integrity / anti-tamper
- Verify your own binary/bundle hash at startup; on Android use **Play Integrity**
  and verify the verdict **server-side**; on Apple use **DeviceCheck/App Attest**.
- Server rejects requests that fail attestation or replay - this is what turns a
  client check into a real control.

## Where trust actually lives
Client-side hardening protects intellectual property and raises reverse-
engineering cost. It cannot make the client trustworthy. Any decision that must
not be tampered with (entitlements, pricing, licensing, scoring, limits) is
computed and enforced on a server, with the client receiving only the outcome.
