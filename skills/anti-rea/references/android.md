# Android (APK / AAB) hardening

REA route: `inspect_android_package` (JADX-style class/method/reference
recovery), archive inventory, plus network capture.

| REA leverage | What it recovers | Defense |
|---|---|---|
| Decompiled class/method/field names | Feature logic & structure | **R8/ProGuard** with aggressive renaming; ship `minifyEnabled true`. See generated `proguard-rules.pro`. Tighten `-keep` rules to only what reflection/framework needs. |
| `SourceFile`/`LineNumberTable` attributes | Readable, line-mapped pseudocode | `-renamesourcefileattribute ''` and keep attributes minimal (generated rules do this). |
| Log/BuildConfig strings | Trace seeds, endpoints | `-assumenosideeffects` to strip `Log.*`; don't put endpoints/flags in `BuildConfig`; encrypt or fetch at runtime. |
| Plaintext strings in `strings.xml`/code | Endpoints, keys, feature names | Move secrets server-side; for client-only strings consider resource obfuscation and string encryption libraries. |
| TLS traffic via proxy (mitmproxy/Fiddler) | API behavior & payloads | **Certificate pinning**: `network_security_config.xml` + OkHttp `CertificatePinner` (generated). Ignore user-added CAs for pinned domains. Keep a backup pin; rotate before expiry. |
| Native `.so` symbols (NDK) | Readable native pseudocode | Strip symbols, `-fvisibility=hidden`; see `references/native.md`. |

## Also
- **Integrity / anti-tamper:** use Play Integrity API server-side; reject
  requests that fail attestation. Client checks alone are bypassable.
- **Root/instrumentation awareness:** detecting Frida/Xposed/root is a
  speed bump for your own app's protection; treat as signal, not a wall, and
  always enforce the real decision server-side.
- **Resource shrinking:** `shrinkResources true` removes unused, reducing
  surface and readable asset names.

## Honest limits
APKs are recoverable with public tooling. Obfuscation delays and frustrates; it
does not stop a skilled analyst. Protect value by keeping entitlement checks and
secrets on the server, and by making tampering fail server-side attestation.
