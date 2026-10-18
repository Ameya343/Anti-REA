"""Generated hardening configs for toolchains Anti-REA can't run in-process.

For native/Android/iOS/Electron, real protection is done by the platform build
tools. Anti-REA emits correct, ready-to-use configs and snippets for them, each
annotated with the REA capability it defeats.
"""

from __future__ import annotations

import os

TERSER = """\
// terser.config.json  --  run: npx terser in.js -c -m --config-file terser.config.json -o out.js
// Defeats: readable identifiers (module graph), comments (intent), dead-code hints.
{
  "compress": { "drop_console": true, "drop_debugger": true, "passes": 3,
                "pure_funcs": ["console.log", "console.debug"] },
  "mangle":   { "toplevel": true, "properties": { "regex": "^_" } },
  "format":   { "comments": false },
  "sourceMap": false
}
"""

JS_OBFUSCATOR = """\
// javascript-obfuscator.json
// run: npx javascript-obfuscator in.js --output out.js --config javascript-obfuscator.json
// Defeats: string trace-seeds (stringArray), control-flow reconstruction,
//          identifier semantics, and casual AI summarization.
{
  "compact": true,
  "controlFlowFlattening": true,
  "controlFlowFlatteningThreshold": 0.75,
  "deadCodeInjection": true,
  "deadCodeInjectionThreshold": 0.3,
  "identifierNamesGenerator": "hexadecimal",
  "renameGlobals": false,
  "selfDefending": true,
  "simplify": true,
  "splitStrings": true,
  "splitStringsChunkLength": 8,
  "stringArray": true,
  "stringArrayEncoding": ["rc4"],
  "stringArrayThreshold": 0.9,
  "transformObjectKeys": true,
  "sourceMap": false
}
"""

PROGUARD = """\
# proguard-rules.pro  (Android R8/ProGuard)
# Defeats REA Android route: JADX class/method names and static references.
# In build.gradle: buildTypes.release { minifyEnabled true; shrinkResources true
#   proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
#                 'proguard-rules.pro' }

-optimizationpasses 5
-repackageclasses ''
-allowaccessmodification
-overloadaggressively

# Remove log/intent strings that become feature trace-seeds.
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}

# Keep ONLY what the framework/reflection truly needs (tighten to your app):
-keep public class * extends android.app.Activity
-keepattributes *Annotation*
# Strip source-file/line metadata that aids decompiler readability:
-renamesourcefileattribute ''
-keepattributes !SourceFile,!LineNumberTable
"""

ELECTRON_FUSES = """\
// electron-fuses.js  --  run during packaging (e.g. in afterPack).
// Defeats REA runtime route: it checks EnableNodeCliInspectArguments; if OFF,
// the packaged app ignores --inspect and the Inspector cannot attach.
const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');

module.exports = async function hardenFuses(appPath) {
  await flipFuses(appPath, {
    version: FuseVersion.V1,
    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,   // blocks --inspect
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
    [FuseV1Options.EnableCookieEncryption]: true,
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
    [FuseV1Options.LoadBrowserProcessSpecificV8Snapshot]: false,
  });
};
"""

ANDROID_NSC = """\
<!-- res/xml/network_security_config.xml  (reference in AndroidManifest application
     android:networkSecurityConfig="@xml/network_security_config")
     Defeats REA network route: mitmproxy/Fiddler interception of TLS traffic. -->
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors><certificates src="system"/></trust-anchors>
  </base-config>
  <domain-config>
    <domain includeSubdomains="true">api.YOURDOMAIN.com</domain>
    <!-- Pin your leaf/intermediate SPKI. Keep a backup pin. Rotate before expiry. -->
    <pin-set expiration="2027-01-01">
      <pin digest="SHA-256">BASE64_PRIMARY_SPKI_PIN=</pin>
      <pin digest="SHA-256">BASE64_BACKUP_SPKI_PIN=</pin>
    </pin-set>
    <!-- Ignore user-added CAs so a proxy root can't MITM the pinned domain. -->
    <trust-anchors><certificates src="system"/></trust-anchors>
  </domain-config>
</network-security-config>
"""

OKHTTP_PINNING = """\
// OkHttp certificate pinning (Android/Kotlin). Backs up the NSC pins in code.
// Defeats REA network route by rejecting proxy/MITM certificates.
val pinner = CertificatePinner.Builder()
    .add("api.YOURDOMAIN.com", "sha256/BASE64_PRIMARY_SPKI_PIN=")
    .add("api.YOURDOMAIN.com", "sha256/BASE64_BACKUP_SPKI_PIN=")
    .build()
val client = OkHttpClient.Builder().certificatePinner(pinner).build()
"""

NATIVE_BUILD = """\
# native-hardening.md  --  C/C++/Rust/Go shipped binaries
# Defeats REA native route: Ghidra/IDA/Kuna readable symbols & pseudocode quality.

## Strip symbols & debug info (ship stripped; keep unstripped copy for your crash symbolication)
#   objcopy --only-keep-debug app app.debug && strip --strip-all app
#   cc:  -s  -fvisibility=hidden -fvisibility-inlines-hidden
#   link (gnu ld): -Wl,--strip-all -Wl,--exclude-libs,ALL
#   Rust (release): strip = true, panic = "abort", lto = true, codegen-units = 1,
#                   and set opt-level = "z"/"3"; avoid debug = true in release.
#   Go:  -ldflags "-s -w"  (and -trimpath to remove local source paths)

## Raise the disassembly cost (optional, measure overhead)
#   - obfuscator-llvm / compile-time control-flow flattening & bogus control flow
#   - string literal encryption at build time (don't ship plaintext "feature" strings)

## Runtime self-defense (RASP) - see references/native.md
#   - anti-debug (ptrace self-attach / PT_DENY_ATTACH on Apple), check TracerPid
#   - integrity: verify your own code/section hashes at startup
#   - detect injection/instrumentation frameworks you don't ship
"""

README_SNIPPET = """\
# Generated by `antirea gen-config`
These are starting points, not drop-in guarantees. Tighten -keep rules, insert
your real SPKI pins and domains, and MEASURE runtime overhead. The decisive
control is architectural: keep genuinely sensitive logic and secrets on a server
the client cannot read. See THREAT_MODEL.md.
"""

APPLE_HARDENING = """\
# apple-hardening.md  --  iOS / macOS (Swift / Obj-C)
# Defeats REA Apple route (apple-application-analysis) + network interception.

## Strip & obfuscate
- Release build: set `SWIFT_OPTIMIZATION_LEVEL=-O`, `DEPLOYMENT_POSTPROCESSING=YES`,
  `STRIP_INSTALLED_PRODUCT=YES`, `STRIP_STYLE=all`, `GCC_GENERATE_DEBUGGING_SYMBOLS=NO`.
- Ship dSYMs to your crash reporter only; never inside the .app/.ipa.
- Swift mangles symbols, but class/selector names still leak via Obj-C runtime;
  avoid descriptive names for gated logic and keep that logic server-side.

## Anti-debug (your own app)
- `ptrace(PT_DENY_ATTACH, 0, 0, 0)` early in launch, and/or a `sysctl` check of
  `kinfo_proc.kp_proc.p_flag & P_TRACED`. Treat as a speed bump, not a wall.

## Integrity / attestation (the real control)
- Use **App Attest / DeviceCheck**; verify the assertion **server-side** and
  reject requests that fail. Client-only checks are patchable.

## Network
- Pin TLS via `URLSession` delegate SPKI comparison (or TrustKit). Keep a backup
  pin and rotate before expiry. Reject user-installed CAs for pinned hosts.
"""

PYTHON_HARDENING = """\
# python-hardening.md  --  shipped Python apps
# Anti-REA already encodes string literals, strips docstrings/comments, and
# (with --rename) mangles safe local variables. Beyond that:

## Don't ship readable source for IP-sensitive modules
- `antirea harden src dst --rename` for literal-encoding + safe local renaming.
- For aggressive whole-program obfuscation (globals, functions, classes, bytecode
  encryption) use a dedicated tool: **pyarmor** (`pyarmor gen --enable-bcc ...`) or
  Nuitka/Cython to compile hot modules to native (then apply native-hardening.md).
- Shipping `.pyc` only is NOT protection: decompilers reconstruct source.

## Secrets / trusted logic
- Move licensing, entitlement and pricing decisions server-side. A Python client
  is among the easiest targets to inspect at runtime (`-i`, `sys.settrace`, gc).

## Packaging
- PyInstaller/py2exe bundles are unpackable (pyinstxtractor). Compile sensitive
  logic to native or keep it server-side; don't rely on the bundle as a vault.
"""

# name -> (content, platforms it applies to)
CONFIGS = {
    "README.md": (README_SNIPPET, set(PLATFORM_ALL := {
        "web", "electron", "android", "ios", "native", "python"})),
    "terser.config.json": (TERSER, {"web", "electron"}),
    "javascript-obfuscator.json": (JS_OBFUSCATOR, {"web", "electron"}),
    "electron-fuses.js": (ELECTRON_FUSES, {"electron"}),
    "proguard-rules.pro": (PROGUARD, {"android"}),
    "network_security_config.xml": (ANDROID_NSC, {"android"}),
    "okhttp-pinning.kt": (OKHTTP_PINNING, {"android"}),
    "apple-hardening.md": (APPLE_HARDENING, {"ios"}),
    "native-hardening.md": (NATIVE_BUILD, {"native"}),
    "python-hardening.md": (PYTHON_HARDENING, {"python"}),
}


def configs_for(platforms) -> list[str]:
    """Names of configs relevant to the given platforms (README always)."""
    want = set(platforms)
    out = []
    for name, (_content, plats) in CONFIGS.items():
        if name == "README.md" or (want & plats):
            out.append(name)
    return out


def write_configs(out_dir: str, platforms=None) -> list[str]:
    """Write configs for `platforms` (None/empty = all)."""
    names = (configs_for(platforms) if platforms
             else list(CONFIGS.keys()))
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for name in names:
        content, _plats = CONFIGS[name]
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        written.append(path)
    return written
