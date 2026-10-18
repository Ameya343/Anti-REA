"""Detect which platform(s) a target tree targets, so hardening generalizes.

Anti-REA is not tied to one stack. `detect()` inspects a directory and reports
every platform it finds evidence for (a project can be several at once, e.g. an
Electron app is also web; a mobile app may bundle native `.so`s). The CLI uses
this to tailor `gen-config` and to annotate scans.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .analyzers.rea_simulator import SKIP_DIRS

PLATFORMS = ("web", "electron", "android", "ios", "native", "python")

# marker basenames (exact) and extensions that evidence a platform
_MARKER_FILES = {
    "android": ["AndroidManifest.xml", "build.gradle", "build.gradle.kts",
                "gradlew", "settings.gradle", "proguard-rules.pro"],
    "ios": ["Info.plist", "Podfile", "Podfile.lock"],
    "web": ["package.json", "index.html", "webpack.config.js", "vite.config.js",
            "rollup.config.js", "tsconfig.json", "next.config.js"],
    "native": ["Makefile", "CMakeLists.txt", "Cargo.toml", "go.mod",
               "configure", "meson.build"],
    "python": ["pyproject.toml", "requirements.txt", "setup.py", "setup.cfg",
               "Pipfile"],
}
_MARKER_EXTS = {
    "android": {".kt"},
    "ios": {".swift", ".m", ".mm"},
    "web": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"},
    "native": {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs", ".go"},
    "python": {".py"},
}
_MARKER_GLOBS = {
    "ios": (".xcodeproj", ".xcworkspace"),
}
_NATIVE_BINARIES = {".so", ".dll", ".dylib", ".node", ".a", ".o"}


@dataclass
class Detection:
    root: str
    evidence: dict[str, list[str]] = field(default_factory=dict)

    @property
    def platforms(self) -> list[str]:
        return [p for p in PLATFORMS if self.evidence.get(p)]

    def add(self, platform: str, why: str) -> None:
        self.evidence.setdefault(platform, [])
        if why not in self.evidence[platform]:
            self.evidence[platform].append(why)


def _read_package_json(path: str) -> dict | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def detect(root: str) -> Detection:
    root = os.path.abspath(root)
    det = Detection(root=root)
    ext_counts: dict[str, int] = {}
    package_jsons: list[str] = []

    target_is_file = os.path.isfile(root)
    walk_root = os.path.dirname(root) if target_is_file else root

    for dirpath, dirnames, filenames in os.walk(walk_root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        base = os.path.basename(dirpath)
        for plat, suffixes in _MARKER_GLOBS.items():
            if base.endswith(suffixes):
                det.add(plat, f"dir {base}")
        for fn in filenames:
            if target_is_file and os.path.join(dirpath, fn) != root:
                continue
            ext = os.path.splitext(fn)[1].lower()
            ext_counts[ext] = ext_counts.get(ext, 0) + 1
            for plat, files in _MARKER_FILES.items():
                if fn in files:
                    det.add(plat, f"file {fn}")
            if ext in _NATIVE_BINARIES:
                det.add("native", f"binary {ext}")
            if fn == "package.json":
                package_jsons.append(os.path.join(dirpath, fn))

    # extension-census evidence (needs a couple of files to count)
    for plat, exts in _MARKER_EXTS.items():
        n = sum(ext_counts.get(e, 0) for e in exts)
        if n >= 2 or (n >= 1 and plat in det.evidence):
            det.add(plat, f"{n} source file(s)")

    # Electron is a specialization of web: look inside package.json
    for pj in package_jsons:
        data = _read_package_json(pj)
        if not data:
            continue
        det.add("web", "package.json")
        deps = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps.update(data.get(key, {}) or {})
        if any(d in deps for d in ("electron", "electron-builder", "@electron/fuses")):
            det.add("electron", "electron in package.json")
        if "build" in data and isinstance(data["build"], dict) and \
                data["build"].get("appId"):
            det.add("electron", "electron-builder config")

    return det
