"""Optional Rust acceleration for the scanner.

If the `antirea-core` binary is available, signal extraction for text files is
done in one parallel Rust process; otherwise the caller falls back to the pure
Python analyzer. The two are kept byte-for-byte equivalent by
tests/test_rust_parity.py, so results do not depend on which path runs.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

from .analyzers.signals import FileSignals


def core_binary() -> str | None:
    """Locate the antirea-core binary, or None if it isn't built/installed."""
    env = os.environ.get("ANTIREA_CORE")
    if env and os.path.exists(env):
        return env
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    exe = "antirea-core.exe" if os.name == "nt" else "antirea-core"
    cand = os.path.join(root, "core", "target", "release", exe)
    if os.path.exists(cand):
        return cand
    return shutil.which("antirea-core")


def scan_paths_fast(items: list[tuple[str, str]]) -> list[FileSignals] | None:
    """Analyze (path, language) pairs via the Rust core.

    Returns FileSignals in the same order, or None if the core is unavailable
    or anything goes wrong (so the caller can fall back to Python). Files the
    core could not read are dropped, matching analyze_file() returning None.
    """
    exe = core_binary()
    if not exe or not items:
        return None
    req = {"files": [{"p": p, "l": lang} for p, lang in items]}
    try:
        r = subprocess.run([exe], input=json.dumps(req).encode("utf-8"),
                           capture_output=True, timeout=120 + len(items) // 20)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    try:
        data = json.loads(r.stdout.decode("utf-8", "replace"))
    except ValueError:
        return None

    by_path = {}
    for fo in data.get("files", []):
        if not fo.get("ok"):
            continue
        sig = FileSignals(path=fo["path"], language=None, size=fo.get("size", 0))
        sig.meaningful_idents = fo["meaningful_idents"]
        sig.total_idents = fo["total_idents"]
        sig.comment_lines = fo["comment_lines"]
        sig.code_lines = fo["code_lines"]
        sig.readable_strings = fo["readable_strings"]
        sig.total_strings = fo["total_strings"]
        sig.urls = list(fo["urls"])
        sig.routes = list(fo["routes"])
        sig.ipc_channels = list(fo["ipc_channels"])
        sig.secrets = [(n, int(s)) for n, s in fo["secrets"]]
        sig.has_sourcemap_ref = fo["has_sourcemap_ref"]
        sig.has_inline_sourcemap = fo["has_inline_sourcemap"]
        sig.has_sibling_map = fo["has_sibling_map"]
        by_path[fo["path"]] = sig

    out = []
    for p, lang in items:
        sig = by_path.get(p)
        if sig is None:
            continue  # unreadable in Rust -> treat like analyze_file() None
        sig.language = lang
        out.append(sig)
    return out
