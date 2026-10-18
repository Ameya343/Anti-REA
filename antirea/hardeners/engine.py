"""Hardening engine: walk a source tree -> write a hardened tree.

Guarantees:
* The source tree is never modified; output goes to a separate directory.
* Source-map sidecar files (.map) are not copied (full-source recovery denied).
* Python files get AST string-encoding + docstring/comment removal.
* JS/C-like files get source-map reference stripping (always) and, optionally,
  comment stripping that is VERIFIED with `node --check` and reverted on failure.
* Anything else is copied byte-for-byte.
* A manifest records exactly what happened to every file.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field

from ..analyzers.rea_simulator import SKIP_DIRS
from ..rules import guess_language
from . import pystrings, textfx

_NODE_CHECKABLE = {".js", ".mjs", ".cjs"}
_C_LIKE_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".c", ".h", ".cc",
               ".cpp", ".hpp", ".cxx", ".java", ".kt", ".go", ".rs", ".cs",
               ".swift", ".css", ".scss"}


@dataclass
class HardenManifest:
    src: str
    dst: str
    processed: int = 0
    skipped_maps: int = 0
    python_hardened: int = 0
    strings_encoded: int = 0
    names_renamed: int = 0
    sourcemaps_stripped: int = 0
    comments_stripped_files: int = 0
    reverted: int = 0
    copied: int = 0
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "src": self.src, "dst": self.dst, "files_processed": self.processed,
            "python_files_hardened": self.python_hardened,
            "strings_encoded": self.strings_encoded,
            "python_names_renamed": self.names_renamed,
            "sourcemap_refs_stripped": self.sourcemaps_stripped,
            "sourcemap_files_dropped": self.skipped_maps,
            "js_comment_stripped_files": self.comments_stripped_files,
            "reverted_for_safety": self.reverted,
            "copied_verbatim": self.copied, "notes": self.notes,
        }


def _node_available() -> bool:
    return shutil.which("node") is not None


_JSCHECK = os.path.join(os.path.dirname(__file__), "jscheck.mjs")


def _node_batch_check(paths: list[str]) -> set[str]:
    """Return the subset of `paths` whose JS fails to parse, verified in ONE
    node process (not one spawn per file). On any launch failure, treat all as
    failing so the caller reverts to the safe (un-comment-stripped) output."""
    if not paths:
        return set()
    payload = "\0".join(paths).encode("utf-8")
    try:
        r = subprocess.run(
            ["node", "--experimental-vm-modules", _JSCHECK],
            input=payload, capture_output=True,
            timeout=60 + len(paths) // 50,
        )
    except (OSError, subprocess.SubprocessError):
        return set(paths)
    if r.returncode != 0:
        return set(paths)
    failed = r.stdout.decode("utf-8", "replace").splitlines()
    return {p for p in failed if p}


def harden_tree(src: str, dst: str, *, strip_js_comments: bool = True,
                force_comments: bool = False, seed: bytes | None = None,
                rename: bool = False,
                ) -> HardenManifest:
    src = os.path.abspath(src)
    dst = os.path.abspath(dst)
    if dst == src or dst.startswith(src + os.sep):
        raise ValueError("output directory must be outside the source tree")
    man = HardenManifest(src=src, dst=dst)
    node_ok = _node_available()
    if strip_js_comments and not node_ok and not force_comments:
        man.notes.append("Node not found: JS comment stripping disabled "
                         "(source-map stripping still applied). Use --force-comments to override.")
    want_comments = strip_js_comments and (node_ok or force_comments)
    # (dst_path, safe_fallback_text, counted) for node-checkable files awaiting
    # a single batched syntax verification after the walk.
    pending: list[tuple[str, str, bool]] = []

    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        rel = os.path.relpath(dirpath, src)
        out_dir = os.path.join(dst, rel) if rel != "." else dst
        os.makedirs(out_dir, exist_ok=True)
        for fn in filenames:
            s = os.path.join(dirpath, fn)
            d = os.path.join(out_dir, fn)
            ext = os.path.splitext(fn)[1].lower()

            if ext == ".map":
                man.skipped_maps += 1
                continue

            man.processed += 1
            lang = guess_language(s)

            if lang == "python":
                stats = pystrings.harden_file(s, d, seed=seed, rename=rename)
                if stats.get("ok"):
                    man.python_hardened += 1
                    man.strings_encoded += stats.get("strings_encoded", 0)
                    man.names_renamed += stats.get("names_renamed", 0)
                    if stats.get("note"):
                        man.notes.append(f"{fn}: {stats['note']}")
                else:
                    man.notes.append(f"{fn}: {stats.get('reason')}")
                continue

            if ext in _C_LIKE_EXT:
                _harden_c_like(s, d, ext, man, node_ok, want_comments,
                               force_comments, pending)
                continue

            # everything else: copy byte-for-byte
            shutil.copy2(s, d)
            man.copied += 1

    # One batched syntax check for every node-verifiable file, then revert any
    # that the comment stripper broke to their safe (sourcemap-only) form.
    failed = _node_batch_check([p for p, _, _ in pending])
    for d, fallback, counted in pending:
        if d in failed:
            with open(d, "w", encoding="utf-8", newline="") as fh:
                fh.write(fallback)
            man.reverted += 1
            if counted:
                man.comments_stripped_files -= 1

    return man


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def _harden_c_like(s: str, d: str, ext: str, man: HardenManifest,
                   node_ok: bool, want_comments: bool, force_comments: bool,
                   pending: list) -> None:
    try:
        with open(s, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        shutil.copy2(s, d)
        man.copied += 1
        return

    base, n_sm = textfx.strip_sourcemaps(text)   # always-safe transform
    man.sourcemaps_stripped += n_sm

    if not want_comments:
        _write(d, base)
        return

    stripped, n_c = textfx.strip_c_comments(base)
    if ext in _NODE_CHECKABLE and node_ok:
        # write optimistically; a single batched node check verifies later and
        # reverts to `base` on failure.
        _write(d, stripped)
        if n_c:
            man.comments_stripped_files += 1
        pending.append((d, base, n_c > 0))
    elif force_comments:
        # unverifiable (e.g. .ts) but explicitly forced: trust the stripper
        _write(d, stripped)
        if n_c:
            man.comments_stripped_files += 1
    else:
        # unverifiable and not forced: keep comments (sourcemap strip only)
        _write(d, base)
