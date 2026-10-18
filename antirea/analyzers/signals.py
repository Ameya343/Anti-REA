"""Per-file signal extraction.

A "signal" is anything a reverse engineer or an AI-assisted platform can harvest
from a shipped artifact to understand its features. We measure the signals that
REA's documented methodology depends on so we can (a) report them and (b) prove
that hardening removes them.

Nothing here executes the target. Files are read as text/bytes only.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field

from .. import rules


@dataclass
class FileSignals:
    path: str
    language: str | None
    size: int = 0
    # leakage counts
    meaningful_idents: int = 0
    total_idents: int = 0
    comment_lines: int = 0
    code_lines: int = 0
    readable_strings: int = 0
    total_strings: int = 0
    urls: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)
    ipc_channels: list[str] = field(default_factory=list)
    secrets: list[tuple[str, int]] = field(default_factory=list)  # (rule, severity)
    has_sourcemap_ref: bool = False
    has_inline_sourcemap: bool = False
    has_sibling_map: bool = False
    symbol_hits: int = 0  # for binaries: readable symbol-ish tokens
    notes: list[str] = field(default_factory=list)

    @property
    def meaningful_ratio(self) -> float:
        if not self.total_idents:
            return 0.0
        return self.meaningful_idents / self.total_idents

    @property
    def comment_density(self) -> float:
        total = self.comment_lines + self.code_lines
        if not total:
            return 0.0
        return self.comment_lines / total


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent  # 0..8 bits/byte


def _looks_readable(s: str) -> bool:
    """A string literal that carries feature meaning (a trace seed), vs noise."""
    core = s[1:-1] if len(s) >= 2 and s[0] in "\"'`" else s
    core = core.strip()
    if len(core) < 4:
        return False
    letters = sum(c.isalpha() for c in core)
    if letters < 3:
        return False
    # sentence-ish, path-ish, identifier-ish, or URL-ish all count as signal
    if " " in core or "/" in core or "_" in core or "." in core:
        return True
    return letters / len(core) > 0.6


def analyze_binary(path: str, data: bytes) -> FileSignals:
    """Light, dependency-free check for symbol/debug leakage in a binary.

    Full disassembly is out of scope; we approximate how much readable symbol
    information a tool like Ghidra/JADX would immediately recover by counting
    long printable identifier runs and known debug markers.
    """
    sig = FileSignals(path=path, language="binary", size=len(data))
    # Extract ascii runs >= 5 chars that look like identifiers.
    run = bytearray()
    ident_like = 0
    debug_markers = (b".debug_info", b".symtab", b".pdb", b"NB10", b"RSDS",
                     b"Java_", b"_ZN", b"__cxa", b"LineNumberTable",
                     b"LocalVariableTable", b"SourceFile")

    def _is_ident_byte(x: int) -> bool:
        # A-Z, a-z, 0-9, underscore
        return (65 <= x <= 90) or (97 <= x <= 122) or (48 <= x <= 57) or x == 95

    for b in data:
        if _is_ident_byte(b):
            run.append(b)
        else:
            if len(run) >= 5:
                tok = run.decode("ascii", "ignore")
                if rules.is_meaningful_identifier(tok):
                    ident_like += 1
            run = bytearray()
    if len(run) >= 5:  # trailing run
        tok = run.decode("ascii", "ignore")
        if rules.is_meaningful_identifier(tok):
            ident_like += 1
    sig.symbol_hits = ident_like
    for m in debug_markers:
        if m in data:
            sig.symbol_hits += 50
            sig.notes.append(f"debug/symbol marker present: {m.decode('ascii','ignore')}")
    if _entropy(data[: 1 << 16]) < 6.0:
        sig.notes.append("low entropy header: not packed/encrypted (easy static load)")
    return sig


def analyze_text(path: str, text: str, language: str | None) -> FileSignals:
    sig = FileSignals(path=path, language=language, size=len(text))

    # --- source maps
    if rules.SOURCEMAP_REF_RE.search(text):
        sig.has_sourcemap_ref = True
    if rules.INLINE_SOURCEMAP_RE.search(text):
        sig.has_inline_sourcemap = True
    if os.path.exists(path + ".map"):
        sig.has_sibling_map = True

    # --- comments vs code (line heuristic, language aware)
    comment_lines = 0
    code_lines = 0
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if language == "python":
            if line.startswith("#"):
                comment_lines += 1
            else:
                code_lines += 1
            continue
        # c-like block comments
        if in_block:
            comment_lines += 1
            if "*/" in line:
                in_block = False
            continue
        if line.startswith("//"):
            comment_lines += 1
        elif line.startswith("/*"):
            comment_lines += 1
            if "*/" not in line:
                in_block = True
        else:
            code_lines += 1
    sig.comment_lines = comment_lines
    sig.code_lines = code_lines

    # --- strings (and strip them before identifier counting to avoid noise)
    strings = rules.STRING_RE.findall(text)
    sig.total_strings = len(strings)
    sig.readable_strings = sum(1 for s in strings if _looks_readable(s))
    for m in rules.URL_RE.finditer(text):
        sig.urls.append(m.group(0))
    for m in rules.ROUTE_RE.finditer(text):
        sig.routes.append(m.group(1))
    for m in rules.IPC_RE.finditer(text):
        sig.ipc_channels.append(m.group(1))

    # --- secrets
    for name, rx, sev in rules.SECRET_RULES:
        if rx.search(text):
            sig.secrets.append((name, sev))

    # --- identifiers (on code with strings/comments removed)
    code_only = rules.STRING_RE.sub('""', text)
    idents = rules.IDENT_RE.findall(code_only)
    sig.total_idents = len(idents)
    sig.meaningful_idents = sum(1 for i in idents if rules.is_meaningful_identifier(i))

    return sig


def analyze_file(path: str) -> FileSignals | None:
    language = rules.guess_language(path)
    try:
        if language == "binary":
            with open(path, "rb") as fh:
                return analyze_binary(path, fh.read())
        if language is None:
            # Only scan known text-ish files; skip unknown types quietly.
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return analyze_text(path, fh.read(), language)
    except (OSError, ValueError):
        return None
