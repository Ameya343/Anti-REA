"""Model a REA-style pass over an application tree.

This does NOT run REA or any reverse-engineering engine. It reads the artifact
the way REA's documented static methodology does and tallies the signals REA
would turn into "Evidence" and "feature trace seeds":

* readable strings, API endpoints, routes, IPC channel names  -> trace seeds
* source maps / sibling .map files                            -> source recovery
* meaningful identifiers + comments                           -> LLM comprehension
* hardcoded secrets                                           -> verbatim extraction
* symbol/debug markers in binaries                            -> pseudocode quality

The point is a stable, reproducible measurement so you can show the reduction
after hardening, and a checklist of exactly what still leaks.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .signals import FileSignals, analyze_file

# Directories that are never shipped / not worth scanning.
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".idea",
             ".vscode", "dist-check", ".pytest_cache", ".mypy_cache", ".tox",
             "rea-quarantine"}


@dataclass
class AppReport:
    root: str
    files: list[FileSignals] = field(default_factory=list)

    # aggregates
    total_files: int = 0
    sourcemap_files: int = 0
    secret_findings: list[tuple[str, str, int]] = field(default_factory=list)  # (path,rule,sev)
    trace_seeds: list[tuple[str, str, str]] = field(default_factory=list)  # (kind,value,path)
    meaningful_idents: int = 0
    total_idents: int = 0
    comment_lines: int = 0
    code_lines: int = 0
    readable_strings: int = 0
    total_strings: int = 0
    binary_symbol_hits: int = 0

    def add(self, sig: FileSignals) -> None:
        self.files.append(sig)
        self.total_files += 1
        self.meaningful_idents += sig.meaningful_idents
        self.total_idents += sig.total_idents
        self.comment_lines += sig.comment_lines
        self.code_lines += sig.code_lines
        self.readable_strings += sig.readable_strings
        self.total_strings += sig.total_strings
        self.binary_symbol_hits += sig.symbol_hits
        if sig.has_sourcemap_ref or sig.has_inline_sourcemap or sig.has_sibling_map:
            self.sourcemap_files += 1
        rel = os.path.relpath(sig.path, self.root)
        for rule, sev in sig.secrets:
            self.secret_findings.append((rel, rule, sev))
        for u in sig.urls:
            self.trace_seeds.append(("endpoint", u, rel))
        for r in sig.routes:
            self.trace_seeds.append(("route", r, rel))
        for c in sig.ipc_channels:
            self.trace_seeds.append(("ipc-channel", c, rel))

    @property
    def meaningful_ratio(self) -> float:
        return self.meaningful_idents / self.total_idents if self.total_idents else 0.0

    @property
    def comment_density(self) -> float:
        tot = self.comment_lines + self.code_lines
        return self.comment_lines / tot if tot else 0.0


def scan_tree(root: str) -> AppReport:
    root = os.path.abspath(root)
    report = AppReport(root=root)
    if os.path.isfile(root):
        sig = analyze_file(root)
        if sig:
            report.root = os.path.dirname(root) or root
            report.add(sig)
        return report
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(".map"):
                # Count the map itself as a severe leak and keep scanning.
                continue
            path = os.path.join(dirpath, fn)
            sig = analyze_file(path)
            if sig:
                report.add(sig)
    return report
