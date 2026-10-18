"""The Rust core must produce byte-for-byte the same signals as Python.

Skipped when the core isn't built; runs wherever it is (locally and in the
optional Rust CI job).
"""

import glob
import os

import pytest

from antirea import fastscan
from antirea.analyzers.signals import analyze_file
from antirea.rules import guess_language

needs_core = pytest.mark.skipif(fastscan.core_binary() is None,
                                reason="antirea-core not built")

_FIELDS = ("meaningful_idents", "total_idents", "comment_lines", "code_lines",
           "readable_strings", "total_strings", "urls", "routes", "ipc_channels",
           "secrets", "has_sourcemap_ref", "has_inline_sourcemap", "has_sibling_map")


def _corpus():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    items = []
    for base in ("antirea", "examples", "tests"):
        pat = os.path.join(root, base, "**", "*")
        for p in glob.glob(pat, recursive=True):
            if not os.path.isfile(p):
                continue
            lang = guess_language(p)
            if lang and lang != "binary":
                items.append((os.path.abspath(p), lang))
    return items


@needs_core
def test_rust_matches_python_over_repo():
    items = _corpus()
    assert len(items) > 10
    fast = fastscan.scan_paths_fast(items)
    assert fast is not None and len(fast) == len(items)
    for (p, _lang), r in zip(items, fast):
        py = analyze_file(p)
        assert py is not None, p
        for attr in _FIELDS:
            assert getattr(r, attr) == getattr(py, attr), (
                f"{attr} mismatch in {p}: rust={getattr(r, attr)} py={getattr(py, attr)}")
