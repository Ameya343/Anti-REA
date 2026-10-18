"""Signal extraction and end-to-end scoring on the sample app."""

import os

from antirea.analyzers import signals
from antirea.analyzers.rea_simulator import scan_tree
from antirea.hardeners.engine import harden_tree
from antirea import report

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "sample-app")


def test_detects_secrets_endpoints_ipc_sourcemaps():
    rep = scan_tree(SAMPLE)
    d = report.to_dict(rep)
    assert d["signals"]["sourcemap_files"] >= 1
    assert d["signals"]["secret_findings"] >= 1
    kinds = d["signals"]["feature_trace_seed_kinds"]
    assert kinds.get("endpoint", 0) >= 1
    assert kinds.get("ipc-channel", 0) >= 1


def test_meaningful_identifier_heuristic():
    assert signals.rules.is_meaningful_identifier("validateLicense")
    assert signals.rules.is_meaningful_identifier("subscription_tier")
    assert not signals.rules.is_meaningful_identifier("a")
    assert not signals.rules.is_meaningful_identifier("_0x3f")
    assert not signals.rules.is_meaningful_identifier("xzql")  # no vowel


def test_hardening_reduces_reversibility(tmp_path):
    out = tmp_path / "hardened"
    harden_tree(SAMPLE, str(out))
    before = report.compute_scores(scan_tree(SAMPLE))
    after = report.compute_scores(scan_tree(str(out)))
    assert after["reversibility"] < before["reversibility"]
    assert after["resistance"] > before["resistance"]
    # sourcemaps and encoded secrets should be gone
    da = report.to_dict(scan_tree(str(out)))
    assert da["signals"]["sourcemap_files"] == 0


def test_output_tree_must_be_outside_source(tmp_path):
    inside = os.path.join(SAMPLE, "nested_out")
    try:
        import pytest
        with pytest.raises(ValueError):
            harden_tree(SAMPLE, inside)
    finally:
        if os.path.isdir(inside):
            import shutil
            shutil.rmtree(inside, ignore_errors=True)
