"""`antirea score --min-resistance N` exit-code gate (used as a CI release gate)."""

import os

from antirea import cli

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "sample-app")


def test_gate_fails_when_below_threshold(capsys):
    rc = cli.main(["score", SAMPLE, "--min-resistance", "90"])
    assert rc == 1
    assert "FAIL" in capsys.readouterr().err


def test_gate_passes_when_met():
    rc = cli.main(["score", SAMPLE, "--min-resistance", "1"])
    assert rc == 0


def test_no_threshold_returns_zero():
    assert cli.main(["score", SAMPLE]) == 0
