"""String tokenization in the signal scanner (regression for multiline strings)."""

from antirea.analyzers import signals


def test_triple_quoted_contents_not_counted_as_identifiers():
    # A docstring's words must be seen as ONE string literal, not as code.
    text = (
        "x = 1\n"
        '"""\n'
        "secretAlgorithm proprietaryHeuristic validateLicense\n"
        '"""\n'
        "y = 2\n"
    )
    sig = signals.analyze_text("t.py", text, "python")
    assert sig.total_strings >= 1
    # the descriptive words live inside the string, so they must not inflate
    # the meaningful-identifier count (only x and y remain, both too short)
    assert sig.meaningful_idents == 0


def test_triple_single_quoted_also_handled():
    text = "a = 1\n'''\nvalidateLicenseKey computeSignature\n'''\nb = 2\n"
    sig = signals.analyze_text("t.py", text, "python")
    assert sig.meaningful_idents == 0
    assert sig.total_strings >= 1


def test_single_line_strings_still_detected():
    text = 'url = "https://api.example.com/v1/users"\n'
    sig = signals.analyze_text("t.py", text, "python")
    assert sig.total_strings == 1
    assert sig.urls == ["https://api.example.com/v1/users"]
