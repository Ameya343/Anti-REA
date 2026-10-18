"""The Python hardener must be semantics-preserving above all else."""

import textwrap

from antirea.hardeners import pystrings


def _run(src, name):
    ns = {}
    exec(compile(src, f"<{name}>", "exec"), ns)
    return ns


def test_string_encoding_preserves_values():
    src = textwrap.dedent('''
        GREETING = "hello world"
        PATH = "/api/v1/users"
        NUMS = (1, 2, 3)
        def label(x):
            return "value=" + str(x)
    ''')
    hardened, stats = pystrings.harden_source(src, seed=b"seed")
    assert stats["strings_encoded"] >= 3
    assert '"hello world"' not in hardened        # literal no longer present
    assert "hello world" not in hardened
    orig, new = _run(src, "o"), _run(hardened, "h")
    assert new["GREETING"] == orig["GREETING"] == "hello world"
    assert new["PATH"] == "/api/v1/users"
    assert new["NUMS"] == (1, 2, 3)
    assert new["label"](7) == orig["label"](7) == "value=7"


def test_docstrings_removed():
    src = textwrap.dedent('''
        """module doc describing the feature"""
        def f():
            """function doc"""
            return 1
    ''')
    hardened, stats = pystrings.harden_source(src, seed=b"seed")
    assert stats["docstrings_removed"] == 2
    assert "describing the feature" not in hardened
    assert "function doc" not in hardened
    assert _run(hardened, "h")["f"]() == 1


def test_fstrings_left_intact_and_correct():
    src = 'name = "x"\nmsg = f"hi {name} at /api/go"\n'
    hardened, _ = pystrings.harden_source(src, seed=b"seed")
    # f-string parts are not encoded (documented limitation)
    assert "/api/go" in hardened
    assert _run(hardened, "h")["msg"] == "hi x at /api/go"


def test_annotations_preserved():
    src = textwrap.dedent('''
        def f(a: "int", b: str = "d") -> "bool":
            return True
    ''')
    hardened, _ = pystrings.harden_source(src, seed=b"seed")
    ns = _run(hardened, "h")
    ann = ns["f"].__annotations__
    assert ann["a"] == "int" and ann["return"] == "bool"


def test_match_patterns_not_broken():
    src = textwrap.dedent('''
        def classify(x):
            match x:
                case "red":
                    return 1
                case "green":
                    return 2
                case _:
                    return 0
    ''')
    hardened, _ = pystrings.harden_source(src, seed=b"seed")
    f = _run(hardened, "h")["classify"]
    assert (f("red"), f("green"), f("blue")) == (1, 2, 0)


def test_bytes_literals_preserved():
    src = 'DATA = b"\\x01\\x02hello"\n'
    hardened, _ = pystrings.harden_source(src, seed=b"seed")
    assert _run(hardened, "h")["DATA"] == b"\x01\x02hello"


def test_syntax_error_is_reported_not_crashed(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("def (:\n", encoding="utf-8")
    out = tmp_path / "out.py"
    res = pystrings.harden_file(str(bad), str(out), seed=b"seed")
    assert res["ok"] is False
    assert out.read_text(encoding="utf-8") == "def (:\n"  # copied verbatim
