"""The Python local renamer must be safe above all: never change behavior."""

import re
import textwrap

from antirea.hardeners import pystrings


def _run(src, name="m"):
    ns = {}
    exec(compile(src, f"<{name}>", "exec"), ns)
    return ns


def _has_ident(src, name):
    return re.search(rf"(?<![\w]){re.escape(name)}(?![\w])", src) is not None


def test_simple_locals_renamed_behavior_preserved():
    src = textwrap.dedent('''
        def area(width, height):
            result = width * height
            scaled = result * 2
            return scaled
    ''')
    out, stats = pystrings.harden_source(src, seed=b"s", rename=True)
    assert stats["names_renamed"] == 2
    assert not _has_ident(out, "result")
    assert not _has_ident(out, "scaled")
    assert _has_ident(out, "width") and _has_ident(out, "height")  # params kept
    assert _run(out)["area"](3, 4) == _run(src)["area"](3, 4) == 24


def test_keyword_call_still_works_params_not_renamed():
    src = textwrap.dedent('''
        def connect(host, port=80):
            url = host + ":" + str(port)
            return url
    ''')
    out, _ = pystrings.harden_source(src, seed=b"s", rename=True)
    conn = _run(out)["connect"]
    assert conn(host="h", port=81) == "h:81"       # keyword args intact
    assert not _has_ident(out, "url")


def test_closure_freevar_not_renamed():
    src = textwrap.dedent('''
        def make_counter(start):
            count = start
            def inc():
                nonlocal count
                count += 1
                return count
            return inc
    ''')
    out, _ = pystrings.harden_source(src, seed=b"s", rename=True)
    c = _run(out)["make_counter"](0)
    assert (c(), c(), c()) == (1, 2, 3)            # closure still works


def test_comprehension_freevar_not_renamed():
    src = textwrap.dedent('''
        def totals(items):
            factor = 10
            return [x * factor for x in items]
    ''')
    out, _ = pystrings.harden_source(src, seed=b"s", rename=True)
    assert _run(out)["totals"]([1, 2, 3]) == [10, 20, 30]


def test_local_renamed_even_with_comprehension_present():
    src = textwrap.dedent('''
        def f(items):
            marker = 1
            squares = [i * i for i in items]
            return marker + len(squares)
    ''')
    out, stats = pystrings.harden_source(src, seed=b"s", rename=True)
    assert stats["names_renamed"] >= 2
    assert not _has_ident(out, "marker") and not _has_ident(out, "squares")
    assert _run(out)["f"]([1, 2, 3]) == 4


def test_global_function_skipped():
    src = textwrap.dedent('''
        G = 0
        def bump():
            global G
            G += 1
            return G
    ''')
    out, stats = pystrings.harden_source(src, seed=b"s", rename=True)
    assert stats["names_renamed"] == 0
    ns = _run(out)
    assert (ns["bump"](), ns["bump"]()) == (1, 2)


def test_dynamic_locals_call_skipped():
    # renaming here would change the dict keys locals() returns -> must skip
    src = textwrap.dedent('''
        def dyn():
            secret = 42
            return locals()
    ''')
    out, stats = pystrings.harden_source(src, seed=b"s", rename=True)
    assert stats["names_renamed"] == 0
    assert _run(out)["dyn"]() == {"secret": 42}
