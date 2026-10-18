"""JS/C text transforms: remove comments without corrupting code."""

from antirea.hardeners import textfx


def test_strip_sourcemaps():
    src = "const a = 1;\n//# sourceMappingURL=app.js.map\n"
    out, n = textfx.strip_sourcemaps(src)
    assert n == 1
    assert "sourceMappingURL" not in out
    assert "const a = 1;" in out


def test_line_and_block_comments_removed():
    src = "var x = 1; // keep code, drop this\n/* block\ncomment */ var y = 2;\n"
    out, n = textfx.strip_c_comments(src)
    assert "drop this" not in out
    assert "block" not in out
    assert "var x = 1;" in out and "var y = 2;" in out
    assert n == 2


def test_comment_markers_inside_strings_are_preserved():
    src = 'const u = "http://example.com/path"; // real comment\n'
    out, _ = textfx.strip_c_comments(src)
    assert "http://example.com/path" in out      # // inside string kept
    assert "real comment" not in out             # trailing comment removed


def test_regex_literal_with_slashes_preserved():
    # a regex containing // must not be eaten as a comment
    src = "const re = /a\\/\\/b/g;\nconst y = 2; // gone\n"
    out, _ = textfx.strip_c_comments(src)
    assert "/a\\/\\/b/g" in out
    assert "gone" not in out


def test_division_not_mistaken_for_regex():
    src = "const z = a / b / c; // tail\n"
    out, _ = textfx.strip_c_comments(src)
    assert "a / b / c" in out
    assert "tail" not in out


def test_template_literal_preserved():
    src = 'const t = `value ${x} // not a comment`; // real one\n'
    out, _ = textfx.strip_c_comments(src)
    assert "// not a comment" in out      # inside template, preserved
    assert "real one" not in out
