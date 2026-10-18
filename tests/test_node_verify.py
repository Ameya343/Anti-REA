"""Batched JS syntax verification + the revert-on-break safety net."""

import shutil

import pytest

from antirea.hardeners import engine, textfx

node = shutil.which("node")
needs_node = pytest.mark.skipif(not node, reason="node not available")


@needs_node
def test_batch_check_flags_only_broken(tmp_path):
    good = tmp_path / "good.js"
    good.write_text("const x = 1;\nfunction f() { return x; }\n", encoding="utf-8")
    bad = tmp_path / "bad.js"
    bad.write_text("const y = ;;;\nfunction (\n", encoding="utf-8")
    failed = engine._node_batch_check([str(good), str(bad)])
    assert str(bad) in failed
    assert str(good) not in failed


@needs_node
def test_harden_reverts_when_stripping_breaks_js(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.js").write_text(
        'var a = 1; // keep\nvar b = "https://x/y";\n//# sourceMappingURL=a.js.map\n',
        encoding="utf-8",
    )
    # Force the comment stripper to emit invalid JS so the batch check fails it.
    monkeypatch.setattr(textfx, "strip_c_comments", lambda t: ("function ( {", 1))
    out = tmp_path / "out"
    man = engine.harden_tree(str(src), str(out))
    assert man.reverted >= 1
    assert man.comments_stripped_files == 0          # the optimistic count was undone
    written = (out / "a.js").read_text(encoding="utf-8")
    assert "function ( {" not in written            # broken output not kept
    assert "var a = 1;" in written                   # reverted to safe base
    assert "sourceMappingURL" not in written          # source-map strip still applied
