"""Python source hardener (AST-based, semantics-preserving).

What it does, and why each step denies a REA signal:

* Encodes str/bytes literals into runtime-decoded integer tuples.
    -> REA uses readable string literals as "feature trace seeds" and the AI
       layer uses them to name features. After this, static extraction sees
       opaque numbers, not "/api/license/validate" or "Trial expired".
* Removes module/class/function docstrings.
    -> Docstrings are plain-English feature descriptions; pure gift to an LLM.
* Re-emits via ast.unparse, which drops all comments and original formatting.
    -> Comments are intent annotations; formatting/whitespace is a weak signal.

Honest limits (documented, not hidden):
* This defeats static grep and naive AI reading; it is NOT encryption. The key
  and decoder ship in the file, so a determined analyst who runs or single-steps
  the code can recover strings. The win is cost: casual/static/AI reconstruction
  gets much harder. For real secrets, move them server-side (see THREAT_MODEL).
* f-string literal parts are intentionally left intact (safe-by-default).
* Type annotations and ``match`` patterns are left intact (correctness).
* Requires the running interpreter to support the target's syntax (ast.unparse).
"""

from __future__ import annotations

import ast
import os

from . import pynames

HEADER_TEMPLATE = (
    "# hardened by anti-rea (string literals encoded; not encryption)\n"
    "def _ar_x(d, k):\n"
    "    return bytes(c ^ k[i % len(k)] for i, c in enumerate(d))\n"
    "def _ar_s(d, k):\n"
    "    return _ar_x(d, k).decode('utf-8')\n"
    "def _ar_b(d, k):\n"
    "    return _ar_x(d, k)\n"
    "_ar_k = {key!r}\n"
)


def _make_key(seed: bytes | None = None) -> tuple[int, ...]:
    if seed is not None:
        # deterministic key for reproducible tests
        return tuple((7 + i * 31 + seed[i % len(seed)]) % 251 + 1 for i in range(12))
    key = os.urandom(12)
    return tuple(b or 1 for b in key)  # avoid zero bytes (xor no-op)


def _collect_skip(tree: ast.AST) -> set[int]:
    """Constant nodes we must NOT replace (annotations and match patterns)."""
    skip: set[int] = set()

    def mark(node: ast.AST) -> None:
        for n in ast.walk(node):
            if isinstance(n, ast.Constant):
                skip.add(id(n))

    match_case = getattr(ast, "match_case", None)
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and node.annotation:
            mark(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.returns:
                mark(node.returns)
            a = node.args
            args = (list(a.args) + list(getattr(a, "posonlyargs", []))
                    + list(a.kwonlyargs))
            if a.vararg:
                args.append(a.vararg)
            if a.kwarg:
                args.append(a.kwarg)
            for arg in args:
                if arg and arg.annotation:
                    mark(arg.annotation)
        elif isinstance(node, ast.arg) and node.annotation:
            mark(node.annotation)
        elif match_case is not None and isinstance(node, match_case):
            mark(node.pattern)
    return skip


def _strip_docstrings(tree: ast.AST) -> int:
    removed = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                node.body = body[1:] or [ast.Pass()]
                removed += 1
    return removed


class _Encoder(ast.NodeTransformer):
    def __init__(self, key: tuple[int, ...], skip: set[int]):
        self.key = key
        self.skip = skip
        self.count = 0

    def visit_JoinedStr(self, node: ast.JoinedStr):  # f-strings: leave intact
        return node

    def visit_Constant(self, node: ast.Constant):
        if id(node) in self.skip:
            return node
        v = node.value
        if isinstance(v, str) and len(v) >= 2:
            return self._wrap("_ar_s", v.encode("utf-8"), node)
        if isinstance(v, (bytes, bytearray)) and len(v) >= 2:
            return self._wrap("_ar_b", bytes(v), node)
        return node

    def _wrap(self, fn: str, raw: bytes, origin: ast.AST) -> ast.AST:
        self.count += 1
        enc = [raw[i] ^ self.key[i % len(self.key)] for i in range(len(raw))]
        call = ast.Call(
            func=ast.Name(id=fn, ctx=ast.Load()),
            args=[
                ast.Tuple(elts=[ast.Constant(n) for n in enc], ctx=ast.Load()),
                ast.Name(id="_ar_k", ctx=ast.Load()),
            ],
            keywords=[],
        )
        return ast.copy_location(call, origin)


def harden_source(src: str, seed: bytes | None = None,
                  rename: bool = False) -> tuple[str, dict]:
    """Return (hardened_source, stats). Raises SyntaxError if src doesn't parse."""
    tree = ast.parse(src)
    names_renamed = pynames.harden_names(tree) if rename else 0
    skip = _collect_skip(tree)
    removed_docs = _strip_docstrings(tree)
    key = _make_key(seed)
    enc = _Encoder(key, skip)
    tree = enc.visit(tree)
    ast.fix_missing_locations(tree)
    body = ast.unparse(tree)
    header = HEADER_TEMPLATE.format(key=key)
    stats = {"strings_encoded": enc.count, "docstrings_removed": removed_docs,
             "names_renamed": names_renamed}
    return header + "\n" + body + "\n", stats


def harden_file(src_path: str, dst_path: str, seed: bytes | None = None,
                rename: bool = False) -> dict:
    with open(src_path, "r", encoding="utf-8") as fh:
        src = fh.read()
    note = None
    try:
        out, stats = harden_source(src, seed=seed, rename=rename)
        # Safety net: the output must at least compile. If renaming somehow
        # produced invalid code, fall back to encoding-only; never ship broken.
        try:
            compile(out, dst_path, "exec")
        except SyntaxError:
            if rename:
                out, stats = harden_source(src, seed=seed, rename=False)
                compile(out, dst_path, "exec")
                note = "rename reverted (failed compile verification)"
            else:
                raise
    except SyntaxError as exc:
        with open(dst_path, "w", encoding="utf-8", newline="") as fh:
            fh.write(src)
        return {"ok": False, "reason": f"syntax error, copied verbatim: {exc}"}
    with open(dst_path, "w", encoding="utf-8", newline="") as fh:
        fh.write(out)
    stats["ok"] = True
    if note:
        stats["note"] = note
    return stats
