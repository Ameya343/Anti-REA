"""Safe Python local-variable renamer (opt-in).

Descriptive names are a top signal for AI-assisted reconstruction. Fully
renaming Python identifiers is unsafe in general (reflection, keyword args,
cross-module imports, closures). This pass therefore renames ONLY the set it can
prove is safe, and leaves everything else untouched:

Renamed:  a variable that is
  * bound by plain assignment at a function's OWN level (=, for/with targets,
    augmented assign, walrus), and
  * never a parameter, and
  * never used inside any nested scope (lambda/comprehension/inner def/class),
    so it is not a closure cell and cannot be referenced from another scope, and
  * not a dunder.

Never touched:  parameters (keyword-call safety), function/class names and
imports (cross-module + reflection), module- and class-level names, anything in
a function that declares global/nonlocal or calls locals/globals/vars/eval/exec.

Because a renamed name is purely local, not a parameter, and never appears in a
nested scope, renaming every occurrence of it within its function body is
behavior-preserving on all Python 3 versions. The engine additionally verifies
each hardened file with compile() and reverts on any failure.
"""

from __future__ import annotations

import ast
import builtins
import keyword

_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef,
                ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_DYNAMIC_CALLS = {"locals", "globals", "vars", "eval", "exec", "compile"}


def _param_names(args: ast.arguments) -> set[str]:
    names = set()
    for a in (list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)):
        names.add(a.arg)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _names_in_target(t: ast.AST) -> set[str]:
    out = set()
    if isinstance(t, ast.Name):
        out.add(t.id)
    elif isinstance(t, ast.Starred):
        out |= _names_in_target(t.value)
    elif isinstance(t, (ast.Tuple, ast.List)):
        for e in t.elts:
            out |= _names_in_target(e)
    return out


def _own_walk(stmts):
    """Yield nodes in the scope owning `stmts`, not descending nested scopes.

    Nested scope nodes are yielded themselves (so callers can inspect them) but
    their interiors are not traversed here.
    """
    stack = list(stmts)
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, _SCOPE_NODES):
            continue
        stack.extend(ast.iter_child_nodes(n))


def _all_identifiers(node: ast.AST) -> set[str]:
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.arg):
            out.add(n.arg)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(n.name)
        elif isinstance(n, ast.alias):
            out.add((n.asname or n.name).split(".")[0])
    return out


def _renameable_for(func: ast.AST) -> set[str]:
    params = _param_names(func.args)
    own_assigned: set[str] = set()
    nested: set[str] = set()
    for n in _own_walk(func.body):
        if isinstance(n, (ast.Global, ast.Nonlocal)):
            return set()  # bail on this function entirely
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) \
                and n.func.id in _DYNAMIC_CALLS:
            return set()
        if isinstance(n, _SCOPE_NODES):
            nested |= _all_identifiers(n)
            continue
        if isinstance(n, ast.Assign):
            for tgt in n.targets:
                own_assigned |= _names_in_target(tgt)
        elif isinstance(n, ast.AnnAssign) and n.value is not None:
            own_assigned |= _names_in_target(n.target)
        elif isinstance(n, ast.AugAssign):
            own_assigned |= _names_in_target(n.target)
        elif isinstance(n, (ast.For, ast.AsyncFor)):
            own_assigned |= _names_in_target(n.target)
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            for item in n.items:
                if item.optional_vars is not None:
                    own_assigned |= _names_in_target(item.optional_vars)
        elif isinstance(n, ast.NamedExpr):
            own_assigned |= _names_in_target(n.target)

    out = set()
    for name in own_assigned:
        if name in params or name in nested:
            continue
        if name.startswith("__") and name.endswith("__"):
            continue
        out.add(name)
    return out


def _fresh(reserved: set[str], counter: list[int]) -> str:
    while True:
        cand = f"_av{counter[0]}"
        counter[0] += 1
        if cand not in reserved:
            reserved.add(cand)
            return cand


def _transform(node, func_map: dict, func_maps: dict) -> None:
    if isinstance(node, ast.Name) and node.id in func_map:
        node.id = func_map[node.id]

    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        # decorators / defaults / annotations / returns live in the ENCLOSING scope
        for dec in node.decorator_list:
            _transform(dec, func_map, func_maps)
        _transform_args_enclosing(node.args, func_map, func_maps)
        if node.returns is not None:
            _transform(node.returns, func_map, func_maps)
        body_map = func_maps.get(id(node), {})
        for stmt in node.body:
            _transform(stmt, body_map, func_maps)
        return

    if isinstance(node, ast.Lambda):
        _transform_args_enclosing(node.args, func_map, func_maps)
        _transform(node.body, {}, func_maps)  # no outer rename can apply inside
        return

    for child in ast.iter_child_nodes(node):
        _transform(child, func_map, func_maps)


def _transform_args_enclosing(args: ast.arguments, func_map, func_maps) -> None:
    for d in args.defaults:
        _transform(d, func_map, func_maps)
    for d in args.kw_defaults:
        if d is not None:
            _transform(d, func_map, func_maps)
    allargs = (list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs))
    if args.vararg:
        allargs.append(args.vararg)
    if args.kwarg:
        allargs.append(args.kwarg)
    for a in allargs:
        if a.annotation is not None:
            _transform(a.annotation, func_map, func_maps)


def harden_names(tree: ast.Module) -> int:
    """Rename safe locals in-place. Returns the number of names renamed."""
    reserved = _all_identifiers(tree) | set(dir(builtins)) | set(keyword.kwlist)
    counter = [0]
    func_maps: dict[int, dict] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            renameable = _renameable_for(node)
            mapping = {}
            for old in sorted(renameable):
                mapping[old] = _fresh(reserved, counter)
            func_maps[id(node)] = mapping
    _transform(tree, {}, func_maps)  # module scope: nothing renamed
    return sum(len(m) for m in func_maps.values())
