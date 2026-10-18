"""Turn an AppReport into a Reversibility Score and a human/JSON report.

Reversibility score (0-100): higher means *easier* to reverse engineer.
Resistance score = 100 - reversibility.

The weighting reflects how much each signal actually helps a REA-style pass:
source maps and plaintext secrets are decisive; comments and descriptive names
are strong AI-comprehension aids; endpoints/IPC are feature seeds.
"""

from __future__ import annotations

import json

from .analyzers.rea_simulator import AppReport

# weights sum to 100 (the max reversibility contribution of each factor)
W_SOURCEMAP = 22      # full source recovery
W_SECRETS = 18        # verbatim credential/logic extraction
W_NAMES = 20          # descriptive identifiers -> AI feature reconstruction
W_COMMENTS = 10       # comments/docstrings -> intent
W_STRINGS = 15        # readable strings -> trace seeds + comprehension
W_SEEDS = 10          # endpoints/routes/ipc -> feature graph seeds
W_SYMBOLS = 5         # binary symbol/debug leakage


def _saturate(x: float) -> float:
    return 0.0 if x < 0 else (1.0 if x > 1 else x)


def compute_scores(rep: AppReport) -> dict:
    # source maps: any at all is most of the penalty
    sm = _saturate(rep.sourcemap_files / max(1, rep.total_files) * 4)
    sm = max(sm, 0.85 if rep.sourcemap_files else 0.0)

    # secrets: severity-weighted, saturates fast
    sev = sum(s for _, _, s in rep.secret_findings)
    secrets = _saturate(sev / 6.0)

    names = _saturate(rep.meaningful_ratio / 0.35)      # 35%+ meaningful == max
    comments = _saturate(rep.comment_density / 0.20)    # 20%+ comment lines == max
    strings = _saturate(rep.readable_strings / max(1, rep.total_strings) / 0.5)
    seeds = _saturate(len(rep.trace_seeds) / 40.0)
    symbols = _saturate(rep.binary_symbol_hits / 400.0)

    parts = {
        "source_maps": sm * W_SOURCEMAP,
        "secrets": secrets * W_SECRETS,
        "descriptive_names": names * W_NAMES,
        "comments": comments * W_COMMENTS,
        "readable_strings": strings * W_STRINGS,
        "feature_seeds": seeds * W_SEEDS,
        "binary_symbols": symbols * W_SYMBOLS,
    }
    reversibility = round(sum(parts.values()), 1)
    return {
        "reversibility": reversibility,
        "resistance": round(100 - reversibility, 1),
        "grade": _grade(100 - reversibility),
        "breakdown": {k: round(v, 1) for k, v in parts.items()},
    }


def _grade(resistance: float) -> str:
    if resistance >= 90:
        return "A"
    if resistance >= 75:
        return "B"
    if resistance >= 60:
        return "C"
    if resistance >= 40:
        return "D"
    return "F"


def to_dict(rep: AppReport) -> dict:
    scores = compute_scores(rep)
    seed_kinds: dict[str, int] = {}
    for kind, _, _ in rep.trace_seeds:
        seed_kinds[kind] = seed_kinds.get(kind, 0) + 1
    return {
        "root": rep.root,
        "files_scanned": rep.total_files,
        "scores": scores,
        "signals": {
            "sourcemap_files": rep.sourcemap_files,
            "secret_findings": len(rep.secret_findings),
            "meaningful_identifier_ratio": round(rep.meaningful_ratio, 3),
            "comment_density": round(rep.comment_density, 3),
            "readable_strings": rep.readable_strings,
            "total_strings": rep.total_strings,
            "feature_trace_seeds": len(rep.trace_seeds),
            "feature_trace_seed_kinds": seed_kinds,
            "binary_symbol_hits": rep.binary_symbol_hits,
        },
        "secret_findings": [
            {"file": p, "rule": r, "severity": s} for p, r, s in rep.secret_findings
        ],
        "top_trace_seeds": [
            {"kind": k, "value": (v[:80] + "...") if len(v) > 80 else v, "file": f}
            for k, v, f in rep.trace_seeds[:25]
        ],
    }


def render_text(rep: AppReport) -> str:
    d = to_dict(rep)
    s = d["scores"]
    lines = []
    lines.append("=" * 64)
    lines.append(" Anti-REA  -  Reversibility Report")
    lines.append("=" * 64)
    lines.append(f" Target        : {d['root']}")
    lines.append(f" Files scanned : {d['files_scanned']}")
    lines.append("")
    lines.append(f" REVERSIBILITY : {s['reversibility']:5}/100   (higher = easier to reverse)")
    lines.append(f" RESISTANCE    : {s['resistance']:5}/100   grade {s['grade']}")
    lines.append("")
    lines.append(" Contribution to reversibility (points):")
    for k, v in sorted(s["breakdown"].items(), key=lambda kv: -kv[1]):
        bar = "#" * int(v)
        lines.append(f"   {k:<20} {v:5.1f}  {bar}")
    lines.append("")
    sg = d["signals"]
    lines.append(" Leaked signals:")
    lines.append(f"   source-map files ...... {sg['sourcemap_files']}")
    lines.append(f"   hardcoded secrets ..... {sg['secret_findings']}")
    lines.append(f"   descriptive-name ratio  {sg['meaningful_identifier_ratio']:.0%}")
    lines.append(f"   comment density ....... {sg['comment_density']:.0%}")
    lines.append(f"   readable strings ...... {sg['readable_strings']}/{sg['total_strings']}")
    lines.append(f"   feature trace seeds ... {sg['feature_trace_seeds']} "
                 f"{sg['feature_trace_seed_kinds']}")
    if sg["binary_symbol_hits"]:
        lines.append(f"   binary symbol hits .... {sg['binary_symbol_hits']}")
    if d["secret_findings"]:
        lines.append("")
        lines.append(" !! Hardcoded secrets (never auto-edited - move them "
                     "server-side):")
        for f in d["secret_findings"][:15]:
            lines.append(f"    [sev {f['severity']}] {f['rule']}  ->  {f['file']}")
    if d["top_trace_seeds"]:
        lines.append("")
        lines.append(" Example feature trace seeds REA would use:")
        for t in d["top_trace_seeds"][:12]:
            lines.append(f"    ({t['kind']}) {t['value']}   [{t['file']}]")
    lines.append("=" * 64)
    return "\n".join(lines)


def render_json(rep: AppReport) -> str:
    return json.dumps(to_dict(rep), indent=2)
