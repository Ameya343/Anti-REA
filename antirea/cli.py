"""Anti-REA command-line interface.

    antirea scan    <path>            measure reverse-engineering signal (report)
    antirea score   <path>            just the reversibility/resistance numbers
    antirea harden  <src> <dst>       write a hardened copy of a source tree
    antirea gen-config <out_dir>      emit platform hardening configs/snippets
    antirea test-rea <path>           before/after demo vs a simulated REA pass
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from . import __version__, configs, platforms, report
from .analyzers.rea_simulator import scan_tree
from .hardeners.engine import harden_tree


def _cmd_scan(args) -> int:
    rep = scan_tree(args.path)
    print(report.render_json(rep) if args.json else report.render_text(rep))
    return 0


def _cmd_score(args) -> int:
    rep = scan_tree(args.path)
    scores = report.compute_scores(rep)
    if args.json:
        print(json.dumps(scores, indent=2))
    else:
        print(f"reversibility {scores['reversibility']}/100  |  "
              f"resistance {scores['resistance']}/100  |  grade {scores['grade']}")
    return 0


def _cmd_detect(args) -> int:
    det = platforms.detect(args.path)
    if args.json:
        print(json.dumps({"root": det.root, "platforms": det.platforms,
                          "evidence": det.evidence}, indent=2))
    else:
        print("platforms: " + (", ".join(det.platforms) or "(none detected)"))
        for p in det.platforms:
            print(f"  {p}: {', '.join(det.evidence[p])}")
        if det.platforms:
            print("\nrelevant configs: " + ", ".join(configs.configs_for(det.platforms)))
    return 0


def _cmd_harden(args) -> int:
    seed = bytes.fromhex(args.seed) if args.seed else None
    man = harden_tree(
        args.src, args.dst,
        strip_js_comments=not args.no_js_comments,
        force_comments=args.force_comments,
        seed=seed,
        rename=args.rename,
    )
    print(json.dumps(man.as_dict(), indent=2))
    if not args.no_rescore:
        before = report.compute_scores(scan_tree(args.src))
        after = report.compute_scores(scan_tree(args.dst))
        print("\nresistance: {} -> {}  (reversibility {} -> {})".format(
            before["resistance"], after["resistance"],
            before["reversibility"], after["reversibility"]))
    return 0


def _cmd_gen_config(args) -> int:
    plats = None  # None => all
    if args.for_path:
        det = platforms.detect(args.for_path)
        plats = det.platforms
        print("detected platforms: " + (", ".join(plats) or "(none)"))
    if args.platform:
        plats = None if "all" in args.platform else args.platform
    written = configs.write_configs(args.out_dir, platforms=plats)
    scope = "all platforms" if plats is None else ", ".join(plats)
    print(f"wrote {len(written)} config(s) for [{scope}] to {args.out_dir}:")
    for p in written:
        print("  " + os.path.basename(p))
    return 0


def _cmd_test_rea(args) -> int:
    src = os.path.abspath(args.path)
    before = scan_tree(src)
    b = report.compute_scores(before)

    tmp = args.out or tempfile.mkdtemp(prefix="antirea_hardened_")
    man = harden_tree(src, tmp, strip_js_comments=not args.no_js_comments,
                      force_comments=args.force_comments, rename=args.rename)
    det = platforms.detect(src)
    after = scan_tree(tmp)
    a = report.compute_scores(after)

    bd, ad = report.to_dict(before), report.to_dict(after)
    line = "-" * 60
    print(line)
    print(" Anti-REA  -  simulated REA pass  (BEFORE  ->  AFTER)")
    print(line)
    print(f" target: {src}")
    print(f" hardened copy: {tmp}")
    print(" platforms: " + (", ".join(det.platforms) or "(none detected)"))
    print(line)
    print(f" reversibility : {b['reversibility']:6} -> {a['reversibility']:<6}")
    print(f" resistance    : {b['resistance']:6} -> {a['resistance']:<6}   "
          f"grade {b['grade']} -> {a['grade']}")
    print(line)

    def row(label, x, y):
        print(f" {label:<26} {x!s:>8} -> {y!s:<8}")

    sb, sa = bd["signals"], ad["signals"]
    row("source-map files", sb["sourcemap_files"], sa["sourcemap_files"])
    row("hardcoded secrets", sb["secret_findings"], sa["secret_findings"])
    row("readable strings", sb["readable_strings"], sa["readable_strings"])
    row("feature trace seeds", sb["feature_trace_seeds"], sa["feature_trace_seeds"])
    row("comment density", f"{sb['comment_density']:.0%}", f"{sa['comment_density']:.0%}")
    row("descriptive-name ratio", f"{sb['meaningful_identifier_ratio']:.0%}",
        f"{sa['meaningful_identifier_ratio']:.0%}")
    print(line)
    print(" harden manifest:")
    for k, v in man.as_dict().items():
        if k in ("src", "dst", "notes"):
            continue
        print(f"   {k}: {v}")
    for note in man.notes:
        print(f"   note: {note}")
    print(line)
    if sa["secret_findings"]:
        print(" ACTION: secrets still present - Anti-REA never rewrites secrets.")
        print("         Move them server-side; rotate anything already shipped.")
    print(" Independent validation (NOT run by Anti-REA - review before running):")
    print("   REA's own CLI can analyze the hardened copy; compare its recovered")
    print("   evidence against the original, e.g. for a JS/Electron tree:")
    print(f"     npx -y rea-agents@latest analyze-javascript-application \"{tmp}\" --json")
    print(line)
    if not args.out and not args.keep:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
        print(" (removed temp hardened copy; pass --keep or --out DIR to retain)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="antirea", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"antirea {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="measure reverse-engineering signal")
    sp.add_argument("path")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_scan)

    sp = sub.add_parser("score", help="print reversibility/resistance scores")
    sp.add_argument("path")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_score)

    sp = sub.add_parser("detect", help="detect which platform(s) a target targets")
    sp.add_argument("path")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_detect)

    sp = sub.add_parser("harden", help="write a hardened copy of a source tree")
    sp.add_argument("src")
    sp.add_argument("dst")
    sp.add_argument("--rename", action="store_true",
                    help="also rename safe Python local variables (verified by compile)")
    sp.add_argument("--no-js-comments", action="store_true",
                    help="do not strip comments from JS/C-like files")
    sp.add_argument("--force-comments", action="store_true",
                    help="strip JS/C comments even when node --check is unavailable")
    sp.add_argument("--no-rescore", action="store_true",
                    help="skip the before/after resistance comparison")
    sp.add_argument("--seed", help="hex seed for deterministic string keys (testing)")
    sp.set_defaults(func=_cmd_harden)

    sp = sub.add_parser("gen-config", help="emit platform hardening configs")
    sp.add_argument("out_dir")
    sp.add_argument("--platform", nargs="*",
                    choices=list(platforms.PLATFORMS) + ["all"],
                    help="limit to these platforms (default: all)")
    sp.add_argument("--for", dest="for_path",
                    help="auto-detect platforms from this project path")
    sp.set_defaults(func=_cmd_gen_config)

    sp = sub.add_parser("test-rea", help="before/after demo vs a simulated REA pass")
    sp.add_argument("path")
    sp.add_argument("--out", help="write hardened copy here (kept)")
    sp.add_argument("--keep", action="store_true", help="keep the temp hardened copy")
    sp.add_argument("--rename", action="store_true",
                    help="also rename safe Python local variables")
    sp.add_argument("--no-js-comments", action="store_true")
    sp.add_argument("--force-comments", action="store_true")
    sp.set_defaults(func=_cmd_test_rea)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"antirea: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
