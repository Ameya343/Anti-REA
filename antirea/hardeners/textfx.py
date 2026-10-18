"""Text transforms for C-like languages (JS/TS/C/C++/Java/...).

Two transforms:

1. strip_sourcemaps(text)  -- ALWAYS SAFE. Removes `//# sourceMappingURL=` /
   `/*# sourceMappingURL= */` references. Combined with not copying sibling
   `.map` files (the engine's job), this denies REA full original-source
   recovery, which is the single biggest JS/TS leak.

2. strip_c_comments(text)  -- BEST EFFORT. A string/template/regex-aware scanner
   that removes line and block comments. JS's regex-vs-divide ambiguity means a
   hand-written scanner can never be 100% safe, so the engine verifies the
   result with `node --check` when Node is present and reverts on any failure;
   without Node it is opt-in (--force-comments).

For production JS minification + identifier mangling + string encryption, use a
real tool; Anti-REA emits ready configs for terser and javascript-obfuscator
(see antirea/configs and `antirea gen-config`).
"""

from __future__ import annotations

from ..rules import SOURCEMAP_REF_RE

# chars after which `/` begins a regex literal (not division)
_REGEX_PREV_CHARS = set("(,=:[!&|?;{}+-*%<>^~")
# keywords after which `/` begins a regex literal
_REGEX_PREV_WORDS = {"return", "typeof", "instanceof", "in", "of", "do", "else",
                     "yield", "case", "void", "delete", "new", "throw", "await"}


def strip_sourcemaps(text: str) -> tuple[str, int]:
    new, n = SOURCEMAP_REF_RE.subn("", text)
    return new, n


def _last_word(buf: list[str]) -> str:
    # read back over emitted chars to get the trailing identifier word
    i = len(buf) - 1
    word = []
    while i >= 0 and (buf[i].isalnum() or buf[i] in "_$"):
        word.append(buf[i])
        i -= 1
    return "".join(reversed(word))


def strip_c_comments(text: str) -> tuple[str, int]:
    out: list[str] = []
    i, n = 0, len(text)
    removed = 0
    prev_sig = ""

    while i < n:
        c = text[i]
        nx = text[i + 1] if i + 1 < n else ""

        # line comment
        if c == "/" and nx == "/":
            j = text.find("\n", i)
            removed += 1
            if j == -1:
                break
            i = j  # keep the newline
            continue

        # block comment
        if c == "/" and nx == "*":
            j = text.find("*/", i + 2)
            removed += 1
            out.append(" ")  # avoid gluing adjacent tokens
            if j == -1:
                break
            i = j + 2
            continue

        # string / template literal: copy verbatim
        if c in ("\"", "'", "`"):
            q = c
            out.append(c)
            i += 1
            while i < n:
                d = text[i]
                out.append(d)
                if d == "\\" and i + 1 < n:
                    out.append(text[i + 1])
                    i += 2
                    continue
                i += 1
                if d == q:
                    break
            prev_sig = q
            continue

        # regex literal (heuristic)
        if c == "/":
            word = _last_word(out)
            is_regex = (prev_sig == "" or prev_sig in _REGEX_PREV_CHARS
                        or word in _REGEX_PREV_WORDS)
            if is_regex:
                out.append(c)
                i += 1
                in_class = False
                while i < n:
                    d = text[i]
                    out.append(d)
                    if d == "\\" and i + 1 < n:
                        out.append(text[i + 1])
                        i += 2
                        continue
                    i += 1
                    if d == "[":
                        in_class = True
                    elif d == "]":
                        in_class = False
                    elif d == "/" and not in_class:
                        break
                prev_sig = "/"
                continue

        out.append(c)
        if not c.isspace():
            prev_sig = c
        i += 1

    return "".join(out), removed
