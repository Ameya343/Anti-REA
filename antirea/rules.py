"""Signatures for the signals REA-style analysis uses as leverage.

Each rule maps to a concrete reverse-engineering leverage point:

* secrets  -> hardcoded credentials an analyst extracts verbatim
* endpoints-> API surface / routes used as "feature trace seeds"
* sourcemaps-> full original-source recovery
* symbols  -> native/debug metadata that yields readable pseudocode

Keep these conservative: false positives here only inflate the reversibility
score, they never silently rewrite code (Anti-REA never auto-edits secrets).
"""

import re

# --- Languages -------------------------------------------------------------

LANG_BY_EXT = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cxx": "cpp",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
    ".cs": "csharp",
    ".swift": "swift",
    ".css": "css",
    ".scss": "css",
    # Config / data files: scanned for leaked secrets, endpoints and strings.
    # (They have no "code", but are a common home for API keys and URLs.)
    ".json": "json",
    ".jsonc": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".ini": "ini",
    ".cfg": "ini",
    ".properties": "properties",
}

# Treated as compiled/binary artifacts: we look for symbol/debug leakage.
BINARY_EXT = {".so", ".dll", ".dylib", ".exe", ".o", ".a", ".node", ".wasm",
              ".apk", ".aab", ".ipa", ".jar", ".dex", ".class"}

C_LIKE = {"javascript", "typescript", "c", "cpp", "java", "kotlin", "go",
          "rust", "csharp", "swift", "css"}


# --- Secret signatures -----------------------------------------------------
# (name, compiled regex, severity 1-3)
SECRET_RULES = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 3),
    ("aws_secret_access_key",
     re.compile(r"(?i)aws.{0,20}?(secret|private).{0,5}?['\"][0-9a-zA-Z/+]{40}['\"]"), 3),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), 3),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), 3),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), 3),
    ("stripe_key", re.compile(r"\b[sr]k_(live|test)_[0-9a-zA-Z]{16,}\b"), 3),
    ("private_key_block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), 3),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), 2),
    ("generic_secret_assignment",
     re.compile(r"(?i)(?<![A-Za-z])(api[_-]?key|secret|passwd|password|token|"
                r"auth[_-]?token|client[_-]?secret|signing[_-]?secret)(?![A-Za-z])"
                r"['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]"), 2),
    ("bearer_literal", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}"), 2),
    ("high_entropy_hex",
     re.compile(r"['\"][0-9a-fA-F]{32,}['\"]"), 1),
]

# --- Endpoint / feature-seed signatures ------------------------------------
URL_RE = re.compile(r"\bhttps?://[^\s'\"`<>)]+", re.IGNORECASE)
# quoted path that looks like an API route, e.g. "/api/v1/users"
ROUTE_RE = re.compile(r"['\"`](/[A-Za-z0-9_][A-Za-z0-9_\-/]*(?:/[A-Za-z0-9_{}:.\-]+)+)['\"`]")
# Electron/IPC channel registration names, a prime REA feature seed.
IPC_RE = re.compile(
    r"\b(?:ipcMain|ipcRenderer)\.(?:on|handle|send|invoke)\(\s*['\"`]([^'\"`]+)['\"`]")

# --- Source map leakage ----------------------------------------------------
SOURCEMAP_REF_RE = re.compile(r"(?m)^[ \t]*(?://[#@]|/\*[#@])\s*sourceMappingURL=.*$")
INLINE_SOURCEMAP_RE = re.compile(r"sourceMappingURL=data:application/json")

# --- Identifiers / strings / comments --------------------------------------
IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
VOWEL_RE = re.compile(r"[aeiouAEIOU]")

# String literals. Triple-quoted forms come first so their multi-line contents
# are recognized as ONE string instead of leaking words into identifier counts
# (e.g. a Python docstring must not be scored as code). Then single-line single/
# double-quoted strings (which do not span newlines), then JS template literals.
STRING_RE = re.compile(
    r'"""[\s\S]*?"""'
    r"|'''[\s\S]*?'''"
    r'|"(?:\\.|[^"\\\n])*"'
    r"|'(?:\\.|[^'\\\n])*'"
    r"|`(?:\\.|[^`\\])*`"
)

# Minimal keyword set so we don't count language keywords as "meaningful names".
KEYWORDS = set("""
if else for while do switch case break continue return function func def class
const let var new delete typeof instanceof void this super import from export
public private protected static final abstract interface extends implements
try catch finally throw throws raise with as in is not and or none true false
null nil undefined print lambda yield async await package struct enum impl fn
self pub use mod match where type val fun object companion when suspend
""".split())


def guess_language(path):
    import os
    ext = os.path.splitext(path)[1].lower()
    if ext in BINARY_EXT:
        return "binary"
    return LANG_BY_EXT.get(ext)


def is_meaningful_identifier(name):
    """Heuristic: does this identifier leak human intent?

    Minified/obfuscated names (``a``, ``_0x3f``, ``t``, ``e2``) carry almost no
    semantic signal; descriptive names (``validateLicense``) do. REA's AI layer
    leans heavily on the latter to reconstruct features.
    """
    low = name.lower().strip("_$")
    if len(low) < 4:
        return False
    if low in KEYWORDS:
        return False
    if not VOWEL_RE.search(low):
        return False
    if low.startswith("0x") or name.startswith("_0x"):
        return False
    # Mostly-digits tail like "x123" is weak signal.
    letters = sum(c.isalpha() for c in low)
    return letters >= 3
