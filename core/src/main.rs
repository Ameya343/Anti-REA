// antirea-core: parallel signal extraction, a drop-in accelerator for the
// Python scanner. It MUST produce the same FileSignals the Python code does
// (tests/test_rust_parity.py enforces this); when in doubt, match Python.
//
// Protocol: stdin = JSON {"files":[{"p":"<path>","l":"<language|null>"}, ...]}
//           stdout = JSON {"files":[{...signals...}, ...]} in the same order.
// Only text languages are sent here; the Python side handles binaries.

use std::sync::LazyLock;

use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};

static SOURCEMAP_REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?://[#@]|/\*[#@])\s*sourceMappingURL=.*$").unwrap()
});
static STRING_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#""""[\s\S]*?""""#, "|",
        r#"'''[\s\S]*?'''"#, "|",
        r#""(?:\\.|[^"\\\n])*""#, "|",
        r#"'(?:\\.|[^'\\\n])*'"#, "|",
        r"`(?:\\.|[^`\\])*`",
    )).unwrap()
});
static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bhttps?://[^\s'"`<>)]+"#).unwrap());
static ROUTE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"`](/[A-Za-z0-9_][A-Za-z0-9_\-/]*(?:/[A-Za-z0-9_{}:.\-]+)+)['"`]"#).unwrap()
});
static IPC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:ipcMain|ipcRenderer)\.(?:on|handle|send|invoke)\(\s*['"`]([^'"`]+)['"`]"#)
        .unwrap()
});
static IDENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z_$][A-Za-z0-9_$]*").unwrap());

// (name, regex, severity). generic_secret_assignment is rewritten without
// look-around (unsupported by the regex crate) but is equivalent for presence.
static SECRET_RULES: LazyLock<Vec<(&'static str, Regex, u8)>> = LazyLock::new(|| {
    vec![
        ("aws_access_key_id", Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(), 3),
        ("aws_secret_access_key",
         Regex::new(r#"(?i)aws.{0,20}?(secret|private).{0,5}?['"][0-9a-zA-Z/+]{40}['"]"#).unwrap(), 3),
        ("google_api_key", Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b").unwrap(), 3),
        ("slack_token", Regex::new(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b").unwrap(), 3),
        ("github_token", Regex::new(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b").unwrap(), 3),
        ("stripe_key", Regex::new(r"\b[sr]k_(live|test)_[0-9a-zA-Z]{16,}\b").unwrap(), 3),
        ("private_key_block",
         Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----").unwrap(), 3),
        ("jwt",
         Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b").unwrap(), 2),
        ("generic_secret_assignment",
         Regex::new(concat!(
            r#"(?i)(?:^|[^A-Za-z])(api[_-]?key|secret|passwd|password|token|"#,
            r#"auth[_-]?token|client[_-]?secret|signing[_-]?secret)"#,
            r#"['"]?\s*[:=]\s*['"][^'"]{8,}['"]"#)).unwrap(), 2),
        ("bearer_literal", Regex::new(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}").unwrap(), 2),
        ("high_entropy_hex", Regex::new(r#"['"][0-9a-fA-F]{32,}['"]"#).unwrap(), 1),
    ]
});

const KEYWORDS: &[&str] = &[
    "if", "else", "for", "while", "do", "switch", "case", "break", "continue",
    "return", "function", "func", "def", "class", "const", "let", "var", "new",
    "delete", "typeof", "instanceof", "void", "this", "super", "import", "from",
    "export", "public", "private", "protected", "static", "final", "abstract",
    "interface", "extends", "implements", "try", "catch", "finally", "throw",
    "throws", "raise", "with", "as", "in", "is", "not", "and", "or", "none",
    "true", "false", "null", "nil", "undefined", "print", "lambda", "yield",
    "async", "await", "package", "struct", "enum", "impl", "fn", "self", "pub",
    "use", "mod", "match", "where", "type", "val", "fun", "object", "companion",
    "when", "suspend",
];

fn has_vowel(s: &str) -> bool {
    s.chars().any(|c| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u'))
}

fn is_meaningful(name: &str) -> bool {
    let low = name.to_lowercase();
    let low = low.trim_matches(|c| c == '_' || c == '$');
    if low.chars().count() < 4 {
        return false;
    }
    if KEYWORDS.contains(&low) {
        return false;
    }
    if !has_vowel(low) {
        return false;
    }
    if low.starts_with("0x") || name.starts_with("_0x") {
        return false;
    }
    low.chars().filter(|c| c.is_alphabetic()).count() >= 3
}

fn looks_readable(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    let core: String = if chars.len() >= 2 && matches!(chars[0], '"' | '\'' | '`') {
        chars[1..chars.len() - 1].iter().collect()
    } else {
        s.to_string()
    };
    let core = core.trim();
    if core.chars().count() < 4 {
        return false;
    }
    let letters = core.chars().filter(|c| c.is_alphabetic()).count();
    if letters < 3 {
        return false;
    }
    if core.contains(' ') || core.contains('/') || core.contains('_') || core.contains('.') {
        return true;
    }
    (letters as f64) / (core.chars().count() as f64) > 0.6
}

fn comment_code_lines(text: &str, is_python: bool) -> (u64, u64) {
    let (mut comment, mut code) = (0u64, 0u64);
    let mut in_block = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if is_python {
            if line.starts_with('#') {
                comment += 1;
            } else {
                code += 1;
            }
            continue;
        }
        if in_block {
            comment += 1;
            if line.contains("*/") {
                in_block = false;
            }
            continue;
        }
        if line.starts_with("//") {
            comment += 1;
        } else if line.starts_with("/*") {
            comment += 1;
            if !line.contains("*/") {
                in_block = true;
            }
        } else {
            code += 1;
        }
    }
    (comment, code)
}

#[derive(Deserialize)]
struct FileIn {
    p: String,
    l: Option<String>,
}
#[derive(Deserialize)]
struct Req {
    files: Vec<FileIn>,
}

#[derive(Serialize)]
struct FileOut {
    path: String,
    ok: bool,
    meaningful_idents: u64,
    total_idents: u64,
    comment_lines: u64,
    code_lines: u64,
    readable_strings: u64,
    total_strings: u64,
    urls: Vec<String>,
    routes: Vec<String>,
    ipc_channels: Vec<String>,
    secrets: Vec<(String, u8)>,
    has_sourcemap_ref: bool,
    has_inline_sourcemap: bool,
    has_sibling_map: bool,
    size: u64,
}
#[derive(Serialize)]
struct Resp {
    files: Vec<FileOut>,
}

fn analyze(f: &FileIn) -> FileOut {
    // Match Python's open(..., errors="replace"): lossy-decode rather than fail
    // on non-UTF-8 input, so both scanners see (and keep) the same files.
    let text = match std::fs::read(&f.p) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(_) => {
            return FileOut {
                path: f.p.clone(), ok: false, meaningful_idents: 0, total_idents: 0,
                comment_lines: 0, code_lines: 0, readable_strings: 0, total_strings: 0,
                urls: vec![], routes: vec![], ipc_channels: vec![], secrets: vec![],
                has_sourcemap_ref: false, has_inline_sourcemap: false,
                has_sibling_map: false, size: 0,
            };
        }
    };
    let is_python = f.l.as_deref() == Some("python");

    let has_sourcemap_ref = SOURCEMAP_REF.is_match(&text);
    let has_inline_sourcemap = text.contains("sourceMappingURL=data:application/json");
    let has_sibling_map = std::path::Path::new(&format!("{}.map", f.p)).exists();

    let (comment_lines, code_lines) = comment_code_lines(&text, is_python);

    let mut total_strings = 0u64;
    let mut readable_strings = 0u64;
    for m in STRING_RE.find_iter(&text) {
        total_strings += 1;
        if looks_readable(m.as_str()) {
            readable_strings += 1;
        }
    }

    let urls: Vec<String> = URL_RE.find_iter(&text).map(|m| m.as_str().to_string()).collect();
    let routes: Vec<String> =
        ROUTE_RE.captures_iter(&text).map(|c| c[1].to_string()).collect();
    let ipc_channels: Vec<String> =
        IPC_RE.captures_iter(&text).map(|c| c[1].to_string()).collect();

    let mut secrets = Vec::new();
    for (name, re, sev) in SECRET_RULES.iter() {
        if re.is_match(&text) {
            secrets.push((name.to_string(), *sev));
        }
    }

    let code_only = STRING_RE.replace_all(&text, "\"\"");
    let mut total_idents = 0u64;
    let mut meaningful_idents = 0u64;
    for m in IDENT_RE.find_iter(&code_only) {
        total_idents += 1;
        if is_meaningful(m.as_str()) {
            meaningful_idents += 1;
        }
    }

    FileOut {
        path: f.p.clone(), ok: true, meaningful_idents, total_idents, comment_lines,
        code_lines, readable_strings, total_strings, urls, routes, ipc_channels,
        secrets, has_sourcemap_ref, has_inline_sourcemap, has_sibling_map,
        size: text.len() as u64,
    }
}

fn main() {
    let mut input = String::new();
    if std::io::Read::read_to_string(&mut std::io::stdin(), &mut input).is_err() {
        std::process::exit(2);
    }
    let req: Req = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(_) => std::process::exit(2),
    };
    let files: Vec<FileOut> = req.files.par_iter().map(analyze).collect();
    let resp = Resp { files };
    println!("{}", serde_json::to_string(&resp).unwrap());
}
